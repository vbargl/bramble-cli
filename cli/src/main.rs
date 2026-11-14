mod desktop;

use base64::{engine::general_purpose::STANDARD as b64, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    version,
    about = "Read Bramble credentials through a local daemon or paired desktop app"
)]
struct Cli {
    #[arg(long, env = "BRAMBLE_SOCKET")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Daemon {
        vault: PathBuf,
        /// Enable the paired desktop as an additional credential source.
        #[arg(long)]
        desktop: bool,
        #[command(flatten)]
        connection: desktop::Options,
    },
    /// Pair this CLI with the desktop app (open Settings → Connect a browser first).
    Pair {
        #[command(flatten)]
        connection: desktop::Options,
    },
    Unseal {
        /// Prompt for the vault password even when the desktop is available.
        #[arg(long)]
        manual: bool,
    },
    Seal,
    Status,
    List {
        /// Desktop connections support exact hostname lookup, not full vault enumeration.
        #[arg(long)]
        hostname: Option<String>,
    },
    Get {
        id: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Unseal { password: String },
    Resume,
    Seal,
    Status,
    List { hostname: Option<String> },
    Get { id: String },
}
#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    message: String,
}
fn fail(message: impl ToString) -> Response {
    Response {
        ok: false,
        message: message.to_string(),
    }
}
fn ok(message: impl ToString) -> Response {
    Response {
        ok: true,
        message: message.to_string(),
    }
}
fn socket_path(p: Option<PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = p {
        return Ok(p);
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .ok_or("XDG_RUNTIME_DIR is required; alternatively use --socket")?;
    Ok(PathBuf::from(base).join("bramble-cli/socket"))
}
struct Vault {
    slots: Vec<Vec<u8>>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
}
fn parse(bytes: &[u8]) -> Result<Vault, String> {
    if bytes.len() < 6 || &bytes[..5] != b"VLT1\x02" {
        return Err("unsupported vault format (expected VLT1 version 2)".into());
    }
    let count = bytes[5] as usize;
    if !(1..=16).contains(&count) {
        return Err("invalid slot count".into());
    }
    let mut pos = 6;
    let mut slots = Vec::new();
    for _ in 0..count {
        let header = bytes.get(pos..pos + 3).ok_or("truncated slot header")?;
        let len = u16::from_be_bytes([header[1], header[2]]) as usize;
        pos += 3;
        let payload = bytes.get(pos..pos + len).ok_or("truncated slot")?;
        pos += len;
        if header[0] == 1 {
            if len != 124 {
                return Err("invalid password slot".into());
            }
            slots.push(payload.to_vec());
        }
    }
    let iv = bytes
        .get(pos..pos + 12)
        .ok_or("truncated entries IV")?
        .to_vec();
    pos += 12;
    Ok(Vault {
        slots,
        iv,
        ciphertext: bytes[pos..].to_vec(),
    })
}
fn read_vault(path: &Path) -> Result<Vault, String> {
    parse(&fs::read(path).map_err(|e| e.to_string())?)
}
fn unlock(v: &Vault, password: &str) -> Result<bool, String> {
    for s in &v.slots {
        let result = vault_crypto::unwrap_vek_password(
            password.to_owned(),
            b64.encode(&s[16..32]),
            b64.encode(&s[..16]),
            b64.encode(&s[32..64]),
            b64.encode(&s[64..76]),
            b64.encode(&s[76..124]),
            b"VLT1\x02".to_vec(),
        )
        .map_err(|e| e.to_string())?;
        if result {
            return Ok(true);
        }
    }
    Ok(false)
}
fn entries(v: &Vault) -> Result<Vec<serde_json::Value>, String> {
    if vault_crypto::is_locked() {
        return Err("daemon is sealed".into());
    }
    if v.ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    let mut outer = vault_crypto::decrypt_with_vek(b64.encode(&v.iv), b64.encode(&v.ciphertext))
        .map_err(|e| e.to_string())?;
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&outer);
    outer.zeroize();
    let payload = parsed.map_err(|_| "invalid entries payload")?;
    let entries = payload
        .get("entries")
        .and_then(|x| x.as_array())
        .or_else(|| payload.as_array())
        .ok_or("invalid entries payload")?;
    Ok(entries.clone())
}
fn decrypt(entry: &serde_json::Value) -> Result<serde_json::Value, String> {
    let field = |name| {
        entry
            .get(name)
            .and_then(|v| v.as_str())
            .map(str::to_owned)
            .ok_or("invalid encrypted entry")
    };
    let mut plain = vault_crypto::decrypt_entry(
        field("ciphertext")?,
        field("iv")?,
        field("wrappedDek")?,
        field("dekIv")?,
    )
    .map_err(|e| e.to_string())?;
    let value: Result<serde_json::Value, _> = serde_json::from_str(&plain);
    plain.zeroize();
    value.map_err(|_| "invalid decrypted entry".into())
}
fn get(v: &Vault, id: &str) -> Result<String, String> {
    let entries = entries(v)?;
    let entry = entries
        .iter()
        .find(|x| x.get("id").and_then(|v| v.as_str()) == Some(id))
        .ok_or("entry not found")?;
    let mut value = decrypt(entry)?;
    let password = value
        .get("password")
        .and_then(|v| v.as_str())
        .ok_or("entry has no password")?
        .to_owned();
    if let Some(serde_json::Value::String(s)) = value.get_mut("password") {
        s.zeroize();
    }
    Ok(password)
}
fn list(v: &Vault) -> Result<String, String> {
    let mut result = Vec::new();
    for entry in entries(v)? {
        let id = entry
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or("invalid entry id")?;
        let mut value = decrypt(&entry)?;
        let name = value.get("name").and_then(|x| x.as_str()).unwrap_or("");
        result.push(serde_json::json!({"id": id, "name": name}));
        if let Some(serde_json::Value::String(s)) = value.get_mut("password") {
            s.zeroize();
        }
    }
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

struct State {
    vault: PathBuf,
    desktop: Option<(PathBuf, PathBuf)>,
    desktop_enabled: bool,
}
impl State {
    fn desktop_request(&self, body: serde_json::Value) -> Result<serde_json::Value, String> {
        let (socket, identity) = self
            .desktop
            .as_ref()
            .ok_or("desktop connection is not enabled")?;
        if !self.desktop_enabled {
            return Err("daemon is sealed".into());
        }
        desktop::request(socket, identity, body)
    }
    fn desktop_status(&self) -> Result<(), String> {
        self.desktop_request(
            serde_json::json!({"op":"query", "hostname":"bramble-cli-status.invalid"}),
        )
        .map(|_| ())
    }
}

fn handle(req: Request, state: &mut State) -> Response {
    let result = match req {
        Request::Status => {
            if !vault_crypto::is_locked() {
                return ok("unsealed");
            }
            if !state.desktop_enabled {
                return ok("sealed");
            }
            return ok(match state.desktop_status() {
                Ok(()) => "unsealed (desktop)".into(),
                Err(e) => format!("sealed ({e})"),
            });
        }
        Request::Seal => {
            vault_crypto::lock();
            state.desktop_enabled = false;
            return ok("sealed");
        }
        Request::Resume => {
            if !vault_crypto::is_locked() {
                return ok("unsealed");
            }
            state.desktop_enabled = state.desktop.is_some();
            match state.desktop_status() {
                Ok(()) => return ok("unsealed (desktop)"),
                Err(e) => {
                    state.desktop_enabled = false;
                    Err(e)
                }
            }
        }
        Request::Unseal { mut password } => {
            if !vault_crypto::is_locked() {
                password.zeroize();
                return fail("already unsealed");
            }
            let result = read_vault(&state.vault).and_then(|v| unlock(&v, &password));
            password.zeroize();
            match result {
                Ok(true) => return ok("unsealed"),
                Ok(false) => Err("incorrect password or no password slot".into()),
                Err(e) => Err(e),
            }
        }
        Request::List { hostname } => {
            if !vault_crypto::is_locked() {
                if hostname.is_some() {
                    Err("hostname lookup requires desktop access; omit --hostname to list the local vault".into())
                } else {
                    read_vault(&state.vault).and_then(|v| list(&v))
                }
            } else {
                hostname.filter(|h| !h.trim().is_empty()).ok_or_else(|| "desktop lookup requires list --hostname HOST; full list requires manual unseal".into())
                    .and_then(|hostname| state.desktop_request(serde_json::json!({"op":"query", "hostname":hostname})))
                    .and_then(|answer| answer.get("matches").and_then(|m| m.as_array()).ok_or("desktop reply missing matches".into()).and_then(|matches| {
                        let items: Vec<_> = matches.iter().map(|m| serde_json::json!({"id":m["id"], "name":m["name"]})).collect();
                        serde_json::to_string(&items).map_err(|e| e.to_string())
                    }))
            }
        }
        Request::Get { id } => {
            if !vault_crypto::is_locked() {
                read_vault(&state.vault).and_then(|v| get(&v, &id))
            } else {
                state
                    .desktop_request(serde_json::json!({"op":"fetch", "id":id}))
                    .and_then(|mut answer| {
                        let password = answer
                            .get_mut("password")
                            .map(serde_json::Value::take)
                            .ok_or("desktop reply missing password")?;
                        match password {
                            serde_json::Value::String(s) => Ok(s),
                            _ => Err("desktop reply missing password".into()),
                        }
                    })
            }
        }
    };
    match result {
        Ok(x) => ok(x),
        Err(e) => fail(e),
    }
}

fn private_dir(parent: &Path) -> Result<(), String> {
    if !parent.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|e| e.to_string())?;
    }
    let meta = fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
    if !meta.is_dir()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("socket or pairing directory must be owned by the current user and accessible only by that user".into());
    }
    Ok(())
}

fn daemon(socket: &Path, vault: &Path, desktop: Option<(PathBuf, PathBuf)>) -> Result<(), String> {
    read_vault(vault)?;
    let parent = socket.parent().ok_or("socket needs a parent directory")?;
    private_dir(parent)?;
    let mut state = State {
        vault: vault.to_owned(),
        desktop_enabled: desktop.is_some(),
        desktop,
    };
    let listener = UnixListener::bind(socket).map_err(|e| format!("bind socket: {e}"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    vault_crypto::lock();
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut line = String::new();
        let read = BufReader::new(&stream)
            .take(1024 * 1024)
            .read_line(&mut line);
        let mut response = match read {
            Ok(_) => match serde_json::from_str(&line) {
                Ok(req) => handle(req, &mut state),
                Err(_) => fail("invalid request"),
            },
            Err(_) => fail("read error"),
        };
        line.zeroize();
        let mut encoded = serde_json::to_vec(&response).unwrap();
        encoded.push(b'\n');
        let _ = stream.write_all(&encoded);
        encoded.zeroize();
        response.message.zeroize();
    }
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
fn call(socket: &Path, mut request: Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    let mut data = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    data.push(b'\n');
    if let Request::Unseal { password } = &mut request {
        password.zeroize();
    }
    let result = stream.write_all(&data);
    data.zeroize();
    result.map_err(|e| e.to_string())?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    let response = serde_json::from_str(&line).map_err(|e| e.to_string());
    line.zeroize();
    response
}
fn run() -> Result<(), String> {
    let cli = Cli::parse();
    // Pairing talks directly to the desktop, so it needs neither a daemon nor XDG_RUNTIME_DIR.
    if let Command::Pair { connection } = &cli.command {
        let (socket, identity) = connection.paths()?;
        desktop::pair(&socket, &identity, |digits| {
            eprintln!("Compare with the desktop: {digits}");
            eprint!("Do all twelve digits match? Type yes to confirm: ");
            std::io::stderr().flush().map_err(|e| e.to_string())?;
            let mut answer = String::new();
            std::io::stdin()
                .read_line(&mut answer)
                .map_err(|e| e.to_string())?;
            Ok(answer.trim() == "yes")
        })?;
        println!("paired with desktop");
        return Ok(());
    }
    let socket = socket_path(cli.socket)?;
    let request = match cli.command {
        Command::Daemon {
            vault,
            desktop,
            connection,
        } => {
            let desktop = if desktop {
                Some(connection.paths()?)
            } else {
                None
            };
            return daemon(&socket, &vault, desktop);
        }
        Command::Unseal { manual } => {
            if !manual {
                let response = call(&socket, Request::Resume)?;
                if response.ok {
                    println!("{}", response.message);
                    return Ok(());
                }
                eprintln!("{}; trying manual unseal", response.message);
            }
            Request::Unseal {
                password: rpassword::prompt_password("Master password: ")
                    .map_err(|e| e.to_string())?,
            }
        }
        Command::Seal => Request::Seal,
        Command::Status => Request::Status,
        Command::List { hostname } => Request::List { hostname },
        Command::Get { id } => Request::Get { id },
        Command::Pair { .. } => unreachable!(),
    };
    let mut response = call(&socket, request)?;
    if response.ok {
        println!("{}", response.message);
        response.message.zeroize();
        Ok(())
    } else {
        Err(response.message)
    }
}
use std::io::Read;

#[cfg(test)]
mod tests;
