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
    about = "Read Bramble vaults through a manually unsealed local daemon"
)]
struct Cli {
    #[arg(long, env = "BRAMBLE_SOCKET")]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Daemon { vault: PathBuf },
    Unseal,
    Seal,
    Status,
    Get { id: String },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Unseal { password: String },
    Seal,
    Status,
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
fn get(v: &Vault, id: &str) -> Result<String, String> {
    if vault_crypto::is_locked() {
        return Err("daemon is sealed".into());
    }
    if v.ciphertext.is_empty() {
        return Err("entry not found".into());
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
    let entry = entries
        .iter()
        .find(|x| x.get("id").and_then(|v| v.as_str()) == Some(id))
        .ok_or("entry not found")?;
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
    let mut value = value.map_err(|_| "invalid decrypted entry")?;
    let password = value
        .get_mut("password")
        .and_then(|v| v.as_str())
        .ok_or("entry has no password")?
        .to_owned();
    if let Some(serde_json::Value::String(s)) = value.get_mut("password") {
        s.zeroize();
    }
    Ok(password)
}
fn handle(req: Request, vault: &Path) -> Response {
    match req {
        Request::Status => ok(if vault_crypto::is_locked() {
            "sealed"
        } else {
            "unsealed"
        }),
        Request::Seal => {
            vault_crypto::lock();
            ok("sealed")
        }
        Request::Unseal { mut password } => {
            if !vault_crypto::is_locked() {
                password.zeroize();
                return fail("already unsealed");
            }
            let result = read_vault(vault).and_then(|v| unlock(&v, &password));
            password.zeroize();
            match result {
                Ok(true) => ok("unsealed"),
                Ok(false) => fail("incorrect password or no password slot"),
                Err(e) => fail(e),
            }
        }
        Request::Get { id } => match read_vault(vault).and_then(|v| get(&v, &id)) {
            Ok(x) => ok(x),
            Err(e) => fail(e),
        },
    }
}
fn daemon(socket: &Path, vault: &Path) -> Result<(), String> {
    read_vault(vault)?;
    let parent = socket.parent().ok_or("socket needs a parent directory")?;
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
        return Err(
            "socket directory must be owned by the current user and accessible only by that user"
                .into(),
        );
    }
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
                Ok(req) => handle(req, vault),
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
fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let socket = socket_path(cli.socket)?;
    let mut request = match cli.command {
        Command::Daemon { vault } => return daemon(&socket, &vault),
        Command::Unseal => Request::Unseal {
            password: rpassword::prompt_password("Master password: ").map_err(|e| e.to_string())?,
        },
        Command::Seal => Request::Seal,
        Command::Status => Request::Status,
        Command::Get { id } => Request::Get { id },
    };
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
    let response: Response = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    line.zeroize();
    if response.ok {
        println!("{}", response.message);
        Ok(())
    } else {
        Err(response.message)
    }
}
use std::io::Read;
