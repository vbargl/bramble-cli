mod desktop;
mod guidance;
mod pairing_ui;
mod service;

use base64::{engine::general_purpose::STANDARD as b64, Engine};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
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
    /// Never prompt; report the next command instead.
    #[arg(long, global = true)]
    no_input: bool,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the daemon in this terminal (selects the only local vault when omitted).
    Daemon(Source),
    /// Install, start or stop the user daemon service.
    Service {
        #[command(subcommand)]
        action: ServiceCommand,
    },
    /// Pair with desktop Bramble using an interactive setup checklist.
    Pair {
        #[command(flatten)]
        connection: desktop::Options,
    },
    /// Enable access through the desktop, or unlock the local vault manually.
    Unseal {
        /// Prompt for the vault password even when the desktop is available.
        #[arg(long)]
        manual: bool,
    },
    /// Disable all credential access through this daemon.
    Seal,
    /// Show daemon availability and vault access without changing anything.
    Status,
    /// List entry IDs and names (desktop mode requires --hostname).
    List {
        /// Desktop connections support exact hostname lookup, not full vault enumeration.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Print the password for one entry ID.
    Get { id: String },
}
#[derive(clap::Args)]
struct Source {
    /// Local .vlt file; omit when the desktop has exactly one vault.
    vault: Option<PathBuf>,
    /// Enable the paired desktop as an additional credential source.
    #[arg(long)]
    desktop: bool,
    #[command(flatten)]
    connection: desktop::Options,
}
#[derive(Subcommand)]
enum ServiceCommand {
    /// Install and start a user service, including automatic startup on login.
    Install(Source),
    /// Start the installed user service.
    Start,
    /// Stop the user service and discard any manually unsealed key.
    Stop,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum Request {
    Unseal { password: String },
    Resume,
    Seal,
    Status,
    List { hostname: Option<String> },
    Get { id: String },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NextAction {
    Unseal,
    Pair,
    OpenDesktop,
    OpenPairedVault,
    ManualList,
    Hostname,
    SelectEntry,
}
#[derive(Serialize, Deserialize)]
struct Response {
    ok: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<NextAction>,
}
fn fail(message: impl ToString) -> Response {
    Response {
        ok: false,
        message: message.to_string(),
        next: None,
    }
}
fn ok(message: impl ToString) -> Response {
    Response {
        ok: true,
        message: message.to_string(),
        next: None,
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
    parse(&fs::read(path).map_err(|e| {
        format!(
            "Cannot read vault {}: {e}. Choose an existing vault file accessible to this user.",
            path.display()
        )
    })?)
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
    let credential = matches!(req, Request::Get { .. } | Request::List { .. });
    if credential && vault_crypto::is_locked() && !state.desktop_enabled {
        let mut response = fail("Daemon is sealed.");
        response.next = Some(NextAction::Unseal);
        return response;
    }
    let result = match req {
        Request::Status => {
            if !vault_crypto::is_locked() {
                return ok("unsealed");
            }
            if !state.desktop_enabled {
                let mut response = ok("sealed");
                response.next = Some(NextAction::Unseal);
                return response;
            }
            return match state.desktop_status() {
                Ok(()) => ok("unsealed (desktop)"),
                Err(e) => {
                    let mut response = access_failure(e);
                    response.ok = true;
                    response.message = format!("sealed: {}", response.message);
                    response
                }
            };
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
        Err(e) => access_failure(e),
    }
}

fn access_failure(e: String) -> Response {
    let next = if e == "daemon is sealed" {
        Some(NextAction::Unseal)
    } else if e == "desktop: locked" {
        Some(NextAction::OpenDesktop)
    } else if e == "desktop: not linked to the open vault" {
        Some(NextAction::OpenPairedVault)
    } else if e == "desktop: not linked to this app" {
        Some(NextAction::Pair)
    } else if e == "desktop: not paired" {
        Some(NextAction::Pair)
    } else if e.starts_with("connect desktop:") {
        Some(NextAction::OpenDesktop)
    } else if e.starts_with("desktop lookup requires") {
        Some(NextAction::ManualList)
    } else if e.starts_with("hostname lookup requires") {
        Some(NextAction::Hostname)
    } else if e == "entry not found" || e == "desktop: unknown entry" {
        Some(NextAction::SelectEntry)
    } else {
        None
    };
    let message = match next {
        Some(NextAction::Unseal) => "Daemon is sealed.".to_owned(),
        Some(NextAction::Pair) => "The CLI is not paired with this desktop vault.".to_owned(),
        Some(NextAction::OpenDesktop) => {
            "Desktop Bramble is unavailable or its vault is locked.".to_owned()
        }
        Some(NextAction::OpenPairedVault) => {
            "The open desktop vault is not paired with this CLI.".to_owned()
        }
        Some(NextAction::ManualList) => {
            "Desktop access can list logins by hostname only.".to_owned()
        }
        Some(NextAction::Hostname) => {
            "The local vault is manually unsealed; hostname lookup uses desktop access.".to_owned()
        }
        Some(NextAction::SelectEntry) => "Entry was not found in this vault.".to_owned(),
        None => e,
    };
    Response {
        ok: false,
        message,
        next,
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

fn bind_daemon(socket: &Path) -> Result<(UnixListener, fs::File), String> {
    let mut lock_name = socket.as_os_str().to_owned();
    lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&lock_path)
        .map_err(|e| format!("Cannot reserve daemon socket {}: {e}", socket.display()))?;
    let meta = lock.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.permissions().mode() & 0o077 != 0
    {
        return Err("Daemon lock must be a private file owned by this account.".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::WouldBlock {
            return Err(format!("Cannot reserve the daemon socket: {error}"));
        }
        return Err(format!(
            "A daemon is already running at {}. Use status to check it.",
            socket.display()
        ));
    }
    match fs::symlink_metadata(socket) {
        Ok(meta) => {
            if !meta.file_type().is_socket() || meta.uid() != unsafe { libc::geteuid() } {
                return Err(format!("Cannot use {}: another file already occupies the socket path. Choose another --socket path.", socket.display()));
            }
            match UnixStream::connect(socket) {
                Ok(_) => return Err("A daemon is already running. Use status to check it.".into()),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) =>
                {
                    fs::remove_file(socket)
                        .map_err(|e| format!("Cannot remove stale daemon socket: {e}"))?;
                }
                Err(e) => return Err(format!("Cannot check the existing daemon socket: {e}")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(format!("Cannot inspect daemon socket: {e}")),
    }
    let listener = UnixListener::bind(socket)
        .map_err(|e| format!("Cannot start daemon at {}: {e}", socket.display()))?;
    Ok((listener, lock))
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
    let (listener, _lock) = bind_daemon(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    vault_crypto::lock();
    eprintln!("✅ Daemon started");
    eprintln!(
        "⏳ In another terminal, run: {}",
        guidance::command(Some(socket), &["status"])
    );
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
fn call(mut stream: UnixStream, mut request: Request) -> Result<Response, String> {
    let seconds = if matches!(request, Request::Unseal { .. }) {
        30
    } else {
        5
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(seconds)))
        .and_then(|_| stream.set_write_timeout(Some(std::time::Duration::from_secs(5))))
        .map_err(|_| "Cannot configure the daemon connection.".to_owned())?;
    let mut data = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    data.push(b'\n');
    if let Request::Unseal { password } = &mut request {
        password.zeroize();
    }
    let result = stream.write_all(&data);
    data.zeroize();
    result.map_err(|_| {
        "Daemon connection was lost. Retry the command after checking the daemon's terminal or user-service log.".to_owned()
    })?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|_| "Daemon did not answer. Check its terminal, or run: journalctl --user -u bramble-cli.service -n 20 --no-pager".to_owned())?;
    let response = serde_json::from_str(&line).map_err(|_| {
        "Daemon returned an invalid response. Restart the daemon with the same CLI version."
            .to_owned()
    });
    line.zeroize();
    response
}
fn next_command(next: NextAction, socket: &Path) -> String {
    match next {
        NextAction::Unseal => format!("Run: {}", guidance::command(Some(socket), &["unseal"])),
        NextAction::Pair => format!(
            "Pair using {}, or unlock locally using {}.",
            guidance::command(None, &["pair"]),
            guidance::command(Some(socket), &["unseal", "--manual"])
        ),
        NextAction::OpenDesktop => format!(
            "Open and unlock desktop Bramble, or run: {}",
            guidance::command(Some(socket), &["unseal", "--manual"])
        ),
        NextAction::OpenPairedVault => format!(
            "Open the originally paired vault in desktop Bramble, or run: {}",
            guidance::command(Some(socket), &["unseal", "--manual"])
        ),
        NextAction::ManualList => format!(
            "Use list --hostname HOST, or run {} for a full list.",
            guidance::command(Some(socket), &["unseal", "--manual"])
        ),
        NextAction::Hostname => "Omit --hostname to list the local vault.".into(),
        NextAction::SelectEntry => {
            "Use an entry ID from list (list --hostname HOST in desktop mode).".into()
        }
    }
}
fn response_result(mut response: Response, socket: &Path) -> Result<(), String> {
    if response.ok {
        println!("{}", response.message);
        response.message.zeroize();
        if let Some(next) = response.next {
            eprintln!("⏳ {}", next_command(next, socket));
        }
        Ok(())
    } else if let Some(next) = response.next {
        Err(format!(
            "{}\n⏳ {}",
            response.message,
            next_command(next, socket)
        ))
    } else {
        Err(response.message)
    }
}

fn run() -> Result<(), String> {
    use std::io::IsTerminal;
    let cli = Cli::parse();
    let interactive = !cli.no_input && std::io::stdin().is_terminal();
    // Pairing talks directly to the desktop, so it needs neither a daemon nor XDG_RUNTIME_DIR.
    if let Command::Pair { connection } = &cli.command {
        let (socket, identity) = connection.paths()?;
        pairing_ui::run(
            &socket,
            &identity,
            &mut std::io::stdin().lock(),
            &mut std::io::stderr(),
            interactive,
        )?;
        return Ok(());
    }
    let socket = socket_path(cli.socket)?;
    let managed = socket_path(None).ok().as_ref() == Some(&socket);
    let request = match cli.command {
        Command::Daemon(source) => {
            let vault = guidance::vault(source.vault, interactive)?;
            let desktop = if source.desktop {
                Some(source.connection.paths()?)
            } else {
                None
            };
            return daemon(&socket, &vault, desktop);
        }
        Command::Service { action } => {
            match action {
                ServiceCommand::Install(source) => {
                    let vault = guidance::vault(source.vault, interactive)?;
                    let desktop = if source.desktop {
                        Some(source.connection.paths()?)
                    } else {
                        None
                    };
                    service::install(&socket, &vault, desktop.as_ref())?;
                    eprintln!("✅ Daemon service installed and started");
                }
                ServiceCommand::Start => {
                    service::start(&socket)?;
                    eprintln!("✅ Daemon service started");
                }
                ServiceCommand::Stop => {
                    if service::stop()? {
                        eprintln!("✅ Daemon service stopped");
                    } else {
                        eprintln!("Daemon service is not installed; nothing to stop.");
                    }
                    return Ok(());
                }
            }
            eprintln!(
                "⏳ Check access: {}",
                guidance::command(Some(&socket), &["status"])
            );
            return Ok(());
        }
        Command::Unseal { manual } => {
            let stream = guidance::connect(&socket, managed, interactive)?;
            if !manual {
                let response = call(stream, Request::Resume)?;
                if response.ok {
                    return response_result(response, &socket);
                }
            } else {
                drop(stream);
            }
            if !interactive {
                return Err(format!("Manual unseal needs a password entered in a terminal.\n⏳ Run in a terminal: {}", guidance::command(Some(&socket), &["unseal", "--manual"])));
            }
            eprintln!("⏳ Unlock the local vault manually (independent of desktop Bramble)");
            let mut password = rpassword::prompt_password("Master password: ")
                .map_err(|_| "Cannot read the password. Run unseal in a terminal.".to_owned())?;
            let stream = match guidance::connect(&socket, managed, false) {
                Ok(stream) => stream,
                Err(e) => {
                    password.zeroize();
                    return Err(e);
                }
            };
            return response_result(call(stream, Request::Unseal { password })?, &socket);
        }
        Command::Seal => Request::Seal,
        Command::Status => Request::Status,
        Command::List { hostname } => Request::List { hostname },
        Command::Get { id } => Request::Get { id },
        Command::Pair { .. } => unreachable!(),
    };
    let can_guide = interactive && matches!(request, Request::List { .. } | Request::Get { .. });
    loop {
        let stream = guidance::connect(&socket, managed, can_guide)?;
        // Retrying contains no secrets: manual unseal returns above and is never replayed.
        let response = call(stream, request.clone())?;
        if !response.ok && can_guide {
            if let Some(
                next @ (NextAction::Unseal
                | NextAction::Pair
                | NextAction::OpenDesktop
                | NextAction::OpenPairedVault
                | NextAction::ManualList),
            ) = response.next
            {
                eprintln!("{}\n⏳ {}", response.message, next_command(next, &socket));
                guidance::read_answer("   Enter once ready to retry · q to cancel: ")?;
                continue;
            }
        }
        return response_result(response, &socket);
    }
}
use std::io::Read;

#[cfg(test)]
mod tests;
