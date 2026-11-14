mod desktop;
mod guidance;
mod pairing_ui;
mod service;
mod terminal;
mod vaults;
use vaults::State;

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
    /// Run the vault-independent daemon in this terminal.
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
        /// Vault name, ID or .vlt path; inferred only when unambiguous.
        vault: Option<PathBuf>,
        /// Prompt for the vault password even when the desktop is available.
        #[arg(long)]
        manual: bool,
    },
    /// Seal one vault; infer the target when exactly one is unsealed.
    Seal { vault: Option<PathBuf> },
    /// Show daemon availability and vault access without changing anything.
    Status,
    /// List entries across all unsealed vaults (desktop access needs --hostname).
    List {
        /// Desktop connections support exact hostname lookup, not full vault enumeration.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Find an entry across all unsealed vaults and print its password.
    Get { id: String },
}
#[derive(clap::Args)]
struct Source {
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
    #[serde(rename = "vault_unseal")]
    Unseal {
        vault: Option<PathBuf>,
        password: String,
    },
    #[serde(rename = "vault_resume")]
    Resume {
        vault: Option<PathBuf>,
    },
    #[serde(rename = "vault_seal")]
    Seal {
        vault: Option<PathBuf>,
    },
    Vaults {
        purpose: vaults::Purpose,
    },
    Status,
    List {
        hostname: Option<String>,
    },
    Get {
        id: String,
    },
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NextAction {
    Unseal,
    Pair,
    OpenDesktop,
    OpenPairedVault,
    ManualList,
    SelectEntry,
    SelectVault,
}
#[derive(Serialize, Deserialize)]
struct Response {
    #[serde(default)]
    protocol: u8,
    ok: bool,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<NextAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    choices: Vec<vaults::Choice>,
}
fn fail(message: impl ToString) -> Response {
    Response {
        protocol: 2,
        ok: false,
        message: message.to_string(),
        next: None,
        vault: None,
        choices: Vec::new(),
    }
}
fn ok(message: impl ToString) -> Response {
    Response {
        protocol: 2,
        ok: true,
        message: message.to_string(),
        next: None,
        vault: None,
        choices: Vec::new(),
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
fn summaries(v: &Vault, hostname: Option<&str>) -> Result<Vec<serde_json::Value>, String> {
    let mut result = Vec::new();
    for entry in entries(v)? {
        let id = entry
            .get("id")
            .and_then(|x| x.as_str())
            .ok_or("invalid entry id")?;
        let mut value = decrypt(&entry)?;
        let name = value.get("name").and_then(|x| x.as_str()).unwrap_or("");
        let matches = hostname.is_none_or(|host| {
            value["type"] == "login"
                && value["archived"] != true
                && value["urls"].as_array().is_some_and(|urls| {
                    urls.iter().filter_map(|url| url.as_str()).any(|raw| {
                        let raw = if raw.contains("://") {
                            raw.to_owned()
                        } else {
                            format!("https://{raw}")
                        };
                        url::Url::parse(&raw)
                            .ok()
                            .filter(|url| {
                                !["androidapp", "android", "iosapp", "ios", "appid"]
                                    .contains(&url.scheme())
                            })
                            .and_then(|url| url.host_str().map(str::to_owned))
                            .is_some_and(|name| name.eq_ignore_ascii_case(host.trim()))
                    })
                })
        });
        if matches {
            result.push(serde_json::json!({"id": id, "name": name}));
        }
        if let Some(serde_json::Value::String(s)) = value.get_mut("password") {
            s.zeroize();
        }
    }
    Ok(result)
}

fn handle(req: Request, state: &mut State) -> Response {
    state.handle(req)
}

fn access_failure(e: String) -> Response {
    let next = if e == "daemon is sealed" {
        Some(NextAction::Unseal)
    } else if e == "desktop: locked" {
        Some(NextAction::OpenDesktop)
    } else if e == "desktop: not linked to the open vault"
        || e == "desktop: wrong vault"
        || e == "desktop: vault changed"
    {
        Some(NextAction::OpenPairedVault)
    } else if e == "desktop: not linked to this app" {
        Some(NextAction::Pair)
    } else if e == "desktop: not paired" {
        Some(NextAction::Pair)
    } else if e.starts_with("connect desktop:")
        || e == "desktop: unavailable"
        || e == "desktop: cannot identify vault"
    {
        Some(NextAction::OpenDesktop)
    } else if e.starts_with("desktop lookup requires") {
        Some(NextAction::ManualList)
    } else if e == "entry not found" || e == "desktop: unknown entry" {
        Some(NextAction::SelectEntry)
    } else {
        None
    };
    let message = if e == "desktop: vault changed" {
        "Desktop vault changed during the request. Retry after selecting the intended vault in desktop Bramble.".to_owned()
    } else if e == "desktop: wrong vault" {
        "The selected vault is not active in desktop Bramble.".to_owned()
    } else if e == "desktop: cannot identify vault" {
        "The active desktop vault could not be identified.".to_owned()
    } else {
        match next {
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
            Some(NextAction::SelectEntry) => {
                "Entry was not found in any unsealed vault.".to_owned()
            }
            Some(NextAction::SelectVault) => "Choose the vault to change.".to_owned(),
            None => e,
        }
    };
    Response {
        protocol: 2,
        ok: false,
        message,
        next,
        vault: None,
        choices: Vec::new(),
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

fn daemon(socket: &Path, desktop: Option<(PathBuf, PathBuf)>) -> Result<(), String> {
    let parent = socket.parent().ok_or("socket needs a parent directory")?;
    private_dir(parent)?;
    let mut state = State::new(desktop);
    let (listener, _lock) = bind_daemon(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    vault_crypto::lock();
    eprintln!("✅ Daemon started");
    terminal::instructions(&[terminal::action(
        "In another terminal, check access:",
        &guidance::command(Some(socket), &["status"]),
    )]);
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
        if matches!(
            e.as_str(),
            "Cancelled."
                | "Cancelled (input closed)."
                | "pairing cancelled"
                | "pairing cancelled (input closed)"
                | "pairing cancelled; desktop identity was not saved"
        ) {
            eprintln!("{e}");
        } else {
            terminal::error(&e);
        }
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
    if let Request::Unseal { password, .. } = &mut request {
        password.zeroize();
    }
    let result = stream.write_all(&data);
    data.zeroize();
    result.map_err(|_| {
        terminal::recovery(
            "Daemon connection was lost.",
            &[
                "Check its terminal and retry the command.".into(),
                terminal::action(
                    "Check a user service's log:",
                    "journalctl --user -u bramble-cli.service -n 20 --no-pager",
                ),
            ],
        )
    })?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).map_err(|_| {
        terminal::recovery(
            "Daemon did not answer.",
            &[
                "Check its foreground terminal.".into(),
                terminal::action(
                    "Check a user service's log:",
                    "journalctl --user -u bramble-cli.service -n 20 --no-pager",
                ),
            ],
        )
    })?;
    let response: Result<Response, String> = serde_json::from_str(&line).map_err(|_| {
        terminal::recovery(
            "Daemon returned an invalid response.",
            &["Restart the daemon using this build.".into()],
        )
    });
    line.zeroize();
    let mut response = response?;
    if response.protocol != 2 {
        response.message.zeroize();
        return Err(terminal::recovery(
            "Daemon needs an update.",
            &[
                "For an installed service, rerun service install with the same connection options used for installation.".into(),
                "For a foreground daemon, stop it and restart it using this build.".into(),
            ],
        ));
    }
    Ok(response)
}
fn next_actions(next: NextAction, socket: &Path, vault: Option<&Path>) -> Vec<String> {
    let target = vault.map(|p| p.to_string_lossy().into_owned());
    let mut unseal = vec!["unseal"];
    if let Some(target) = target.as_deref() {
        unseal.push(target);
    }
    let mut manual = unseal.clone();
    manual.push("--manual");
    match next {
        NextAction::Unseal => vec![terminal::action(
            "Unseal the vault:",
            &guidance::command(Some(socket), &unseal),
        )],
        NextAction::Pair => vec![
            terminal::action(
                "Pair with desktop Bramble:",
                &guidance::command(None, &["pair"]),
            ),
            terminal::action(
                "Unlock the local vault manually:",
                &guidance::command(Some(socket), &manual),
            ),
        ],
        NextAction::OpenDesktop => vec![
            "Open and unlock desktop Bramble.".into(),
            terminal::action(
                "Unlock the local vault manually:",
                &guidance::command(Some(socket), &manual),
            ),
        ],
        NextAction::OpenPairedVault => vec![
            "Open the intended paired vault in desktop Bramble.".into(),
            terminal::action(
                "Unlock the local vault manually:",
                &guidance::command(Some(socket), &manual),
            ),
        ],
        NextAction::ManualList => vec![
            terminal::action(
                "Look up logins by hostname:",
                &guidance::command(Some(socket), &["list", "--hostname", "HOST"]),
            ),
            terminal::action(
                "Unlock the local vault for a full list:",
                &guidance::command(Some(socket), &manual),
            ),
        ],
        NextAction::SelectEntry => {
            vec!["Use an ID from list (with --hostname HOST when using desktop access).".into()]
        }
        NextAction::SelectVault => vec!["Choose a vault by name, ID or path.".into()],
    }
}

fn response_result(mut response: Response, socket: &Path) -> Result<(), String> {
    if response.ok {
        println!("{}", response.message);
        response.message.zeroize();
        if let Some(next) = response.next {
            terminal::instructions(&next_actions(next, socket, response.vault.as_deref()));
        }
        Ok(())
    } else if let Some(next) = response.next {
        Err(terminal::recovery(
            &response.message,
            &next_actions(next, socket, response.vault.as_deref()),
        ))
    } else {
        Err(response.message)
    }
}

fn select_target(
    socket: &Path,
    managed: bool,
    interactive: bool,
    explicit: Option<PathBuf>,
    purpose: vaults::Purpose,
) -> Result<Option<PathBuf>, String> {
    if explicit.as_ref().is_some_and(|p| p.is_absolute()) {
        return Ok(explicit);
    }
    let stream = guidance::connect(
        socket,
        managed,
        interactive && matches!(purpose, vaults::Purpose::Unseal),
    )?;
    let query = if explicit.is_some() {
        vaults::Purpose::Catalog
    } else {
        purpose
    };
    let response = call(stream, Request::Vaults { purpose: query })?;
    if !response.ok {
        return Err(response.message);
    }
    let choices = if let Some(reference) = explicit {
        let name = reference.to_string_lossy();
        let choices: Vec<_> = response
            .choices
            .into_iter()
            .filter(|v| v.name == name || v.path.file_stem() == reference.file_stem())
            .collect();
        if choices.is_empty() {
            return Err(format!(
                "Vault was not found: {name}. Use a listed name, ID or .vlt path."
            ));
        }
        choices
    } else {
        response.choices
    };
    if choices.is_empty() && matches!(purpose, vaults::Purpose::Seal) {
        return Ok(None);
    }
    guidance::choose_vault(&choices, interactive).map(Some)
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
            let desktop = if source.desktop {
                Some(source.connection.paths()?)
            } else {
                None
            };
            return daemon(&socket, desktop);
        }
        Command::Service { action } => {
            match action {
                ServiceCommand::Install(source) => {
                    let desktop = if source.desktop {
                        Some(source.connection.paths()?)
                    } else {
                        None
                    };
                    service::install(&socket, desktop.as_ref())?;
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
            terminal::instructions(&[terminal::action(
                "Check access:",
                &guidance::command(Some(&socket), &["status"]),
            )]);
            return Ok(());
        }
        Command::Unseal { vault, manual } => {
            let explicit = vault.as_deref().map(vaults::reference).transpose()?;
            let mut target = select_target(
                &socket,
                managed,
                interactive,
                explicit,
                vaults::Purpose::Unseal,
            )?
            .ok_or("Choose a vault to unseal")?;
            let stream = guidance::connect(&socket, managed, interactive)?;
            if !manual {
                let response = call(
                    stream,
                    Request::Resume {
                        vault: Some(target.clone()),
                    },
                )?;
                if response.ok {
                    return response_result(response, &socket);
                }
                if matches!(response.next, Some(NextAction::SelectVault)) {
                    return Err(response.message);
                }
                if let Some(path) = response.vault {
                    target = path;
                }
            } else {
                // Detect old daemons and already-held local keys before asking for a password.
                let state = call(
                    stream,
                    Request::Vaults {
                        purpose: vaults::Purpose::Catalog,
                    },
                )?;
                if state
                    .choices
                    .iter()
                    .any(|v| v.path == target && v.access == "manual")
                {
                    return response_result(ok("unsealed"), &socket);
                }
            }
            // Validate the selected local file before asking for its password.
            let local = read_vault(&target)?;
            if local.slots.is_empty() {
                return Err(
                    "This vault has no master-password slot. Use desktop access instead.".into(),
                );
            }
            if !interactive {
                return Err(terminal::recovery(
                    "Manual unseal needs a password entered in a terminal.",
                    &[terminal::action(
                        "Run in a terminal:",
                        &guidance::command(
                            Some(&socket),
                            &["unseal", &target.to_string_lossy(), "--manual"],
                        ),
                    )],
                ));
            }
            eprintln!(
                "Unlock {} manually",
                target
                    .file_stem()
                    .unwrap_or(target.as_os_str())
                    .to_string_lossy()
            );
            let mut password = rpassword::prompt_password("Master password: ")
                .map_err(|_| "Cannot read the password. Run unseal in a terminal.".to_owned())?;
            let stream = match guidance::connect(&socket, managed, false) {
                Ok(stream) => stream,
                Err(e) => {
                    password.zeroize();
                    return Err(e);
                }
            };
            return response_result(
                call(
                    stream,
                    Request::Unseal {
                        vault: Some(target),
                        password,
                    },
                )?,
                &socket,
            );
        }
        Command::Seal { vault } => {
            let explicit = vault.as_deref().map(vaults::reference).transpose()?;
            let target = select_target(
                &socket,
                managed,
                interactive,
                explicit,
                vaults::Purpose::Seal,
            )?;
            Request::Seal { vault: target }
        }
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
                terminal::error(&terminal::recovery(
                    &response.message,
                    &next_actions(next, &socket, response.vault.as_deref()),
                ));
                guidance::read_answer("\n  Enter once ready to retry · q to cancel: ")?;
                continue;
            }
        }
        return response_result(response, &socket);
    }
}
use std::io::Read;

#[cfg(test)]
mod tests;
