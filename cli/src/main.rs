mod desktop;
mod entry;
mod guidance;
mod output;
mod pairing_ui;
mod save;
mod service;
mod terminal;
mod vaults;
use output::{CliError, Step};
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
    /// Print one JSON document on stdout, never prompt, and keep stderr empty.
    #[arg(long, global = true)]
    json: bool,
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
    /// List entry IDs, titles and vaults across all unsealed vaults (desktop access needs --hostname).
    List {
        /// Desktop connections support exact hostname lookup, not full vault enumeration.
        #[arg(long)]
        hostname: Option<String>,
    },
    /// Find an entry across all unsealed vaults and print its password, or the chosen fields.
    Get {
        id: String,
        /// Field to print: title, username, password, url, urls, notes, totp or field:NAME.
        /// Repeat the option for several fields; the default is the password.
        #[arg(short, long = "field", value_name = "FIELD")]
        fields: Vec<String>,
    },
    /// Create an entry, or update the one named by ID; omitted fields are kept.
    Save(SaveArgs),
}
#[derive(clap::Args)]
struct SaveArgs {
    /// Entry to update; omit to create a new entry.
    id: Option<String>,
    /// Vault name, ID or path; inferred when exactly one vault is unsealed.
    #[arg(long)]
    vault: Option<String>,
    /// Entry title (required for a new entry).
    #[arg(long)]
    title: Option<String>,
    #[arg(long)]
    username: Option<String>,
    /// Password. Visible to other local users in the process list; prefer --password-stdin.
    #[arg(long, conflicts_with = "password_stdin")]
    password: Option<String>,
    /// Read the password from the first line of stdin.
    #[arg(long)]
    password_stdin: bool,
    /// Website URL; repeat for several. Replaces the entry's URL list.
    #[arg(long = "url", value_name = "URL")]
    urls: Vec<String>,
    #[arg(long)]
    notes: Option<String>,
    /// Set a custom field, addressed by its exact name: NAME=VALUE.
    #[arg(long = "field", value_name = "NAME=VALUE")]
    fields: Vec<String>,
    /// Set a hidden custom field: NAME=VALUE.
    #[arg(long = "secret-field", value_name = "NAME=VALUE")]
    secret_fields: Vec<String>,
    /// Remove a field: username, password, url, notes or field:NAME. Repeatable.
    #[arg(long = "clear", value_name = "FIELD")]
    clear: Vec<String>,
    /// Read fields from a JSON document (a file, or - for stdin); options override it.
    #[arg(long, value_name = "FILE")]
    input: Option<String>,
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
        /// Empty selects the password and answers with the password as the message.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        fields: Vec<String>,
    },
    Save {
        id: Option<String>,
        vault: Option<PathBuf>,
        change: entry::Change,
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
    ManualUnseal,
    LockDesktop,
}
const PROTOCOL: u8 = 3;
#[derive(Serialize, Deserialize)]
struct Response {
    #[serde(default)]
    protocol: u8,
    ok: bool,
    message: String,
    /// Stable failure code (see output::ERROR_CODES); absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next: Option<NextAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vault: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    choices: Vec<vaults::Choice>,
    /// Structured result or failure details; may hold secrets and is wiped after use.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}
impl Response {
    fn wipe(&mut self) {
        self.message.zeroize();
        if let Some(data) = &mut self.data {
            entry::wipe(data);
        }
    }
}
fn fail(message: impl ToString) -> Response {
    Response {
        protocol: PROTOCOL,
        ok: false,
        message: message.to_string(),
        code: None,
        next: None,
        vault: None,
        choices: Vec::new(),
        data: None,
    }
}
fn fail_code(code: &str, message: impl ToString) -> Response {
    let mut response = fail(message);
    response.code = Some(code.to_owned());
    response
}
fn ok(message: impl ToString) -> Response {
    Response {
        ok: true,
        ..fail(message)
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
    /// Bytes before the entries IV: magic, version and every key slot, copied as-is on save.
    header_len: usize,
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
    let header_len = pos;
    let iv = bytes
        .get(pos..pos + 12)
        .ok_or("truncated entries IV")?
        .to_vec();
    pos += 12;
    Ok(Vault {
        slots,
        header_len,
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
/// The decrypted outer payload: `{entries, tombstones, ...}`, or a bare entry array from
/// older vaults. Only envelopes are in it; entry contents stay sealed under their own keys.
fn payload(v: &Vault) -> Result<serde_json::Value, String> {
    if vault_crypto::is_locked() {
        return Err("daemon is sealed".into());
    }
    if v.ciphertext.is_empty() {
        return Ok(serde_json::json!({"entries": [], "tombstones": []}));
    }
    let mut outer = vault_crypto::decrypt_with_vek(b64.encode(&v.iv), b64.encode(&v.ciphertext))
        .map_err(|e| e.to_string())?;
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&outer);
    outer.zeroize();
    let payload = parsed.map_err(|_| "invalid entries payload")?;
    if payload.get("entries").is_none() && !payload.is_array() {
        return Err("invalid entries payload".into());
    }
    Ok(payload)
}
fn entries(v: &Vault) -> Result<Vec<serde_json::Value>, String> {
    let payload = payload(v)?;
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
/// The selected fields of one entry as a JSON object keyed by selector. Errors are
/// `entry not found` or `field not found: a, b`.
fn get_fields(v: &Vault, id: &str, fields: &[entry::Field]) -> Result<serde_json::Value, String> {
    let entries = entries(v)?;
    let envelope = entries
        .iter()
        .find(|x| x.get("id").and_then(|v| v.as_str()) == Some(id))
        .ok_or("entry not found")?;
    let mut plain = decrypt(envelope)?;
    let selected = entry::select(&plain, fields);
    entry::wipe(&mut plain);
    match selected {
        Ok(found) => Ok(serde_json::Value::Object(found)),
        Err(missing) => Err(format!("field not found: {}", missing.join(", "))),
    }
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
    let (code, next) = if e == "daemon is sealed" {
        ("sealed", Some(NextAction::Unseal))
    } else if e == "desktop: locked" {
        ("desktop_locked", Some(NextAction::OpenDesktop))
    } else if e == "desktop: not linked to the open vault"
        || e == "desktop: wrong vault"
        || e == "desktop: vault changed"
    {
        ("wrong_vault", Some(NextAction::OpenPairedVault))
    } else if e == "desktop: not linked to this app" || e == "desktop: not paired" {
        ("not_paired", Some(NextAction::Pair))
    } else if e.starts_with("connect desktop:") || e == "desktop: unavailable" {
        ("desktop_unavailable", Some(NextAction::OpenDesktop))
    } else if e == "desktop: cannot identify vault" {
        ("vault_unidentified", Some(NextAction::OpenDesktop))
    } else if e.starts_with("desktop lookup requires") {
        ("list_unsupported", Some(NextAction::ManualList))
    } else if e.starts_with("desktop supports only") {
        ("field_unsupported", Some(NextAction::ManualUnseal))
    } else if e == "entry not found" || e == "desktop: unknown entry" {
        ("entry_not_found", Some(NextAction::SelectEntry))
    } else if e.starts_with("field not found:") {
        ("field_not_found", None)
    } else {
        ("error", None)
    };
    let message = if e == "desktop: vault changed" {
        "Desktop vault changed during the request. Retry after selecting the intended vault in desktop Bramble.".to_owned()
    } else if e == "desktop: wrong vault" {
        "The selected vault is not active in desktop Bramble.".to_owned()
    } else if e == "desktop: cannot identify vault" {
        "The active desktop vault could not be identified.".to_owned()
    } else if e.starts_with("field not found:") {
        format!(
            "The entry has no {}.",
            e["field not found:".len()..].trim().replace(", ", ", no ")
        )
    } else if e.starts_with("desktop supports only") {
        e.clone()
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
            _ => e,
        }
    };
    Response {
        code: Some(code.to_owned()),
        next,
        ..fail(message)
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
fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Daemon(_) => "daemon",
        Command::Service { .. } => "service",
        Command::Pair { .. } => "pair",
        Command::Unseal { .. } => "unseal",
        Command::Seal { .. } => "seal",
        Command::Status => "status",
        Command::List { .. } => "list",
        Command::Get { .. } => "get",
        Command::Save(_) => "save",
    }
}
fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            // Help and version stay human text; a usage mistake in JSON mode is a JSON error.
            if e.use_stderr() && std::env::args_os().any(|a| a == "--json") {
                let message = e.to_string();
                let message = message.lines().next().unwrap_or("Invalid usage.");
                let message = message.strip_prefix("error: ").unwrap_or(message);
                output::emit(&CliError::new("invalid_usage", message).to_json("cli"));
                std::process::exit(2);
            }
            e.exit()
        }
    };
    let json = cli.json;
    let command = command_name(&cli.command);
    if let Err(e) = run(cli) {
        if json {
            output::emit(&e.to_json(command));
        } else if e.cancelled() {
            eprintln!("{}", e.message);
        } else {
            terminal::error(&e.plain());
        }
        std::process::exit(e.exit_code());
    }
}
fn call(mut stream: UnixStream, mut request: Request) -> Result<Response, CliError> {
    let seconds = if matches!(request, Request::Unseal { .. }) {
        30
    } else {
        5
    };
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(seconds)))
        .and_then(|_| stream.set_write_timeout(Some(std::time::Duration::from_secs(5))))
        .map_err(|_| {
            CliError::new(
                "daemon_connection",
                "Cannot configure the daemon connection.",
            )
        })?;
    let mut data = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    data.push(b'\n');
    match &mut request {
        Request::Unseal { password, .. } => password.zeroize(),
        Request::Save { change, .. } => change.wipe(),
        _ => (),
    }
    let result = stream.write_all(&data);
    data.zeroize();
    let log = || {
        Step::run(
            "Check a user service's log:",
            "journalctl --user -u bramble-cli.service -n 20 --no-pager",
        )
    };
    result.map_err(|_| {
        CliError::new("daemon_connection", "Daemon connection was lost.").steps(vec![
            Step::text("Check its terminal and retry the command."),
            log(),
        ])
    })?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).map_err(|_| {
        CliError::new("daemon_connection", "Daemon did not answer.")
            .steps(vec![Step::text("Check its foreground terminal."), log()])
    })?;
    let response: Result<Response, CliError> = serde_json::from_str(&line).map_err(|_| {
        CliError::new("daemon_outdated", "Daemon returned an invalid response.")
            .steps(vec![Step::text("Restart the daemon using this build.")])
    });
    line.zeroize();
    let mut response = response?;
    if response.protocol != PROTOCOL {
        response.wipe();
        return Err(CliError::new("daemon_outdated", "Daemon needs an update.").steps(vec![
            Step::text("For an installed service, rerun service install with the same connection options used for installation."),
            Step::text("For a foreground daemon, stop it and restart it using this build."),
        ]));
    }
    Ok(response)
}
fn next_actions(next: NextAction, socket: &Path, vault: Option<&Path>) -> Vec<Step> {
    let target = vault.map(|p| p.to_string_lossy().into_owned());
    let mut unseal = vec!["unseal"];
    if let Some(target) = target.as_deref() {
        unseal.push(target);
    }
    let mut manual = unseal.clone();
    manual.push("--manual");
    let manual_step = || {
        Step::run(
            "Unlock the local vault manually:",
            guidance::command(Some(socket), &manual),
        )
    };
    match next {
        NextAction::Unseal => vec![Step::run(
            "Unseal the vault:",
            guidance::command(Some(socket), &unseal),
        )],
        NextAction::Pair => vec![
            Step::run(
                "Pair with desktop Bramble:",
                guidance::command(None, &["pair"]),
            ),
            manual_step(),
        ],
        NextAction::OpenDesktop => vec![
            Step::text("Open and unlock desktop Bramble."),
            manual_step(),
        ],
        NextAction::OpenPairedVault => vec![
            Step::text("Open the intended paired vault in desktop Bramble."),
            manual_step(),
        ],
        NextAction::ManualList => vec![
            Step::run(
                "Look up logins by hostname:",
                guidance::command(Some(socket), &["list", "--hostname", "HOST"]),
            ),
            Step::run(
                "Unlock the local vault for a full list:",
                guidance::command(Some(socket), &manual),
            ),
        ],
        NextAction::ManualUnseal => vec![Step::run(
            "Unlock the local vault manually:",
            guidance::command(Some(socket), &manual),
        )],
        NextAction::LockDesktop => vec![Step::text(
            "Lock desktop Bramble or switch it to another vault, then retry.",
        )],
        NextAction::SelectEntry => vec![Step::text(
            "Use an ID from list (with --hostname HOST when using desktop access).",
        )],
        NextAction::SelectVault => vec![Step::text("Choose a vault by name, ID or path.")],
    }
}

/// How a run reports: plain text, or exactly one JSON document.
struct Ctx {
    json: bool,
    interactive: bool,
    command: &'static str,
}
impl Ctx {
    /// Report success. Plain mode prints `stdout` when there is any; JSON mode prints `data`.
    fn done(&self, data: serde_json::Value, stdout: Option<String>) -> Result<(), CliError> {
        if self.json {
            output::emit(&output::success(self.command, data));
        } else if let Some(text) = stdout {
            println!("{text}");
        }
        Ok(())
    }
    /// Human guidance and progress notes belong on stderr, never in a JSON run.
    fn note(&self, text: &str) {
        if !self.json {
            eprintln!("{text}");
        }
    }
}

fn failure(response: &mut Response, socket: &Path) -> CliError {
    let code = response.code.as_deref().unwrap_or("error");
    let code = output::ERROR_CODES
        .iter()
        .find(|known| **known == code)
        .copied()
        .unwrap_or("error");
    let steps = response
        .next
        .map(|next| next_actions(next, socket, response.vault.as_deref()))
        .unwrap_or_default();
    let error = CliError::new(code, std::mem::take(&mut response.message))
        .steps(steps)
        .choices(std::mem::take(&mut response.choices))
        .details(response.data.take());
    response.wipe();
    error
}

fn response_result(ctx: &Ctx, mut response: Response, socket: &Path) -> Result<(), CliError> {
    if !response.ok {
        return Err(failure(&mut response, socket));
    }
    let steps = response
        .next
        .map(|next| next_actions(next, socket, response.vault.as_deref()))
        .unwrap_or_default();
    let message = std::mem::take(&mut response.message);
    if ctx.json {
        let mut data = serde_json::json!({"message": message});
        if let Some(vault) = &response.vault {
            data["vault"] = serde_json::json!(vault);
        }
        if !response.choices.is_empty() {
            data["vaults"] = serde_json::json!(response.choices);
        }
        if !steps.is_empty() {
            data["next"] = serde_json::json!(steps);
        }
        return ctx.done(data, None);
    }
    println!("{message}");
    let mut message = message;
    message.zeroize();
    if !steps.is_empty() {
        terminal::instructions(&steps.iter().map(Step::render).collect::<Vec<_>>());
    }
    Ok(())
}

fn select_target(
    socket: &Path,
    managed: bool,
    interactive: bool,
    explicit: Option<PathBuf>,
    purpose: vaults::Purpose,
) -> Result<Option<PathBuf>, CliError> {
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
    let mut response = call(stream, Request::Vaults { purpose: query })?;
    if !response.ok {
        return Err(failure(&mut response, socket));
    }
    let choices = if let Some(reference) = explicit {
        let name = reference.to_string_lossy();
        let choices: Vec<_> = response
            .choices
            .into_iter()
            .filter(|v| v.name == name || v.path.file_stem() == reference.file_stem())
            .collect();
        if choices.is_empty() {
            return Err(CliError::new(
                "vault_not_found",
                format!("Vault was not found: {name}. Use a listed name, ID or .vlt path."),
            ));
        }
        choices
    } else {
        response.choices
    };
    if choices.is_empty() && matches!(purpose, vaults::Purpose::Seal | vaults::Purpose::Save) {
        // Nothing is unsealed: seal is a no-op and save lets the daemon explain what to unseal.
        return Ok(None);
    }
    guidance::choose_vault(&choices, interactive).map(Some)
}

/// Tell a script or user which option picks the vault when a new entry has several candidates.
fn ambiguous_save_target(error: CliError) -> CliError {
    if error.code != "ambiguous_vault" {
        return error;
    }
    let names: Vec<_> = error
        .choices
        .iter()
        .map(|v| {
            let shared = error.choices.iter().filter(|o| o.name == v.name).count() > 1;
            if shared {
                v.path.display().to_string()
            } else {
                v.name.clone()
            }
        })
        .collect();
    CliError::new(
        "ambiguous_vault",
        "Several vaults are unsealed. Choose where to save the entry.",
    )
    .steps(vec![Step::text(format!(
        "Add --vault with one of: {}",
        names.join(", ")
    ))])
    .choices(error.choices)
}

fn invalid(message: impl ToString) -> CliError {
    CliError::new("invalid_input", message)
}

fn read_input(source: &str) -> Result<serde_json::Value, CliError> {
    let mut text = zeroize::Zeroizing::new(String::new());
    if source == "-" {
        std::io::stdin()
            .lock()
            .take(4 * 1024 * 1024)
            .read_to_string(&mut text)
            .map_err(|e| invalid(format!("Cannot read the input from stdin: {e}")))?;
    } else {
        fs::File::open(source)
            .and_then(|f| f.take(4 * 1024 * 1024).read_to_string(&mut text))
            .map_err(|e| invalid(format!("Cannot read the input file {source}: {e}")))?;
    }
    serde_json::from_str(&text).map_err(|e| invalid(format!("The input is not valid JSON: {e}")))
}

fn name_value(text: &str, option: &str) -> Result<(String, String), CliError> {
    let (name, value) = text
        .split_once('=')
        .ok_or_else(|| invalid(format!("--{option} expects NAME=VALUE.")))?;
    Ok((name.to_owned(), value.to_owned()))
}

/// Everything `save` was asked to do: the JSON input document first, options on top.
fn save_request(
    args: SaveArgs,
) -> Result<(Option<String>, Option<String>, entry::Change), CliError> {
    if args.input.as_deref() == Some("-") && args.password_stdin {
        return Err(invalid(
            "--input - and --password-stdin both read stdin; use one.",
        ));
    }
    let mut input = match &args.input {
        Some(source) => entry::parse_input(&read_input(source)?).map_err(invalid)?,
        None => entry::SaveInput::default(),
    };
    let change = &mut input.change;
    change.title = args.title.or(change.title.take());
    change.username = args.username.or(change.username.take());
    change.password = args.password.or(change.password.take());
    change.notes = args.notes.or(change.notes.take());
    if !args.urls.is_empty() {
        change.urls = Some(args.urls);
    }
    for (list, hidden) in [(&args.fields, None), (&args.secret_fields, Some(true))] {
        for text in list {
            let (name, value) = name_value(
                text,
                if hidden.is_some() {
                    "secret-field"
                } else {
                    "field"
                },
            )?;
            change.fields.retain(|f| f.name != name);
            change.fields.push(entry::CustomValue {
                name,
                value,
                hidden,
            });
        }
    }
    change.clear.extend(args.clear);
    if args.password_stdin {
        let mut line = zeroize::Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| invalid(format!("Cannot read the password from stdin: {e}")))?;
        change.password = Some(line.trim_end_matches(['\r', '\n']).to_owned());
    }
    Ok((
        args.id.or(input.id),
        args.vault.or(input.vault),
        input.change,
    ))
}

fn run(cli: Cli) -> Result<(), CliError> {
    use std::io::IsTerminal;
    let ctx = Ctx {
        json: cli.json,
        interactive: !cli.no_input && !cli.json && std::io::stdin().is_terminal(),
        command: command_name(&cli.command),
    };
    let interactive = ctx.interactive;
    if ctx.json
        && matches!(
            cli.command,
            Command::Daemon(_) | Command::Service { .. } | Command::Pair { .. }
        )
    {
        return Err(CliError::new(
            "unsupported",
            format!(
                "--json is not available for {}: it is interactive or runs in the foreground.",
                ctx.command
            ),
        ));
    }
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
    let mut get_fields: Vec<entry::Field> = Vec::new();
    let request = match cli.command {
        Command::Daemon(source) => {
            let desktop = if source.desktop {
                Some(source.connection.paths()?)
            } else {
                None
            };
            return Ok(daemon(&socket, desktop)?);
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
                    return response_result(&ctx, response, &socket);
                }
                if matches!(response.next, Some(NextAction::SelectVault)) {
                    return Err(CliError::new("ambiguous_vault", response.message)
                        .choices(response.choices));
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
                    return response_result(&ctx, ok("unsealed"), &socket);
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
                return Err(CliError::new(
                    "interactive_required",
                    "Manual unseal needs a password entered in a terminal.",
                )
                .steps(vec![Step::run(
                    "Run in a terminal:",
                    guidance::command(
                        Some(&socket),
                        &["unseal", &target.to_string_lossy(), "--manual"],
                    ),
                )]));
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
                &ctx,
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
        Command::Get { id, fields } => {
            get_fields = entry::parse_fields(&fields).map_err(invalid)?;
            // Without options the password is returned as before; JSON always names fields.
            let named = if fields.is_empty() && ctx.json {
                vec!["password".to_owned()]
            } else {
                get_fields.iter().map(entry::Field::selector).collect()
            };
            Request::Get { id, fields: named }
        }
        Command::Save(args) => {
            let (id, vault, change) = save_request(args)?;
            if change.is_empty() {
                return Err(invalid(
                    "Nothing to save. Give at least one field option, for example --title or --password-stdin.",
                ));
            }
            let target = match vault {
                Some(vault) => Some(vaults::reference(Path::new(&vault))?),
                None if id.is_none() => {
                    select_target(&socket, managed, interactive, None, vaults::Purpose::Save)
                        .map_err(|e| ambiguous_save_target(e))?
                }
                None => None,
            };
            let stream = guidance::connect(&socket, managed, false)?;
            // A save carries the new secrets, so it is sent once and never replayed.
            let mut response = call(
                stream,
                Request::Save {
                    id,
                    vault: target,
                    change,
                },
            )?;
            if !response.ok {
                return Err(failure(&mut response, &socket));
            }
            let data = response.data.take().unwrap_or_default();
            let id = data["id"].as_str().unwrap_or("").to_owned();
            ctx.note(
                match (data["created"].as_bool(), data["changed"].as_bool()) {
                    (Some(true), _) => "✅ Entry created",
                    (_, Some(false)) => "No changes: the entry already has these values",
                    _ => "✅ Entry updated",
                },
            );
            return ctx.done(data, Some(id));
        }
        Command::Pair { .. } => unreachable!(),
    };
    let can_guide = interactive && matches!(request, Request::List { .. } | Request::Get { .. });
    loop {
        let stream = guidance::connect(&socket, managed, can_guide)?;
        // Retrying contains no secrets: manual unseal returns above and is never replayed.
        let mut response = call(stream, request.clone())?;
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
                    &next_actions(next, &socket, response.vault.as_deref())
                        .iter()
                        .map(Step::render)
                        .collect::<Vec<_>>(),
                ));
                guidance::read_answer("\n  Enter once ready to retry · q to cancel: ")?;
                continue;
            }
        }
        return match &request {
            Request::Get { .. } => print_get(&ctx, &mut response, &get_fields, &socket),
            Request::List { .. } => print_list(&ctx, &mut response, &socket),
            _ => response_result(&ctx, response, &socket),
        };
    }
}

/// `get`: the password alone by default, otherwise the requested fields in request order.
fn print_get(
    ctx: &Ctx,
    response: &mut Response,
    fields: &[entry::Field],
    socket: &Path,
) -> Result<(), CliError> {
    if !response.ok {
        return Err(failure(response, socket));
    }
    let Some(mut data) = response.data.take() else {
        // No fields were named: the message is the password.
        let mut password = std::mem::take(&mut response.message);
        println!("{password}");
        password.zeroize();
        return Ok(());
    };
    let shown = |value: &serde_json::Value| match value {
        serde_json::Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
        other => other.as_str().unwrap_or_default().to_owned(),
    };
    let text = if let [only] = fields {
        shown(&data["fields"][only.selector()])
    } else {
        fields
            .iter()
            .map(|f| {
                let value = shown(&data["fields"][f.selector()]);
                format!("{}\t{}", f.selector(), value.replace('\n', "\\n"))
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let result = ctx.done(data.clone(), Some(text.clone()));
    let mut text = text;
    text.zeroize();
    entry::wipe(&mut data);
    result
}

fn print_list(ctx: &Ctx, response: &mut Response, socket: &Path) -> Result<(), CliError> {
    if !response.ok {
        return Err(failure(response, socket));
    }
    let entries: Vec<serde_json::Value> = serde_json::from_str(&response.message)
        .map_err(|_| "Daemon returned an invalid listing.".to_owned())?;
    if ctx.json {
        return ctx.done(serde_json::json!({ "entries": entries }), None);
    }
    let mut rows: Vec<_> = entries
        .iter()
        .map(|e| {
            let field = |key: &str| e[key].as_str().unwrap_or("").to_owned();
            (field("id"), field("name"), field("vault"))
        })
        .collect();
    rows.sort_by_cached_key(|(id, title, vault)| {
        (vault.to_lowercase(), title.to_lowercase(), id.clone())
    });
    if rows.is_empty() {
        eprintln!("No entries.");
        return Ok(());
    }
    println!("{}", output::entry_table(&rows, output::terminal_width()));
    Ok(())
}
use std::io::Read;

#[cfg(test)]
mod tests;
