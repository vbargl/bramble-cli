//! Recover prerequisites one step at a time. Read-only commands and non-TTY callers never
//! install services, start processes, or wait for interactive input.
use crate::{desktop, service};
use std::{
    ffi::OsStr,
    fs,
    io::{self, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

fn quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./-".contains(c))
    {
        value.into_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}
pub fn command(socket: Option<&Path>, args: &[&str]) -> String {
    let binary = std::env::args_os()
        .next()
        .unwrap_or_else(|| "bramble-cli".into());
    let mut parts = vec![quote(&binary)];
    if let Some(socket) =
        socket.filter(|path| crate::socket_path(None).ok().as_deref() != Some(*path))
    {
        parts.extend(["--socket".into(), quote(socket.as_os_str())]);
    }
    parts.extend(args.iter().map(|arg| quote(OsStr::new(arg))));
    parts.join(" ")
}
pub fn read_answer(prompt: &str) -> Result<String, String> {
    eprint!("{prompt}");
    io::stderr().flush().map_err(|e| e.to_string())?;
    let mut answer = String::new();
    if io::stdin()
        .read_line(&mut answer)
        .map_err(|e| e.to_string())?
        == 0
    {
        return Err("Cancelled (input closed).".into());
    }
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("q") {
        return Err("Cancelled.".into());
    }
    Ok(answer.to_owned())
}

pub fn vault(path: Option<PathBuf>, interactive: bool) -> Result<PathBuf, String> {
    if let Some(path) = path {
        return fs::canonicalize(&path).map_err(|_| {
            format!(
                "Vault file was not found: {}. Choose an existing .vlt file.",
                path.display()
            )
        });
    }
    let (socket, _) = (desktop::Options {
        desktop_socket: None,
        pairing_file: None,
    })
    .paths()?;
    let directory = socket
        .parent()
        .ok_or("Cannot locate desktop vaults")?
        .join("vaults");
    let mut choices = Vec::new();
    match fs::read_dir(&directory) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension() == Some(OsStr::new("vlt")) && path.is_file() {
                    choices.push(path);
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(_) => {
            return Err(format!(
                "Cannot read vault directory: {}. Supply the vault path explicitly.",
                directory.display()
            ))
        }
    }
    choices.sort();
    if choices.len() == 1 {
        return Ok(choices.remove(0));
    }
    if !interactive {
        return Err("Choose a vault file by supplying its path: daemon /path/to/vault.vlt or service install /path/to/vault.vlt.".into());
    }
    if !choices.is_empty() {
        eprintln!("Choose the vault:");
        for (i, path) in choices.iter().enumerate() {
            eprintln!("  {}  {}", i + 1, path.display());
        }
    }
    loop {
        let value = read_answer("⏳ Vault path or number (q to cancel): ")?;
        if let Ok(number) = value.parse::<usize>() {
            if let Some(path) = number.checked_sub(1).and_then(|i| choices.get(i)) {
                return Ok(path.clone());
            }
        }
        if !value.is_empty() {
            if let Ok(path) = fs::canonicalize(&value) {
                if path.is_file() {
                    return Ok(path);
                }
            }
        }
        eprintln!("Choose an existing .vlt file.");
    }
}

pub fn unavailable(error: &io::Error, socket: &Path, managed: bool) -> String {
    use io::ErrorKind;
    if error.kind() == ErrorKind::PermissionDenied {
        return format!("Cannot access the daemon at {}.\n⏳ Use the same user account as the daemon and check this socket's permissions.", socket.display());
    }
    if !matches!(
        error.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused
    ) {
        return format!(
            "Cannot connect to the daemon at {}: {error}",
            socket.display()
        );
    }
    let manual = command(Some(socket), &["daemon", "--desktop"]);
    if !managed {
        return format!(
            "No daemon is listening at {}.\n⏳ In another terminal, run: {manual}",
            socket.display()
        );
    }
    match service::state() {
        service::State::Missing => format!("Daemon service is not installed.\n⏳ Install and start it: {}\n   Or run manually in another terminal: {manual}", command(Some(socket), &["service", "install", "--desktop"])),
        service::State::Stopped => format!("Daemon service is stopped.\n⏳ Run: {}", command(Some(socket), &["service", "start"])),
        service::State::Failed => "Daemon service failed to start.\n⏳ Check: journalctl --user -u bramble-cli.service -n 20 --no-pager".into(),
        service::State::Active => "Daemon service is running but is not responding at this socket.\n⏳ Check: journalctl --user -u bramble-cli.service -n 20 --no-pager".into(),
        service::State::Unknown => format!("Daemon is not running; user-service state could not be checked.\n⏳ In another terminal, run: {manual}"),
    }
}

pub fn connect(socket: &Path, managed: bool, interactive: bool) -> Result<UnixStream, String> {
    loop {
        let error = match UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(e) => e,
        };
        if !interactive
            || !matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            )
        {
            return Err(unavailable(&error, socket, managed));
        }
        let state = if managed {
            service::state()
        } else {
            service::State::Unknown
        };
        eprintln!(
            "{}",
            unavailable(&error, socket, managed)
                .lines()
                .next()
                .unwrap_or("Daemon is unavailable.")
        );
        let choice = if matches!(state, service::State::Missing) {
            read_answer("⏳ [i] Install user service · [m] Start manually · [q] Cancel: ")?
        } else if matches!(state, service::State::Stopped | service::State::Failed) {
            read_answer("⏳ [s] Start user service · [m] Start manually · [q] Cancel: ")?
        } else {
            "m".into()
        };
        match choice.as_str() {
            "i" if state == service::State::Missing => {
                let vault = vault(None, true)?;
                let desktop = (desktop::Options {
                    desktop_socket: None,
                    pairing_file: None,
                })
                .paths()?;
                service::install(socket, &vault, Some(&desktop))?;
                eprintln!("✅ Daemon service installed and started");
            }
            "s" if matches!(state, service::State::Stopped | service::State::Failed) => {
                service::start(socket)?;
                eprintln!("✅ Daemon service started");
            }
            "m" => {
                eprintln!(
                    "⏳ In another terminal, run: {}",
                    command(Some(socket), &["daemon", "--desktop"])
                );
                read_answer("   Enter once it is running · q to cancel: ")?;
            }
            _ => eprintln!("Choose one of the offered actions."),
        }
    }
}
