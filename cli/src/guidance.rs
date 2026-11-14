//! Recover prerequisites one step at a time. Read-only commands and non-TTY callers never
//! install services, start processes, or wait for interactive input.
use crate::{desktop, service};
use std::{
    ffi::OsStr,
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

pub fn choose_vault(
    choices: &[crate::vaults::Choice],
    interactive: bool,
) -> Result<PathBuf, String> {
    if let [choice] = choices {
        return Ok(choice.path.clone());
    }
    if choices.is_empty() {
        return Err("No vault was found. Open or restore a vault in desktop Bramble, or supply its .vlt path to unseal.".into());
    }
    if !interactive {
        return Err(format!(
            "Choose the vault to change by supplying its name, ID or path.\n{}",
            choices
                .iter()
                .map(|v| format!("  {} ({})", v.name, v.path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        ));
    }
    eprintln!("Choose the vault:");
    for (i, vault) in choices.iter().enumerate() {
        if choices
            .iter()
            .filter(|other| other.name == vault.name)
            .count()
            > 1
        {
            eprintln!(
                "  {}  {} ({}; {})",
                i + 1,
                vault.name,
                vault.access,
                vault.path.display()
            );
        } else {
            eprintln!("  {}  {} ({})", i + 1, vault.name, vault.access);
        }
    }
    loop {
        let value = read_answer("⏳ Vault number (q to cancel): ")?;
        if let Ok(index) = value.parse::<usize>() {
            if let Some(vault) = index.checked_sub(1).and_then(|i| choices.get(i)) {
                return Ok(vault.path.clone());
            }
        }
        eprintln!("Choose one of the listed numbers.");
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
                let desktop = (desktop::Options {
                    desktop_socket: None,
                    pairing_file: None,
                })
                .paths()?;
                service::install(socket, Some(&desktop))?;
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
