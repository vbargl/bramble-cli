//! Recover prerequisites one step at a time. Read-only commands and non-TTY callers never
//! install services, start processes, or wait for interactive input.
use crate::{
    desktop,
    output::{CliError, Step},
    service, terminal,
};
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
    // Some shells expand argv[0] to an absolute path. Prefer the same executable relative
    // to the current directory when possible, keeping follow-up commands short and copyable.
    let relative = std::env::current_dir().ok().and_then(|cwd| {
        Path::new(&binary)
            .strip_prefix(cwd)
            .ok()
            .map(|path| Path::new(".").join(path))
    });
    let mut parts = vec![quote(
        relative.as_deref().map(Path::as_os_str).unwrap_or(&binary),
    )];
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
) -> Result<PathBuf, CliError> {
    if let [choice] = choices {
        return Ok(choice.path.clone());
    }
    if choices.is_empty() {
        return Err(CliError::new("vault_not_found", "No vault was found. Open or restore a vault in desktop Bramble, or supply its .vlt path to unseal."));
    }
    if !interactive {
        return Err(CliError::new(
            "ambiguous_vault",
            "Several vaults are available. Choose one by supplying its name, ID or path.",
        )
        .steps(vec![Step::text(format!(
            "Available vaults:\n{}",
            choices
                .iter()
                .map(|v| format!("  {} ({})", v.name, v.path.display()))
                .collect::<Vec<_>>()
                .join("\n")
        ))])
        .choices(choices.to_vec()));
    }
    eprintln!("Choose the vault:\n");
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
        let value = read_answer("\n  Vault number (q to cancel): ")?;
        if let Ok(index) = value.parse::<usize>() {
            if let Some(vault) = index.checked_sub(1).and_then(|i| choices.get(i)) {
                return Ok(vault.path.clone());
            }
        }
        eprintln!("Choose one of the listed numbers.");
    }
}

pub fn unavailable(error: &io::Error, socket: &Path, managed: bool) -> CliError {
    use io::ErrorKind;
    let fail = |message: String, steps: Vec<Step>| {
        CliError::new("daemon_unavailable", message).steps(steps)
    };
    if error.kind() == ErrorKind::PermissionDenied {
        return fail(
            format!("Cannot access the daemon at {}.", socket.display()),
            vec![Step::text(
                "Use the same user account as the daemon and check this socket's permissions.",
            )],
        );
    }
    if !matches!(
        error.kind(),
        ErrorKind::NotFound | ErrorKind::ConnectionRefused
    ) {
        return fail(
            format!(
                "Cannot connect to the daemon at {}: {error}",
                socket.display()
            ),
            Vec::new(),
        );
    }
    let manual = Step::run(
        "Run in another terminal:",
        command(Some(socket), &["daemon", "--desktop"]),
    );
    if !managed {
        return fail(
            format!("No daemon is listening at {}.", socket.display()),
            vec![manual],
        );
    }
    let log = || {
        Step::run(
            "Check the service log:",
            "journalctl --user -u bramble-cli.service -n 20 --no-pager",
        )
    };
    match service::state() {
        service::State::Missing => fail(
            "Daemon service is not installed.".into(),
            vec![
                Step::run(
                    "Install and start the service:",
                    command(Some(socket), &["service", "install", "--desktop"]),
                ),
                manual,
            ],
        ),
        service::State::Stopped => fail(
            "Daemon service is stopped.".into(),
            vec![Step::run(
                "Start the service:",
                command(Some(socket), &["service", "start"]),
            )],
        ),
        service::State::Failed => fail("Daemon service failed to start.".into(), vec![log()]),
        service::State::Active => fail(
            "Daemon service is running but is not responding at this socket.".into(),
            vec![log()],
        ),
        service::State::Unknown => fail(
            "Daemon is not running; user-service state could not be checked.".into(),
            vec![manual],
        ),
    }
}

pub fn connect(socket: &Path, managed: bool, interactive: bool) -> Result<UnixStream, CliError> {
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
        let problem = unavailable(&error, socket, managed);
        let heading = problem.message.as_str();
        let choice = if state == service::State::Missing {
            terminal::error(&terminal::recovery(
                heading,
                &[
                    "[i] Install user service".into(),
                    "[m] Start manually".into(),
                ],
            ));
            read_answer("\n  Choose i or m (q to cancel): ")?
        } else if matches!(state, service::State::Stopped | service::State::Failed) {
            terminal::error(&terminal::recovery(
                heading,
                &["[s] Start user service".into(), "[m] Start manually".into()],
            ));
            read_answer("\n  Choose s or m (q to cancel): ")?
        } else {
            terminal::error(&problem.plain());
            read_answer("\n  Enter once ready to retry · q to cancel: ")?;
            continue;
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
                terminal::instructions(&[terminal::action(
                    "Run in another terminal:",
                    &command(Some(socket), &["daemon", "--desktop"]),
                )]);
                read_answer("\n  Enter once it is running · q to cancel: ")?;
            }
            _ => eprintln!("Choose one of the offered actions."),
        }
    }
}
