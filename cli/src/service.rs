//! Linux user-service lifecycle. Installation is explicit; inspecting state never changes it.
use std::io::Write;
use std::{
    fs,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const UNIT: &str = "bramble-cli.service";
const MARKER: &str = "# Managed by bramble-cli.\n";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum State {
    Missing,
    Stopped,
    Failed,
    Active,
    Unknown,
}

pub fn state() -> State {
    let output = match Command::new("systemctl")
        .args([
            "--user",
            "show",
            UNIT,
            "--property=LoadState",
            "--property=ActiveState",
        ])
        .output()
    {
        Ok(output) => output,
        Err(_) => return State::Unknown,
    };
    let text = String::from_utf8_lossy(&output.stdout);
    if text.lines().any(|l| l == "LoadState=not-found") {
        return State::Missing;
    }
    if !output.status.success() {
        return State::Unknown;
    }
    if text.lines().any(|l| l == "ActiveState=failed") {
        State::Failed
    } else if text
        .lines()
        .any(|l| l == "ActiveState=active" || l == "ActiveState=activating")
    {
        State::Active
    } else if text.lines().any(|l| l == "LoadState=loaded") {
        State::Stopped
    } else {
        State::Unknown
    }
}

fn systemctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("systemctl")
        .arg("--user")
        .args(args)
        .output()
        .map_err(|_| {
            "User services are unavailable. Start the daemon manually instead.".to_owned()
        })?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "Could not manage the daemon service.\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn start(socket: &Path) -> Result<(), String> {
    if state() == State::Missing {
        return Err(format!(
            "Daemon service is not installed.\n⏳ Run: {}",
            crate::guidance::command(Some(socket), &["service", "install", "--desktop"])
        ));
    }
    systemctl(&["start", UNIT])?;
    wait_ready(socket)
}
pub fn stop() -> Result<bool, String> {
    if state() == State::Missing {
        return Ok(false);
    }
    systemctl(&["stop", UNIT])?;
    Ok(true)
}

fn home_path(env: &str, fallback: &str) -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os(env).filter(|p| Path::new(p).is_absolute()) {
        return Ok(path.into());
    }
    Ok(PathBuf::from(std::env::var_os("HOME").ok_or("HOME is required")?).join(fallback))
}

// systemd expands specifiers and environment variables even inside quoted arguments.
fn quote(arg: &std::ffi::OsStr) -> Result<String, String> {
    let arg = arg.to_str().ok_or("Service paths must be valid UTF-8")?;
    let escaped = arg
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('%', "%%")
        .replace('$', "$$");
    Ok(format!("\"{escaped}\""))
}

fn unit(
    binary: &Path,
    socket: &Path,
    desktop: Option<&(PathBuf, PathBuf)>,
) -> Result<String, String> {
    let mut args = vec![
        binary.as_os_str(),
        std::ffi::OsStr::new("--socket"),
        socket.as_os_str(),
        std::ffi::OsStr::new("daemon"),
    ];
    if let Some((socket, identity)) = desktop {
        args.extend([
            std::ffi::OsStr::new("--desktop"),
            std::ffi::OsStr::new("--desktop-socket"),
            socket.as_os_str(),
            std::ffi::OsStr::new("--pairing-file"),
            identity.as_os_str(),
        ]);
    }
    let command = args
        .into_iter()
        .map(quote)
        .collect::<Result<Vec<_>, _>>()?
        .join(" ");
    Ok(format!("{MARKER}[Unit]\nDescription=Bramble CLI credential daemon\n\n[Service]\nType=exec\nExecStart={command}\nUMask=0077\n\n[Install]\nWantedBy=default.target\n"))
}

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&temp)
        .map_err(|e| format!("Cannot prepare {}: {e}", path.display()))?;
    let result = file
        .write_all(data)
        .and_then(|_| file.sync_all())
        .and_then(|_| fs::rename(&temp, path));
    if let Err(e) = result {
        let _ = fs::remove_file(&temp);
        return Err(format!("Cannot install {}: {e}", path.display()));
    }
    Ok(())
}

pub fn install(socket: &Path, desktop: Option<&(PathBuf, PathBuf)>) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("User-service installation requires Linux with systemd. Start the daemon manually instead.".into());
    }
    let initial = state();
    if initial == State::Unknown {
        return Err(
            "Cannot contact the user service manager. Start the daemon manually instead.".into(),
        );
    }
    if initial != State::Active && std::os::unix::net::UnixStream::connect(socket).is_ok() {
        return Err("A foreground daemon is already running. Stop it with Ctrl-C before installing the service.".into());
    }
    let directory = home_path("XDG_CONFIG_HOME", ".config")?.join("systemd/user");
    fs::create_dir_all(&directory)
        .map_err(|e| format!("Cannot create user-service directory: {e}"))?;
    let path = directory.join(UNIT);
    match fs::symlink_metadata(&path) {
        Ok(meta) => {
            if !meta.is_file()
                || !fs::read_to_string(&path)
                    .map_err(|e| e.to_string())?
                    .starts_with(MARKER)
            {
                return Err(format!("{} already exists and is not managed by this CLI. Keep it and configure the service there.", path.display()));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(format!("Cannot inspect user service: {e}")),
    }
    if initial != State::Missing {
        let output = Command::new("systemctl")
            .args(["--user", "show", UNIT, "--property=FragmentPath", "--value"])
            .output()
            .map_err(|e| e.to_string())?;
        let loaded = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !output.status.success() || (!loaded.is_empty() && Path::new(&loaded) != path) {
            return Err(
                "A daemon service is already configured elsewhere. Keep it and update it there."
                    .into(),
            );
        }
    }
    // Keep the service independent of the checkout/build directory used for installation.
    let bin = home_path("XDG_DATA_HOME", ".local/share")?.join("bramble-cli/bin");
    crate::private_dir(&bin)?;
    let binary = bin.join("bramble-cli");
    let executable =
        fs::read(std::env::current_exe().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    let absolute = |path: &Path| -> Result<PathBuf, String> {
        if path.is_absolute() {
            Ok(path.to_owned())
        } else {
            Ok(std::env::current_dir()
                .map_err(|e| e.to_string())?
                .join(path))
        }
    };
    let socket = absolute(socket)?;
    let desktop = desktop
        .map(|(socket, identity)| -> Result<_, String> {
            Ok((absolute(socket)?, absolute(identity)?))
        })
        .transpose()?;
    let unit = unit(&binary, &socket, desktop.as_ref())?;
    write_atomic(&binary, &executable, 0o700)?;
    write_atomic(&path, unit.as_bytes(), 0o600)?;
    systemctl(&["daemon-reload"])?;
    systemctl(&["enable", UNIT])?;
    systemctl(&["restart", UNIT])?;
    wait_ready(&socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_arguments_survive_systemd_expansion() {
        let result = unit(
            Path::new("/tmp/build dir/cli"),
            Path::new("/run/user/123/100% $socket/quote\".sock"),
            Some(&(
                PathBuf::from("/tmp/desktop.sock"),
                PathBuf::from("/tmp/client.json"),
            )),
        )
        .unwrap();
        assert!(result.contains("\"/tmp/build dir/cli\" \"--socket\""));
        assert!(result.contains("100%% $$socket/quote\\\".sock"));
        assert!(result.contains("\"--desktop\" \"--desktop-socket\""));
        assert!(result.contains("UMask=0077"));
    }
}

fn wait_ready(socket: &Path) -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::os::unix::net::UnixStream::connect(socket).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    Err("Daemon service did not become ready. Check: journalctl --user -u bramble-cli.service -n 20 --no-pager".into())
}
