use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

fn fixture(path: &Path) {
    fixture_entries(path, &[("entry-1", "Example", "synthetic-password")]);
}
fn fixture_entries(path: &Path, entries: &[(&str, &str, &str)]) {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = LOCK.lock().unwrap();
    vault_crypto::generate_vek().unwrap();
    let salt = vault_crypto::generate_salt().unwrap();
    let id = vault_crypto::generate_slot_id().unwrap();
    let slot = vault_crypto::wrap_vek_password(
        "correct".into(),
        salt.clone(),
        id.clone(),
        b"VLT1\x02".to_vec(),
    )
    .unwrap();
    let entries:Vec<_>=entries.iter().map(|(id,name,password)|{
        let entry=vault_crypto::encrypt_entry(json!({"type":"login","name":name,"password":password,"urls":["https://Example.com/login"]}).to_string()).unwrap();
        let mut entry=serde_json::to_value(entry).unwrap(); entry["id"]=json!(id); entry
    }).collect();
    let outer =
        vault_crypto::encrypt_with_vek(json!({"entries":entries,"tombstones":[]}).to_string())
            .unwrap();
    let mut data = b"VLT1\x02\x01\x01\x00\x7c".to_vec();
    for part in [
        &id,
        &salt,
        &slot.verifier,
        &slot.wrap_iv,
        &slot.wrapped_vek,
        &outer.iv,
        &outer.ciphertext,
    ] {
        data.extend(B64.decode(part).unwrap());
    }
    fs::write(path, data).unwrap();
    vault_crypto::lock();
}
struct Running(Child);
impl std::ops::Deref for Running {
    type Target = Child;
    fn deref(&self) -> &Child {
        &self.0
    }
}
impl std::ops::DerefMut for Running {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn start(socket: &Path, vault: &Path) -> Running {
    start_with_options(socket, vault, &[])
}
fn start_with_options(socket: &Path, _vault: &Path, options: &[&std::ffi::OsStr]) -> Running {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
            .arg("--socket")
            .arg(socket)
            .arg("daemon")
            .env("XDG_DATA_HOME", socket.parent().unwrap().join("data"))
            .args(options)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap(),
    );
    for _ in 0..200 {
        if UnixStream::connect(socket).is_ok() {
            return child;
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("daemon exited before readiness: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("daemon failed to start");
}
fn request(socket: &Path, req: Value) -> Value {
    let mut s = UnixStream::connect(socket).unwrap();
    writeln!(s, "{req}").unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}
#[test]
fn lifecycle_with_upstream_vault() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("socket");
    let vault = dir.path().join("vault.vlt");
    fixture(&vault);
    let mut daemon = start(&socket, &vault);
    assert_eq!(
        request(&socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":vault,"password":"wrong"})
        )["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":vault,"password":"correct"})
        )["ok"],
        true
    );
    assert_eq!(
        request(&socket, json!({"op":"list"}))["message"],
        r#"[{"id":"entry-1","name":"Example","vault":"vault"}]"#
    );
    for _ in 0..2 {
        assert_eq!(
            request(&socket, json!({"op":"get","id":"entry-1"}))["message"],
            "synthetic-password"
        );
    }
    assert_eq!(request(&socket, json!({"op":"vault_seal"}))["ok"], true);
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":vault,"password":"correct"})
        )["ok"],
        true
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let mut daemon = start(&socket, &vault);
    assert_eq!(
        request(&socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();

    // Exercise the executable's desktop flags, IPC resume, and explicit manual fallback
    // with a desktop that is not running. The local vault remains available independently.
    let desktop_socket = dir.path().join("absent-desktop.sock");
    let pairing_file = dir.path().join("absent-pairing.json");
    let mut daemon = start_with_options(
        &socket,
        &vault,
        &[
            std::ffi::OsStr::new("--desktop"),
            std::ffi::OsStr::new("--desktop-socket"),
            desktop_socket.as_os_str(),
            std::ffi::OsStr::new("--pairing-file"),
            pairing_file.as_os_str(),
        ],
    );
    let status = request(&socket, json!({"op":"status"}));
    assert_eq!(status["next"], "open_desktop");
    assert_eq!(status["ok"], true);
    assert_eq!(request(&socket, json!({"op":"vault_resume"}))["ok"], false);
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":vault,"password":"correct"})
        )["ok"],
        true
    );
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .args(["--socket"])
        .arg(&socket)
        .arg("unseal")
        .output()
        .unwrap();
    assert!(output.status.success()); // Already manually unsealed: no terminal prompt.
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "unsealed");
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .args(["get", "entry-1"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        "synthetic-password"
    );
    assert_eq!(request(&socket, json!({"op":"vault_seal"}))["ok"], true);
    assert!(request(&socket, json!({"op":"status"}))["message"]
        .as_str()
        .unwrap()
        .starts_with("sealed"));
    daemon.kill().unwrap();
    daemon.wait().unwrap();
}

#[test]
fn pair_guides_preparation_without_a_daemon_or_runtime_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let identity = dir.path().join("client.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .env_remove("XDG_RUNTIME_DIR")
        .args(["pair", "--desktop-socket"])
        .arg(dir.path().join("missing.sock"))
        .arg("--pairing-file")
        .arg(&identity)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"q\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    let text = String::from_utf8(output.stderr).unwrap();
    assert!(text.contains("Run in a terminal:"));
    assert!(!text.contains("Type yes"));
    assert!(!text.contains("Enter when ready"));
    assert!(!text.contains("✅ Paired"));
    assert!(!identity.exists());
}

// Isolated service-manager fixture: commands below can only reach this test's temporary
// files and synthetic vault. The generated daemon executable itself is real.
struct ServiceFixture {
    root: tempfile::TempDir,
    socket: std::path::PathBuf,
    vault: std::path::PathBuf,
}
impl ServiceFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["bin", "config", "data", "runtime", "home"] {
            fs::create_dir(root.path().join(name)).unwrap();
            fs::set_permissions(root.path().join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let vault = root.path().join("vault.vlt");
        fixture(&vault);
        let socket = root.path().join("runtime/bramble-cli/socket");
        let script = root.path().join("bin/systemctl");
        fs::write(&script, r#"#!/bin/sh
set -eu
case "$2" in
  show)
    case "$*" in
      *FragmentPath*) printf '%s\n' "$XDG_CONFIG_HOME/systemd/user/bramble-cli.service"; exit 0 ;;
    esac
    state=missing
    if test -f "$TEST_ROOT/state"; then state=$(cat "$TEST_ROOT/state"); fi
    case "$state" in
      missing) printf 'LoadState=not-found\nActiveState=inactive\n' ;;
      stopped) printf 'LoadState=loaded\nActiveState=inactive\n' ;;
      failed) printf 'LoadState=loaded\nActiveState=failed\n' ;;
      active) printf 'LoadState=loaded\nActiveState=active\n' ;;
      *) exit 1 ;;
    esac ;;
  daemon-reload|enable) : ;;
  restart|start)
    if test "$2" = start && test -f "$TEST_ROOT/pid"; then exit 0; fi
    if test -f "$TEST_ROOT/pid"; then kill "$(cat "$TEST_ROOT/pid")" 2>/dev/null || true; sleep 0.05; fi
    "$XDG_DATA_HOME/bramble-cli/bin/bramble-cli" --socket "$TEST_SOCKET" daemon >/dev/null 2>"$TEST_ROOT/daemon.log" &
    printf '%s\n' "$!" >"$TEST_ROOT/pid"
    printf 'active\n' >"$TEST_ROOT/state" ;;
  stop)
    if test -f "$TEST_ROOT/pid"; then kill "$(cat "$TEST_ROOT/pid")" 2>/dev/null || true; rm "$TEST_ROOT/pid"; fi
    printf 'stopped\n' >"$TEST_ROOT/state" ;;
  *) exit 1 ;;
esac
"#).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            root,
            socket,
            vault,
        }
    }
    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bramble-cli"));
        let path = std::env::join_paths(
            std::iter::once(self.root.path().join("bin"))
                .chain(std::env::split_paths(&std::env::var_os("PATH").unwrap())),
        )
        .unwrap();
        command
            .env("PATH", path)
            .env("HOME", self.root.path().join("home"))
            .env("XDG_RUNTIME_DIR", self.root.path().join("runtime"))
            .env("XDG_CONFIG_HOME", self.root.path().join("config"))
            .env("XDG_DATA_HOME", self.root.path().join("data"))
            .env("TEST_ROOT", self.root.path())
            .env("TEST_SOCKET", &self.socket)
            .env("TEST_VAULT", &self.vault)
            .env_remove("BRAMBLE_SOCKET");
        command
    }
}
impl Drop for ServiceFixture {
    fn drop(&mut self) {
        if let Ok(pid) = fs::read_to_string(self.root.path().join("pid")) {
            if let Ok(pid) = pid.trim().parse::<i32>() {
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
            }
        }
    }
}

#[test]
fn status_diagnoses_missing_stopped_failed_and_unknown_service_without_prompting() {
    let fixture = ServiceFixture::new();
    for (state, expected) in [
        ("missing", "Daemon service is not installed."),
        ("stopped", "Daemon service is stopped."),
        ("failed", "Daemon service failed to start."),
        ("unknown", "user-service state could not be checked"),
    ] {
        fs::write(fixture.root.path().join("state"), state).unwrap();
        let output = fixture.command().arg("status").output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("os error"));
        assert!(!error.contains("[i]"));
        assert!(!fixture
            .root
            .path()
            .join("config/systemd/user/bramble-cli.service")
            .exists());
    }
    let output = fixture
        .command()
        .arg("--socket")
        .arg(fixture.root.path().join("custom.sock"))
        .arg("status")
        .output()
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("No daemon is listening"));
    assert!(!error.contains("not installed"));
    assert!(error.contains("--socket"));
    // Unseal must diagnose the missing daemon before considering a password prompt.
    let output = fixture
        .command()
        .args(["--no-input", "unseal", "--manual"])
        .output()
        .unwrap();
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(!error.contains("Master password"));
    assert!(error.contains("Daemon is not running"));
}

#[test]
fn service_install_copies_binary_preserves_foreign_units_and_starts_a_real_synthetic_daemon() {
    let fixture = ServiceFixture::new();
    let unit = fixture
        .root
        .path()
        .join("config/systemd/user/bramble-cli.service");
    let output = fixture
        .command()
        .args(["service", "install"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        request(&fixture.socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    let binary = fixture.root.path().join("data/bramble-cli/bin/bramble-cli");
    assert_eq!(
        fs::metadata(&binary).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let content = fs::read_to_string(&unit).unwrap();
    assert!(content.contains("Type=exec"));
    assert!(!content.contains(&fixture.vault.to_string_lossy().to_string()));
    let status = fixture.command().arg("status").output().unwrap();
    assert!(status.status.success());
    assert!(!status.stderr.windows(3).any(|w| w == b"[i]"));
    // Reinstallation updates an owned unit and restarts with a fresh sealed process.
    assert_eq!(
        request(
            &fixture.socket,
            json!({"op":"vault_unseal","vault":fixture.vault,"password":"correct"})
        )["ok"],
        true
    );
    let output = fixture
        .command()
        .args(["service", "install"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        request(&fixture.socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    let output = fixture
        .command()
        .args(["service", "stop"])
        .output()
        .unwrap();
    assert!(output.status.success());
    fs::write(&unit, "# Maintained by the user\n").unwrap();
    let output = fixture
        .command()
        .args(["service", "install"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not managed by this CLI"));
    assert_eq!(
        fs::read_to_string(&unit).unwrap(),
        "# Maintained by the user\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn interactive_get_resumes_original_request_after_either_setup_route() {
    use std::os::fd::FromRawFd;
    for choice in [b"m\n".as_slice(), b"i\n".as_slice()] {
        let fixture = ServiceFixture::new();
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut terminal = unsafe { fs::File::from_raw_fd(master) };
        let stdin = unsafe { fs::File::from_raw_fd(slave) };
        let log = fixture.root.path().join("interaction.log");
        let mut child = fixture
            .command()
            .args(["get", "entry-1"])
            .stdin(stdin)
            .stderr(fs::File::create(&log).unwrap())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let wait_for = |needle: &str| {
            for _ in 0..300 {
                let text = fs::read_to_string(&log).unwrap();
                if text.contains(needle) {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            panic!(
                "Missing prompt {needle}: {}",
                fs::read_to_string(&log).unwrap()
            );
        };
        wait_for("[i] Install user service");
        terminal.write_all(choice).unwrap();
        let mut daemon = if choice == b"m\n" {
            wait_for("Enter once it is running");
            Some(start(&fixture.socket, &fixture.vault))
        } else {
            // Service installation is vault-independent and must not ask for a vault.
            wait_for("Enter once ready to retry");
            None
        };
        assert_eq!(
            request(
                &fixture.socket,
                json!({"op":"vault_unseal","vault":fixture.vault,"password":"correct"})
            )["ok"],
            true
        );
        terminal.write_all(b"\n").unwrap();
        for _ in 0..300 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
            panic!("get did not resume");
        }
        let output = child.wait_with_output().unwrap();
        if let Some(daemon) = &mut daemon {
            daemon.kill().unwrap();
            daemon.wait().unwrap();
        }
        assert!(
            output.status.success(),
            "{}",
            fs::read_to_string(&log).unwrap()
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "synthetic-password\n"
        );
        assert!(!fs::read_to_string(&log)
            .unwrap()
            .contains("synthetic-password"));
        assert_eq!(
            fixture
                .root
                .path()
                .join("config/systemd/user/bramble-cli.service")
                .exists(),
            choice == b"i\n"
        );
    }
}

#[test]
fn multiple_vaults_query_together_and_mutate_independently() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("socket");
    let data = dir.path().join("data/app.bramble.desktop");
    let personal = data.join("vaults/personal.vlt");
    let work = data.join("vaults/work.vlt");
    // Startup must succeed before any vault exists or is selected.
    let mut daemon = start(&socket, &personal);
    assert_eq!(
        request(&socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    fs::create_dir_all(data.join("vaults")).unwrap();
    fs::write(data.join("meta.json"),json!({"vault.registry":{"vaults":[{"id":"personal","label":"Personal"},{"id":"work","label":"Work"}]}}).to_string()).unwrap();
    fixture_entries(
        &personal,
        &[
            ("alpha", "Alpha", "alpha-secret"),
            ("shared", "Duplicate", "personal-shared"),
        ],
    );
    fixture_entries(
        &work,
        &[
            ("beta", "Beta", "beta-secret"),
            ("shared", "Duplicate", "work-shared"),
        ],
    );
    let choices = request(&socket, json!({"op":"vaults","purpose":"unseal"}));
    assert_eq!(choices["choices"].as_array().unwrap().len(), 2);
    assert_eq!(
        request(&socket, json!({"op":"vault_resume"}))["next"],
        "select_vault"
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":personal,"password":"correct"})
        )["ok"],
        true
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":work,"password":"wrong"})
        )["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"alpha"}))["message"],
        "alpha-secret"
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":work,"password":"correct"})
        )["ok"],
        true
    );
    for (id, secret) in [("alpha", "alpha-secret"), ("beta", "beta-secret")] {
        let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
            .arg("--socket")
            .arg(&socket)
            .args(["get", id])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{secret}\n")
        );
    }
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .args(["--json", "list"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty()); // No vault selection for a query.
    let document: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(document["ok"], true);
    let rows = document["data"]["entries"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 4);
    assert!(rows
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["vault"] == "Personal"));
    assert!(rows
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["vault"] == "Work"));
    assert_eq!(
        request(&socket, json!({"op":"get","id":"shared"}))["ok"],
        false
    );
    for (path, secret) in [(&personal, "personal-shared"), (&work, "work-shared")] {
        let id = format!("{}::shared", path.display());
        assert!(rows.as_array().unwrap().iter().any(|v| v["id"] == id));
        assert_eq!(
            request(&socket, json!({"op":"get","id":id}))["message"],
            secret
        );
    }
    let filtered = request(&socket, json!({"op":"list","hostname":"example.com"}));
    assert_eq!(
        serde_json::from_str::<Value>(filtered["message"].as_str().unwrap())
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        4
    );
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .args(["--no-input", "seal"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8(output.stderr).unwrap();
    assert!(error.contains("Personal") && error.contains("Work"));
    assert_eq!(
        request(&socket, json!({"op":"vault_seal"}))["next"],
        "select_vault"
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"beta"}))["message"],
        "beta-secret"
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut terminal = unsafe { fs::File::from_raw_fd(master) };
        let stdin = unsafe { fs::File::from_raw_fd(slave) };
        let log = dir.path().join("seal.log");
        let mut child = Running(
            Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
                .arg("--socket")
                .arg(&socket)
                .arg("seal")
                .stdin(stdin)
                .stderr(fs::File::create(&log).unwrap())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        for _ in 0..300 {
            if fs::read_to_string(&log).unwrap().contains("Vault number") {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let prompt = fs::read_to_string(&log).unwrap();
        assert!(
            prompt.contains("Personal") && prompt.contains("Work"),
            "{prompt}"
        );
        terminal.write_all(b"1\n").unwrap();
        for _ in 0..300 {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(child.try_wait().unwrap().is_some(), "seal did not finish");
        assert!(child.wait().unwrap().success());
    }
    #[cfg(not(target_os = "linux"))]
    assert_eq!(
        request(&socket, json!({"op":"vault_seal","vault":"Personal"}))["ok"],
        true
    );

    assert_eq!(
        request(&socket, json!({"op":"get","id":"alpha"}))["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"beta"}))["message"],
        "beta-secret"
    );
    // A sole unsealed vault supplies the context even when several files exist.
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .arg("unseal")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .arg("seal")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        request(&socket, json!({"op":"get","id":"beta"}))["ok"],
        false
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":"Personal","password":"correct"})
        )["ok"],
        true
    );
    assert_eq!(
        request(
            &socket,
            json!({"op":"vault_unseal","vault":"Work","password":"correct"})
        )["ok"],
        true
    );
    fs::remove_file(&personal).unwrap();
    assert_eq!(
        request(&socket, json!({"op":"vault_seal","vault":personal}))["ok"],
        true
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"beta"}))["message"],
        "beta-secret"
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    let mut daemon = start(&socket, &work);
    assert_eq!(
        request(&socket, json!({"op":"status"}))["message"],
        "sealed"
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"beta"}))["ok"],
        false
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();
}

#[test]
fn newer_client_cannot_trigger_an_old_daemons_global_seal() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = dir.path().join("socket");
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let worker = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let value: Value = serde_json::from_str(&line).unwrap();
        // This is the old daemon's mutating opcode; it must never be sent by this build.
        assert_ne!(value["op"], "seal");
        writeln!(stream, "{{\"ok\":false,\"message\":\"invalid request\"}}").unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(&socket)
        .arg("seal")
        .arg(dir.path().join("any.vlt"))
        .output()
        .unwrap();
    worker.join().unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Daemon needs an update"));
}

#[cfg(target_os = "linux")]
#[test]
fn error_hierarchy_is_readable_in_colored_plain_and_dumb_terminals() {
    use std::{io::Read, os::fd::FromRawFd};
    let fixture = ServiceFixture::new();
    for (term, no_color, colored) in [
        ("xterm", None, true),
        ("xterm", Some("1"), false),
        ("dumb", None, false),
    ] {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let mut terminal = unsafe { fs::File::from_raw_fd(master) };
        let stderr = unsafe { fs::File::from_raw_fd(slave) };
        let mut command = fixture.command();
        command
            .arg("status")
            .env("TERM", term)
            .env_remove("NO_COLOR")
            .stderr(stderr);
        if let Some(value) = no_color {
            command.env("NO_COLOR", value);
        }
        let output = command.output().unwrap();
        drop(command); // Close the parent's duplicate of the slave before reading to EOF.
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let mut bytes = Vec::new();
        let _ = terminal.read_to_end(&mut bytes); // Linux PTYs report EIO at the final EOF.
        let text = String::from_utf8(bytes).unwrap().replace('\r', "");
        assert_eq!(text.contains("\x1b[1;31m"), colored, "{text:?}");
        if !colored {
            assert!(!text.contains('\x1b'));
        }
        assert_eq!(
            text.contains("\x1b[1m    "),
            colored,
            "commands are bold: {text:?}"
        );
        assert_eq!(text.contains("\x1b[2m  -- or --"), colored, "{text:?}");
        let plain = ["\x1b[1;31m", "\x1b[1m", "\x1b[2m", "\x1b[0m"]
            .iter()
            .fold(text.clone(), |text, code| text.replace(code, ""));
        let lines: Vec<_> = plain.lines().collect();
        assert_eq!(lines.len(), 9, "{plain}");
        assert_eq!(lines[0], "! Daemon service is not installed.");
        assert_eq!(lines[1], "");
        assert_eq!(lines[2], "  1️⃣ Install and start the service:");
        assert!(lines[3].starts_with("    ") && lines[3].ends_with(" service install --desktop"));
        assert_eq!(&lines[4..7], &["", "  -- or --", ""]);
        assert_eq!(lines[7], "  2️⃣ Run in another terminal:");
        assert!(lines[8].starts_with("    ") && lines[8].ends_with(" daemon --desktop"));
        assert!(!plain.contains("⏳"));
    }
    assert!(!fixture
        .root
        .path()
        .join("config/systemd/user/bramble-cli.service")
        .exists());
}
