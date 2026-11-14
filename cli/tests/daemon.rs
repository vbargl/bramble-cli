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
    let entry = vault_crypto::encrypt_entry(
        json!({"type":"login","name":"Example","password":"synthetic-password"}).to_string(),
    )
    .unwrap();
    let mut entry = serde_json::to_value(entry).unwrap();
    entry["id"] = json!("entry-1");
    let outer =
        vault_crypto::encrypt_with_vek(json!({"entries":[entry],"tombstones":[]}).to_string())
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
fn start(socket: &Path, vault: &Path) -> Child {
    start_with_options(socket, vault, &[])
}
fn start_with_options(socket: &Path, vault: &Path, options: &[&std::ffi::OsStr]) -> Child {
    let child = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(socket)
        .arg("daemon")
        .arg(vault)
        .args(options)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    for _ in 0..200 {
        if socket.exists() {
            return child;
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
        request(&socket, json!({"op":"unseal","password":"wrong"}))["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"unseal","password":"correct"}))["ok"],
        true
    );
    assert_eq!(
        request(&socket, json!({"op":"list"}))["message"],
        r#"[{"id":"entry-1","name":"Example"}]"#
    );
    for _ in 0..2 {
        assert_eq!(
            request(&socket, json!({"op":"get","id":"entry-1"}))["message"],
            "synthetic-password"
        );
    }
    assert_eq!(request(&socket, json!({"op":"seal"}))["ok"], true);
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"unseal","password":"correct"}))["ok"],
        true
    );
    daemon.kill().unwrap();
    daemon.wait().unwrap();
    fs::remove_file(&socket).unwrap();
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
    fs::remove_file(&socket).unwrap();
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
    assert!(request(&socket, json!({"op":"status"}))["message"]
        .as_str()
        .unwrap()
        .starts_with("sealed ("));
    assert_eq!(request(&socket, json!({"op":"resume"}))["ok"], false);
    assert_eq!(
        request(&socket, json!({"op":"get","id":"entry-1"}))["ok"],
        false
    );
    assert_eq!(
        request(&socket, json!({"op":"unseal","password":"correct"}))["ok"],
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
    assert_eq!(request(&socket, json!({"op":"seal"}))["ok"], true);
    assert_eq!(
        request(&socket, json!({"op":"status"}))["message"],
        "sealed"
    );
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
    assert!(text.contains("✅ CLI ready"));
    assert!(text.contains("⏳ Open desktop Bramble"));
    assert!(text.contains("🔒 Compare the pairing digits"));
    assert!(text.contains("pairing cancelled"));
    assert!(!text.contains("✅ Pairing saved"));
    assert!(!identity.exists());
}
