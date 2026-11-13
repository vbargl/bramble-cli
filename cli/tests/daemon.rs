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
    let child = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(socket)
        .arg("daemon")
        .arg(vault)
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
}
