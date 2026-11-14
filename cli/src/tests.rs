use super::*;
use desktop::{read_frame, write_frame};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use vault_crypto::handshake as noise;

struct Desktop {
    root: tempfile::TempDir,
    socket: PathBuf,
    locked: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    switch_on_fetch: Arc<AtomicBool>,
    revoked: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    key: Arc<Mutex<Option<String>>>,
    sas: Arc<Mutex<Option<String>>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Desktop {
    fn new(approve: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.path().join("vaults")).unwrap();
        fs::write(root.path().join("meta.json"), json!({"active-vault":"vault","vault.registry":{"vaults":[{"id":"vault","label":"Desktop vault"}]}}).to_string()).unwrap();
        let socket = root.path().join("desktop.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let locked = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(true));
        let prepared = ready.clone();
        let switch_on_fetch = Arc::new(AtomicBool::new(false));
        let switching = switch_on_fetch.clone();
        let metadata_path = root.path().join("meta.json");
        let revoked = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let key = Arc::new(Mutex::new(None));
        let sas = Arc::new(Mutex::new(None));
        let (l, r, s, k, verification) = (
            locked.clone(),
            revoked.clone(),
            stop.clone(),
            key.clone(),
            sas.clone(),
        );
        let worker = thread::spawn(move || {
            let kp = noise::handshake_generate_keypair().unwrap();
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        stream
                            .set_write_timeout(Some(Duration::from_secs(3)))
                            .unwrap();
                        let _ = serve(
                            &mut stream,
                            &kp,
                            &k,
                            &verification,
                            &l,
                            &r,
                            &prepared,
                            approve,
                            &|| {
                                if switching.swap(false, Ordering::SeqCst) {
                                    fs::write(
                                        &metadata_path,
                                        json!({"active-vault":"other"}).to_string(),
                                    )
                                    .unwrap();
                                }
                            },
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            }
        });
        Self {
            root,
            socket,
            locked,
            ready,
            switch_on_fetch,
            revoked,
            stop,
            key,
            sas,
            worker: Some(worker),
        }
    }
    fn identity(&self) -> PathBuf {
        self.root.path().join("client.json")
    }
    fn pair(&self) {
        desktop::pair(&self.socket, &self.identity(), |event| {
            if let desktop::PairEvent::Compare(digits) = event {
                assert_eq!(self.sas.lock().unwrap().as_deref(), Some(digits));
            }
            Ok(true)
        })
        .unwrap();
    }
    fn call(&self, body: Value) -> Result<Value, String> {
        desktop::request(&self.socket, &self.identity(), body)
    }
}
impl Drop for Desktop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

struct CryptoSession(u32);
impl Drop for CryptoSession {
    fn drop(&mut self) {
        noise::handshake_close(self.0);
    }
}
fn receive(stream: &mut UnixStream, id: u32) -> Result<Value, String> {
    let frame = read_frame(stream)?;
    let plain =
        noise::handshake_decrypt(id, frame["sealed"].as_str().ok_or("no sealed body")?.into())
            .map_err(|e| e.to_string())?;
    serde_json::from_str(&plain).map_err(|e| e.to_string())
}
fn send(stream: &mut UnixStream, id: u32, body: Value) -> Result<(), String> {
    let sealed = noise::handshake_encrypt(id, body.to_string()).map_err(|e| e.to_string())?;
    write_frame(stream, &json!({"sealed":sealed}))
}

// A protocol peer using upstream Noise, not a stub of the CLI's authentication. It verifies
// commit/reveal and derives the SAS independently, then enforces desktop approval and lock.
#[allow(clippy::too_many_arguments)]
fn serve(
    stream: &mut UnixStream,
    kp: &noise::KeypairResult,
    key: &Mutex<Option<String>>,
    sas: &Mutex<Option<String>>,
    locked: &AtomicBool,
    revoked: &AtomicBool,
    ready: &AtomicBool,
    approve: bool,
    on_fetch: &dyn Fn(),
) -> Result<(), String> {
    let hello = read_frame(stream)?;
    assert_eq!(hello["v"], 1);
    let linking = hello["kind"] == "link";
    if linking && !ready.load(Ordering::SeqCst) {
        return write_frame(stream, &json!({"ok":false,"error":"refused","done":false}));
    }
    let id = if linking {
        assert_eq!(hello["label"], "Bramble CLI");
        noise::handshake_link_responder(kp.private_key.clone())
    } else {
        let public = hello["publicKey"].as_str().ok_or("no public key")?;
        if key.lock().unwrap().as_deref() != Some(public) {
            return Err("unpaired".into());
        }
        noise::handshake_start_responder(kp.private_key.clone(), public.into())
    }
    .map_err(|e| e.to_string())?;
    let _guard = CryptoSession(id);
    loop {
        let message = read_frame(stream)?["message"]
            .as_str()
            .ok_or("no message")?
            .to_owned();
        let step = noise::handshake_read(id, message).map_err(|e| e.to_string())?;
        write_frame(
            stream,
            &json!({"ok":true,"message":step.message,"done":step.done}),
        )?;
        if step.done {
            break;
        }
    }
    if linking {
        let commit = receive(stream, id)?;
        assert_eq!(commit["op"], "linkCommit");
        let nonce = [42; 32];
        send(stream, id, json!({"ok":true,"nonce":b64.encode(nonce)}))?;
        let reveal = receive(stream, id)?;
        assert_eq!(reveal["op"], "linkReveal");
        let client = b64.decode(reveal["nonce"].as_str().unwrap()).unwrap();
        assert_eq!(commit["commit"], b64.encode(Sha256::digest(&client)));
        let hash = b64.decode(noise::handshake_hash(id).unwrap()).unwrap();
        // Mirror the published TypeScript WebCrypto algorithm, independently of sas_digits.
        let mut input = b"bramble/link/sas-input/v1".to_vec();
        input.extend(hash);
        input.extend(nonce);
        input.extend(client);
        let material = Sha256::digest(&input);
        let mut bits = [0; 8];
        hkdf::Hkdf::<Sha256>::new(Some(&[]), &material)
            .expand(b"bramble/link/sas/v1", &mut bits)
            .unwrap();
        let n = format!("{:012}", u64::from_be_bytes(bits) % 1_000_000_000_000);
        *sas.lock().unwrap() = Some(format!("{} {} {}", &n[..4], &n[4..8], &n[8..]));
        send(stream, id, json!({"ok":true}))?;
        let confirm = receive(stream, id)?;
        assert_eq!(confirm["op"], "linkConfirm");
        if !approve {
            return send(stream, id, json!({"ok":false,"error":"refused"}));
        }
        send(stream, id, json!({"ok":true,"paired":true}))?;
        let complete = receive(stream, id)?;
        assert_eq!(complete["op"], "linkComplete");
        *key.lock().unwrap() = Some(noise::handshake_remote_static(id).unwrap());
        return send(stream, id, json!({"ok":true}));
    }
    if revoked.load(Ordering::SeqCst) {
        return send(
            stream,
            id,
            json!({"ok":false,"error":"not linked to this app"}),
        );
    }
    let request = receive(stream, id)?;
    // Exercise nonce sequencing in the presence of unsolicited traffic.
    send(stream, id, json!({"op":"syncOffer"}))?;
    if locked.load(Ordering::SeqCst) {
        return send(stream, id, json!({"ok":false,"error":"locked"}));
    }
    if request["op"] == "fetch" {
        on_fetch();
    }
    let answer = match request["op"].as_str() {
        Some("query") => {
            json!({"ok":true,"matches": if request["hostname"] == "example.com" { vec![json!({"id":"entry-1","name":"Example","secondary":"alice"})] } else { vec![] }})
        }
        Some("fetch") if request["id"] == "entry-1" => {
            json!({"ok":true,"username":"alice","password":"desktop-password"})
        }
        Some("fetch") => json!({"ok":false,"error":"unknown entry"}),
        _ => panic!("unexpected request: {request}"),
    };
    send(stream, id, answer)
}

#[test]
fn desktop_pairing_and_authentication() {
    let desktop = Desktop::new(true);
    desktop.pair();
    let path = desktop.identity();
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(desktop.key.lock().unwrap().is_some());
    assert_eq!(
        desktop.call(json!({"op":"fetch","id":"entry-1"})).unwrap()["password"],
        "desktop-password"
    );
    assert!(desktop
        .call(json!({"op":"fetch","id":"missing"}))
        .unwrap_err()
        .contains("unknown entry"));
    // A client cannot silently replace an already pinned identity.
    assert!(
        desktop::pair(&desktop.socket, &path, |_| panic!("must not prompt"))
            .unwrap_err()
            .contains("already exists")
    );
    let identity = desktop::Identity::load(&path).unwrap();
    // Alter the pinned desktop public key. The genuine desktop must fail authentication.
    let mut data: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    data["appPublicKey"] = json!(noise::handshake_generate_keypair().unwrap().public_key);
    fs::write(&path, data.to_string()).unwrap();
    assert!(desktop
        .call(json!({"op":"query","hostname":"example.com"}))
        .is_err());
    // Restore the valid identity for permissions/symlink checks.
    // Use its serialized form without logging key material.
    fs::write(&path, serde_json::to_vec(&identity).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(desktop::Identity::load(&path)
        .err()
        .unwrap()
        .contains("accessible only"));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = path.with_extension("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(desktop::Identity::load(&link).is_err());
}

#[test]
fn pairing_requires_both_confirmations() {
    let desktop = Desktop::new(true);
    assert!(
        desktop::pair(&desktop.socket, &desktop.identity(), |event| Ok(!matches!(
            event,
            desktop::PairEvent::Compare(_)
        )))
        .is_err()
    );
    assert!(!desktop.identity().exists());
    assert!(desktop.key.lock().unwrap().is_none());
    let desktop = Desktop::new(false);
    assert!(desktop::pair(&desktop.socket, &desktop.identity(), |_| Ok(true)).is_err());
    assert!(!desktop.identity().exists());
    assert!(desktop.key.lock().unwrap().is_none());
}

#[test]
fn framing_rejects_oversized_and_truncated_messages() {
    let (mut tx, mut rx) = UnixStream::pair().unwrap();
    tx.write_all(&(1024_u32 * 1024 + 1).to_le_bytes()).unwrap();
    assert!(read_frame(&mut rx).unwrap_err().contains("too large"));
    let (mut tx, mut rx) = UnixStream::pair().unwrap();
    tx.write_all(&8_u32.to_le_bytes()).unwrap();
    tx.write_all(b"{}").unwrap();
    drop(tx);
    assert!(read_frame(&mut rx).is_err());
}

#[test]
fn sas_matches_upstream_published_vector() {
    assert_eq!(
        b64.encode(desktop::sas_material(&[1; 32], &[2; 32], &[3; 32])),
        "S8naVfRk7bIlPFMxZJojFyQc+1fyQSEaCA2PzZ4RjDs="
    );
}

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
        json!({"type":"login","name":"Example","password":"local-password"}).to_string(),
    )
    .unwrap();
    let mut entry = serde_json::to_value(entry).unwrap();
    entry["id"] = json!("entry-1");
    let outer = vault_crypto::encrypt_with_vek(json!({"entries":[entry]}).to_string()).unwrap();
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
        data.extend(b64.decode(part).unwrap());
    }
    fs::write(path, data).unwrap();
    vault_crypto::lock();
}

#[test]
fn desktop_lock_seal_revocation_and_manual_fallback() {
    let desktop = Desktop::new(true);
    desktop.pair();
    let vault = desktop.root.path().join("vaults/vault.vlt");
    fixture(&vault);
    let mut state = State::new(Some((desktop.socket.clone(), desktop.identity())));
    assert_eq!(
        handle(Request::Status, &mut state).message,
        "unsealed:\n  Desktop vault (desktop)"
    );
    assert_eq!(
        handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .message,
        "desktop-password"
    );
    let list = handle(
        Request::List {
            hostname: Some("example.com".into()),
        },
        &mut state,
    );
    assert!(list.ok);
    assert_eq!(
        list.message,
        r#"[{"id":"entry-1","name":"Example","vault":"Desktop vault"}]"#
    );
    assert!(!handle(Request::List { hostname: None }, &mut state).ok);
    desktop.locked.store(true, Ordering::SeqCst);
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
    assert!(handle(Request::Status, &mut state)
        .message
        .contains("locked"));
    desktop.locked.store(false, Ordering::SeqCst);
    assert_eq!(
        handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .message,
        "desktop-password"
    );
    assert!(
        handle(
            Request::Seal {
                vault: Some(vault.clone())
            },
            &mut state
        )
        .ok
    );
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
    assert_eq!(handle(Request::Status, &mut state).message, "sealed");
    assert!(!desktop.locked.load(Ordering::SeqCst)); // CLI seal did not lock the desktop.
    assert!(
        handle(
            Request::Resume {
                vault: Some(vault.clone())
            },
            &mut state
        )
        .ok
    );
    desktop.revoked.store(true, Ordering::SeqCst);
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
    desktop.revoked.store(false, Ordering::SeqCst);
    // Desktop disappears: no automatic fallback using retained vault keys.
    state.desktop.as_mut().unwrap().0 = desktop.root.path().join("missing.sock");
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
    assert!(
        !handle(
            Request::Resume {
                vault: Some(vault.clone())
            },
            &mut state
        )
        .ok
    );
    assert!(
        !handle(
            Request::Unseal {
                vault: Some(vault.clone()),
                password: "wrong".into()
            },
            &mut state
        )
        .ok
    );
    assert!(
        handle(
            Request::Unseal {
                vault: Some(vault.clone()),
                password: "correct".into()
            },
            &mut state
        )
        .ok
    );
    assert_eq!(
        handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .message,
        "local-password"
    );
    assert!(vault_crypto::is_locked());
    assert!(handle(Request::List { hostname: None }, &mut state).ok);
    assert!(vault_crypto::is_locked());
    // Explicit manual access is independent of the desktop's lock state.
    desktop.locked.store(true, Ordering::SeqCst);
    assert_eq!(
        handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .message,
        "local-password"
    );
    handle(
        Request::Seal {
            vault: Some(vault.clone()),
        },
        &mut state,
    );
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
}

struct BeforeInput<F> {
    inner: std::io::Cursor<Vec<u8>>,
    before: F,
}
impl<F: FnMut()> Read for BeforeInput<F> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}
impl<F: FnMut()> BufRead for BeforeInput<F> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        (self.before)();
        self.inner.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        self.inner.consume(amount);
    }
}

#[test]
fn guide_waits_for_desktop_preparation_then_pairs() {
    let desktop = Desktop::new(true);
    desktop.ready.store(false, Ordering::SeqCst);
    let mut input = BeforeInput {
        inner: std::io::Cursor::new(b"\nyes\n".to_vec()),
        before: || {
            desktop.ready.store(true, Ordering::SeqCst);
        },
    };
    let mut output = Vec::new();
    pairing_ui::run(
        &desktop.socket,
        &desktop.identity(),
        &mut input,
        &mut output,
        true,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output
        .contains("⏳ In desktop Bramble: unlock vault → Settings → Browser extension → Connect."));
    assert!(output.contains("Enter when ready"));
    assert!(output.contains("🔒 Compare digits and approve"));
    assert!(output.contains("⏳ Click Approve in desktop Bramble"));
    assert!(output.ends_with("✅ Paired; ready to use\n"));
    assert!(desktop.identity().exists());
}

#[test]
fn guide_handles_missing_desktop_and_closed_input_without_claiming_success() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for input in [b"q\n".as_slice(), b""] {
        let mut output = Vec::new();
        let error = pairing_ui::run(
            &root.path().join("absent.sock"),
            &root.path().join("client.json"),
            &mut std::io::Cursor::new(input),
            &mut output,
            true,
        )
        .unwrap_err();
        assert!(error.contains("cancelled"));
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("⏳ In desktop Bramble:"));
        assert!(!output.contains("✅ Local desktop connection opened"));
        assert!(!output.contains("✅ Paired"));
        assert_eq!(output.lines().count(), 3);
        assert!(!output.contains("Desktop reported"));
        assert!(!root.path().join("client.json").exists());
    }
}

#[test]
fn guide_checks_existing_pairing_and_waits_for_unlock_without_replacing_credentials() {
    let desktop = Desktop::new(true);
    desktop.pair();
    let before = fs::read(desktop.identity()).unwrap();
    desktop.locked.store(true, Ordering::SeqCst);
    let mut input = BeforeInput {
        inner: std::io::Cursor::new(b"\n".to_vec()),
        before: || {
            desktop.locked.store(false, Ordering::SeqCst);
        },
    };
    let mut output = Vec::new();
    pairing_ui::run(
        &desktop.socket,
        &desktop.identity(),
        &mut input,
        &mut output,
        true,
    )
    .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("⏳ Unlock your vault in desktop Bramble"));
    assert!(output.contains("✅ Paired; ready to use"));
    assert!(before == fs::read(desktop.identity()).unwrap());
    desktop.revoked.store(true, Ordering::SeqCst);
    let error = pairing_ui::run(
        &desktop.socket,
        &desktop.identity(),
        &mut std::io::Cursor::new(b""),
        &mut Vec::new(),
        true,
    )
    .unwrap_err();
    assert!(
        error.contains("Open the vault originally paired"),
        "{error}"
    );
    assert!(before == fs::read(desktop.identity()).unwrap());
}

#[test]
fn guide_never_treats_enter_as_approval() {
    let desktop = Desktop::new(true);
    let mut output = Vec::new();
    assert!(pairing_ui::run(
        &desktop.socket,
        &desktop.identity(),
        &mut std::io::Cursor::new(b"\n"),
        &mut output,
        true,
    )
    .unwrap_err()
    .contains("cancelled"));
    assert!(!desktop.identity().exists());
    assert!(!String::from_utf8(output).unwrap().contains("✅ Paired"));
}

#[test]
fn daemon_socket_restart_preserves_live_daemons_and_unrelated_files() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.path().join("socket");
    let (listener, lock) = bind_daemon(&socket).unwrap();
    assert!(bind_daemon(&socket).is_err());
    assert!(UnixStream::connect(&socket).is_ok());
    drop(listener);
    drop(lock);
    // Simulate a crash: the old socket file remains but has no live listener.
    let (listener, lock) = bind_daemon(&socket).unwrap();
    assert!(UnixStream::connect(&socket).is_ok());
    drop(listener);
    drop(lock);
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, "unrelated file").unwrap();
    assert!(bind_daemon(&socket).is_err());
    assert_eq!(fs::read_to_string(&socket).unwrap(), "unrelated file");
}

#[test]
fn desktop_vault_switch_cannot_serve_a_secret_for_the_previous_vault() {
    let desktop = Desktop::new(true);
    desktop.pair();
    let original = desktop.root.path().join("vaults/vault.vlt");
    let mut state = State::new(Some((desktop.socket.clone(), desktop.identity())));
    desktop.switch_on_fetch.store(true, Ordering::SeqCst);
    let response = handle(
        Request::Get {
            id: "entry-1".into(),
        },
        &mut state,
    );
    assert!(!response.ok);
    assert!(!response.message.contains("desktop-password"));
    assert!(matches!(response.next, Some(NextAction::OpenPairedVault)));
    // A per-vault seal does not disable a different desktop vault.
    assert!(
        handle(
            Request::Seal {
                vault: Some(original.clone())
            },
            &mut state
        )
        .ok
    );
    assert_eq!(
        handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .message,
        "desktop-password"
    );
    fs::write(
        desktop.root.path().join("meta.json"),
        json!({"active-vault":"vault"}).to_string(),
    )
    .unwrap();
    assert!(
        !handle(
            Request::Get {
                id: "entry-1".into()
            },
            &mut state
        )
        .ok
    );
    // Explicitly asking to resume a different vault must never authorize the active one.
    fs::write(
        desktop.root.path().join("meta.json"),
        json!({"active-vault":"other"}).to_string(),
    )
    .unwrap();
    assert!(
        !handle(
            Request::Resume {
                vault: Some(original)
            },
            &mut state
        )
        .ok
    );
}
