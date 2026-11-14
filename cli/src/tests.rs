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
        let socket = root.path().join("desktop.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let locked = Arc::new(AtomicBool::new(false));
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
                        let _ = serve(&mut stream, &kp, &k, &verification, &l, &r, approve);
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
        desktop::pair(&self.socket, &self.identity(), |digits| {
            assert_eq!(self.sas.lock().unwrap().as_deref(), Some(digits));
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
    approve: bool,
) -> Result<(), String> {
    let hello = read_frame(stream)?;
    assert_eq!(hello["v"], 1);
    let linking = hello["kind"] == "link";
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
    assert!(desktop::pair(&desktop.socket, &desktop.identity(), |_| Ok(false)).is_err());
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
    let vault = desktop.root.path().join("vault.vlt");
    fixture(&vault);
    let mut state = State {
        vault,
        desktop: Some((desktop.socket.clone(), desktop.identity())),
        desktop_enabled: true,
    };
    assert_eq!(
        handle(Request::Status, &mut state).message,
        "unsealed (desktop)"
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
    assert_eq!(list.message, r#"[{"id":"entry-1","name":"Example"}]"#);
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
    assert!(handle(Request::Seal, &mut state).ok);
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
    assert!(handle(Request::Resume, &mut state).ok);
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
    assert!(!handle(Request::Resume, &mut state).ok);
    assert!(
        !handle(
            Request::Unseal {
                password: "wrong".into()
            },
            &mut state
        )
        .ok
    );
    assert!(
        handle(
            Request::Unseal {
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
    assert!(handle(Request::List { hostname: None }, &mut state).ok);
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
    handle(Request::Seal, &mut state);
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
