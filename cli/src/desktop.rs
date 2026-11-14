//! Desktop protocol v1, matching Bramble revision 7acadf3. No vault sync or VEK caching.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    time::Duration,
};
use vault_crypto::handshake as noise;
use zeroize::{Zeroize, Zeroizing};

const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, clap::Args)]
pub struct Options {
    /// Use a non-default desktop socket.
    #[arg(long)]
    pub desktop_socket: Option<PathBuf>,
    /// Private file holding this client's pairing key and pinned desktop identity.
    #[arg(long)]
    pub pairing_file: Option<PathBuf>,
}

impl Options {
    pub fn paths(&self) -> Result<(PathBuf, PathBuf), String> {
        let base = match std::env::var_os("XDG_DATA_HOME").filter(|p| Path::new(p).is_absolute()) {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from(std::env::var_os("HOME").ok_or("HOME is required")?)
                .join(".local/share"),
        };
        #[cfg(target_os = "macos")]
        let desktop = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is required")?)
            .join("Library/Application Support/app.bramble.desktop/bramble.sock");
        #[cfg(not(target_os = "macos"))]
        let desktop = base.join("app.bramble.desktop/bramble.sock");
        Ok((
            self.desktop_socket.clone().unwrap_or(desktop),
            self.pairing_file
                .clone()
                .unwrap_or_else(|| base.join("bramble-cli/desktop.json")),
        ))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Identity {
    private_key: String,
    public_key: String,
    app_public_key: String,
}
impl Drop for Identity {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl Identity {
    pub fn load(path: &Path) -> Result<Self, String> {
        crate::private_dir(
            path.parent()
                .ok_or("pairing file needs a parent directory")?,
        )?;
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| format!("read pairing file: {e}; run bramble-cli pair first"))?;
        let meta = file.metadata().map_err(|e| e.to_string())?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(
                "pairing file must be owned by the current user and accessible only by that user"
                    .into(),
            );
        }
        let mut data = Zeroizing::new(Vec::new());
        Read::by_ref(&mut file)
            .take(MAX_FRAME as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() > MAX_FRAME {
            return Err("pairing file too large".into());
        }
        serde_json::from_slice(&data).map_err(|_| "invalid pairing file".into())
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        crate::private_dir(
            path.parent()
                .ok_or("pairing file needs a parent directory")?,
        )?;
        let data = Zeroizing::new(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("create pairing file: {e}"))?;
        if let Err(e) = file.write_all(&data).and_then(|_| file.sync_all()) {
            let _ = fs::remove_file(path);
            return Err(format!("save pairing file: {e}"));
        }
        Ok(())
    }
}

pub struct Session {
    stream: UnixStream,
    id: u32,
}
impl Drop for Session {
    fn drop(&mut self) {
        noise::handshake_close(self.id);
    }
}

fn crypto<T>(r: Result<T, vault_crypto::CryptoError>) -> Result<T, String> {
    r.map_err(|e| format!("desktop authentication: {e}"))
}

pub fn write_frame(stream: &mut UnixStream, value: &Value) -> Result<(), String> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    if bytes.len() > MAX_FRAME {
        return Err("desktop frame too large".into());
    }
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|e| format!("write desktop: {e}"))
}

pub fn read_frame(stream: &mut UnixStream) -> Result<Value, String> {
    let mut len = [0; 4];
    stream
        .read_exact(&mut len)
        .map_err(|e| format!("read desktop: {e}"))?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err("desktop frame too large".into());
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    stream
        .read_exact(&mut bytes)
        .map_err(|e| format!("read desktop: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid desktop frame".into())
}

fn field(value: &Value, name: &str) -> Result<String, String> {
    value[name]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("desktop reply missing {name}"))
}
fn accepted(value: Value) -> Result<Value, String> {
    if value["ok"] == true {
        Ok(value)
    } else {
        Err(format!(
            "desktop: {}",
            value["error"].as_str().unwrap_or("refused")
        ))
    }
}

impl Session {
    fn start(
        path: &Path,
        start: noise::StartResult,
        hello: Value,
        connected: impl FnOnce() -> Result<(), String>,
    ) -> Result<Self, String> {
        // Close the crypto session even if connecting or the handshake fails.
        let stream = match UnixStream::connect(path) {
            Ok(s) => s,
            Err(e) => {
                noise::handshake_close(start.session_id);
                return Err(format!("connect desktop: {e}"));
            }
        };
        let mut session = Self {
            stream,
            id: start.session_id,
        };
        session.timeout(Duration::from_secs(5))?;
        connected()?;
        write_frame(&mut session.stream, &hello)?;
        write_frame(&mut session.stream, &json!({"message": start.message}))?;
        let reply = accepted(read_frame(&mut session.stream)?)?;
        let step = crypto(noise::handshake_read(session.id, field(&reply, "message")?))?;
        if let Some(message) = step.message {
            write_frame(&mut session.stream, &json!({"message": message}))?;
            let reply = accepted(read_frame(&mut session.stream)?)?;
            if reply["done"] != true || !step.done {
                return Err("desktop handshake incomplete".into());
            }
        } else if !step.done || reply["done"] != true {
            return Err("desktop handshake incomplete".into());
        }
        Ok(session)
    }

    fn timeout(&self, duration: Duration) -> Result<(), String> {
        self.stream
            .set_read_timeout(Some(duration))
            .and_then(|_| self.stream.set_write_timeout(Some(duration)))
            .map_err(|e| e.to_string())
    }

    pub fn connect(socket: &Path, identity: &Identity) -> Result<Self, String> {
        let start = crypto(noise::handshake_start_initiator(
            identity.private_key.clone(),
            identity.app_public_key.clone(),
        ))?;
        Self::start(
            socket,
            start,
            json!({"kind":"hello", "v":1, "publicKey":identity.public_key}),
            || Ok(()),
        )
    }

    pub fn request(&mut self, body: Value) -> Result<Value, String> {
        accepted(self.request_raw(body)?)
    }

    // Keep authenticated refusals structured so the interactive guide can distinguish a
    // locked vault from a revoked pairing without guessing from an I/O error string.
    pub fn request_raw(&mut self, body: Value) -> Result<Value, String> {
        let plain = Zeroizing::new(body.to_string());
        let sealed = crypto(noise::handshake_encrypt(self.id, plain.to_string()))?;
        // A revoked connection can already have a sealed refusal queued after the
        // handshake, followed by EOF. Read that authenticated refusal even if our write
        // races the close; otherwise revocation looks like an unhelpful broken pipe.
        let sent = write_frame(&mut self.stream, &json!({"sealed": sealed}));
        // The desktop may push sync offers or page-fill events. They share Noise's nonce
        // sequence, so decrypt every frame, even though this client never syncs or fills pages.
        for _ in 0..64 {
            let frame = read_frame(&mut self.stream)
                .map_err(|e| sent.as_ref().err().cloned().unwrap_or(e))?;
            let plain = Zeroizing::new(crypto(noise::handshake_decrypt(
                self.id,
                field(&frame, "sealed")?,
            ))?);
            let value: Value =
                serde_json::from_str(&plain).map_err(|_| "invalid desktop answer")?;
            if value.get("ok").is_some() {
                if value["ok"] == true {
                    if let Err(e) = &sent {
                        return Err(e.clone());
                    }
                }
                return Ok(value);
            }
        }
        Err("desktop sent too many unsolicited frames".into())
    }
}

pub fn request(socket: &Path, pairing_file: &Path, body: Value) -> Result<Value, String> {
    let identity = Identity::load(pairing_file)?;
    Session::connect(socket, &identity)?.request(body)
}

pub fn sas_material(hash: &[u8], desktop: &[u8], client: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"bramble/link/sas-input/v1");
    h.update(hash);
    h.update(desktop);
    h.update(client);
    h.finalize().to_vec()
}

fn sas_digits(material: &[u8]) -> String {
    let mut bits = [0; 8];
    Hkdf::<Sha256>::new(None, material)
        .expand(b"bramble/link/sas/v1", &mut bits)
        .expect("fixed HKDF output size");
    let digits = format!("{:012}", u64::from_be_bytes(bits) % 1_000_000_000_000);
    format!("{} {} {}", &digits[..4], &digits[4..8], &digits[8..])
}

pub enum PairEvent<'a> {
    Connected,
    Compare(&'a str),
    AwaitingDesktop,
}

/// The caller compares the SAS with the desktop UI. Never auto-approve this check.
pub fn pair(
    socket: &Path,
    path: &Path,
    mut progress: impl FnMut(PairEvent<'_>) -> Result<bool, String>,
) -> Result<(), String> {
    crate::private_dir(
        path.parent()
            .ok_or("pairing file needs a parent directory")?,
    )?;
    if path.symlink_metadata().is_ok() {
        return Err(
            "pairing file already exists; remove it only when deliberately re-pairing".into(),
        );
    }
    let mut kp = crypto(noise::handshake_generate_keypair())?;
    let start = crypto(noise::handshake_link_initiator(kp.private_key.clone()));
    let private_key = std::mem::take(&mut kp.private_key);
    let mut identity = Identity {
        private_key,
        public_key: kp.public_key,
        app_public_key: String::new(),
    };
    let mut session = Session::start(
        socket,
        start?,
        json!({"kind":"link", "v":1, "label":"Bramble CLI"}),
        || progress(PairEvent::Connected).map(|_| ()),
    )?;
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(|e| e.to_string())?;
    let answer =
        session.request(json!({"op":"linkCommit", "commit":B64.encode(Sha256::digest(nonce))}))?;
    let desktop_nonce = B64
        .decode(field(&answer, "nonce")?)
        .map_err(|_| "invalid desktop nonce")?;
    if desktop_nonce.len() != 32 {
        return Err("invalid desktop nonce length".into());
    }
    session.request(json!({"op":"linkReveal", "nonce":B64.encode(nonce)}))?;
    let hash = B64
        .decode(crypto(noise::handshake_hash(session.id))?)
        .map_err(|_| "invalid handshake hash")?;
    identity.app_public_key = crypto(noise::handshake_remote_static(session.id))?;
    let digits = sas_digits(&sas_material(&hash, &desktop_nonce, &nonce));
    if !progress(PairEvent::Compare(&digits))? {
        return Err("pairing cancelled; desktop identity was not saved".into());
    }
    progress(PairEvent::AwaitingDesktop)?;
    session.timeout(Duration::from_secs(180))?;
    let answer = session.request(json!({"op":"linkConfirm"}))?;
    if answer["paired"] != true {
        return Err("desktop did not confirm pairing".into());
    }
    session.timeout(Duration::from_secs(5))?;
    // This client needs credential delegation only. Do not claim a sync invite or copy a vault.
    session.request(json!({"op":"linkComplete"}))?;
    identity.save(path)
}
