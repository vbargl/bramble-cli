//! Writing entries into a local vault file.
//!
//! A save re-encrypts only the outer entries payload. Every byte before it (the key slots,
//! including kinds this CLI cannot read) is copied verbatim, every untouched entry keeps its
//! envelope, and unknown payload members (tombstones, settings, files, conflicts) survive.
//! The new file is written beside the old one, verified by decrypting it again, and only then
//! renamed over it, so a failure at any point leaves the original vault untouched.
use crate::{
    entry::{self, Change},
    parse, payload, read_vault,
    vaults::with_key,
    Vault,
};
use base64::{engine::general_purpose::STANDARD as b64, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, Zeroizing};

/// The writer name stamped on envelopes this CLI creates.
const NODE: &str = "bramble-cli";

pub struct SaveError {
    pub code: &'static str,
    pub message: String,
}
fn error(code: &'static str, message: impl ToString) -> SaveError {
    SaveError {
        code,
        message: message.to_string(),
    }
}

pub struct Saved {
    pub id: String,
    pub created: bool,
    pub changed: bool,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A random (version 4) UUID, the id format Bramble gives its own entries.
fn new_id() -> Result<String, SaveError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| error("write_failed", e))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn entries_mut(payload: &mut Value) -> Option<&mut Vec<Value>> {
    match payload {
        Value::Array(entries) => Some(entries),
        Value::Object(map) => map.get_mut("entries").and_then(Value::as_array_mut),
        _ => None,
    }
}

fn read_back(bytes: &[u8]) -> Result<Value, String> {
    let vault: Vault = parse(bytes)?;
    payload(&vault)
}

/// Create (`id` is `None`) or update one login entry in the vault file at `path`.
pub fn save(path: &Path, key: &str, id: Option<&str>, change: &Change) -> Result<Saved, SaveError> {
    let original = fs::read(path).map_err(|e| {
        error(
            "write_failed",
            format!("Cannot read vault {}: {e}", path.display()),
        )
    })?;
    let vault = parse(&original).map_err(|e| error("write_failed", e))?;
    let header = original[..vault.header_len].to_vec();
    with_key(key, || Ok(prepare(&vault, header, id, change)))
        .map_err(|e| error("write_failed", e))?
        .and_then(|(next, saved)| match next {
            Some(bytes) => replace(path, &original, &bytes).map(|_| saved),
            None => Ok(saved),
        })
}

/// Everything that needs the vault key: edit the payload, re-encrypt, verify.
/// Returns the new file bytes, or `None` when the save would change nothing.
fn prepare(
    vault: &Vault,
    header: Vec<u8>,
    id: Option<&str>,
    change: &Change,
) -> Result<(Option<Vec<u8>>, Saved), SaveError> {
    let mut payload = payload(vault).map_err(|e| error("write_failed", e))?;
    let wall = now_ms();
    let (entry_id, created, floor, mut plain, mut envelope) = match id {
        None => {
            let plain = entry::new_login(change).map_err(|e| error("invalid_input", e))?;
            (new_id()?, true, 0, plain, json!({}))
        }
        Some(id) => {
            if payload
                .get("conflicts")
                .and_then(Value::as_array)
                .is_some_and(|c| c.iter().any(|e| e["id"] == id))
            {
                return Err(error(
                    "conflict_pending",
                    "This entry has unresolved sync conflicts. Resolve them in desktop Bramble before editing it here.",
                ));
            }
            let envelope = entries_mut(&mut payload)
                .ok_or_else(|| error("write_failed", "invalid entries payload"))?
                .iter()
                .find(|e| e.get("id").and_then(Value::as_str) == Some(id))
                .cloned()
                .ok_or_else(|| error("entry_not_found", "entry not found"))?;
            let mut plain = crate::decrypt(&envelope).map_err(|e| error("write_failed", e))?;
            // Compare before stamping: re-saving the same values must not churn the vault.
            let mut before = plain.clone();
            let applied = entry::apply(&mut plain, change);
            let unchanged = applied.is_ok() && before == plain;
            entry::wipe(&mut before);
            if let Err(e) = applied {
                entry::wipe(&mut plain);
                return Err(error("invalid_input", e));
            }
            if unchanged {
                entry::wipe(&mut plain);
                return Ok((
                    None,
                    Saved {
                        id: id.to_owned(),
                        created: false,
                        changed: false,
                    },
                ));
            }
            let floor = envelope["hlc"]["wall"].as_u64().map_or(0, |w| w + 1);
            (id.to_owned(), false, floor, plain, envelope)
        }
    };
    let object = plain.as_object_mut().expect("entries are objects");
    // Part stamps describe the version they were written with. This edit is not stamped
    // per part, so they are dropped and readers treat it as a whole-entry change.
    for stale in ["partStamps", "itemStamps", "partStampsAt"] {
        object.remove(stale);
    }
    object.insert("updatedAt".into(), json!(wall));
    if created || object.get("createdAt").is_none() {
        object.insert("createdAt".into(), json!(wall));
    }
    let mut text = Zeroizing::new(plain.to_string());
    entry::wipe(&mut plain);
    let encrypted =
        vault_crypto::encrypt_entry(text.to_string()).map_err(|e| error("write_failed", e))?;
    text.zeroize();
    let encrypted = serde_json::to_value(encrypted).map_err(|e| error("write_failed", e))?;
    let envelope_object = envelope.as_object_mut().expect("envelopes are objects");
    envelope_object.insert("id".into(), json!(entry_id));
    for member in ["ciphertext", "iv", "wrappedDek", "dekIv"] {
        envelope_object.insert(member.into(), encrypted[member].clone());
    }
    // Causal history belongs to the version it described; without it a reader orders this
    // write by its stamp alone, and the stamp always outranks the one it replaces.
    envelope_object.remove("vv");
    envelope_object.remove("floor");
    envelope_object.insert(
        "hlc".into(),
        json!({"wall": wall.max(floor), "counter": 0, "node": NODE}),
    );
    let expected = envelope.clone();
    let entries = entries_mut(&mut payload)
        .ok_or_else(|| error("write_failed", "invalid entries payload"))?;
    match entries
        .iter_mut()
        .find(|e| e.get("id").and_then(Value::as_str) == Some(entry_id.as_str()))
    {
        Some(slot) => *slot = envelope,
        None => entries.push(envelope),
    }
    let sealed = vault_crypto::encrypt_with_vek(payload.to_string())
        .map_err(|e| error("write_failed", e))?;
    let mut bytes = header;
    for part in [&sealed.iv, &sealed.ciphertext] {
        bytes.extend(b64.decode(part).map_err(|e| error("write_failed", e))?);
    }
    // Verify the exact bytes that will be installed: they must decrypt, hold the saved
    // envelope, and leave every other entry and payload member as it was.
    let roundtrip = read_back(&bytes)
        .map_err(|e| error("write_failed", format!("verification failed: {e}")))?;
    if roundtrip != payload {
        return Err(error(
            "write_failed",
            "verification failed: the written vault differs from the intended one",
        ));
    }
    let saved_ok = roundtrip
        .get("entries")
        .and_then(Value::as_array)
        .or_else(|| roundtrip.as_array())
        .is_some_and(|list| list.contains(&expected));
    if !saved_ok {
        return Err(error(
            "write_failed",
            "verification failed: entry missing after write",
        ));
    }
    Ok((
        Some(bytes),
        Saved {
            id: entry_id,
            created,
            changed: true,
        },
    ))
}

fn temp_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.bramble-cli-{}.tmp", std::process::id()))
}

/// Install `bytes` as the vault file, but only if the file is still exactly `original`.
fn replace(path: &Path, original: &[u8], bytes: &[u8]) -> Result<(), SaveError> {
    let io = |what: &str, e: std::io::Error| {
        error("write_failed", format!("{what} {}: {e}", path.display()))
    };
    let mode = fs::metadata(path)
        .map_err(|e| io("Cannot inspect", e))?
        .permissions();
    let temp = temp_path(path);
    let result = (|| {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .map_err(|e| io("Cannot create a temporary file for", e))?;
        file.write_all(bytes)
            .and_then(|_| file.set_permissions(mode))
            .and_then(|_| file.sync_all())
            .map_err(|e| io("Cannot write", e))?;
        drop(file);
        // Another writer (desktop sync, a second CLI) may have changed the vault since it
        // was read; installing our version would silently discard that change.
        let current = fs::read(path).map_err(|e| io("Cannot reread", e))?;
        if current != original {
            return Err(error(
                "changed_externally",
                "The vault file changed while saving. Nothing was written; retry the command.",
            ));
        }
        fs::rename(&temp, path).map_err(|e| io("Cannot replace", e))?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result?;
    // The installed file is what future reads see; confirm it is readable.
    read_vault(path)
        .map(|_| ())
        .map_err(|e| error("write_failed", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vault_changed_underneath_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vlt");
        fs::write(&path, b"VLT1 original").unwrap();
        // Another writer replaces the file between the read and the install.
        fs::write(&path, b"VLT1 changed elsewhere").unwrap();
        let error = replace(&path, b"VLT1 original", b"VLT1 ours")
            .err()
            .unwrap();
        assert_eq!(error.code, "changed_externally");
        assert_eq!(fs::read(&path).unwrap(), b"VLT1 changed elsewhere");
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "temporary file left behind"
        );
    }
    #[test]
    fn an_unchanged_vault_is_replaced_atomically_keeping_its_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.vlt");
        fs::write(&path, b"VLT1\x02old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        // The new bytes must still parse as a vault for the final read check.
        let mut bytes = b"VLT1\x02\x01".to_vec();
        bytes.extend([1, 0, 124]);
        bytes.extend([0u8; 124 + 12]);
        replace(&path, b"VLT1\x02old", &bytes).ok().unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[test]
    fn new_entry_ids_are_random_version_4_uuids() {
        let (a, b) = (new_id().ok().unwrap(), new_id().ok().unwrap());
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        assert_eq!(&a[14..15], "4");
        assert!(["8", "9", "a", "b"].contains(&&a[19..20]));
    }
}
