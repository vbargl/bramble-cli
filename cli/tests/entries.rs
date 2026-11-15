//! End-to-end behavior of `get` fields, `list`, `save` and the global `--json` mode, driven
//! through the real binary against synthetic vaults.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::Duration,
};

/// The crypto core keeps one global key slot, so in-process vault work is serialized.
static CRYPTO: Mutex<()> = Mutex::new(());
const OPAQUE_SLOT: [u8; 5] = [9, 8, 7, 6, 5];

fn envelope(id: &str, plain: &Value) -> Value {
    let sealed = vault_crypto::encrypt_entry(plain.to_string()).unwrap();
    let mut envelope = serde_json::to_value(sealed).unwrap();
    envelope["id"] = json!(id);
    envelope["hlc"] = json!({"wall": 1_700_000_000_000u64, "counter": 3, "node": "desktop-a"});
    envelope["vv"] =
        json!({"desktop-a": {"wall": 1_700_000_000_000u64, "counter": 3, "node": "desktop-a"}});
    envelope
}

/// Write a VLT1 vault: a password slot (`correct`), an unreadable extra slot kind, the given
/// entries, and payload members this CLI does not understand.
fn vault(path: &Path, entries: &[(&str, Value)]) {
    let _guard = CRYPTO.lock().unwrap_or_else(|e| e.into_inner());
    vault_crypto::generate_vek().unwrap();
    let salt = vault_crypto::generate_salt().unwrap();
    let slot_id = vault_crypto::generate_slot_id().unwrap();
    let slot = vault_crypto::wrap_vek_password(
        "correct".into(),
        salt.clone(),
        slot_id.clone(),
        b"VLT1\x02".to_vec(),
    )
    .unwrap();
    let envelopes: Vec<_> = entries
        .iter()
        .map(|(id, plain)| envelope(id, plain))
        .collect();
    let payload = json!({
        "entries": envelopes,
        "tombstones": [{"id": "gone", "hlc": {"wall": 5, "counter": 0, "node": "desktop-a"}}],
        "settings": {"theme": {"hlc": {"wall": 6, "counter": 0, "node": "desktop-a"}, "value": "dark"}},
    });
    let outer = vault_crypto::encrypt_with_vek(payload.to_string()).unwrap();
    let mut data = b"VLT1\x02\x02\x01\x00\x7c".to_vec();
    for part in [
        &slot_id,
        &salt,
        &slot.verifier,
        &slot.wrap_iv,
        &slot.wrapped_vek,
    ] {
        data.extend(B64.decode(part).unwrap());
    }
    data.extend([7, 0, OPAQUE_SLOT.len() as u8]);
    data.extend(OPAQUE_SLOT);
    for part in [&outer.iv, &outer.ciphertext] {
        data.extend(B64.decode(part).unwrap());
    }
    fs::write(path, data).unwrap();
    vault_crypto::lock();
}

/// Decrypt a vault file with its password: the payload plus every entry's plaintext by ID.
fn open(path: &Path) -> (Value, serde_json::Map<String, Value>) {
    let _guard = CRYPTO.lock().unwrap_or_else(|e| e.into_inner());
    let bytes = fs::read(path).unwrap();
    assert_eq!(&bytes[..6], b"VLT1\x02\x02");
    let slot = &bytes[9..9 + 124];
    vault_crypto::lock();
    let unwrapped = vault_crypto::unwrap_vek_password(
        "correct".into(),
        B64.encode(&slot[16..32]),
        B64.encode(&slot[..16]),
        B64.encode(&slot[32..64]),
        B64.encode(&slot[64..76]),
        B64.encode(&slot[76..124]),
        b"VLT1\x02".to_vec(),
    )
    .unwrap();
    assert!(unwrapped);
    let header = 9 + 124 + 3 + OPAQUE_SLOT.len();
    let outer = vault_crypto::decrypt_with_vek(
        B64.encode(&bytes[header..header + 12]),
        B64.encode(&bytes[header + 12..]),
    )
    .unwrap();
    let payload: Value = serde_json::from_str(&outer).unwrap();
    let mut plain = serde_json::Map::new();
    for entry in payload["entries"].as_array().unwrap() {
        let text = vault_crypto::decrypt_entry(
            entry["ciphertext"].as_str().unwrap().into(),
            entry["iv"].as_str().unwrap().into(),
            entry["wrappedDek"].as_str().unwrap().into(),
            entry["dekIv"].as_str().unwrap().into(),
        )
        .unwrap();
        plain.insert(
            entry["id"].as_str().unwrap().into(),
            serde_json::from_str(&text).unwrap(),
        );
    }
    vault_crypto::lock();
    (payload, plain)
}

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    _daemon: Daemon,
}
impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let socket = dir.path().join("socket");
        let child = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
            .arg("--socket")
            .arg(&socket)
            .arg("daemon")
            .env("XDG_DATA_HOME", dir.path().join("data"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = Daemon(child);
        for _ in 0..300 {
            if UnixStream::connect(&socket).is_ok() {
                return Self {
                    dir,
                    socket,
                    _daemon: daemon,
                };
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("daemon failed to start");
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn run(&self, args: &[&str], stdin: Option<&str>) -> Output {
        let mut child = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
            .arg("--socket")
            .arg(&self.socket)
            .args(args)
            .env("XDG_DATA_HOME", self.dir.path().join("data"))
            .env("NO_COLOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        if let Some(text) = stdin {
            input.write_all(text.as_bytes()).unwrap();
        }
        drop(input);
        child.wait_with_output().unwrap()
    }
    fn unseal(&self, vault: &Path) {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        writeln!(
            stream,
            "{}",
            json!({"op":"vault_unseal","vault":vault,"password":"correct"})
        )
        .unwrap();
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(stream), &mut line).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&line).unwrap()["ok"],
            true,
            "{line}"
        );
    }
}
fn text(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).unwrap()
}
fn err(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).unwrap()
}
/// A `--json` run: stdout is one document, stderr is empty, the exit status matches.
fn document(output: &Output) -> Value {
    assert!(output.stderr.is_empty(), "stderr: {}", err(output));
    let document: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {}", text(output)));
    assert_eq!(
        document["ok"] == true,
        output.status.success(),
        "{document}"
    );
    document
}

fn login() -> Value {
    json!({
        "type": "login", "name": "Example", "username": "ada", "password": "s3cret",
        "urls": ["https://example.com/login", "https://example.org"], "totp": "JBSWY3DP",
        "notes": "first line\nsecond line", "tags": ["work"],
        "customFields": [{"key":"API key","value":"k-1","hidden":true},{"key":"Region","value":"eu"}],
        "passkeys": [{"credentialId":"abc"}], "partStamps": {"password": {"wall":1,"counter":0,"node":"desktop-a"}},
        "partStampsAt": {"wall": 1_700_000_000_000u64, "counter": 3, "node": "desktop-a"},
    })
}
fn bare() -> Value {
    json!({"type":"login","name":"Bare","username":"","password":"bare-pass","urls":[]})
}

fn basic() -> (Harness, PathBuf) {
    let h = Harness::new();
    let path = h.path("Personal.vlt");
    vault(
        &path,
        &[
            ("full", login()),
            ("bare", bare()),
            (
                "memo",
                json!({"type":"note","name":"Memo","notes":"remember"}),
            ),
        ],
    );
    h.unseal(&path);
    (h, path)
}

#[test]
fn get_returns_the_password_by_default_and_any_selected_fields() {
    let (h, _) = basic();
    assert_eq!(text(&h.run(&["get", "full"], None)), "s3cret\n");
    assert_eq!(
        text(&h.run(&["get", "full", "-f", "username"], None)),
        "ada\n"
    );
    assert_eq!(
        text(&h.run(&["get", "full", "--field", "field:API key"], None)),
        "k-1\n"
    );
    assert_eq!(
        text(&h.run(&["get", "full", "-f", "url"], None)),
        "https://example.com/login\n"
    );
    assert_eq!(
        text(&h.run(&["get", "full", "-f", "urls"], None)),
        "https://example.com/login\nhttps://example.org\n"
    );
    let several = h.run(
        &[
            "get", "full", "-f", "title", "-f", "password", "-f", "notes",
        ],
        None,
    );
    assert_eq!(
        text(&several),
        "title\tExample\npassword\ts3cret\nnotes\tfirst line\\nsecond line\n"
    );
    assert!(several.stderr.is_empty());
    assert_eq!(
        text(&h.run(&["get", "full", "-f", "totp"], None)),
        "JBSWY3DP\n"
    );
}

#[test]
fn get_reports_missing_and_unknown_fields_without_partial_output() {
    let (h, _) = basic();
    let missing = h.run(
        &[
            "get",
            "bare",
            "-f",
            "password",
            "-f",
            "notes",
            "-f",
            "field:Nope",
        ],
        None,
    );
    assert_eq!(missing.status.code(), Some(3));
    assert!(missing.stdout.is_empty());
    assert!(
        err(&missing).contains("The entry has no notes, no field:Nope."),
        "{}",
        err(&missing)
    );
    let unknown = h.run(&["get", "full", "-f", "pasword"], None);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(err(&unknown).contains("Choose one of"));
    // An empty value is still a value.
    assert_eq!(text(&h.run(&["get", "bare", "-f", "username"], None)), "\n");
    let notes = h.run(&["get", "bare", "-f", "url"], None);
    assert_eq!(notes.status.code(), Some(3));
    assert_eq!(h.run(&["get", "nothing"], None).status.code(), Some(3));
    // A non-login entry has no password.
    assert_eq!(h.run(&["get", "memo"], None).status.code(), Some(3));
    assert_eq!(
        text(&h.run(&["get", "memo", "-f", "notes"], None)),
        "remember\n"
    );
}

#[test]
fn get_json_returns_named_fields_with_arrays_and_stable_errors() {
    let (h, _) = basic();
    let ok = document(&h.run(
        &["--json", "get", "full", "-f", "username", "-f", "urls"],
        None,
    ));
    assert_eq!(ok["command"], "get");
    assert_eq!(ok["data"]["id"], "full");
    assert_eq!(ok["data"]["vault"], "Personal");
    assert_eq!(ok["data"]["fields"]["username"], "ada");
    assert_eq!(
        ok["data"]["fields"]["urls"],
        json!(["https://example.com/login", "https://example.org"])
    );
    // JSON names the password even when no field is requested.
    assert_eq!(
        document(&h.run(&["--json", "get", "full"], None))["data"]["fields"]["password"],
        "s3cret"
    );
    let output = h.run(&["--json", "get", "bare", "-f", "notes"], None);
    let failed = document(&output);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(failed["error"]["code"], "field_not_found");
    assert!(failed["error"]["message"]
        .as_str()
        .unwrap()
        .contains("notes"));
    let output = h.run(&["--json", "get", "missing"], None);
    assert_eq!(document(&output)["error"]["code"], "entry_not_found");
    assert_eq!(output.status.code(), Some(3));
}

#[test]
fn get_distinguishes_duplicate_ids_across_vaults_for_every_field() {
    let h = Harness::new();
    let (a, b) = (h.path("Personal.vlt"), h.path("Work.vlt"));
    vault(
        &a,
        &[(
            "shared",
            json!({"type":"login","name":"One","username":"u1","password":"p1","urls":[]}),
        )],
    );
    vault(
        &b,
        &[(
            "shared",
            json!({"type":"login","name":"Two","username":"u2","password":"p2","urls":[]}),
        )],
    );
    h.unseal(&a);
    h.unseal(&b);
    let output = h.run(&["--json", "get", "shared", "-f", "username"], None);
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "ambiguous_entry");
    assert_eq!(output.status.code(), Some(5));
    let ids = failed["error"]["details"]["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    for (id, expected) in ids.iter().zip(["u1", "u2"]) {
        let id = id.as_str().unwrap();
        let output = h.run(&["get", id, "-f", "username"], None);
        assert_eq!(text(&output), format!("{expected}\n"), "{id}");
    }
}

#[test]
fn list_prints_an_aligned_table_without_secret_values() {
    let (h, _) = basic();
    let output = h.run(&["list"], None);
    assert!(output.status.success() && output.stderr.is_empty());
    let table = text(&output);
    assert_eq!(
        table,
        "ID    TITLE    VAULT\nbare  Bare     Personal\nfull  Example  Personal\nmemo  Memo     Personal\n"
    );
    for secret in ["s3cret", "bare-pass", "k-1", "JBSWY3DP", "remember"] {
        assert!(!table.contains(secret), "{secret} leaked");
    }
    let json = document(&h.run(&["--json", "list"], None));
    assert_eq!(json["command"], "list");
    let entries = json["data"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 3);
    assert!(entries
        .iter()
        .any(|e| e["id"] == "full" && e["name"] == "Example" && e["vault"] == "Personal"));
    assert!(!json.to_string().contains("s3cret"));
}

#[test]
fn list_qualifies_duplicate_ids_and_names_each_vault() {
    let h = Harness::new();
    let (a, b) = (h.path("Personal.vlt"), h.path("Work.vlt"));
    vault(&a, &[("shared", bare())]);
    vault(&b, &[("shared", bare()), ("only-work", bare())]);
    h.unseal(&a);
    h.unseal(&b);
    let table = text(&h.run(&["list"], None));
    assert_eq!(table.lines().count(), 4, "{table}");
    assert!(table.contains(&format!("{}::shared", a.display())));
    assert!(table.contains(&format!("{}::shared", b.display())));
    assert!(table
        .lines()
        .any(|l| l.starts_with("only-work") && l.ends_with("Work")));
}

#[test]
fn list_of_an_empty_vault_prints_no_rows() {
    let h = Harness::new();
    let path = h.path("Personal.vlt");
    vault(&path, &[]);
    h.unseal(&path);
    let output = h.run(&["list"], None);
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(err(&output), "No entries.\n");
    assert_eq!(
        document(&h.run(&["--json", "list"], None))["data"]["entries"],
        json!([])
    );
}

#[test]
fn save_creates_an_entry_with_every_basic_field() {
    let (h, path) = basic();
    let before = fs::read(&path).unwrap();
    let output = h.run(
        &[
            "save",
            "--title",
            "GitHub",
            "--username",
            "octocat",
            "--password-stdin",
            "--url",
            "https://github.com",
            "--url",
            "https://gist.github.com",
            "--notes",
            "two\nlines",
            "--field",
            "Region=eu",
            "--secret-field",
            "Token=t0k",
        ],
        Some("hunter2\n"),
    );
    assert!(output.status.success(), "{}", err(&output));
    assert!(err(&output).contains("Entry created"));
    let id = text(&output).trim().to_owned();
    assert_eq!(id.len(), 36, "{id}");
    // Read back through the CLI.
    let all = [
        "title",
        "username",
        "password",
        "urls",
        "notes",
        "field:Region",
        "field:Token",
    ];
    let args: Vec<&str> = ["--json", "get", &id]
        .into_iter()
        .chain(all.iter().flat_map(|f| ["-f", *f]))
        .collect();
    let fields = document(&h.run(&args, None))["data"]["fields"].clone();
    assert_eq!(fields["title"], "GitHub");
    assert_eq!(fields["username"], "octocat");
    assert_eq!(fields["password"], "hunter2");
    assert_eq!(
        fields["urls"],
        json!(["https://github.com", "https://gist.github.com"])
    );
    assert_eq!(fields["notes"], "two\nlines");
    assert_eq!(fields["field:Token"], "t0k");
    // The vault file keeps its key slots (including the unreadable kind), other entries and
    // every payload member this CLI does not understand; the new entry carries sync metadata.
    let after = fs::read(&path).unwrap();
    let header = 9 + 124 + 3 + OPAQUE_SLOT.len();
    assert_eq!(after[..header], before[..header]);
    assert_ne!(after, before);
    let (payload, plain) = open(&path);
    assert_eq!(plain.len(), 4);
    assert_eq!(plain["full"], login());
    assert_eq!(plain[&id]["type"], "login");
    assert_eq!(
        plain[&id]["customFields"][1],
        json!({"key":"Token","value":"t0k","hidden":true})
    );
    assert_eq!(payload["tombstones"].as_array().unwrap().len(), 1);
    assert_eq!(payload["settings"]["theme"]["value"], "dark");
    let created = payload["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == id)
        .unwrap();
    assert_eq!(created["hlc"]["node"], "bramble-cli");
    assert!(created.get("vv").is_none());
    let old = payload["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "full")
        .unwrap();
    assert_eq!(old["hlc"]["node"], "desktop-a");
    assert_eq!(old["vv"]["desktop-a"]["counter"], 3);
    // And it lists.
    assert!(text(&h.run(&["list"], None)).contains("GitHub"));
    assert!(fs::read_dir(h.dir.path()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains(".tmp")));
}

#[test]
fn save_updates_only_the_named_fields_and_preserves_the_rest() {
    let (h, path) = basic();
    let output = h.run(&["save", "full", "--password", "rotated"], None);
    assert!(output.status.success(), "{}", err(&output));
    assert_eq!(text(&output), "full\n");
    assert!(err(&output).contains("Entry updated"));
    let (payload, plain) = open(&path);
    let mut expected = login();
    expected["password"] = json!("rotated");
    // Stamps and the update time are the only differences besides the new password.
    let mut actual = plain["full"].clone();
    assert!(actual["updatedAt"].as_u64().unwrap() > 0);
    assert!(actual["createdAt"].as_u64().unwrap() > 0);
    for key in ["updatedAt", "createdAt"] {
        actual.as_object_mut().unwrap().remove(key);
    }
    for stale in ["partStamps", "partStampsAt"] {
        expected.as_object_mut().unwrap().remove(stale);
        assert!(actual.get(stale).is_none());
    }
    assert_eq!(actual, expected);
    assert_eq!(plain["bare"], bare());
    let envelope = payload["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "full")
        .unwrap();
    assert_eq!(envelope["hlc"]["node"], "bramble-cli");
    assert!(envelope["hlc"]["wall"].as_u64().unwrap() > 1_700_000_000_000);
    assert!(envelope.get("vv").is_none());
    // Every other entry still has the exact envelope it had.
    let untouched = payload["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == "bare")
        .unwrap();
    assert_eq!(untouched["hlc"]["node"], "desktop-a");

    let output = h.run(
        &[
            "save",
            "full",
            "--title",
            "Renamed",
            "--url",
            "https://new.example",
            "--field",
            "Region=us",
            "--clear",
            "notes",
            "--clear",
            "field:API key",
        ],
        None,
    );
    assert!(output.status.success(), "{}", err(&output));
    let (_, plain) = open(&path);
    let entry = &plain["full"];
    assert_eq!(entry["name"], "Renamed");
    assert_eq!(entry["urls"], json!(["https://new.example"]));
    assert_eq!(
        entry["customFields"],
        json!([{"key":"Region","value":"us"}])
    );
    assert!(entry.get("notes").is_none());
    assert_eq!(entry["username"], "ada");
    assert_eq!(entry["password"], "rotated");
    assert_eq!(entry["tags"], json!(["work"]));
    assert_eq!(entry["passkeys"], json!([{"credentialId":"abc"}]));
    assert_eq!(entry["totp"], "JBSWY3DP");

    let output = h.run(
        &["save", "full", "--clear", "username", "--clear", "url"],
        None,
    );
    assert!(output.status.success());
    let (_, plain) = open(&path);
    assert_eq!(plain["full"]["username"], "");
    assert_eq!(plain["full"]["urls"], json!([]));
    assert_eq!(plain["full"]["password"], "rotated");
}

#[test]
fn saving_unchanged_values_does_not_touch_the_vault() {
    let (h, path) = basic();
    let before = fs::read(&path).unwrap();
    let output = h.run(
        &[
            "--json",
            "save",
            "full",
            "--title",
            "Example",
            "--username",
            "ada",
        ],
        None,
    );
    let result = document(&output);
    assert_eq!(result["data"]["changed"], false);
    assert_eq!(result["data"]["created"], false);
    assert_eq!(result["data"]["id"], "full");
    assert_eq!(fs::read(&path).unwrap(), before);
    let output = h.run(&["save", "full", "--clear", "field:Absent"], None);
    assert!(output.status.success());
    assert!(err(&output).contains("No changes"));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn save_accepts_a_json_input_document_with_options_on_top() {
    let (h, path) = basic();
    let document_text = json!({
        "title": "From JSON", "username": "json-user", "password": "json-pass",
        "urls": ["https://json.example"], "notes": "n",
        "fields": {"Plain": "v", "Secret": {"value": "s", "hidden": true}},
    })
    .to_string();
    let output = h.run(
        &["--json", "save", "--input", "-", "--title", "Overridden"],
        Some(&document_text),
    );
    let result = document(&output);
    assert_eq!(result["command"], "save");
    assert_eq!(result["data"]["created"], true);
    assert_eq!(result["data"]["vault"], "Personal");
    let id = result["data"]["id"].as_str().unwrap().to_owned();
    let (_, plain) = open(&path);
    let entry = &plain[&id];
    assert_eq!(entry["name"], "Overridden");
    assert_eq!(entry["password"], "json-pass");
    assert_eq!(
        entry["customFields"],
        json!([{"key":"Plain","value":"v"},{"key":"Secret","value":"s","hidden":true}])
    );
    // The same document can update by ID, from a file.
    let file = h.path("input.json");
    fs::write(&file, json!({"id": id, "notes": "changed"}).to_string()).unwrap();
    let output = h.run(&["--json", "save", "--input", file.to_str().unwrap()], None);
    assert_eq!(document(&output)["data"]["id"], id.as_str());
    assert_eq!(open(&path).1[&id]["notes"], "changed");
}

#[test]
fn save_asks_for_the_vault_when_several_are_unsealed_and_never_guesses() {
    let h = Harness::new();
    let (a, b) = (h.path("Personal.vlt"), h.path("Work.vlt"));
    vault(&a, &[("shared", bare()), ("personal-only", bare())]);
    vault(&b, &[("shared", bare())]);
    h.unseal(&a);
    h.unseal(&b);
    let (before_a, before_b) = (fs::read(&a).unwrap(), fs::read(&b).unwrap());

    let output = h.run(&["--json", "save", "--title", "New"], None);
    let failed = document(&output);
    assert_eq!(output.status.code(), Some(5));
    assert_eq!(failed["error"]["code"], "ambiguous_vault");
    assert_eq!(failed["error"]["choices"].as_array().unwrap().len(), 2);
    let plain = h.run(&["save", "--title", "New"], None);
    assert_eq!(plain.status.code(), Some(5));
    assert!(err(&plain).contains("Work"), "{}", err(&plain));

    // An ID held by both vaults is ambiguous too; a scoped ID, or --vault, resolves it.
    let output = h.run(&["--json", "save", "shared", "--notes", "x"], None);
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "ambiguous_entry");
    assert_eq!(
        failed["error"]["details"]["ids"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        (fs::read(&a).unwrap(), fs::read(&b).unwrap()),
        (before_a.clone(), before_b.clone())
    );

    // An ID held by one vault is unambiguous even with several unsealed.
    assert!(h
        .run(&["save", "personal-only", "--notes", "ok"], None)
        .status
        .success());
    let scoped = format!("{}::shared", b.display());
    assert!(h
        .run(&["save", &scoped, "--notes", "scoped"], None)
        .status
        .success());
    assert!(h
        .run(
            &["save", "shared", "--vault", "Personal", "--notes", "named"],
            None
        )
        .status
        .success());
    assert_eq!(open(&b).1["shared"]["notes"], "scoped");
    assert_eq!(open(&a).1["shared"]["notes"], "named");
    // Creating with an explicit vault works, and the contradiction is refused.
    assert!(h
        .run(&["save", "--title", "Fresh", "--vault", "Work"], None)
        .status
        .success());
    assert_eq!(open(&b).1.len(), 2);
    let clash = h.run(
        &[
            "--json", "save", &scoped, "--vault", "Personal", "--notes", "x",
        ],
        None,
    );
    assert_eq!(document(&clash)["error"]["code"], "invalid_input");
    let missing = h.run(
        &["--json", "save", "--title", "T", "--vault", "Nowhere"],
        None,
    );
    assert_eq!(document(&missing)["error"]["code"], "vault_not_found");
}

#[test]
fn save_rejects_bad_input_before_touching_the_vault() {
    let (h, path) = basic();
    let before = fs::read(&path).unwrap();
    let cases: &[(&[&str], &str, i32)] = &[
        (&["--json", "save", "--username", "x"], "invalid_input", 2), // new entry without a title
        (&["--json", "save", "--password", "x"], "invalid_input", 2),
        (
            &["--json", "save", "full", "--notes", "x", "--clear", "notes"],
            "invalid_input",
            2,
        ),
        (
            &["--json", "save", "full", "--clear", "title"],
            "invalid_input",
            2,
        ),
        (
            &["--json", "save", "full", "--clear", "nonsense"],
            "invalid_input",
            2,
        ),
        (
            &["--json", "save", "full", "--field", "no-equals-sign"],
            "invalid_input",
            2,
        ),
        (
            &["--json", "save", "full", "--title", " "],
            "invalid_input",
            2,
        ),
        (&["--json", "save", "full", "--url", ""], "invalid_input", 2),
        (
            &["--json", "save", "memo", "--password", "x"],
            "invalid_input",
            2,
        ),
        (&["--json", "save", "full"], "invalid_input", 2), // nothing to change
        (
            &["--json", "save", "ghost", "--notes", "x"],
            "entry_not_found",
            3,
        ),
    ];
    for (args, code, status) in cases {
        let output = h.run(args, None);
        assert_eq!(document(&output)["error"]["code"], *code, "{args:?}");
        assert_eq!(output.status.code(), Some(*status), "{args:?}");
    }
    let bad = h.run(&["--json", "save", "--input", "-"], Some("{ not json"));
    assert_eq!(document(&bad)["error"]["code"], "invalid_input");
    let unknown = h.run(
        &["--json", "save", "--input", "-"],
        Some(r#"{"passwrod":"x"}"#),
    );
    assert_eq!(document(&unknown)["error"]["code"], "invalid_input");
    let both = h.run(
        &["--json", "save", "--password", "a", "--password-stdin"],
        Some("b\n"),
    );
    assert_eq!(document(&both)["error"]["code"], "invalid_usage");
    assert_eq!(both.status.code(), Some(2));
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn a_failed_write_leaves_the_vault_intact_and_leaves_no_temporary_file() {
    let (h, path) = basic();
    let before = fs::read(&path).unwrap();
    let locked = h.path("locked");
    fs::create_dir(&locked).unwrap();
    let moved = locked.join("Personal.vlt");
    fs::rename(&path, &moved).unwrap();
    // The daemon tracks the old path; a read-only parent makes the temporary file impossible.
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o500)).unwrap();
    h.unseal(&moved);
    let output = h.run(
        &[
            "--json",
            "save",
            "--title",
            "Doomed",
            "--vault",
            moved.to_str().unwrap(),
        ],
        None,
    );
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "write_failed");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(fs::read(&moved).unwrap(), before);
    assert_eq!(fs::read_dir(&locked).unwrap().count(), 1);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    // The vault still saves once the problem is fixed, and the earlier failure left no trace.
    assert!(h
        .run(
            &[
                "save",
                "--title",
                "Fine",
                "--vault",
                moved.to_str().unwrap()
            ],
            None
        )
        .status
        .success());
    assert_eq!(open(&moved).1.len(), 4);
}

#[test]
fn save_without_access_reports_the_unseal_step() {
    let h = Harness::new();
    let output = h.run(&["--json", "save", "--title", "T"], None);
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "sealed");
    assert_eq!(output.status.code(), Some(4));
    assert!(failed["error"]["next"][0]["command"]
        .as_str()
        .unwrap()
        .contains("unseal"));
}

#[test]
fn json_mode_keeps_stdout_parseable_without_a_terminal_or_input() {
    let (h, path) = basic();
    let status = document(&h.run(&["--json", "status"], None));
    assert_eq!(status["command"], "status");
    assert!(status["data"]["message"]
        .as_str()
        .unwrap()
        .starts_with("unsealed"));
    let vaults = status["data"]["vaults"].as_array().unwrap();
    assert!(vaults
        .iter()
        .any(|v| v["name"] == "Personal" && v["access"] == "manual"));
    // Manual unseal needs a password, which a JSON run can never prompt for.
    let sealed = document(&h.run(&["--json", "seal", "Personal"], None));
    assert_eq!(sealed["command"], "seal");
    let output = h.run(
        &["--json", "unseal", path.to_str().unwrap(), "--manual"],
        None,
    );
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "interactive_required");
    assert_eq!(output.status.code(), Some(7));
    assert!(failed["error"]["next"][0]["command"]
        .as_str()
        .unwrap()
        .contains("--manual"));
    // Commands that run in the foreground or need a person say so instead of hanging.
    for args in [["--json", "daemon"], ["--json", "pair"]] {
        let output = h.run(&args, None);
        assert_eq!(document(&output)["error"]["code"], "unsupported");
        assert_eq!(output.status.code(), Some(6));
    }
    // Usage mistakes are JSON too; help stays human text.
    let usage = h.run(&["--json", "get"], None);
    assert_eq!(document(&usage)["error"]["code"], "invalid_usage");
    assert_eq!(usage.status.code(), Some(2));
    let help = h.run(&["--json", "get", "--help"], None);
    assert!(text(&help).contains("Usage"));
}

#[test]
fn json_mode_reports_an_unreachable_daemon_with_next_steps() {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_bramble-cli"))
        .arg("--socket")
        .arg(dir.path().join("none"))
        .args(["--json", "list"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let failed = document(&output);
    assert_eq!(failed["error"]["code"], "daemon_unavailable");
    assert_eq!(output.status.code(), Some(4));
    assert!(failed["error"]["next"][0]["command"]
        .as_str()
        .unwrap()
        .contains("daemon"));
}

#[test]
fn redirected_plain_output_stays_free_of_guidance_and_styling() {
    let (h, _) = basic();
    for args in [
        vec!["get", "full"],
        vec!["list"],
        vec!["get", "full", "-f", "username"],
    ] {
        let output = h.run(&args, None);
        assert!(output.stderr.is_empty(), "{args:?}: {}", err(&output));
        assert!(!text(&output).contains('\x1b'));
    }
}
