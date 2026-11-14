//! Vault-scoped access. The daemon serves requests serially; upstream's single VEK slot is
//! populated only for one local operation and cleared on every exit, including errors.
use crate::{desktop, fail, ok, read_vault, NextAction, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
pub struct Choice {
    pub path: PathBuf,
    pub name: String,
    pub access: String,
}
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Purpose {
    Unseal,
    Seal,
    Catalog,
}

#[derive(Default, Deserialize)]
struct Metadata {
    #[serde(rename = "active-vault")]
    active: Option<String>,
    #[serde(rename = "vault.registry")]
    registry: Option<Registry>,
}
#[derive(Deserialize)]
struct Registry {
    vaults: Vec<Record>,
}
#[derive(Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    label: String,
}

pub fn normalize(path: &Path) -> Result<PathBuf, String> {
    if let Ok(path) = fs::canonicalize(path) {
        return Ok(path);
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(path)
    };
    // Sealing must still work after a file was deleted. Resolve the parent where possible.
    if let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) {
        if let Ok(parent) = fs::canonicalize(parent) {
            return Ok(parent.join(name));
        }
    }
    let mut result = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => (),
            other => result.push(other.as_os_str()),
        }
    }
    Ok(result)
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}
fn default_root() -> Result<PathBuf, String> {
    let (socket, _) = (desktop::Options {
        desktop_socket: None,
        pairing_file: None,
    })
    .paths()?;
    Ok(socket
        .parent()
        .ok_or("Cannot locate desktop vaults")?
        .to_owned())
}
pub fn reference(value: &Path) -> Result<PathBuf, String> {
    if !value.is_absolute()
        && value.components().count() == 1
        && value.extension().is_none()
        && !value.exists()
    {
        return Ok(value.to_owned());
    }
    normalize(value)
}

fn metadata(root: &Path) -> Result<Metadata, String> {
    use std::io::Read;
    let file =
        fs::File::open(root.join("meta.json")).map_err(|_| "desktop: cannot identify vault")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "desktop: cannot identify vault")?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err("desktop: cannot identify vault".into());
    }
    // Unknown metadata (including sync secrets) is skipped, never stored in the parsed value.
    serde_json::from_slice(&bytes).map_err(|_| "desktop: cannot identify vault".into())
}

struct ClearKey;
impl Drop for ClearKey {
    fn drop(&mut self) {
        vault_crypto::lock();
    }
}
fn with_key<T>(key: &str, operation: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    let _guard = ClearKey;
    vault_crypto::unlock_with_vek(key.to_owned()).map_err(|e| e.to_string())?;
    operation()
}

pub struct State {
    keys: BTreeMap<PathBuf, Zeroizing<String>>,
    blocked: BTreeSet<PathBuf>,
    pub(crate) desktop: Option<(PathBuf, PathBuf)>,
}
impl State {
    pub fn new(desktop: Option<(PathBuf, PathBuf)>) -> Self {
        Self {
            keys: BTreeMap::new(),
            blocked: BTreeSet::new(),
            desktop,
        }
    }
    fn root(&self) -> Result<PathBuf, String> {
        match &self.desktop {
            Some((socket, _)) => Ok(socket
                .parent()
                .ok_or("Cannot locate desktop vaults")?
                .to_owned()),
            None => default_root(),
        }
    }
    fn current(&self) -> Result<PathBuf, String> {
        let root = self.root()?;
        let meta = metadata(&root)?;
        let id = match meta.active {
            Some(id) => id,
            None => match meta.registry {
                Some(reg) if reg.vaults.len() == 1 => reg.vaults[0].id.clone(),
                None => "default".into(),
                _ => return Err("desktop: cannot identify vault".into()),
            },
        };
        if !valid_id(&id) {
            return Err("desktop: cannot identify vault".into());
        }
        normalize(&root.join("vaults").join(format!("{id}.vlt")))
    }
    fn catalog(&self) -> Vec<Choice> {
        let mut names = BTreeMap::new();
        if let Ok(root) = self.root() {
            if let Ok(meta) = metadata(&root) {
                if let Some(reg) = meta.registry {
                    for record in reg.vaults {
                        if valid_id(&record.id) && !record.label.is_empty() {
                            if let Ok(path) =
                                normalize(&root.join("vaults").join(format!("{}.vlt", record.id)))
                            {
                                names.insert(path, record.label);
                            }
                        }
                    }
                }
            }
            if let Ok(entries) = fs::read_dir(root.join("vaults")) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "vlt") && path.is_file() {
                        if let Ok(path) = normalize(&path) {
                            names
                                .entry(path.clone())
                                .or_insert_with(|| fallback_name(&path));
                        }
                    }
                }
            }
        }
        for path in self.keys.keys().chain(self.blocked.iter()) {
            names
                .entry(path.clone())
                .or_insert_with(|| fallback_name(path));
        }
        if self.desktop.is_some() {
            if let Ok(path) = self.current() {
                names
                    .entry(path.clone())
                    .or_insert_with(|| fallback_name(&path));
            }
        }
        names
            .into_iter()
            .map(|(path, name)| Choice {
                access: if self.keys.contains_key(&path) {
                    "manual"
                } else {
                    "sealed"
                }
                .into(),
                path,
                name,
            })
            .collect()
    }
    fn desktop_request(&self, path: &Path, body: Value, resume: bool) -> Result<Value, String> {
        let (socket, identity) = self.desktop.as_ref().ok_or("desktop: unavailable")?;
        if !resume && self.blocked.contains(path) {
            return Err("daemon is sealed".into());
        }
        if self.current()? != path {
            return Err("desktop: wrong vault".into());
        }
        let mut answer = desktop::request(socket, identity, body)?;
        // The upstream protocol addresses the app's active vault, not a vault ID. Refuse
        // mismatched requests and discard a credential if the active vault changed in flight.
        if self.current().as_deref() != Ok(path) {
            for field in ["password", "totp", "username"] {
                if let Some(Value::String(value)) = answer.get_mut(field) {
                    value.zeroize();
                }
            }
            return Err("desktop: vault changed".into());
        }
        Ok(answer)
    }
    fn sources(&self) -> Result<Vec<PathBuf>, String> {
        let mut sources: BTreeSet<_> = self.keys.keys().cloned().collect();
        if self.desktop.is_some() {
            if let Ok(path) = self.current() {
                if !sources.contains(&path) && !self.blocked.contains(&path) {
                    match self.desktop_request(
                        &path,
                        json!({"op":"query","hostname":"bramble-cli-status.invalid"}),
                        false,
                    ) {
                        Ok(_) => {
                            sources.insert(path);
                        }
                        Err(e) if expected_unavailable(&e) => (),
                        Err(e) => return Err(e),
                    }
                }
            } else if sources.is_empty() {
                return Err("desktop: cannot identify vault".into());
            } else if let Some((socket, identity)) = &self.desktop {
                match desktop::request(
                    socket,
                    identity,
                    json!({"op":"query","hostname":"bramble-cli-status.invalid"}),
                ) {
                    Ok(_) => return Err("desktop: cannot identify vault".into()),
                    Err(e) if expected_unavailable(&e) => (),
                    Err(e) => return Err(e),
                }
            }
        }
        Ok(sources.into_iter().collect())
    }
    fn choices(&self, purpose: Purpose) -> Result<Vec<Choice>, String> {
        let sources = self
            .sources()
            .unwrap_or_else(|_| self.keys.keys().cloned().collect());
        let mut catalog = self.catalog();
        for vault in &mut catalog {
            if sources.contains(&vault.path) && !self.keys.contains_key(&vault.path) {
                vault.access = "desktop".into();
            }
        }
        if matches!(purpose, Purpose::Catalog) {
            return Ok(catalog);
        }
        let open: Vec<_> = catalog
            .iter()
            .filter(|v| sources.contains(&v.path))
            .cloned()
            .collect();
        // State-changing operations may infer a target only with exactly one unsealed vault.
        // With none, unseal discovers local vaults; seal can still block desktop auto-access.
        if open.len() == 1 {
            return Ok(open);
        }
        if matches!(purpose, Purpose::Seal) {
            return Ok(open);
        }
        Ok(catalog
            .into_iter()
            .map(|mut v| {
                if sources.contains(&v.path) && !self.keys.contains_key(&v.path) {
                    v.access = "desktop".into();
                }
                v
            })
            .collect())
    }
    fn target(&self, path: Option<PathBuf>, purpose: Purpose) -> Result<PathBuf, Response> {
        if let Some(path) = path {
            if !path.is_absolute() && path.components().count() == 1 && path.extension().is_none() {
                let text = path.to_string_lossy();
                let choices: Vec<_> = self
                    .catalog()
                    .into_iter()
                    .filter(|v| {
                        v.name == text
                            || v.path.file_stem().is_some_and(|id| id == path.as_os_str())
                    })
                    .collect();
                match choices.as_slice() {
                    [choice] => return Ok(choice.path.clone()),
                    [] => {
                        return Err(fail(format!(
                            "Vault was not found: {text}. Use a listed name, ID or .vlt path."
                        )))
                    }
                    _ => {
                        let mut response =
                            fail("Several vaults have that name. Choose a specific vault.");
                        response.next = Some(NextAction::SelectVault);
                        response.choices = choices;
                        return Err(response);
                    }
                }
            }
            return normalize(&path).map_err(fail);
        }
        let choices = self.choices(purpose).map_err(fail)?;
        match choices.as_slice() {
            [choice] => Ok(choice.path.clone()),
            [] => Err(fail("No vault was found. Open or restore a vault in desktop Bramble, or supply its .vlt path to unseal.")),
            _ => { let mut response=fail("Choose the vault to change."); response.next=Some(NextAction::SelectVault); response.choices=choices; Err(response) },
        }
    }
    fn error(&self, e: String, path: Option<PathBuf>) -> Response {
        let mut response = crate::access_failure(e);
        if response.next.is_none() {
            if let Some(path) = &path {
                response.message = format!("{}: {}", fallback_name(path), response.message);
            }
        }
        response.vault = path;
        response
    }
    fn inaccessible(&self) -> Response {
        if let Some(_) = self.desktop {
            if let Ok(path) = self.current() {
                if !self.blocked.contains(&path) {
                    if let Err(e) = self.desktop_request(
                        &path,
                        json!({"op":"query","hostname":"bramble-cli-status.invalid"}),
                        false,
                    ) {
                        return self.error(e, Some(path));
                    }
                }
                return self.error("daemon is sealed".into(), Some(path));
            }
            return self.error("desktop: cannot identify vault".into(), None);
        }
        self.error("daemon is sealed".into(), None)
    }
    fn scoped(&self, path: &Path, id: &str) -> String {
        format!("{}::{id}", path.display())
    }
    fn list_all(&self, hostname: Option<String>) -> Response {
        let sources = match self.sources() {
            Ok(v) => v,
            Err(e) => return self.error(e, None),
        };
        if sources.is_empty() {
            return self.inaccessible();
        }
        let names = self.catalog();
        let mut rows = Vec::new();
        for path in &sources {
            let entries = if let Some(key) = self.keys.get(path) {
                with_key(key, || {
                    crate::summaries(&read_vault(path)?, hostname.as_deref())
                })
            } else {
                let Some(hostname) = hostname.as_ref().filter(|h| !h.trim().is_empty()) else {
                    return self.error(
                        "desktop lookup requires hostname".into(),
                        Some(path.clone()),
                    );
                };
                self.desktop_request(path, json!({"op":"query","hostname":hostname}), false)
                    .and_then(|answer| {
                        answer["matches"]
                            .as_array()
                            .cloned()
                            .ok_or("desktop reply missing matches".into())
                    })
            };
            let entries = match entries {
                Ok(v) => v,
                Err(e) => return self.error(e, Some(path.clone())),
            };
            for entry in entries {
                rows.push((path.clone(), entry));
            }
        }
        let mut counts = BTreeMap::new();
        for (_, row) in &rows {
            if let Some(id) = row["id"].as_str() {
                *counts.entry(id.to_owned()).or_insert(0) += 1;
            }
        }
        let result: Vec<_> = rows
            .into_iter()
            .map(|(path, row)| {
                let id = row["id"].as_str().unwrap_or("");
                let id = if counts.get(id).is_some_and(|n| *n > 1) {
                    self.scoped(&path, id)
                } else {
                    id.to_owned()
                };
                let name = names
                    .iter()
                    .find(|v| v.path == path)
                    .map(|v| v.name.clone())
                    .unwrap_or_else(|| fallback_name(&path));
                json!({"id":id,"name":row["name"],"vault":name})
            })
            .collect();
        ok(serde_json::to_string(&result).unwrap())
    }
    fn get_all(&self, id: String) -> Response {
        let sources = match self.sources() {
            Ok(v) => v,
            Err(e) => return self.error(e, None),
        };
        if let Some(choice) = self
            .catalog()
            .into_iter()
            .filter(|v| id.starts_with(&format!("{}::", v.path.display())))
            .max_by_key(|v| v.path.as_os_str().len())
        {
            if !sources.contains(&choice.path) {
                return self.error("daemon is sealed".into(), Some(choice.path));
            }
        }
        if sources.is_empty() {
            return self.inaccessible();
        }
        let scoped = sources
            .iter()
            .filter_map(|path| {
                id.strip_prefix(&format!("{}::", path.display()))
                    .map(|entry| (path.clone(), entry.to_owned()))
            })
            .max_by_key(|(path, _)| path.as_os_str().len());
        let mut found = Vec::new();
        for path in &sources {
            if scoped
                .as_ref()
                .is_some_and(|(selected, _)| selected != path)
            {
                continue;
            }
            let entry = scoped.as_ref().map(|(_, id)| id.as_str()).unwrap_or(&id);
            let result = if let Some(key) = self.keys.get(path) {
                with_key(key, || crate::get(&read_vault(path)?, entry))
            } else {
                self.desktop_request(path, json!({"op":"fetch","id":entry}), false)
                    .and_then(
                        |mut answer| match answer.get_mut("password").map(Value::take) {
                            Some(Value::String(password)) => Ok(password),
                            _ => Err("desktop reply missing password".into()),
                        },
                    )
            };
            match result {
                Ok(password) => found.push((path.clone(), Zeroizing::new(password))),
                Err(e) if e == "entry not found" || e == "desktop: unknown entry" => (),
                Err(e) => return self.error(e, Some(path.clone())),
            }
        }
        match found.as_slice() {
            [] => self.error("entry not found".into(), None),
            [(_, password)] => ok(password.as_str()),
            _ => fail(format!(
                "Entry ID exists in several vaults. Use a scoped ID from list:\n{}",
                found
                    .iter()
                    .map(|(path, _)| self.scoped(path, &id))
                    .collect::<Vec<_>>()
                    .join("\n")
            )),
        }
    }
    pub fn handle(&mut self, req: Request) -> Response {
        match req {
            Request::Vaults { purpose } => {
                let mut response = ok("");
                match self.choices(purpose) {
                    Ok(choices) => response.choices = choices,
                    Err(e) => return fail(e),
                }
                response
            }
            Request::Status => {
                let sources = match self.sources() {
                    Ok(v) => v,
                    Err(e) => {
                        let mut response = self.error(e, None);
                        response.ok = true;
                        response.message = if self.keys.is_empty() {
                            format!("sealed: {}", response.message)
                        } else {
                            format!(
                                "{} local vault(s) unsealed. {}",
                                self.keys.len(),
                                response.message
                            )
                        };
                        return response;
                    }
                };
                let mut response = if sources.is_empty() {
                    ok("sealed")
                } else {
                    ok(format!(
                        "unsealed:\n{}",
                        sources
                            .iter()
                            .map(|p| format!(
                                "  {} ({})",
                                self.catalog()
                                    .iter()
                                    .find(|v| v.path == *p)
                                    .map(|v| v.name.clone())
                                    .unwrap_or_else(|| fallback_name(p)),
                                if self.keys.contains_key(p) {
                                    "manual"
                                } else {
                                    "desktop"
                                }
                            ))
                            .collect::<Vec<_>>()
                            .join("\n")
                    ))
                };
                if sources.is_empty() {
                    let blocked = self.inaccessible();
                    response.message = if self.desktop.is_some()
                        && !matches!(blocked.next, Some(NextAction::Unseal))
                    {
                        format!("sealed: {}", blocked.message)
                    } else {
                        "sealed".into()
                    };
                    response.next = blocked.next;
                    response.vault = blocked.vault;
                }
                response
            }
            Request::Seal { vault } => {
                if vault.is_none() && self.sources().unwrap_or_default().is_empty() {
                    return ok("sealed");
                }
                let path = match self.target(vault, Purpose::Seal) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                self.keys.remove(&path);
                self.blocked.insert(path.clone());
                let mut response = ok("sealed");
                response.vault = Some(path);
                response
            }
            Request::Resume { vault } => {
                let path = match self.target(vault, Purpose::Unseal) {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if self.keys.contains_key(&path) {
                    return ok("unsealed");
                }
                match self.desktop_request(
                    &path,
                    json!({"op":"query","hostname":"bramble-cli-status.invalid"}),
                    true,
                ) {
                    Ok(_) => {
                        self.blocked.remove(&path);
                        let mut response = ok("unsealed (desktop)");
                        response.vault = Some(path);
                        response
                    }
                    Err(e) => self.error(e, Some(path)),
                }
            }
            Request::Unseal {
                vault,
                mut password,
            } => {
                let path = match self.target(vault, Purpose::Unseal) {
                    Ok(v) => v,
                    Err(e) => {
                        password.zeroize();
                        return e;
                    }
                };
                if self.keys.contains_key(&path) {
                    password.zeroize();
                    return ok("unsealed");
                }
                let result = {
                    let _guard = ClearKey;
                    vault_crypto::lock();
                    read_vault(&path)
                        .and_then(|v| crate::unlock(&v, &password))
                        .and_then(|correct| {
                            if correct {
                                vault_crypto::export_vek().map_err(|e| e.to_string())
                            } else {
                                Err("incorrect password or no password slot".into())
                            }
                        })
                };
                password.zeroize();
                match result {
                    Ok(key) => {
                        self.keys.insert(path.clone(), Zeroizing::new(key));
                        self.blocked.remove(&path);
                        let mut response = ok("unsealed");
                        response.vault = Some(path);
                        response
                    }
                    Err(e) => self.error(e, Some(path)),
                }
            }
            Request::List { hostname } => self.list_all(hostname),
            Request::Get { id } => self.get_all(id),
        }
    }
}
fn fallback_name(path: &Path) -> String {
    path.file_stem()
        .unwrap_or(path.as_os_str())
        .to_string_lossy()
        .into_owned()
}
fn expected_unavailable(e: &str) -> bool {
    e.starts_with("connect desktop:")
        || matches!(
            e,
            "desktop: locked"
                | "desktop: not paired"
                | "desktop: not linked to this app"
                | "desktop: not linked to the open vault"
                | "daemon is sealed"
        )
}
