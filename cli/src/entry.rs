//! Entry fields: selection for `get` and the edits `save` applies to a decrypted entry.
//! Nothing here touches files or keys, so every rule is unit-testable without a daemon.
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use zeroize::Zeroize;

pub const SELECTORS: &str = "title, username, password, url, urls, notes, totp, field:NAME";

/// A field a caller can ask `get` for, or clear with `save --clear`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    Title,
    Username,
    Password,
    /// The first URL.
    Url,
    /// Every URL.
    Urls,
    Notes,
    Totp,
    Custom(String),
}

impl Field {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if let Some(name) = spec.strip_prefix("field:") {
            if name.is_empty() {
                return Err("A custom field needs a name: field:NAME.".into());
            }
            return Ok(Self::Custom(name.to_owned()));
        }
        match spec.trim().to_ascii_lowercase().as_str() {
            "title" | "name" => Ok(Self::Title),
            "username" => Ok(Self::Username),
            "password" => Ok(Self::Password),
            "url" => Ok(Self::Url),
            "urls" => Ok(Self::Urls),
            "notes" => Ok(Self::Notes),
            "totp" => Ok(Self::Totp),
            _ => Err(format!(
                "Unknown field '{spec}'. Choose one of: {SELECTORS}."
            )),
        }
    }
    /// The canonical selector, used as the key in JSON results.
    pub fn selector(&self) -> String {
        match self {
            Self::Title => "title".into(),
            Self::Username => "username".into(),
            Self::Password => "password".into(),
            Self::Url => "url".into(),
            Self::Urls => "urls".into(),
            Self::Notes => "notes".into(),
            Self::Totp => "totp".into(),
            Self::Custom(name) => format!("field:{name}"),
        }
    }
    /// The desktop protocol returns only these fields of an entry.
    pub fn desktop_supported(&self) -> bool {
        matches!(self, Self::Username | Self::Password | Self::Totp)
    }
}

pub fn parse_fields(specs: &[String]) -> Result<Vec<Field>, String> {
    let mut fields = Vec::new();
    for spec in specs {
        let field = Field::parse(spec)?;
        if !fields.contains(&field) {
            fields.push(field);
        }
    }
    Ok(fields)
}

fn text(plain: &Value, key: &str) -> Option<Value> {
    plain.get(key).and_then(Value::as_str).map(|s| json!(s))
}

fn urls(plain: &Value) -> Option<Vec<String>> {
    match plain.get("urls") {
        Some(Value::Array(list)) => Some(
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        ),
        // Entries written before `urls` existed carry a single `url` string.
        _ => plain
            .get("url")
            .and_then(Value::as_str)
            .map(|u| vec![u.to_owned()]),
    }
}

/// The requested fields of a decrypted entry. A field the entry does not have is reported
/// by selector instead of being silently dropped or returned empty.
pub fn select(plain: &Value, fields: &[Field]) -> Result<Map<String, Value>, Vec<String>> {
    let mut found = Map::new();
    let mut missing = Vec::new();
    for field in fields {
        let value = match field {
            Field::Title => text(plain, "name"),
            Field::Username => text(plain, "username"),
            Field::Password => text(plain, "password"),
            Field::Notes => text(plain, "notes"),
            Field::Totp => text(plain, "totp"),
            Field::Url => urls(plain).and_then(|u| u.first().map(|u| json!(u))),
            Field::Urls => urls(plain).map(|u| json!(u)),
            Field::Custom(name) => plain
                .get("customFields")
                .and_then(Value::as_array)
                .and_then(|list| {
                    list.iter()
                        .find(|f| f.get("key").and_then(Value::as_str) == Some(name))
                })
                .and_then(|f| text(f, "value")),
        };
        match value {
            Some(value) => {
                found.insert(field.selector(), value);
            }
            None => missing.push(field.selector()),
        }
    }
    if missing.is_empty() {
        Ok(found)
    } else {
        Err(missing)
    }
}

/// One custom field to create or update, addressed by its exact name.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomValue {
    pub name: String,
    pub value: String,
    /// `None` keeps an existing field's flag and creates new fields visible.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<bool>,
}

/// What `save` changes. Omitted fields are preserved; only `clear` removes anything.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Change {
    pub title: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Replaces the whole URL list.
    pub urls: Option<Vec<String>>,
    pub notes: Option<String>,
    pub fields: Vec<CustomValue>,
    /// Selectors as accepted by `get`: username, password, url(s), notes, field:NAME.
    pub clear: Vec<String>,
}

impl Change {
    /// Wipe values after use; a request holds the password and hidden custom values.
    pub fn wipe(&mut self) {
        for value in [&mut self.password, &mut self.username, &mut self.notes]
            .into_iter()
            .flatten()
        {
            value.zeroize();
        }
        for field in &mut self.fields {
            field.value.zeroize();
        }
    }
    pub fn is_empty(&self) -> bool {
        self.title.is_none()
            && self.username.is_none()
            && self.password.is_none()
            && self.urls.is_none()
            && self.notes.is_none()
            && self.fields.is_empty()
            && self.clear.is_empty()
    }
}

/// Zero every string inside a decrypted value before it is dropped.
pub fn wipe(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => map.values_mut().for_each(wipe),
        _ => (),
    }
}

fn clean_urls(urls: &[String]) -> Result<Vec<String>, String> {
    let mut result: Vec<String> = Vec::new();
    for url in urls {
        let url = url.trim();
        if url.is_empty() {
            return Err("A URL must not be empty. Use --clear url to remove all URLs.".into());
        }
        if !result.iter().any(|existing| existing == url) {
            result.push(url.to_owned());
        }
    }
    Ok(result)
}

/// A new login entry's plaintext.
pub fn new_login(change: &Change) -> Result<Value, String> {
    if change.title.as_deref().is_none_or(|t| t.trim().is_empty()) {
        return Err("A new entry needs a title (--title).".into());
    }
    let mut entry = json!({
        "type": "login",
        "name": "",
        "username": "",
        "password": "",
        "urls": [],
    });
    apply(&mut entry, change)?;
    Ok(entry)
}

/// Apply `change` to a decrypted entry, preserving every field it does not mention.
pub fn apply(plain: &mut Value, change: &Change) -> Result<(), String> {
    let login = plain
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(|t| t == "login");
    let entry = plain.as_object_mut().ok_or("The entry is malformed.")?;

    let mut cleared = Vec::new();
    for spec in &change.clear {
        let field = Field::parse(spec)?;
        match field {
            Field::Title => {
                return Err("The title cannot be cleared; set a new one instead.".into())
            }
            Field::Totp => {
                return Err("Clearing the one-time-password secret is not supported.".into())
            }
            _ => cleared.push(field),
        }
    }
    let touches = |field: &Field| -> bool {
        match field {
            Field::Username => change.username.is_some(),
            Field::Password => change.password.is_some(),
            Field::Url | Field::Urls => change.urls.is_some(),
            Field::Notes => change.notes.is_some(),
            Field::Custom(name) => change.fields.iter().any(|f| &f.name == name),
            _ => false,
        }
    };
    if let Some(field) = cleared.iter().find(|field| touches(field)) {
        return Err(format!(
            "'{}' is both set and cleared. Choose one.",
            field.selector()
        ));
    }
    if !login
        && (change.username.is_some()
            || change.password.is_some()
            || change.urls.is_some()
            || cleared.iter().any(|f| {
                matches!(
                    f,
                    Field::Username | Field::Password | Field::Url | Field::Urls
                )
            }))
    {
        return Err(
            "Only login entries have a username, password or URLs; this entry has another type."
                .into(),
        );
    }

    if let Some(title) = &change.title {
        if title.trim().is_empty() {
            return Err("The title must not be empty.".into());
        }
        entry.insert("name".into(), json!(title));
    }
    if let Some(username) = &change.username {
        entry.insert("username".into(), json!(username));
    }
    if let Some(password) = &change.password {
        entry.insert("password".into(), json!(password));
    }
    if let Some(urls) = &change.urls {
        entry.remove("url");
        entry.insert("urls".into(), json!(clean_urls(urls)?));
    }
    if let Some(notes) = &change.notes {
        entry.insert("notes".into(), json!(notes));
    }
    for field in &cleared {
        match field {
            Field::Username => {
                entry.insert("username".into(), json!(""));
            }
            Field::Password => {
                entry.insert("password".into(), json!(""));
            }
            Field::Url | Field::Urls => {
                entry.remove("url");
                entry.insert("urls".into(), json!([]));
            }
            Field::Notes => {
                entry.remove("notes");
            }
            Field::Custom(name) => {
                if let Some(list) = entry.get_mut("customFields").and_then(Value::as_array_mut) {
                    let matches = list
                        .iter()
                        .filter(|f| f.get("key").and_then(Value::as_str) == Some(name))
                        .count();
                    if matches > 1 {
                        return Err(format!(
                            "Several custom fields are named '{name}'; edit them in desktop Bramble."
                        ));
                    }
                    list.retain(|f| f.get("key").and_then(Value::as_str) != Some(name));
                    if list.is_empty() {
                        entry.remove("customFields");
                    }
                }
            }
            _ => (),
        }
    }
    for custom in &change.fields {
        if custom.name.is_empty() {
            return Err("A custom field needs a name.".into());
        }
        let list = entry
            .entry("customFields")
            .or_insert_with(|| json!([]))
            .as_array_mut()
            .ok_or("The entry's custom fields are malformed.")?;
        let positions: Vec<_> = list
            .iter()
            .enumerate()
            .filter(|(_, f)| f.get("key").and_then(Value::as_str) == Some(custom.name.as_str()))
            .map(|(i, _)| i)
            .collect();
        match positions.as_slice() {
            [] => {
                let mut field = json!({"key": custom.name, "value": custom.value});
                if custom.hidden == Some(true) {
                    field["hidden"] = json!(true);
                }
                list.push(field);
            }
            [index] => {
                let existing = list[*index]
                    .as_object_mut()
                    .ok_or("The entry's custom fields are malformed.")?;
                existing.insert("value".into(), json!(custom.value));
                match custom.hidden {
                    Some(true) => {
                        existing.insert("hidden".into(), json!(true));
                    }
                    Some(false) => {
                        existing.remove("hidden");
                    }
                    None => (),
                }
            }
            _ => {
                return Err(format!(
                    "Several custom fields are named '{}'; edit them in desktop Bramble.",
                    custom.name
                ))
            }
        }
    }
    Ok(())
}

/// Parse the `--input` document: the same keys as the options, with `fields` as an object
/// mapping each name to a string or `{"value": ..., "hidden": ...}`.
pub fn parse_input(document: &Value) -> Result<SaveInput, String> {
    let object = document
        .as_object()
        .ok_or("The input must be a JSON object.")?;
    let mut input = SaveInput::default();
    for (key, value) in object {
        let string = |what: &str| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(format!("'{what}' must be a string."))
        };
        match key.as_str() {
            "id" => input.id = Some(string("id")?),
            "vault" => input.vault = Some(string("vault")?),
            "title" => input.change.title = Some(string("title")?),
            "username" => input.change.username = Some(string("username")?),
            "password" => input.change.password = Some(string("password")?),
            "notes" => input.change.notes = Some(string("notes")?),
            "urls" => {
                let list = value
                    .as_array()
                    .ok_or("'urls' must be an array of strings.")?;
                input.change.urls = Some(
                    list.iter()
                        .map(|u| {
                            u.as_str()
                                .map(str::to_owned)
                                .ok_or("'urls' must be an array of strings.".to_owned())
                        })
                        .collect::<Result<_, _>>()?,
                );
            }
            "clear" => {
                let list = value
                    .as_array()
                    .ok_or("'clear' must be an array of field selectors.")?;
                input.change.clear = list
                    .iter()
                    .map(|u| {
                        u.as_str()
                            .map(str::to_owned)
                            .ok_or("'clear' must be an array of field selectors.".to_owned())
                    })
                    .collect::<Result<_, _>>()?;
            }
            "fields" => {
                let map = value
                    .as_object()
                    .ok_or("'fields' must be an object mapping names to values.")?;
                for (name, field) in map {
                    let custom = match field {
                        Value::String(value) => CustomValue {
                            name: name.clone(),
                            value: value.clone(),
                            hidden: None,
                        },
                        Value::Object(object) => CustomValue {
                            name: name.clone(),
                            value: object
                                .get("value")
                                .and_then(Value::as_str)
                                .ok_or(format!("Field '{name}' needs a string \"value\"."))?
                                .to_owned(),
                            hidden: object.get("hidden").and_then(Value::as_bool),
                        },
                        _ => {
                            return Err(format!(
                                "Field '{name}' must be a string or an object with \"value\"."
                            ))
                        }
                    };
                    input.change.fields.push(custom);
                }
            }
            other => return Err(format!("Unknown input key '{other}'.")),
        }
    }
    Ok(input)
}

#[derive(Default, Debug)]
pub struct SaveInput {
    pub id: Option<String>,
    pub vault: Option<String>,
    pub change: Change,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn login() -> Value {
        json!({
            "type": "login", "name": "Example", "username": "ada", "password": "pw",
            "urls": ["https://example.com", "https://example.org"],
            "notes": "keep", "totp": "SECRET", "tags": ["work"],
            "customFields": [{"key": "API key", "value": "k1", "hidden": true}, {"key": "Region", "value": "eu"}],
        })
    }
    fn fields(specs: &[&str]) -> Vec<Field> {
        parse_fields(&specs.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap()
    }

    #[test]
    fn selects_standard_and_custom_fields() {
        let found = select(
            &login(),
            &fields(&[
                "title",
                "username",
                "url",
                "urls",
                "notes",
                "totp",
                "field:API key",
            ]),
        )
        .unwrap();
        assert_eq!(found["title"], "Example");
        assert_eq!(found["username"], "ada");
        assert_eq!(found["url"], "https://example.com");
        assert_eq!(
            found["urls"],
            json!(["https://example.com", "https://example.org"])
        );
        assert_eq!(found["field:API key"], "k1");
        assert_eq!(found["totp"], "SECRET");
    }
    #[test]
    fn reports_every_missing_field_by_selector() {
        let plain = json!({"type":"login","name":"x","username":"","password":"p","urls":[]});
        let missing =
            select(&plain, &fields(&["notes", "url", "field:Nope", "password"])).unwrap_err();
        assert_eq!(missing, ["notes", "url", "field:Nope"]);
        // An empty value is present; only an absent one is missing.
        assert!(select(&plain, &fields(&["username", "urls"])).is_ok());
    }
    #[test]
    fn legacy_single_url_entries_are_readable() {
        let found = select(
            &json!({"name":"x","url":"https://old.example"}),
            &fields(&["url", "urls"]),
        )
        .unwrap();
        assert_eq!(found["url"], "https://old.example");
        assert_eq!(found["urls"], json!(["https://old.example"]));
    }
    #[test]
    fn rejects_unknown_selectors_and_deduplicates() {
        assert!(Field::parse("pasword")
            .unwrap_err()
            .contains("Choose one of"));
        assert!(Field::parse("field:").is_err());
        assert_eq!(fields(&["name", "title", "TITLE"]), [Field::Title]);
    }
    #[test]
    fn update_preserves_everything_not_mentioned() {
        let mut plain = login();
        let change = Change {
            password: Some("new".into()),
            ..Change::default()
        };
        apply(&mut plain, &change).unwrap();
        let mut expected = login();
        expected["password"] = json!("new");
        assert_eq!(plain, expected);
    }
    #[test]
    fn update_sets_urls_notes_and_custom_fields() {
        let mut plain = login();
        let change = Change {
            title: Some("Renamed".into()),
            urls: Some(vec![
                " https://a.example ".into(),
                "https://a.example".into(),
            ]),
            notes: Some("".into()),
            fields: vec![
                CustomValue {
                    name: "Region".into(),
                    value: "us".into(),
                    hidden: None,
                },
                CustomValue {
                    name: "API key".into(),
                    value: "k2".into(),
                    hidden: None,
                },
                CustomValue {
                    name: "New".into(),
                    value: "n".into(),
                    hidden: Some(true),
                },
            ],
            ..Change::default()
        };
        apply(&mut plain, &change).unwrap();
        assert_eq!(plain["name"], "Renamed");
        assert_eq!(plain["urls"], json!(["https://a.example"]));
        assert_eq!(plain["notes"], "");
        assert_eq!(
            plain["customFields"][0],
            json!({"key":"API key","value":"k2","hidden":true})
        );
        assert_eq!(
            plain["customFields"][1],
            json!({"key":"Region","value":"us"})
        );
        assert_eq!(
            plain["customFields"][2],
            json!({"key":"New","value":"n","hidden":true})
        );
        assert_eq!(plain["tags"], json!(["work"]));
    }
    #[test]
    fn clearing_is_explicit_and_precise() {
        let mut plain = login();
        let change = Change {
            clear: ["username", "notes", "url", "field:Region", "field:Absent"]
                .map(String::from)
                .to_vec(),
            ..Change::default()
        };
        apply(&mut plain, &change).unwrap();
        assert_eq!(plain["username"], "");
        assert!(plain.get("notes").is_none());
        assert_eq!(plain["urls"], json!([]));
        assert_eq!(
            plain["customFields"],
            json!([{"key":"API key","value":"k1","hidden":true}])
        );
        assert_eq!(plain["password"], "pw");
        let both = Change {
            notes: Some("x".into()),
            clear: vec!["notes".into()],
            ..Change::default()
        };
        assert!(apply(&mut login(), &both)
            .unwrap_err()
            .contains("both set and cleared"));
        let title = Change {
            clear: vec!["title".into()],
            ..Change::default()
        };
        assert!(apply(&mut login(), &title).is_err());
    }
    #[test]
    fn clearing_the_last_custom_field_removes_the_list() {
        let mut plain = json!({"type":"login","name":"x","username":"","password":"","urls":[],"customFields":[{"key":"a","value":"b"}]});
        let change = Change {
            clear: vec!["field:a".into()],
            ..Change::default()
        };
        apply(&mut plain, &change).unwrap();
        assert!(plain.get("customFields").is_none());
    }
    #[test]
    fn duplicate_custom_names_are_never_guessed() {
        let mut plain = json!({"type":"login","name":"x","username":"","password":"","urls":[],"customFields":[{"key":"a","value":"1"},{"key":"a","value":"2"}]});
        let set = Change {
            fields: vec![CustomValue {
                name: "a".into(),
                value: "3".into(),
                hidden: None,
            }],
            ..Change::default()
        };
        assert!(apply(&mut plain.clone(), &set)
            .unwrap_err()
            .contains("Several custom fields"));
        let clear = Change {
            clear: vec!["field:a".into()],
            ..Change::default()
        };
        assert!(apply(&mut plain, &clear).is_err());
    }
    #[test]
    fn login_fields_are_refused_on_other_entry_types() {
        let mut note = json!({"type":"note","name":"n","notes":"text"});
        let change = Change {
            password: Some("x".into()),
            ..Change::default()
        };
        assert!(apply(&mut note, &change).unwrap_err().contains("login"));
        let change = Change {
            notes: Some("changed".into()),
            ..Change::default()
        };
        apply(&mut note, &change).unwrap();
        assert_eq!(note["notes"], "changed");
    }
    #[test]
    fn new_entries_need_a_title_and_default_login_fields() {
        assert!(new_login(&Change::default()).unwrap_err().contains("title"));
        assert!(new_login(&Change {
            title: Some(" ".into()),
            ..Change::default()
        })
        .is_err());
        let entry = new_login(&Change {
            title: Some("Site".into()),
            password: Some("pw".into()),
            ..Change::default()
        })
        .unwrap();
        assert_eq!(
            entry,
            json!({"type":"login","name":"Site","username":"","password":"pw","urls":[]})
        );
    }
    #[test]
    fn input_documents_use_the_option_names() {
        let input = parse_input(&json!({
            "id": "abc", "vault": "Work", "title": "T", "urls": ["https://a"],
            "fields": {"Plain": "v", "Secret": {"value": "s", "hidden": true}},
            "clear": ["notes"]
        }))
        .unwrap();
        assert_eq!(input.id.as_deref(), Some("abc"));
        assert_eq!(input.vault.as_deref(), Some("Work"));
        assert_eq!(input.change.title.as_deref(), Some("T"));
        assert_eq!(input.change.fields.len(), 2);
        assert!(parse_input(&json!({"passwrod": "x"}))
            .unwrap_err()
            .contains("Unknown input key"));
        assert!(parse_input(&json!({"urls": "x"})).is_err());
        assert!(parse_input(&json!([])).is_err());
    }
}
