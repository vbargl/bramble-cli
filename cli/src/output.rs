//! How every command reports results and failures.
//!
//! Plain mode prints data on stdout and guidance on stderr. `--json` mode prints exactly one
//! JSON document on stdout (success or failure) and nothing on stderr, so a tool can parse
//! stdout unconditionally and branch on `ok`, the error `code` or the exit status.
use crate::{terminal, vaults::Choice};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::IsTerminal;

/// One recovery action: a sentence, and the command that performs it when there is one.
#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}
impl Step {
    pub fn text(message: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            command: None,
        }
    }
    pub fn run(message: impl ToString, command: impl ToString) -> Self {
        Self {
            message: message.to_string(),
            command: Some(command.to_string()),
        }
    }
    pub fn render(&self) -> String {
        match &self.command {
            Some(command) => terminal::action(&self.message, command),
            None => self.message.clone(),
        }
    }
}

/// A failure with a stable, documented `code`.
#[derive(Debug)]
pub struct CliError {
    pub code: &'static str,
    pub message: String,
    pub steps: Vec<Step>,
    pub choices: Vec<Choice>,
    /// Machine-readable specifics, such as the entry IDs an ambiguous ID could mean.
    pub details: Option<Value>,
    /// Preformatted plain text for failures that still arrive as a rendered string.
    raw: Option<String>,
}
impl CliError {
    pub fn new(code: &'static str, message: impl ToString) -> Self {
        Self {
            code,
            message: message.to_string(),
            steps: Vec::new(),
            choices: Vec::new(),
            details: None,
            raw: None,
        }
    }
    pub fn steps(mut self, steps: Vec<Step>) -> Self {
        self.steps = steps;
        self
    }
    pub fn choices(mut self, choices: Vec<Choice>) -> Self {
        self.choices = choices;
        self
    }
    pub fn details(mut self, details: Option<Value>) -> Self {
        self.details = details;
        self
    }
    /// Plain-mode text: the problem, then the indented recovery actions.
    pub fn plain(&self) -> String {
        match &self.raw {
            Some(raw) => raw.clone(),
            None => terminal::recovery(
                &self.message,
                &self.steps.iter().map(Step::render).collect::<Vec<_>>(),
            ),
        }
    }
    pub fn cancelled(&self) -> bool {
        self.code == "cancelled"
    }
    /// Exit status, identical in plain and JSON mode.
    pub fn exit_code(&self) -> i32 {
        match self.code {
            "invalid_usage" | "invalid_input" => 2,
            "entry_not_found" | "field_not_found" | "vault_not_found" => 3,
            "sealed"
            | "desktop_locked"
            | "desktop_unavailable"
            | "not_paired"
            | "wrong_vault"
            | "vault_unidentified"
            | "daemon_unavailable"
            | "desktop_active" => 4,
            "ambiguous_entry" | "ambiguous_vault" => 5,
            "unsupported" | "list_unsupported" | "field_unsupported" | "write_unsupported" => 6,
            "interactive_required" => 7,
            _ => 1,
        }
    }
    pub fn to_json(&self, command: &str) -> Value {
        let mut error = json!({"code": self.code, "message": self.message});
        if !self.steps.is_empty() {
            error["next"] = json!(self.steps);
        }
        if !self.choices.is_empty() {
            error["choices"] = json!(self.choices);
        }
        if let Some(details) = &self.details {
            error["details"] = details.clone();
        }
        json!({"ok": false, "command": command, "error": error})
    }
}

const CANCELLATIONS: [&str; 5] = [
    "Cancelled.",
    "Cancelled (input closed).",
    "pairing cancelled",
    "pairing cancelled (input closed)",
    "pairing cancelled; desktop identity was not saved",
];
impl From<String> for CliError {
    fn from(text: String) -> Self {
        if CANCELLATIONS.contains(&text.as_str()) {
            return Self::new("cancelled", text);
        }
        let mut error = Self::new("error", text.split("\n\n").next().unwrap_or(&text));
        if text.contains("\n\n") {
            error.raw = Some(text);
        }
        error
    }
}
impl From<&str> for CliError {
    fn from(text: &str) -> Self {
        text.to_owned().into()
    }
}

pub fn success(command: &str, data: Value) -> Value {
    json!({"ok": true, "command": command, "data": data})
}

/// Write the single JSON document of a `--json` run to stdout.
pub fn emit(document: &Value) {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    // A closed pipe is the reader's choice, not an error worth another document.
    let _ = writeln!(stdout, "{document}").and_then(|_| stdout.flush());
}

/// Names for the failure codes this CLI documents; kept in one list so docs and tests agree.
pub const ERROR_CODES: &[&str] = &[
    "invalid_usage",
    "invalid_input",
    "entry_not_found",
    "field_not_found",
    "vault_not_found",
    "sealed",
    "desktop_locked",
    "desktop_unavailable",
    "not_paired",
    "wrong_vault",
    "vault_unidentified",
    "daemon_unavailable",
    "desktop_active",
    "ambiguous_entry",
    "ambiguous_vault",
    "unsupported",
    "list_unsupported",
    "field_unsupported",
    "write_unsupported",
    "interactive_required",
    "daemon_outdated",
    "daemon_connection",
    "changed_externally",
    "conflict_pending",
    "write_failed",
    "cancelled",
    "error",
];

fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn shorten(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let keep: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{keep}…")
}

/// Terminal width when stdout is a terminal; `None` means never truncate.
pub fn terminal_width() -> Option<usize> {
    if !std::io::stdout().is_terminal() {
        return None;
    }
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(1, libc::TIOCGWINSZ, &mut size) } == 0 && size.ws_col > 0 {
        return Some(size.ws_col as usize);
    }
    std::env::var("COLUMNS")
        .ok()
        .and_then(|c| c.parse().ok())
        .filter(|c| *c > 0)
        .or(Some(80))
}

/// Aligned `ID  TITLE  VAULT` rows. IDs are the handle for `get` and `save`, so they are
/// never shortened; long titles and vault names are, but only to fit a terminal.
pub fn entry_table(rows: &[(String, String, String)], width: Option<usize>) -> String {
    const GAP: usize = 2;
    let rows: Vec<_> = rows
        .iter()
        .map(|(id, title, vault)| (clean(id), clean(title), clean(vault)))
        .collect();
    let id_width = rows
        .iter()
        .map(|r| r.0.chars().count())
        .chain([2])
        .max()
        .unwrap_or(2);
    let widest = |pick: fn(&(String, String, String)) -> &String, header: &str| {
        rows.iter()
            .map(|r| pick(r).chars().count())
            .chain([header.len()])
            .max()
            .unwrap_or(0)
    };
    let mut title_width = widest(|r| &r.1, "TITLE");
    let mut vault_width = widest(|r| &r.2, "VAULT");
    if let Some(total) = width {
        let room = total.saturating_sub(id_width + 2 * GAP);
        if title_width + vault_width > room {
            vault_width = vault_width.min((room / 3).max(8));
            title_width = title_width.min(room.saturating_sub(vault_width).max(8));
        }
    }
    let line = |id: &str, title: &str, vault: &str| {
        let text = format!(
            "{id:<id_width$}{gap}{title:<title_width$}{gap}{vault}",
            title = shorten(title, title_width),
            vault = shorten(vault, vault_width),
            gap = " ".repeat(GAP)
        );
        text.trim_end().to_owned()
    };
    let mut out = vec![line("ID", "TITLE", "VAULT")];
    out.extend(rows.iter().map(|(id, title, vault)| line(id, title, vault)));
    out.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, title: &str, vault: &str) -> (String, String, String) {
        (id.into(), title.into(), vault.into())
    }

    #[test]
    fn table_aligns_columns_and_keeps_ids_whole() {
        let table = entry_table(
            &[
                row("a", "GitHub", "Personal"),
                row("long-entry-id", "Bank", "Work"),
            ],
            None,
        );
        assert_eq!(
            table,
            "ID             TITLE   VAULT\na              GitHub  Personal\nlong-entry-id  Bank    Work"
        );
    }
    #[test]
    fn table_shortens_titles_only_when_a_width_is_known() {
        let rows = [row("id-1", &"x".repeat(60), "Personal")];
        assert!(entry_table(&rows, None).contains(&"x".repeat(60)));
        let narrow = entry_table(&rows, Some(40));
        assert!(narrow.lines().all(|l| l.chars().count() <= 40), "{narrow}");
        assert!(narrow.contains('…'));
        assert!(narrow.contains("id-1"));
    }
    #[test]
    fn table_strips_terminal_control_sequences_from_titles() {
        let table = entry_table(&[row("id", "evil\x1b[31m\ntitle", "v")], None);
        assert!(!table.contains('\x1b'));
        assert_eq!(table.lines().count(), 2);
    }
    #[test]
    fn empty_table_is_just_the_header() {
        assert_eq!(entry_table(&[], None), "ID  TITLE  VAULT");
    }
    #[test]
    fn errors_serialize_with_a_code_steps_and_choices() {
        let error = CliError::new("sealed", "Daemon is sealed.")
            .steps(vec![Step::run("Unseal the vault:", "bramble-cli unseal")]);
        let json = error.to_json("get");
        assert_eq!(json["ok"], false);
        assert_eq!(json["command"], "get");
        assert_eq!(json["error"]["code"], "sealed");
        assert_eq!(json["error"]["next"][0]["command"], "bramble-cli unseal");
        assert_eq!(error.exit_code(), 4);
    }
    #[test]
    fn preformatted_failures_keep_a_clean_json_message() {
        let error = CliError::from(terminal::recovery(
            "Daemon failed.",
            &["Restart it.".into()],
        ));
        assert_eq!(error.message, "Daemon failed.");
        assert!(error.plain().contains("Restart it."));
        assert!(CliError::from("Cancelled.").cancelled());
    }
    #[test]
    fn every_documented_code_has_an_exit_status() {
        for code in ERROR_CODES {
            let status = CliError::new(code, "x").exit_code();
            assert!((1..=7).contains(&status), "{code}");
        }
    }
}
