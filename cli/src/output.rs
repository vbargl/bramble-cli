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

/// Aligned `TITLE  VAULT  ID` rows, in the order a reader needs them: the title identifies
/// the entry, the vault tells similar titles apart, and the ID is the handle for `get` and
/// `save`, so it comes last where it never forces the other columns out of line. IDs are
/// never shortened; long titles and vault names are, but only to fit a terminal. `styled`
/// adds emphasis only: bold title, plain vault, dimmed ID and header.
pub fn entry_table(
    rows: &[(String, String, String)],
    width: Option<usize>,
    styled: bool,
) -> String {
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
    // Pad the plain text first so escape sequences never disturb the alignment.
    let cell = |text: &str, width: usize, style: Option<&str>| {
        let padded = format!("{:<width$}", shorten(text, width));
        match style.filter(|_| styled) {
            Some(code) => terminal::style(code, &padded),
            None => padded,
        }
    };
    let gap = " ".repeat(GAP);
    let line = |title: &str, vault: &str, id: &str, title_style, vault_style, id_style| {
        let id = match id_style {
            Some(code) if styled => terminal::style(code, id),
            _ => id.to_owned(),
        };
        let head = format!(
            "{}{gap}{}{gap}",
            cell(title, title_width, title_style),
            cell(vault, vault_width, vault_style)
        );
        format!("{head}{id}")
    };
    let mut out = vec![line(
        "TITLE",
        "VAULT",
        "ID",
        Some(terminal::DIM),
        Some(terminal::DIM),
        Some(terminal::DIM),
    )];
    out.extend(rows.iter().map(|(id, title, vault)| {
        line(
            title,
            vault,
            id,
            Some(terminal::BOLD),
            None,
            Some(terminal::DIM),
        )
    }));
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
            false,
        );
        assert_eq!(
            table,
            "TITLE   VAULT     ID\nGitHub  Personal  a\nBank    Work      long-entry-id"
        );
    }
    #[test]
    fn table_shortens_titles_only_when_a_width_is_known() {
        let rows = [row("id-1", &"x".repeat(60), "Personal")];
        assert!(entry_table(&rows, None, false).contains(&"x".repeat(60)));
        let narrow = entry_table(&rows, Some(40), false);
        assert!(narrow.lines().all(|l| l.chars().count() <= 40), "{narrow}");
        assert!(narrow.contains('…'));
        assert!(narrow.contains("id-1"));
    }
    #[test]
    fn table_strips_terminal_control_sequences_from_titles() {
        let table = entry_table(&[row("id", "evil\x1b[31m\ntitle", "v")], None, false);
        assert!(!table.contains('\x1b'));
        assert_eq!(table.lines().count(), 2);
    }
    #[test]
    fn styled_table_emphasises_titles_and_dims_handles_without_breaking_alignment() {
        let rows = [
            row("id-1", "Bank", "Work"),
            row("id-2", "GitHub", "Personal"),
        ];
        let styled = entry_table(&rows, None, true);
        assert!(styled.contains("\x1b[1mBank  \x1b[0m"), "{styled:?}");
        assert!(styled.contains("\x1b[2mid-1\x1b[0m"));
        assert!(styled.lines().next().unwrap().starts_with("\x1b[2mTITLE"));
        // Stripping the emphasis leaves exactly the plain table.
        let stripped = ["\x1b[1m", "\x1b[2m", "\x1b[0m"]
            .iter()
            .fold(styled, |text, code| text.replace(code, ""));
        assert_eq!(stripped, entry_table(&rows, None, false));
    }
    #[test]
    fn empty_table_is_just_the_header() {
        assert_eq!(entry_table(&[], None, false), "TITLE  VAULT  ID");
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
