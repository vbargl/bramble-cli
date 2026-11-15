//! Shared reading order for plain CLI diagnostics: problem, whitespace, subordinate actions.
//! Application data on stdout never passes through this formatter.
use std::io::IsTerminal;

pub fn action(label: &str, command: &str) -> String {
    format!("{label}\n  {command}")
}

pub fn steps(actions: &[String]) -> String {
    let numbered = actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            if actions.len() > 1 {
                let marker = match index {
                    0 => "1️⃣".to_owned(),
                    1 => "2️⃣".to_owned(),
                    2 => "3️⃣".to_owned(),
                    _ => format!("{}.", index + 1),
                };
                format!("{marker} {action}")
            } else {
                action.clone()
            }
        })
        .collect::<Vec<_>>();
    numbered
        .join("\n\n-- or --\n\n")
        .lines()
        .map(|line| {
            if line.is_empty() {
                String::new()
            } else {
                format!("  {line}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn recovery(problem: &str, actions: &[String]) -> String {
    if actions.is_empty() {
        problem.to_owned()
    } else {
        format!("{problem}\n\n{}", steps(actions))
    }
}

pub const BOLD: &str = "1";
pub const DIM: &str = "2";

/// Emphasis is the only visual tool a terminal reliably offers, so it is spent in three
/// levels: bold (read this first), plain, and dim (chrome and handles). Never colour alone.
pub fn style(code: &str, text: &str) -> String {
    format!("\x1b[{code}m{text}\x1b[0m")
}

fn colors_allowed() -> bool {
    !std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
}
fn color_enabled() -> bool {
    std::io::stderr().is_terminal() && colors_allowed()
}
/// Data on stdout is styled only on a terminal; a pipe or file always gets plain text.
pub fn stdout_styled() -> bool {
    std::io::stdout().is_terminal() && colors_allowed()
}

pub fn render_error(message: &str, color: bool) -> String {
    let (problem, rest) = message.split_once('\n').unwrap_or((message, ""));
    let heading = if color {
        format!("\x1b[1;31m! {problem}\x1b[0m")
    } else {
        format!("! {problem}")
    };
    let body = rest.trim_matches('\n');
    if body.is_empty() {
        return heading;
    }
    let body = body
        .lines()
        .map(|line| {
            let line = if line.is_empty() || line.starts_with("  ") {
                line.to_owned()
            } else {
                format!("  {line}")
            };
            if !color {
                line
            } else if line.trim() == "-- or --" {
                style(DIM, &line)
            } else if line.starts_with("    ") {
                // The command to run is what the reader came for.
                style(BOLD, &line)
            } else {
                line
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("{heading}\n\n{body}")
}

pub fn error_text(message: &str) -> String {
    render_error(message, color_enabled())
}
pub fn error(message: &str) {
    eprintln!("{}", error_text(message));
}
pub fn instructions(actions: &[String]) {
    eprintln!("\n{}", steps(actions));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn error_hierarchy_groups_alternatives_under_the_problem() {
        let message = recovery(
            "Daemon service is not installed.",
            &[
                action(
                    "Install and start the service:",
                    "./tool service install --desktop",
                ),
                action("Run in another terminal:", "./tool daemon --desktop"),
            ],
        );
        let plain = render_error(&message, false);
        assert_eq!(plain,"! Daemon service is not installed.\n\n  1️⃣ Install and start the service:\n    ./tool service install --desktop\n\n  -- or --\n\n  2️⃣ Run in another terminal:\n    ./tool daemon --desktop");
        let colored = render_error(&message, true);
        assert!(colored.starts_with("\x1b[1;31m! Daemon service is not installed.\x1b[0m"));
        assert!(colored.contains("\x1b[1m    ./tool service install --desktop\x1b[0m"));
        assert!(colored.contains("\x1b[2m  -- or --\x1b[0m"));
        // Emphasis never changes the words: stripping it gives the plain rendering.
        let stripped = colored
            .replace("\x1b[1;31m", "")
            .replace("\x1b[1m", "")
            .replace("\x1b[2m", "")
            .replace("\x1b[0m", "");
        assert_eq!(stripped, plain);
    }
}
