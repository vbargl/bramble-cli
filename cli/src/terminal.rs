//! Shared reading order for plain CLI diagnostics: problem, whitespace, subordinate actions.
//! Application data on stdout never passes through this formatter.
use std::io::IsTerminal;

pub fn action(label: &str, command: &str) -> String {
    format!("{label}\n  {command}")
}

pub fn steps(actions: &[String]) -> String {
    actions
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

fn color_enabled() -> bool {
    std::io::stderr().is_terminal()
        && !std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty())
        && std::env::var_os("TERM").is_none_or(|term| term != "dumb")
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
            if line.is_empty() || line.starts_with("  ") {
                line.to_owned()
            } else {
                format!("  {line}")
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
        assert_eq!(plain,"! Daemon service is not installed.\n\n  Install and start the service:\n    ./tool service install --desktop\n\n  -- or --\n\n  Run in another terminal:\n    ./tool daemon --desktop");
        let colored = render_error(&message, true);
        assert_eq!(
            colored,
            plain.replacen(
                "! Daemon service is not installed.",
                "\x1b[1;31m! Daemon service is not installed.\x1b[0m",
                1
            )
        );
    }
}
