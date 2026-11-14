//! Human-guided pairing. Preparation errors can be retried; comparisons are never approved
//! by pressing Enter or by EOF. Existing credentials are verified, never silently replaced.
use crate::desktop::{self, PairEvent};
use serde_json::json;
use std::{
    io::{BufRead, Write},
    path::Path,
};

type Result<T> = std::result::Result<T, String>;

fn show(out: &mut impl Write, lines: &[&str]) -> Result<()> {
    for line in lines {
        writeln!(out, "{line}").map_err(|e| e.to_string())?;
    }
    out.flush().map_err(|e| e.to_string())
}
fn answer(input: &mut impl BufRead) -> Result<String> {
    let mut answer = String::new();
    if input.read_line(&mut answer).map_err(|e| e.to_string())? == 0 {
        return Err("pairing cancelled (input closed)".into());
    }
    Ok(answer.trim().to_owned())
}
fn retry(
    input: &mut impl BufRead,
    out: &mut impl Write,
    problem: &str,
    action: &str,
    interactive: bool,
) -> Result<()> {
    if !interactive {
        return Err(crate::terminal::recovery(
            problem,
            &[
                action.to_owned(),
                crate::terminal::action(
                    "Run in a terminal:",
                    &crate::guidance::command(None, &["pair"]),
                ),
            ],
        ));
    }
    show(
        out,
        &[
            &crate::terminal::error_text(&crate::terminal::recovery(problem, &[action.to_owned()])),
            "",
            "  Enter when ready · q to cancel",
        ],
    )?;
    if answer(input)?.eq_ignore_ascii_case("q") {
        return Err("pairing cancelled".into());
    }
    Ok(())
}

pub fn run(
    socket: &Path,
    identity: &Path,
    input: &mut impl BufRead,
    out: &mut impl Write,
    interactive: bool,
) -> Result<()> {
    // Treat symlinks and unreadable/corrupt files as existing too: never silently overwrite.
    let existing = match identity.symlink_metadata() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(format!("inspect pairing file: {e}")),
    };
    crate::private_dir(
        identity
            .parent()
            .ok_or("pairing file needs a parent directory")?,
    )?;
    if existing {
        let key = desktop::Identity::load(identity)?;
        loop {
            let result = desktop::Session::connect(socket, &key).and_then(|mut session| {
                session.request_raw(json!({"op":"query", "hostname":"bramble-cli-status.invalid"}))
            });
            match result {
                Ok(reply) if reply["ok"] == true => {
                    return show(out, &["✅ Paired; ready to use"]);
                }
                Ok(reply) if reply["error"] == "locked" => {
                    retry(
                        input,
                        out,
                        "Desktop vault is locked.",
                        "Unlock your vault in desktop Bramble.",
                        interactive,
                    )?;
                }
                Ok(_) => {
                    return Err(crate::terminal::recovery("Desktop Bramble rejected the existing pairing.",&[
                        "Open the vault originally paired with this CLI.".into(),
                        format!("Pair again:\n  Disconnect Bramble CLI in desktop Bramble.\n  Move {} aside.\n  Run {}.",identity.display(),crate::guidance::command(None,&["pair"])),
                    ]));
                }
                Err(_) => retry(
                    input,
                    out,
                    "Desktop Bramble is unavailable.",
                    "Open desktop Bramble and unlock your paired vault.",
                    interactive,
                )?,
            }
        }
    }
    if !interactive {
        return Err(crate::terminal::recovery(
            "Pairing needs your confirmation.",
            &[crate::terminal::action(
                "Run in a terminal:",
                &crate::guidance::command(None, &["pair"]),
            )],
        ));
    }
    loop {
        let mut comparing = false;
        let result = desktop::pair(socket, identity, |event| {
            match event {
                PairEvent::Compare(digits) => {
                    comparing = true;
                    show(
                        out,
                        &[
                            "Compare the pairing digits with desktop Bramble:",
                            "",
                            &format!("  {digits}"),
                            "",
                            "  Type yes if all twelve digits match; anything else cancels.",
                        ],
                    )?;
                    return Ok(answer(input)? == "yes");
                }
                PairEvent::AwaitingDesktop => show(
                    out,
                    &[
                        "✅ Digits matched",
                        "",
                        "  Click Approve in desktop Bramble",
                    ],
                )?,
            }
            Ok(true)
        });
        match result {
            Ok(()) => return show(out, &["✅ Paired; ready to use"]),
            // A mismatch, cancelled approval or failed save needs an explicit new invocation.
            Err(e) if comparing => return Err(e),
            Err(_) => retry(
                input,
                out,
                "Desktop Bramble is not ready to pair.",
                "In desktop Bramble: unlock vault → Settings → Browser extension → Connect.",
                interactive,
            )?,
        }
    }
}
