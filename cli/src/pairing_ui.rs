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
    action: &str,
    next: Option<&str>,
) -> Result<()> {
    show(out, &[&format!("⏳ {action}")])?;
    if let Some(next) = next {
        show(out, &[&format!("🔒 {next}")])?;
    }
    show(out, &["   Enter when ready · q to cancel"])?;
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
                    retry(input, out, "Unlock your vault in desktop Bramble.", None)?;
                }
                Ok(_) => {
                    return Err(format!("Open the vault originally paired with this CLI. To pair again, disconnect Bramble CLI in desktop Bramble, move {} aside and rerun pair.", identity.display()));
                }
                Err(_) => retry(
                    input,
                    out,
                    "Open desktop Bramble and unlock your paired vault.",
                    None,
                )?,
            }
        }
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
                            &format!("⏳ Compare with desktop Bramble: {digits}"),
                            "🔒 Approve in desktop Bramble",
                            "   Type yes if all twelve digits match; anything else cancels.",
                        ],
                    )?;
                    return Ok(answer(input)? == "yes");
                }
                PairEvent::AwaitingDesktop => show(
                    out,
                    &["✅ Digits matched", "⏳ Click Approve in desktop Bramble"],
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
                "In desktop Bramble: unlock vault → Settings → Browser extension → Connect.",
                Some("Compare digits and approve"),
            )?,
        }
    }
}
