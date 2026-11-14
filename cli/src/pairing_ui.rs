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
    detail: &str,
    existing: bool,
) -> Result<()> {
    show(
        out,
        &[
            &format!("⏳ {action}"),
            &format!("   Desktop reported: {detail}"),
            if existing {
                "🔒 Verify the existing pairing"
            } else {
                "🔒 Compare the pairing digits"
            },
            if existing {
                "🔒 Finish without changing your credentials"
            } else {
                "🔒 Approve in desktop Bramble and save the pairing"
            },
            "⏳ Press Enter when ready to retry, or type q to cancel.",
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
    show(out, &["✅ CLI ready"])?;
    if existing {
        let key = desktop::Identity::load(identity)?;
        show(
            out,
            &[
                "✅ Existing pairing credentials found",
                "⏳ Checking the desktop connection",
                "🔒 Verify the pairing",
            ],
        )?;
        loop {
            let result = desktop::Session::connect(socket, &key).and_then(|mut session| {
                session.request_raw(json!({"op":"query", "hostname":"bramble-cli-status.invalid"}))
            });
            match result {
                Ok(reply) if reply["ok"] == true => {
                    return show(out, &["✅ Desktop connected and unlocked", "✅ Existing pairing verified; ready to use"]);
                }
                Ok(reply) if reply["error"] == "locked" => {
                    show(out, &["✅ Desktop connected; existing pairing authenticated"])?;
                    retry(input, out, "Unlock the paired vault in desktop Bramble.", "vault is locked", true)?;
                }
                Ok(reply) => {
                    return Err(format!("desktop refused the existing pairing: {}. Open the vault originally paired with this CLI. To deliberately re-pair, disconnect Bramble CLI in desktop Bramble and move {} aside before running pair again. Credentials were not changed.", reply["error"].as_str().unwrap_or("unknown refusal"), identity.display()));
                }
                Err(e) => retry(input, out, "Open desktop Bramble and unlock the paired vault. If it is already open, check its pairing state and logs.", &e, true)?,
            }
        }
    }
    loop {
        show(
            out,
            &[
                "⏳ Checking whether desktop Bramble is ready to pair",
                "🔒 Compare the pairing digits",
                "🔒 Approve in desktop Bramble",
                "🔒 Save the pairing",
            ],
        )?;
        let mut reached = false;
        let mut comparing = false;
        let result =
            desktop::pair(socket, identity, |event| {
                match event {
                    PairEvent::Connected => {
                        reached = true;
                        show(out, &["✅ Local desktop connection opened"])?;
                    }
                    PairEvent::Compare(digits) => {
                        comparing = true;
                        show(out, &[
                        "✅ Desktop accepted the pairing request",
                        &format!("⏳ Compare these digits with desktop Bramble: {digits}"),
                        "🔒 Approve in desktop Bramble",
                        "🔒 Save the pairing",
                        "⏳ Type yes only if all twelve digits match; anything else cancels.",
                    ])?;
                        return Ok(answer(input)? == "yes");
                    }
                    PairEvent::AwaitingDesktop => show(
                        out,
                        &[
                            "✅ Pairing digits confirmed in the CLI",
                            "⏳ Click Approve in desktop Bramble",
                            "🔒 Save the pairing",
                        ],
                    )?,
                }
                Ok(true)
            });
        match result {
            Ok(()) => {
                return show(
                    out,
                    &[
                        "✅ Desktop approved the connection",
                        "✅ Pairing saved; ready to use",
                    ],
                )
            }
            // Do not restart pairing after a mismatch, cancellation, approval or save failure.
            // Such failures need an explicit new invocation; in particular no key is repinned.
            Err(e) if comparing => return Err(e),
            Err(e) => {
                let action = if reached {
                    "In desktop Bramble, unlock the intended vault and open Settings → Browser extension → Connect. Enter its master password and leave that dialog open. If it is already open, reopen it; continued refusal may require checking the desktop logs."
                } else {
                    "Open desktop Bramble, unlock the intended vault, then choose Settings → Browser extension → Connect. Enter its master password and leave that dialog open."
                };
                retry(input, out, action, &e, false)?;
            }
        }
    }
}
