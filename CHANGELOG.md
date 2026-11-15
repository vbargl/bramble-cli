# Changelog

## 0.2.0 (unreleased)

- `get` selects fields: title, username, password, URLs, notes, one-time-password secret
  and custom fields. Without options it still prints only the password.
- `list` prints an aligned `ID  TITLE  VAULT` table and never shows secret values.
  **Breaking:** it no longer prints a JSON array by default; use `--json`.
- `save` creates a login or updates one by ID, keeping omitted fields, with explicit
  `--clear`. It writes only manually unsealed vaults, atomically and with read-back
  verification, and refuses a vault the paired desktop has open.
- Global `--json` gives every data command one JSON document with stable error codes,
  next actions and exit statuses, and never prompts.
- The daemon protocol is version 3; restart or reinstall an older daemon.

## 0.1.0

First release of the Unix CLI and local credential daemon.

- Pair with desktop Bramble using explicit confirmation on both sides.
- Follow the paired desktop's active vault lock state, or unseal local vaults manually.
- Keep multiple vaults unsealed; query them together and seal each independently.
- Guide interactive commands through daemon setup and access recovery.
- Install a systemd user service on Linux, or run the daemon in a terminal.

Desktop integration targets Bramble's internal protocol at the upstream revision
pinned in Cargo.lock. Synthetic protocol and vault tests cover the supported flows;
real desktop approval remains interactive. See README.md for access boundaries,
limitations and upgrade instructions.
