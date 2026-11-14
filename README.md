# bramble-cli

Read Bramble passwords through a single-user local daemon. Use the unlocked desktop app as a paired credential source, or manually unseal the local vault when the desktop is unavailable. CLI `seal` disables both sources in this daemon; it does not lock the desktop app or other devices.

## Build

Rust and Cargo are required. On Nix, `nix-shell nix/shell.nix --run 'just build'` supplies the toolchain. Otherwise run `just build` with Rust, Cargo and [just](https://just.systems/) installed. The binary is `cli/target/release/bramble-cli`. Cargo fetches the Bramble crypto core from the exact revision recorded in `cli/Cargo.lock`; an initial build needs network access. `just test` runs protocol, access-state and synthetic-vault tests; `just check` checks formatting and compilation.

## Pair with desktop

Open Bramble on this computer, unlock the intended vault, and choose Settings → Browser extension → Connect. Enter the master password there, then run:

```sh
bramble-cli pair
```

Compare all twelve digits displayed by the CLI with the desktop's digits. Confirm in both places only if they match. Pairing authenticates the desktop and this CLI with Bramble's Noise protocol. It does not copy a vault or join its sync group. The CLI appears as **Bramble CLI** in the desktop's browser connection list; disconnect it there to revoke desktop access.

Start the daemon with the paired desktop enabled and the **same vault's** file as the manual fallback:

```sh
bramble-cli daemon /path/to/vaults/VAULT_ID.vlt --desktop
```

In another terminal:

```sh
bramble-cli status
bramble-cli list --hostname example.com
bramble-cli get ENTRY_ID
bramble-cli seal
bramble-cli unseal
```

While the desktop is unlocked, credential requests need no additional password. Each request opens an authenticated connection and checks the desktop's current lock and pairing state. Locking or closing the desktop stops subsequent requests; unlocking or reopening restores access, unless you explicitly sealed the daemon. Desktop mode does not retain the vault encryption key or cache credentials. No TCP port or firewall opening is needed.

The desktop protocol supports exact hostname lookup of login entries, not full vault enumeration. Use `list --hostname HOST` in desktop mode. The CLI returns IDs and names as a JSON array. `get` selects by exact ID and prints the password to standard output. Protect terminal output and any receiving pipes or files.

## Manual unseal and seal

Without `--desktop`, the daemon starts sealed and behaves as a local-vault reader:

```sh
bramble-cli daemon /path/to/vaults/VAULT_ID.vlt
```

`unseal` first tries to resume paired desktop access when configured. If that fails (desktop closed, locked, unpaired or unreachable), it prompts for the master password on the terminal and unwraps the local vault key. `unseal --manual` goes straight to that prompt, including when you need a full `list`:

```sh
bramble-cli unseal --manual
bramble-cli list
bramble-cli get ENTRY_ID
bramble-cli seal
```

Manual access is independent: it continues until CLI `seal` or daemon exit, even if the desktop locks or exits. The daemon holds the manually unwrapped key in process memory and rereads the vault file for each request. It does not modify the vault. If its encryption key changes externally, restart and unseal again. Hostname lookup is available only through desktop access; omit `--hostname` while manually unsealed.

`seal` discards any manual key and disables desktop access in this daemon until `unseal`. It never sends a lock or unlock command to desktop Bramble. A restart discards the manual key. Starting again with `--desktop` enables desktop access automatically if the paired desktop is unlocked; an explicit seal is not persisted across daemon restarts. Starting without that flag always starts sealed.

## Local paths

The daemon socket defaults to `$XDG_RUNTIME_DIR/bramble-cli/socket`; global `--socket PATH` or `BRAMBLE_SOCKET` selects another path. All daemon clients must use the same path. The socket's parent must be a directory owned by the current user with no group or other access. The socket is mode 0600. If a daemon terminates, its socket file may remain; after ensuring no daemon is running, remove that file before restarting.

Desktop pairing defaults to `$XDG_DATA_HOME/bramble-cli/desktop.json` (fallback `~/.local/share/bramble-cli/desktop.json`). It contains this client's **private pairing key** and the pinned desktop public key. It is stored as a mode-0600 file in a private, owned directory; it is not stored in the OS credential store. Protect it like a credential. Existing files are never overwritten by `pair`, and files with unsafe ownership/permissions or symlinks are rejected on load.

The desktop socket defaults to `$XDG_DATA_HOME/app.bramble.desktop/bramble.sock` (fallback `~/.local/share/app.bramble.desktop/bramble.sock`) on Linux, or `~/Library/Application Support/app.bramble.desktop/bramble.sock` on macOS. Both `pair` and `daemon` accept `--desktop-socket PATH` and `--pairing-file PATH`; use matching overrides. Pairing works without a running CLI daemon. Windows is not supported by this Unix CLI.

To re-pair, disconnect **Bramble CLI** in desktop Bramble, remove only this CLI's `desktop.json`, then run `pair` again. Do not remove desktop Bramble's own pairing files or credential-store identity.

## Security and limitations

The local user account is the access boundary: any process running as that user can ask this daemon for passwords while access is enabled. Root and processes able to inspect its memory can also access secrets. There is no network listener or extra authentication on the CLI daemon socket. Its persistent pairing key grants access while the paired desktop vault is unlocked; deleting the desktop connection revokes that route, but does not revoke a separately manually unsealed local vault key. Protect the account, pairing file and runtime directory.

Passwords and entries pass through process memory. Best-effort memory wiping cannot guarantee removal of all copies, swap, crash dumps or terminal output. Manual mode supports only VLT1 version 2 vaults with a master-password slot and entries with a string `password`. Desktop access uses Bramble's login/autofill index and requires desktop protocol v1 with emoji/digit pairing and `linkComplete`, as implemented at the pinned upstream revision. This is an upstream internal protocol, not a stable public API. Unit tests use an independent protocol peer with upstream crypto; live desktop pairing still requires confirmation in the actual app.

WebAuthn and recovery-slot unlock, attachments, edits, vault sync, automatic manual unlock, timeout and threshold sharing are not implemented. The desktop decides its own lock timeout. Desktop pairing belongs to the vault selected when pairing; switching to an unpaired vault denies access. Keep the fallback vault path aligned with that pairing.

## License and upstream

GPL-3.0-only; see [LICENSE](LICENSE). The linked [Bramble crypto core](https://github.com/bramble-sh/bramble/tree/7acadf3ef39202b75879b492a771847261341940/packages/core-rust) is GPL-3.0-only and is pinned to revision `7acadf3ef39202b75879b492a771847261341940`. Source for this program and the linked core must accompany distribution as required by the GPL.
