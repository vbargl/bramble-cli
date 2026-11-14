# bramble-cli

A single-user daemon that reads Bramble passwords. Start it independently of any vault,
then use the unlocked desktop app or manually unseal one or more vault files. Queries
search every unsealed vault. `seal` changes access to one vault in this daemon; it does
not lock desktop Bramble or other devices.

## Build

Rust and Cargo are required. On Nix, `nix-shell nix/shell.nix --run 'just build'` supplies
the toolchain. Otherwise run `just build` with Rust, Cargo and [just](https://just.systems/)
installed. The binary is `cli/target/release/bramble-cli`. Cargo fetches the Bramble crypto
core at the exact revision recorded in `cli/Cargo.lock`; the first build needs network
access. `just test` runs protocol, lifecycle and synthetic-vault tests; `just check` checks
formatting and compilation.

## Start the daemon

```sh
bramble-cli service install --desktop   # Linux systemd user service
# Or, in a terminal:
bramble-cli daemon --desktop
```

Neither command accepts, selects, opens or needs a vault file. Omit `--desktop` for a
purely manual daemon. `service start` and `service stop` control the installed service.
`status` inspects the daemon and unsealed vaults without changing anything.

A missing socket alone does not prove that a service is uninstalled: the CLI also checks
the systemd user service. A foreground daemon works without a service. An explicit custom
socket is diagnosed independently. On a terminal, `get`, `list` and `unseal` offer service
installation or manual startup when needed, then resume the requested operation.
Installation requires the explicit `i` choice. `status` and `seal` never enter setup.
Non-TTY input or `--no-input` disables prompts and reports the next action instead.

## Pair desktop access

Run `bramble-cli pair` first, even if desktop Bramble is not yet open. The guide shows
only user actions: ✅ completed, ⏳ do now, 🔒 next. It tells you to unlock your desktop
vault and open Settings → Browser extension → Connect. Finish that dialog, then press
Enter in the CLI to retry; type `q` to cancel. Compare all twelve digits and approve in
both places only if they match. An empty confirmation or closed input cancels.

Pairing uses the desktop's authenticated Noise protocol. It neither copies a vault nor
joins its sync group. The connection appears as **Bramble CLI** in the desktop's browser
connection list; disconnect it there to revoke desktop access. Existing pairing files
are verified, never silently replaced. Non-TTY input and `--no-input` can verify an
existing pairing but cannot approve a new one.

With `--desktop`, the daemon can read the app's currently active, unlocked and paired
vault without another password prompt. Other manually unsealed vaults remain accessible
at the same time. Native desktop Bramble exposes one active vault at a time; this CLI
supports multiple local vault keys independently. Desktop mode checks its adjacent
`meta.json` to identify that active vault and refuses a scoped request if it differs or
changes during the request. Missing or invalid metadata does not cause another vault to
be substituted. The CLI does not modify desktop metadata or vault files.

## Unseal and seal vaults

```sh
bramble-cli unseal                       # Infer or select a vault
bramble-cli unseal Work --manual         # Explicit name, ID or .vlt path
bramble-cli seal Work
bramble-cli status
```

Changes may infer the target when exactly one vault is unsealed. With several unsealed
vaults, specify a name, ID or path, or choose a vault by number on a terminal. A script
must identify an ambiguous target explicitly. Queries never ask for a vault.

When no vault is unsealed, `unseal` discovers desktop vault files and their names. It
uses the sole candidate automatically or offers a numbered choice. External files can
be opened by supplying their `.vlt` path; the daemon remembers them only for this run.
To open an additional vault when one is already unsealed, name that additional vault.
`seal` with no unsealed vault is a no-op; an explicit target can still disable future
desktop access to that vault.

`unseal` first tries the selected vault through the paired desktop. If unavailable, it
asks for that local vault's master password. `unseal --manual` uses the local file,
including when a full list is needed. The CLI checks the daemon and selected file before
asking for a password. `get` never starts a password prompt.

Each manual vault key stays only in daemon memory, independently of other keys, until
that vault is sealed or the daemon exits. Wrong-password attempts do not replace or
clear another key. The upstream crypto core has one working key slot; each local read
loads only its vault's cached key and clears that slot on success or error. The daemon
serves these operations serially and rereads the file per request. If a key changes
externally, seal and unseal that vault again.

`seal VAULT` discards only that vault's manual key and disables its desktop route. Other
vaults remain accessible. It never sends a lock command to desktop Bramble. Successful
unseal re-enables the selected route. Manual access continues even when the desktop
locks or exits. A daemon restart discards all manual keys and per-vault desktop blocks;
`--desktop` again follows the unlocked desktop's active vault automatically.

## Query all unsealed vaults

```sh
bramble-cli list
bramble-cli list --hostname example.com
bramble-cli get ENTRY_ID
```

`list` merges metadata across all unsealed vaults into a JSON array with `id`, `name` and
`vault` fields. `get` searches those vaults for an exact entry ID and prints only its
password to stdout. Neither command requires a vault argument or selection. Guidance
and prompts go to stderr so passwords and JSON remain usable in pipes.

A desktop-backed source supports exact hostname lookup of logins, not full enumeration.
If one is in use, `list` needs `--hostname HOST`, or that vault must be manually unsealed
for a full list. Local hostname queries use login `urls` and exact hostname matching,
excluding archived entries and mobile-app URI schemes. A manual key for the same vault
takes precedence over its desktop route, avoiding duplicate results.

If independent vaults contain the same entry ID (for example, after copying a vault),
`list` qualifies those IDs as `/absolute/vault.vlt::ENTRY_ID`. Pass the complete returned
ID to `get`. A bare ambiguous ID is rejected instead of selecting a vault silently.
Protect terminal output and any pipes or files receiving passwords.

## Services and paths

Service installation copies the executable to `$XDG_DATA_HOME/bramble-cli/bin/bramble-cli`
(fallback `~/.local/share/bramble-cli/bin/bramble-cli`) and writes
`$XDG_CONFIG_HOME/systemd/user/bramble-cli.service` (fallback
`~/.config/systemd/user/bramble-cli.service`). The service stores connection options only,
never a vault selection. Reinstallation updates an owned service and restarts it,
discarding all manual keys. Foreign service units are preserved. Installation requires
Linux and a working systemd user manager; foreground operation works on Unix.

The CLI socket defaults to `$XDG_RUNTIME_DIR/bramble-cli/socket`. Global `--socket PATH`
or `BRAMBLE_SOCKET` selects another endpoint; all clients must use the same one. Its
parent must be private and owned by this user; the socket is mode 0600. Startup recovers
an owned stale socket under an exclusive lock, preserving live daemons and unrelated
files. Windows is not supported.

Desktop pairing defaults to `$XDG_DATA_HOME/bramble-cli/desktop.json` (fallback
`~/.local/share/bramble-cli/desktop.json`). This mode-0600 file in a private directory
contains this client's **private pairing key** and the pinned desktop public key. It is
not in the OS credential store. Protect it like a credential; unsafe permissions,
ownership and symlinks are rejected. Pairing never overwrites it.

The desktop socket defaults to `$XDG_DATA_HOME/app.bramble.desktop/bramble.sock`
(fallback `~/.local/share/app.bramble.desktop/bramble.sock`) on Linux, or
`~/Library/Application Support/app.bramble.desktop/bramble.sock` on macOS. `pair`,
`daemon` and `service install` accept `--desktop-socket PATH` and `--pairing-file PATH`;
use matching options. Vault discovery uses that desktop directory when enabled,
otherwise the standard desktop data directory.

To deliberately re-pair, disconnect **Bramble CLI** in desktop Bramble, move only this
CLI's pairing file aside, then run `pair`. Do not remove desktop Bramble's own pairing
files or OS credential-store identity.

An older daemon must be restarted with this build (or updated using `service install`
with your connection options). The multi-vault protocol versions responses and uses
new mutation opcodes, so a new client cannot trigger an old daemon's global `seal`.

## Security and limitations

The local user account is the access boundary. Any process running as this user can ask
the daemon for passwords while access is enabled; root or a process inspecting daemon
memory can also access secrets. There is no network listener or extra authentication on
the CLI socket. No TCP port or firewall change is needed. Revoking desktop pairing does
not revoke separately cached manual keys; seal those vaults as needed.

Manual mode supports VLT1 version 2 vaults with a master-password slot and entries with
a string `password`. Passwords and keys pass through process memory; best-effort wiping
cannot guarantee removal of every copy, swap, crash dump or terminal output. Pairing
keys persist in the private file; manual vault encryption keys never do.

Desktop access uses Bramble's login/autofill index and internal protocol v1 at the pinned
upstream revision. It is not a stable public API. Tests use synthetic vaults and an
independent protocol peer with upstream crypto; real desktop pairing still needs human
confirmation. Attachments, edits, vault sync, recovery/WebAuthn-slot unlock, automatic
manual unlock, timeout and threshold sharing are not implemented. The desktop decides
its own lock timeout.

## License and upstream

GPL-3.0-only; see [LICENSE](LICENSE). The linked [Bramble crypto core](https://github.com/bramble-sh/bramble/tree/7acadf3ef39202b75879b492a771847261341940/packages/core-rust)
is GPL-3.0-only, pinned to `7acadf3ef39202b75879b492a771847261341940`. Source for this program
and the linked core must accompany distribution as required by the GPL.

See [the CLI interaction contract](docs/cli-ux.md) for command and recovery behavior.
