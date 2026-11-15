# bramble-cli

Source and releases: [vbargl/bramble-cli](https://github.com/vbargl/bramble-cli).

A single-user daemon that reads Bramble entries and, for manually unsealed vaults, saves them. Start it independently of any vault,
then use the unlocked desktop app or manually unseal one or more vault files. Queries
search every unsealed vault. `seal` changes access to one vault in this daemon; it does
not lock desktop Bramble or other devices.

## Build

Rust and Cargo are required. On Nix, `nix-shell nix/shell.nix --run 'just build'` supplies
the toolchain. Otherwise run `just build` with Rust, Cargo and [just](https://just.systems/)
installed. The binary is `cli/target/release/bramble-cli`. Cargo fetches the Bramble crypto
core at the exact revision recorded in `cli/Cargo.lock`; the first build needs network
access. `just test` runs protocol, lifecycle, entry-editing and synthetic-vault tests; `just check` checks
formatting and compilation.

## NixOS installations

When a NixOS or Home Manager configuration manages the daemon, its unit should point
straight to the packaged executable (`bramble-cli daemon --desktop`). Do not also run
`service install`: that command copies the binary for systems without declarative
service management. Nix-managed upgrades must update the unit and restart its daemon;
restarting discards manually unsealed keys. Desktop pairing stays in the user's data
directory and is not part of the Nix store.

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

Diagnostics use an error-first layout: `!` and restrained red emphasis, a blank line,
then indented recovery actions. Alternatives are separated by `-- or --`; commands get
their own indented lines. Ordinary instructions do not carry hourglass icons. Color is
disabled for redirected stderr, nonempty `NO_COLOR`, and `TERM=dumb`; the text hierarchy
is the same without ANSI color.

## Pair desktop access

Run `bramble-cli pair` first, even if desktop Bramble is not yet open. The guide shows
user actions, with a clear error heading and indented recovery steps when blocked.
It tells you to unlock your desktop
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
bramble-cli get ENTRY_ID                      # the password, as before
bramble-cli get ENTRY_ID -f username          # one field: just its value
bramble-cli get ENTRY_ID -f title -f url      # several: NAME<TAB>VALUE per line
bramble-cli get ENTRY_ID -f 'API key'         # a custom field, by exact name
bramble-cli get ENTRY_ID --custom-field notes # a custom field named like a built-in one
```

`list` prints an aligned `ID  TITLE  VAULT` table across all unsealed vaults, sorted by
vault and title. It never shows secret values. Titles and vault names are shortened to
fit a terminal; redirected output is never shortened, and IDs never are. Use `--json`
for machine-readable output. Neither `list` nor `get` requires a vault argument.

`get` selects fields with repeatable `-f/--field`: `title`, `username`, `password`,
`url` (the first), `urls` (all, one per line), `notes` and `totp`. Any other name is a
custom field, matched exactly. A built-in name always means the built-in field, so reach
a custom field that shares one with `--custom-field NAME` (or `-f field:NAME`).
`--custom-field` only ever reads custom fields and its values print after the `-f`
ones. With no `-f` it prints only the password, exactly as before. One field
prints its bare value; several print `name<TAB>value` lines in the order requested, with
newlines in values written as `\n` (use `--json` for exact values). A field the entry
does not have is an error (`field_not_found`, exit 3) and prints nothing; an empty value
is a value, and a misspelled name is reported as a missing custom field. If a custom field name is duplicated in an
entry, the first is returned. Guidance and prompts go to stderr, so values stay usable
in pipes.

A desktop-backed source returns only `username`, `password` and `totp` from `get`, and
supports exact hostname lookup of logins, not full enumeration. Other fields
(`field_unsupported`) and an unfiltered `list` (`list_unsupported`) need the vault to
be unsealed manually, or `--hostname HOST` for `list`. Local hostname queries use login
`urls` and exact hostname matching, excluding archived entries and mobile-app URI
schemes. A manual key for the same vault takes precedence over its desktop route,
avoiding duplicate results.

If independent vaults contain the same entry ID (for example, after copying a vault),
`list` qualifies those IDs as `/absolute/vault.vlt::ENTRY_ID`. Pass the complete returned
ID to `get` or `save`. A bare ambiguous ID is rejected (`ambiguous_entry`) instead of
selecting a vault silently. Protect terminal output and any pipes or files receiving
passwords.

## Create and update entries

```sh
bramble-cli save --title GitHub --username octocat --password-stdin \
    --url https://github.com --notes 'work account' < password.txt   # create; prints the new ID
bramble-cli save ENTRY_ID --password-stdin < new-password.txt        # change one field
bramble-cli save ENTRY_ID --field Region=eu --secret-field Token=t0k # custom fields
bramble-cli save ENTRY_ID --clear notes --clear 'field:Region'       # remove values
bramble-cli save --title Mail --vault Work                           # pick the vault
```

Without an ID, `save` creates a login (a title is required); with an ID it updates that
entry and **keeps every field you do not mention**, including data the CLI does not
edit (tags, passkeys, one-time-password secrets, attachments). It prints the entry's ID.
Re-saving identical values changes nothing and does not rewrite the vault.

| Option | Effect |
| --- | --- |
| `--title`, `--username`, `--notes` | Set the value. |
| `--password VALUE` / `--password-stdin` | Set the password. The first is visible in the process list; prefer the second. |
| `--url URL` (repeatable) | Replace the entry's whole URL list. |
| `--field NAME=VALUE`, `--secret-field NAME=VALUE` | Create or update a custom field by its exact name. `--secret-field` also hides it. An existing field keeps its hidden flag unless `--secret-field` is used. Duplicate names are refused, not guessed. |
| `--clear FIELD` | Remove `username`, `password`, `url`, `notes` or `field:NAME`. Username and password become empty; the title cannot be cleared. Setting and clearing one field together is an error. Clearing an absent custom field does nothing. |
| `--input FILE` / `--input -` | Read fields from a JSON document (see below); options override it. |
| `--vault V` | Vault name, ID or path. |

The input document uses the same names: `{"id": "...", "vault": "...", "title": "...",
"username": "...", "password": "...", "urls": ["..."], "notes": "...", "fields":
{"Region": "eu", "Token": {"value": "t0k", "hidden": true}}, "clear": ["notes"]}`.
Unknown keys are rejected. Only login entries have a username, password and URLs.

**Which vault.** A new entry goes to the only unsealed vault. With several, pass
`--vault` or, on a terminal, choose by number; a script gets `ambiguous_vault` with the
candidates. An update goes to the one vault holding that ID; if several do, use the
scoped ID from `list` (`ambiguous_entry`).

**Where saving works.** Writing is supported only for vaults unsealed **manually**
(`unseal VAULT --manual`), because the CLI edits the local `.vlt` file itself. Desktop
access is read-only: the desktop bridge exposes query and fetch, not writes
(`write_unsupported`). The desktop also keeps its own copy of the open vault and its sync
state, so the CLI **refuses to write a vault that the paired desktop currently has open
and unlocked** (`desktop_active`); lock desktop Bramble or switch it to another vault,
then retry. When the desktop is not configured for this daemon (no `--desktop`) or not
paired, the CLI cannot tell whether it has the vault open; do not save while it does.

**How it is written.** Only the encrypted entries payload is rewritten. Key slots (even
kinds this CLI cannot read), other entries and unknown payload members (deletion
records, settings, file manifests) are preserved. The new file is written next to the
old one, decrypted again and compared with what was intended, and only then renamed over
the vault; if the file changed since it was read, nothing is written
(`changed_externally`). Any failure leaves the original untouched. An entry with
unresolved sync conflicts is not edited (`conflict_pending`).

**Sync.** Saved entries are stamped as written by `bramble-cli` at the current time, so
they win over the version they replace, and carry no per-field history, so a desktop
treats the whole entry as changed. This follows Bramble's internal format at the pinned
revision but has only been tested against synthetic vaults and format rules; **try
`save` on a copy of a vault that syncs before relying on it**, and keep backups. The CLI
does not record superseded passwords in the entry's password history.

## JSON mode for tools

Add the global `--json` option to `get`, `list`, `save`, `status`, `seal` and `unseal`.
It never prompts, ignores whether stdin or stdout is a terminal, writes **exactly one
JSON document to stdout** (no colors, no guidance) and nothing to stderr.

```json
{"ok": true,  "command": "get",  "data": {"id": "e1", "vault": "Personal", "fields": {"username": "ada"}}}
{"ok": true,  "command": "list", "data": {"entries": [{"id": "e1", "name": "Example", "vault": "Personal"}]}}
{"ok": true,  "command": "save", "data": {"id": "e1", "vault": "Personal", "created": false, "changed": true}}
{"ok": false, "command": "get",  "error": {"code": "sealed", "message": "Daemon is sealed.",
  "next": [{"message": "Unseal the vault:", "command": "bramble-cli unseal"}]}}
```

`get` in JSON mode returns the requested fields (the password by default) under
`fields`; `urls` is an array. `status` returns `message` and `vaults` (`name`, `path`,
`access`: `manual`, `desktop` or `sealed`); `seal` and `unseal` return `message`. An
error has a stable `code`, a `message`, optional `next` actions (a `message` and, when
there is one, the `command` to run), `choices` (candidate vaults) and `details` (for
`ambiguous_entry`, the scoped `ids`). Branch on `ok`, `error.code` or the exit status,
not on message text. New keys may be added; documented keys and codes are not changed
or reused within a release series.

Exit statuses are the same in plain and JSON mode: `0` success; `1` other failure
(`error`, `write_failed`, `changed_externally`, `conflict_pending`, `daemon_connection`,
`daemon_outdated`); `2` invalid usage or input (`invalid_usage`, `invalid_input`);
`3` not found (`entry_not_found`, `field_not_found`, `vault_not_found`); `4` access
unavailable (`sealed`, `desktop_locked`, `desktop_unavailable`, `not_paired`,
`wrong_vault`, `vault_unidentified`, `daemon_unavailable`, `desktop_active`); `5`
ambiguous (`ambiguous_entry`, `ambiguous_vault`); `6` unsupported (`unsupported`,
`list_unsupported`, `field_unsupported`, `write_unsupported`); `7` a person is needed
(`interactive_required`, for example a manual unseal password). `--help` and `--version`
stay plain text.

`daemon`, `service` and `pair` are interactive or run in the foreground and answer
`--json` with `unsupported`. The daemon's wire protocol is version 3; restart or
reinstall an older daemon.

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
confirmation. Attachments, editing entry types other than logins' basic fields, vault sync, recovery/WebAuthn-slot unlock, automatic
manual unlock, timeout and threshold sharing are not implemented. The desktop decides
its own lock timeout.

## License and upstream

GPL-3.0-only; see [LICENSE](LICENSE). The linked [Bramble crypto core](https://github.com/bramble-sh/bramble/tree/7acadf3ef39202b75879b492a771847261341940/packages/core-rust)
is GPL-3.0-only, pinned to `7acadf3ef39202b75879b492a771847261341940`. Source for this program
and the linked core must accompany distribution as required by the GPL.

See [the CLI interaction contract](docs/cli-ux.md) for command and recovery behavior.
