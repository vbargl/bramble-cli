# Command-line interaction contract

Commands guide the user to their requested outcome. Show the current obstacle and one
concrete next action, then continue the original operation where possible. Use ordinary
language, keep successful data output usable in pipes, and omit routine internal checks.

Based on [Command Line Interface Guidelines](https://clig.dev/#errors) (errors,
interactivity, discoverability) and [NN/g Error-Message Guidelines](https://www.nngroup.com/articles/error-message-guidelines/)
(clear diagnosis, constructive recovery, respect for user effort).

## States and recovery

A missing socket is not evidence that a service is uninstalled. Check the daemon
connection first, then the user service when the connection is unavailable. A running
foreground daemon works without an installed service. An explicit custom socket refers
to that endpoint, not necessarily to the default service.

| State | User-facing meaning | Next action |
| --- | --- | --- |
| Service missing, no daemon connection | Daemon service is not installed | Set up the daemon |
| Service installed but inactive | Daemon is stopped | Start the service |
| Service failed | Daemon failed to start | Inspect its service error |
| Service active, connection unavailable | Daemon is not responding | Inspect its service error/socket configuration |
| Custom socket unavailable | No daemon is listening at the selected socket | Start a daemon with that socket |
| Access denied | This account cannot access the selected daemon | Correct the socket ownership/permissions |
| CLI sealed | Credential access is disabled | Run unseal |
| Desktop locked | Desktop vault is locked | Unlock it, or explicitly unseal manually |
| Desktop unavailable | Paired desktop is unavailable | Open it, or explicitly unseal manually |
| Pairing missing | CLI is not paired | Run pair |
| Pairing revoked/wrong vault | Pairing does not authorize the open vault | Open the paired vault; deliberately re-pair if needed |
| Manual access active | Local vault is unsealed | Execute the requested credential operation |
| Desktop access active | Desktop can serve this request | Execute the requested credential operation |

Never label a state as known when it could not be checked. Preserve the user's binary,
socket and connection options in suggested follow-up commands.

## Command behavior

- `status` inspects and explains the current state. It does not prompt or change it.
- `pair` guides only the actions needed to pair or validate an existing pairing. It does
  not require a CLI daemon. Never silently replace pairing credentials.
- `unseal [VAULT]` checks daemon availability and the selected file before asking for a
  password. Use desktop access when possible; keep explicit manual fallback.
- `get` and `list` query all unsealed vaults without selecting one. Explain a blocked
  prerequisite before attempting later steps. Do not prompt for passwords as a surprise
  side effect. Keep passwords and JSON on stdout; guidance goes to stderr. Reject a
  bare duplicate entry ID; list supplies source-qualified IDs for that case.
- `get ID [-f FIELD]...` prints the password by default, one field's bare value, or
  `name<TAB>value` lines in request order. A missing field is an error with no partial
  output; an empty value is a value. `list` prints an aligned `ID  TITLE  VAULT` table
  without secrets: IDs are never shortened, titles and vault names are shortened only for
  a terminal. Neither styles stdout.
- `save [ID]` creates (title required) or updates, keeping every field not named.
  Clearing is only explicit (`--clear`). It prints the entry ID on stdout and a short
  result on stderr. It never replays a request, because the request carries secrets.
  It writes only manually unsealed vaults and explains when desktop access cannot write
  or the desktop has the vault open. A new entry follows the multi-vault rule below:
  infer the sole unsealed vault, else ask by number on a terminal, else fail with the
  candidates and `--vault`.
- `seal [VAULT]` affects only the selected vault's CLI access, including its desktop
  route. It does not lock another vault, desktop Bramble or another device.
- Prompt only on a terminal; closed input cancels. An empty response never approves
  a pairing or a state-changing setup action.
- Give errors one visual anchor: `!` and red emphasis on a capable stderr terminal.
  Then leave a blank line and indent the related recovery actions. Put copyable commands
  on a further-indented line. Separate alternatives with a standalone `-- or --` and
  surrounding blank lines. Keep the same reading order across commands.
- Do not label every instruction with an hourglass. Use waiting indicators only for
  actual waits; ordinary user actions remain plain text. Keep success/results distinct
  from errors, and do not print routine connection events or duplicate checklists.
- Honor `NO_COLOR`, `TERM=dumb` and stderr's own TTY state. Hierarchy must still work
  without color, and application data on stdout is never styled.

## JSON mode

`--json` is a global option rather than a separate command, so one command line differs
from its human form only by that flag. It implies `--no-input`, prints exactly one JSON
document on stdout for success and failure, and prints nothing on stderr. Failures carry
a stable `error.code`, `message`, optional `next` actions (`message` plus `command`),
`choices` and `details`, and the exit status is the same as in plain mode: 1 other, 2
usage/input, 3 not found, 4 access unavailable, 5 ambiguous, 6 unsupported, 7 a person
is needed. Recovery text and its numbering exist only in plain mode; JSON consumers get
the same actions as structured `next` entries. `daemon`, `service` and `pair` answer
`unsupported`. Usage errors are JSON in JSON mode; `--help` and `--version` stay text.

## Daemon setup

Both setup routes are available. `service install --desktop` explicitly installs,
enables and starts a systemd user service on Linux. `daemon --desktop` runs in the
foreground. Neither accepts or selects a vault. `service start` and `service stop`
control the installed service.

`get`, `list` and `unseal` may offer those routes on a TTY when their daemon is missing.
Installation requires the explicit `i` choice; empty input never selects it. After setup,
retry the original requested operation. Blocked credential access asks for the next action
in another terminal, then retries on Enter. `get` never initiates a password prompt.

`status` and `seal`, non-TTY calls, and `--no-input` never enter setup. They report the state
and the exact next command, retaining the invoking binary and selected socket. Existing
foreign service units are preserved. Reinstalling an owned service updates its copied binary
and restarts it, discarding any manual key. Foreground restarts safely recover an owned stale
socket; a live daemon or an unrelated file occupying that path is preserved.

## Multiple vaults

The daemon can hold several independent local vault keys. Queries read all currently
unsealed sources and do not request a vault argument, even when several are open.
Changes can infer a target when exactly one vault is unsealed. Otherwise the caller
selects a name, ID or path; a terminal offers numbered, named choices rather than making
the user type a UUID/path. Noninteractive ambiguous changes fail with the available
choices. With no unsealed vault, unseal discovers local candidates and auto-selects a
sole candidate. Seal with no target and no open vault is a no-op.

Failed unseal leaves other keys intact. Seal removes only the target key and blocks only
that target's desktop route. Per-request local key loading always clears the crypto
core's working slot afterward. The desktop exposes one active vault; its adjacent local
metadata identifies that source, and a mismatch or an in-flight switch rejects a scoped
request rather than returning another vault's credential. Closed/unavailable desktop
access does not invalidate manually unsealed vaults.

Restart discards every cached key and per-vault desktop block. Old client/daemon protocol
combinations fail before an old global mutation can be used. Existing service units are
updated only by explicit reinstallation, which removes the former vault argument.
