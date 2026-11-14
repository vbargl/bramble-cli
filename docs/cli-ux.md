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
- `unseal` checks daemon availability before asking for a password. Use desktop access
  when possible; keep explicit manual fallback.
- `get` and `list` explain a blocked prerequisite before attempting later steps. Do not
  prompt for passwords as a surprise side effect. Keep passwords and JSON on stdout;
  guidance goes to stderr.
- `seal` describes its effect on CLI access, without implying that it locked desktop
  Bramble or another device.
- Prompt only on a terminal; closed input cancels. An empty response never approves
  a pairing or a state-changing setup action.
- Use ✅ for completed user actions/results, ⏳ for an action needed now and 🔒 for a
  relevant upcoming user action. Do not print internal connection events or a growing
  duplicate checklist. Keep diagnostics separate from normal guidance.

## Daemon setup

Both setup routes are available. `service install [VAULT] --desktop` explicitly installs,
enables and starts a systemd user service on Linux. `daemon [VAULT] --desktop` runs in the
foreground. A single desktop vault is discovered automatically; otherwise the caller supplies
or selects a path. `service start` and `service stop` control the installed service.

`get`, `list` and `unseal` may offer those routes on a TTY when their daemon is missing.
Installation requires the explicit `i` choice; empty input never selects it. After setup,
retry the original requested operation. Blocked credential access asks for the next action
in another terminal, then retries on Enter. `get` never initiates a password prompt.

`status` and `seal`, non-TTY calls, and `--no-input` never enter setup. They report the state
and the exact next command, retaining the invoking binary and selected socket. Existing
foreign service units are preserved. Reinstalling an owned service updates its copied binary
and restarts it, discarding any manual key. Foreground restarts safely recover an owned stale
socket; a live daemon or an unrelated file occupying that path is preserved.
