# bramble-cli

Read passwords from a local Bramble desktop vault using a manually unsealed, single-user daemon. The daemon starts sealed; `unseal` asks for the master password on a terminal and keeps the vault encryption key in its process memory. `seal` discards that key. Sealing affects only this daemon, not Bramble on other devices.

## Build

Rust and Cargo are required. On Nix, `nix-shell --run 'cargo build --release --locked'` supplies the toolchain. Otherwise run `cargo build --release --locked`. The binary is `target/release/bramble-cli`. Cargo fetches the Bramble crypto core from the exact revision recorded in `Cargo.lock`; an initial build needs network access. `cargo test --locked` runs the synthetic-vault integration test.

## Use

Start the daemon in a terminal, pointing to the existing desktop vault file (`vaults/<vault-id>.vlt` under Bramble's app data directory):

```sh
bramble-cli daemon /path/to/vaults/default.vlt
```

In another terminal:

```sh
bramble-cli status
bramble-cli unseal
bramble-cli get ENTRY_ID
bramble-cli seal
```

`get` prints the password to standard output. Protect terminal output and any pipes or files receiving it. The entry selector is Bramble's exact entry ID; this initial version does not list or search entries. The daemon rereads the vault file for each request. It does not modify it. If the vault key changes externally, restart and unseal again.

By default the socket is `$XDG_RUNTIME_DIR/bramble-cli/socket`; `--socket PATH` or `BRAMBLE_SOCKET` selects another path. All commands must use the same path. The socket's parent must be a directory owned by the current user with no group or other access. The socket is mode 0600. If a daemon terminates, its socket file may remain; after ensuring no daemon is running, remove that file before restarting.

## Security and limitations

The local user account is the access boundary: any process running as that user can connect and retrieve passwords while unsealed. Root and processes able to inspect the daemon's memory can also access secrets. There is no network listener or additional client authentication. Protect the account and its runtime directory. The daemon holds the vault key in the upstream crypto core; it does not deliberately persist keys or decrypted entry caches. Passwords and entries pass through process memory, and memory wiping cannot guarantee removal of all copies, swap, crash dumps, or terminal output. Configure your operating system accordingly.

Only VLT1 version 2 vaults with a master-password slot are supported. Entries must contain a string `password`. WebAuthn and recovery slots, attachment access, edits, pairing and sync are not supported. This CLI reads a local vault file; it does not enroll or synchronize a new device. A daemon restart always starts sealed. There is no automatic unlock, timeout, or threshold sharing.

## License and upstream

GPL-3.0-only; see [LICENSE](LICENSE). The linked [Bramble crypto core](https://github.com/bramble-sh/bramble/tree/7acadf3ef39202b75879b492a771847261341940/packages/core-rust) is GPL-3.0-only and is pinned to revision `7acadf3ef39202b75879b492a771847261341940`. Source for this program and the linked core must accompany distribution as required by the GPL.
