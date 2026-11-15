# Changelog

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
