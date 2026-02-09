# A basic remote command runner

This project is a small exploration of a secure system for running a limited set of remote commands over an e2e encrypted channel. The goal is a simple client–agent workflow I can use to control various embedded Linux devices with strong security boundaries and low overhead. The current design uses a central bastion relay for discovery and message forwarding, while clients and agents will eventually perform an e2e Noise handshake to protect command and output data. Agents will enforce a signed policy bundle to ensure only approved commands can run. The client interface will use a terminal UI to manage sessions, keys, and command templates.

This is a work in progress, obviously. More components will be added as the design stabilizes.

## Development hooks

This repo includes a pre-commit hook at `.githooks/pre-commit` that runs `cargo fmt --all`.

Enable it once per clone:

```bash
git config core.hooksPath .githooks
```
