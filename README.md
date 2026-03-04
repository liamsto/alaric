# A basic remote command runner

This project is a small exploration of a secure system for running a limited set of remote
commands over an end-to-end encrypted channel. It uses a relay server for pairing and byte
forwarding, while the client and agent perform a Noise XX handshake and exchange encrypted command
messages directly.

## Current MVP capabilities

- Relay handshake and tunnel pairing (`server`)
- Client/agent Noise transport setup over the relay tunnel
- Restricted command execution with an agent-local policy file
- Strict argument validation (regex and enum rules)
- Streaming `stdout`/`stderr` output events
- Final completion event with exit code, timeout flag, and truncation flag

## Restricted command policy

The agent loads policy JSON from `AGENT_POLICY_PATH` (default: `./agent-policy.json`) and fails
fast on invalid policy.

Schema:

- `Policy { version, default_timeout_secs, max_output_bytes, commands }`
- `CommandSpec { id, program, fixed_args, arg_specs, timeout_secs?, max_output_bytes? }`
- `ArgSpec { name, required, validation? }`
- `ValidationRule::Regex { pattern } | ValidationRule::Enum { values }`

Example policy is included at `agent-policy.json`.

## Running locally

1. Start the relay server:

```bash
cargo run -p alaric-server
```

2. Start the agent in a second terminal:

```bash
AGENT_ID=agent-default AGENT_POLICY_PATH=./agent-policy.json cargo run -p alaric-agent
```

3. Run a client command in a third terminal:

```bash
TARGET_AGENT_ID=agent-default cargo run -p alaric-client -- \
  --command-id echo_text \
  --arg text=hello
```

Client usage:

```text
alaric-client --command-id <id> [--arg name=value]...
```

Notes:

- One command is processed per session in this MVP.
- The server does not inspect command messages; policy enforcement is agent-local.
- Signed policy bundles and handshake-level authentication are not implemented yet.

## Development hooks

This repo includes a pre-commit hook at `.githooks/pre-commit` that runs `cargo fmt --all`.

Enable it once per clone:

```bash
git config core.hooksPath .githooks
```
