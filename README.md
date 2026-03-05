# A simple remote command runner

This project is a small exploration of a secure system for running a limited set of remote commands over an end-to-end encrypted channel. It uses a relay server for pairing and byte forwarding, while the client and agent perform a Noise XX handshake and exchange encrypted command messages directly.

## Current capabilities
- Relay handshake and tunnel pairing
- Handshake authentication with per-id shared tokens
- Noise transport setup over the relay tunnel
- Restricted command execution with a signed policy bundle
- Argument validation (regex and enum rules)
- Streaming `stdout`/`stderr` output events
- Final completion event with exit code, timeout flag, and truncation flag

## Policy bundle format
The agent loads a signed policy bundle from `AGENT_POLICY_PATH` (default: `./agent-policy.json`)
and trusted Ed25519 verification keys from `AGENT_POLICY_KEYS_PATH` (default: `./policy-keys.json`).
For examples of the aforementioned files, see [policy-keys.json](policy-keys.json) and [agent-policy.json](agent-policy.json)

Bundle schema:
- `SignedPolicyBundle { bundle_version, expires_at_unix, policy, signature }`
- `PolicySignature { key_id, algorithm, value }` where `algorithm` is `ed25519` and `value` is hex

Embedded policy schema:
- `Policy { version, default_timeout_secs, max_output_bytes, commands }`
- `CommandSpec { id, program, fixed_args, arg_specs, timeout_secs?, max_output_bytes? }`
- `ArgSpec { name, required, validation? }`
- `ValidationRule::Regex { pattern } | ValidationRule::Enum { values }`

Unsigned bundles, unknown `key_id`s, invalid signatures, unsupported bundle versions, and any expired bundles are rejected during load.

## Running a simple local test

1. Start the relay server:

```bash
cargo run -p alaric-server
```

2. Start the agent in a second terminal:

```bash
AGENT_ID=agent-default \
AGENT_AUTH_TOKEN=agent-dev-token \
AGENT_POLICY_PATH=./agent-policy.json \
AGENT_POLICY_KEYS_PATH=./policy-keys.json \
cargo run -p alaric-agent
```

3. Run a client command in a third terminal:

```bash
CLIENT_ID=client-local \
CLIENT_AUTH_TOKEN=client-dev-token \
TARGET_AGENT_ID=agent-default \
cargo run -p alaric-client -- \
  --command-id echo_text \
  --arg text=hello
```

Client usage:

```text
alaric-client --command-id <id> [--arg name=value]...
```

Notes:

- One command is processed per session currently.
- The server does not inspect command messages and is generally blind to traffic, policy enforcement is handled by the agent.
- Handshake auth config is read from `SERVER_AUTH_CONFIG_PATH` (default: `./server-auth.json`). See [server-auth.json](server-auth.json) for an example config.

## Development hooks

This repo includes a pre-commit hook at `.githooks/pre-commit` that runs `cargo fmt --all`.

Enable it once per clone:

```bash
git config core.hooksPath .githooks
```
