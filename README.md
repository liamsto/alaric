# A simple remote command runner

This project is a small exploration of a secure system for running a limited set of remote commands over an end-to-end encrypted channel. It uses a relay server for pairing and byte forwarding, while the client and agent perform a Noise XX handshake and exchange encrypted command messages directly.

## Current capabilities
- Relay handshake and tunnel pairing
- Handshake authentication with per-id Ed25519 keys (server stores public keys only)
- Noise transport setup over the relay tunnel
- Restricted command execution with a signed policy bundle
- Argument validation (regex and enum rules)
- Streaming `stdout`/`stderr` output events
- Final completion event with exit code, timeout flag, and truncation flag

## Policy bundle format
The agent loads a signed policy bundle from `AGENT_POLICY_PATH` (default: `./agent-policy.json`)
and trusted Ed25519 verification keys from `AGENT_POLICY_KEYS_PATH` (default: `./policy-keys.json`).
For examples of the aforementioned files, see [policy-keys.example.json](policy-keys.example.json) and [agent-policy.example.json](agent-policy.example.json)

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

1. Create local runtime config files and per-machine auth keys:

```bash
cp agent-policy.example.json agent-policy.json
cp policy-keys.example.json policy-keys.json

# Writes ./server-auth.json and prints shell exports with private keys.
cargo run -q -p alaric-lib --example gen_auth_config -- ./server-auth.json > .dev-auth.env

./scripts/db18-up.sh
export DATABASE_URL=postgres://alaric:alaric@127.0.0.1:55432/alaric
cargo run -q -p alaric-lib --example import_auth_config -- ./server-auth.json
```

2. Start the relay server:

```bash
cargo run -p alaric-server
```

3. Start the agent in a second terminal:

```bash
source ./.dev-auth.env

AGENT_ID=agent-default \
AGENT_POLICY_PATH=./agent-policy.json \
AGENT_POLICY_KEYS_PATH=./policy-keys.json \
cargo run -p alaric-agent
```

4. Run a client command in a third terminal:

```bash
source ./.dev-auth.env

CLIENT_ID=client-local \
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
- Handshake auth uses server-issued nonce challenges and Ed25519 signatures over handshake context.
- Server handshake authorization is loaded from PostgreSQL (`principals` + `principal_keys`).
- The generated `server-auth.json` is still useful as local key material, but runtime authorization is DB-backed.
- Generated local files `server-auth.json` and `.dev-auth.env` are gitignored by default.

## SQLx Compile-Time Checking

The server-side SQL lives in `alaric-lib`, and dependent crates do not need a direct `sqlx` dependency.

Server database env vars:
- `DATABASE_URL` (required for `alaric-server` runtime)
- `DATABASE_MAX_CONNECTIONS` (optional, default `10`)
- `DATABASE_ACQUIRE_TIMEOUT_SECS` (optional, default `5`)
- `LOG_RETENTION_DAYS` (optional, default `60`, allowed `30..=90`)

To refresh query metadata against PostgreSQL 18:

```bash
./scripts/sqlx-prepare.sh
```

This script:
- starts PostgreSQL 18 via `docker-compose.postgres18.yml`
- applies migrations from `lib/migrations`
- runs `cargo sqlx prepare --workspace -- --workspace`

Offline SQLx checking is enabled by default via `.cargo/config.toml` (`SQLX_OFFLINE=true`), so normal builds/tests do not require a running database.

## Development hooks

This repo includes a pre-commit hook at `.githooks/pre-commit` that runs `cargo fmt --all`.

Enable it once per clone:

```bash
git config core.hooksPath .githooks
```
