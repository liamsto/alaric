# A simple remote command runner

This project is a small exploration of a secure system for running a limited set of remote commands over an end-to-end encrypted channel. Clients (i.e. the person running the command) and agents (the device the command is run on) both connect to a centralized relay server. Through that relay, the client and agent perform a Noise XX handshake. Once this is established, the server relays bytes between the two TCP streams with an end-to-end encrypted tunnel. The client and agent know little about each other besides their respective IDs.

## Current capabilities
- Relay handshake and tunnel pairing
- Handshake authentication with per-id Ed25519 keys (server stores public keys only)
- Noise transport setup over the relay tunnel
- Configurable end-to-end peer attestation bound to the Noise handshake transcript
- Restricted command execution with a signed policy bundle
- Argument validation (regex and enum rules)
- Streaming `stdout`/`stderr` output events
- Final completion event with exit code, timeout flag, and truncation flag
- Multi-target command execution from a single client invocation
- Admin-defined agent groups for target shorthands

## Policy bundle format
The agent loads a signed policy bundle from `AGENT_POLICY_PATH` (default: `./agent-policy.json`) and trusted Ed25519 verification keys from `AGENT_POLICY_KEYS_PATH` (default: `./policy-keys.json`). For examples of these, see [policy-keys.example.json](policy-keys.example.json) and [agent-policy.example.json](agent-policy.example.json)

Bundle schema:
- `SignedPolicyBundle { bundle_version, expires_at_unix, policy, signature }`
- `PolicySignature { key_id, algorithm, value }` where `algorithm` is `ed25519` and `value` is hex

Policy schema:
- `Policy { version, default_timeout_secs, max_output_bytes, commands }`
- `CommandSpec { id, program, fixed_args, arg_specs, timeout_secs?, max_output_bytes? }`
- `ArgSpec { name, required, validation? }`
- `ValidationRule::Regex { pattern } | ValidationRule::Enum { values }`

Unsigned bundles, unknown `key_id`s, invalid signatures, unsupported bundle versions, and any expired bundles are rejected during load.

## Peer attestation policy
Peer attestation requires clients and agents to prove their identity using policy bundles shared out of band. The client and agent each load an optional peer-attestation policy JSON file. If unset, both default to:

- `default_mode = preferred`
- no principal overrides
- no pair overrides

Peer attestation serves as an optional additional layer of security. If activated, even a compromise of the server will not lead to a breach of confidentiality in traffic between agent/client pairs.

Schema:

- `default_mode`: `required | preferred | disabled`
- `principal_modes.clients`: map of `client_id -> mode`
- `principal_modes.agents`: map of `agent_id -> mode`
- `pair_modes`: list of `{ client_id, agent_id, mode }`

Resolution precedence is:

- exact pair override
- principal overrides (client + agent), combined by strictest mode
- global default

`required` means the session must complete peer attestation to be activated. `preferred` will attempt attestation when bundle material is available, but otherwise will continue. `disabled` skips peer attestation.

The agent and client each enforce their local policy, so either side can require attestation.

## Running a simple local test

1. Create local runtime config files and per-machine auth keys:

```bash
cp agent-policy.example.json agent-policy.json
cp policy-keys.example.json policy-keys.json
cp peer-attestation-policy.example.json peer-attestation-policy.json

# Writes ./server-auth.json and prints shell exports with private keys.
cargo run -q -p alaric-lib --example gen_auth_config -- ./server-auth.json > .dev-auth.env

# Generate a signed identity bundle for peer attestation
export IDENTITY_BUNDLE_SIGNING_KEY_ID=control-plane-v1
export IDENTITY_BUNDLE_SIGNING_PRIVATE_KEY=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
cargo run -q -p alaric-lib --example gen_identity_bundle -- ./server-auth.json ./identity-bundle.json

./scripts/db18-up.sh
export DATABASE_URL=postgres://alaric:alaric@127.0.0.1:55432/alaric
```

2. Add principals and keys with `aadmin` (requires `jq` for this quick path):

```bash
AGENT_PUBLIC_KEY="$(jq -r '.agents["agent-default"].public_key' ./server-auth.json)"
CLIENT_PUBLIC_KEY="$(jq -r '.clients["client-local"].public_key' ./server-auth.json)"

cargo run -q -p aadmin -- principal add agent agent-default --display-name "Default local agent" --attestation required
cargo run -q -p aadmin -- principal add client client-local --display-name "Default local client" --attestation required

cargo run -q -p aadmin -- key add agent agent-default agent-default-v1 "$AGENT_PUBLIC_KEY"
cargo run -q -p aadmin -- key add client client-local client-local-v1 "$CLIENT_PUBLIC_KEY"

cargo run -q -p aadmin -- principal list
```

3. Start the relay server:

```bash
cargo run -p alaric-server
```

4. Start the agent in a second terminal:

```bash
source ./.dev-auth.env

AGENT_ID=agent-default \
AGENT_POLICY_PATH=./agent-policy.json \
AGENT_POLICY_KEYS_PATH=./policy-keys.json \
AGENT_IDENTITY_BUNDLE_PATH=./identity-bundle.json \
AGENT_PEER_ATTESTATION_POLICY_PATH=./peer-attestation-policy.json \
AGENT_TAGS=local,dev \
cargo run -p alaric-agent
```

5. Run a client command in a third terminal:

```bash
source ./.dev-auth.env

CLIENT_ID=client-local \
CLIENT_TRUSTED_KEYS_PATH=./policy-keys.json \
CLIENT_IDENTITY_BUNDLE_PATH=./identity-bundle.json \
CLIENT_PEER_ATTESTATION_POLICY_PATH=./peer-attestation-policy.json \
TARGET_AGENT_ID=agent-default \
cargo run -p alaric-client -- \
  --command-id echo_text \
  --arg text=hello
```

List online agents:

```bash
source ./.dev-auth.env

CLIENT_ID=client-local \
cargo run -p alaric-client -- list-agents
```

Create and inspect an agent group:

```bash
cargo run -q -p aadmin -- group upsert ca-west-prod01 --display-name "Canada West Production 1" --member agent-default
cargo run -q -p aadmin -- group list
```

Run a command against multiple targets (direct targets and group aliases can be mixed):

```bash
source ./.dev-auth.env

CLIENT_ID=client-local \
CLIENT_TRUSTED_KEYS_PATH=./policy-keys.json \
CLIENT_IDENTITY_BUNDLE_PATH=./identity-bundle.json \
CLIENT_PEER_ATTESTATION_POLICY_PATH=./peer-attestation-policy.json \
cargo run -p alaric-client -- \
  run \
  --command-id echo_text \
  --target agent-default \
  --group ca-west-prod01 \
  --arg text=hello
```

6. Admin tasks:

```bash
# lists all principals
cargo run -q -p aadmin -- principal list

# disable/enable a client principal
cargo run -q -p aadmin -- principal disable client client-local
cargo run -q -p aadmin -- principal add client client-local --display-name "Default local client"

# revoke a specific key
cargo run -q -p aadmin -- key revoke client client-local client-local-v1

# rotate an agent key (be sure the agent is updated to use the new private key)
cargo run -q -p aadmin -- key rotate agent agent-default agent-default-v2 <new_public_key_hex>
```

Client usage:

```text
alaric-client list-agents
alaric-client run --command-id <id> [--target <agent_id>]... [--group <group_id>]... [--arg name=value]...
alaric-client --command-id <id> [--target <agent_id>]... [--group <group_id>]... [--arg name=value]...
```

Notes:

- One command is processed per session currently.
- The server does not inspect command messages and is generally blind to traffic, policy enforcement is handled by the agent.
- Handshake auth uses server-issued nonce challenges and Ed25519 signatures over handshake context.
- Command sessions run peer attestation after Noise XX according to client/agent policy (`required | preferred | disabled`).
- Server handshake authorization is loaded from PostgreSQL (`principals` + `principal_keys`).
- Server handshake authorization hot-reloads from PostgreSQL via `LISTEN/NOTIFY` on auth config changes.
- The generated `server-auth.json` is still useful as local key material, but runtime authorization is DB-backed.
- Generated local files `server-auth.json` and `.dev-auth.env` are gitignored by default.

## Admin provisioning CLI

`aadmin` is a CLI for managing handshake principals and keys in PostgreSQL. It doesn't do any relaying or send any traffic, that responsibility remains with `alaric-server` which acts as a daemon.

Commands:

```text
aadmin principal add <agent|client> <external_id> [--display-name <name>] [--attestation <required|preferred|disabled>]
aadmin principal set-attestation <agent|client> <external_id> <required|preferred|disabled>
aadmin principal disable <agent|client> <external_id>
aadmin principal list [agent|client|all]
aadmin key add <agent|client> <external_id> <key_id> <public_key_hex>
aadmin key rotate <agent|client> <external_id> <new_key_id> <new_public_key_hex>
aadmin key revoke <agent|client> <external_id> <key_id>
aadmin group create <group_id> [--display-name <name>]
aadmin group add <group_id> <agent_id>
aadmin group remove <group_id> <agent_id>
aadmin group move <old_group_id> <new_group_id> <agent_id>
aadmin group set-name <group_id> <display_name>
aadmin group delete <group_id>
aadmin group list
```

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
