Networking Improvements:
Goal: make tunnels durable, observable, and efficient enough for multi-command and multi-agent workflows.
- Connection liveness and health:
  heartbeat/ping frames, idle timeout enforcement, half-open connection detection, and explicit disconnect reasons.
- Session resume:
  reconnect with short-lived resume tokens, replay-safe sequence numbers, and bounded resume windows after transient drops.
- Multiplexed request streams:
  support multiple concurrent command streams on one secure tunnel, with stream IDs and independent stream lifecycle state.
- Flow control and backpressure:
  sliding windows per stream/session, bounded buffers, and sender throttling to prevent relay/client memory blowups.
- Retry and idempotency semantics:
  idempotency keys per command request so client retries cannot accidentally execute twice.
- Relay resilience and abuse controls:
  rate limits, handshake throttling, connection caps per principal, and adaptive penalties for repeated failed auth.
- Presence and discovery:
  heartbeat-backed agent presence registry and optional filtered `list agents` endpoint (capabilities, tags, status age).
- Network observability:
  per-session metrics (latency percentiles, bytes in/out, reconnect count, drop reasons) and structured trace IDs.

PostgreSQL Ideas:
Goal: persist identity, policy, execution, and scheduling state with strong auditability.
- Identity and trust tables:
  principals, API keys, cert fingerprints, key rotations, and revocations with effective timestamps.
- Agent registry and liveness:
  agent inventory, capability metadata, lease/heartbeat records, and last-seen snapshots across restarts.
- Session and command persistence:
  sessions, command_runs, command_events, cancellation records, and final outcomes for lifecycle reconstruction.
- Policy management:
  policy bundles, signature metadata, rollout history, and rollback markers tied to agent groups/environments.
- Audit and compliance:
  append-only audit_log with hash-chained entries for tamper evidence, plus queryable compliance views.
- Queueing and orchestration:
  jobs, retries with backoff, schedules, dead-letter queue, and per-target concurrency controls.
- Operational database concerns:
  migration strategy, partitioning for high-volume event tables, retention windows, and PITR backup/restore runbooks.
- Integration patterns:
  outbox table for reliable event publishing and `LISTEN/NOTIFY` for low-latency worker wakeups.

Additional Improvement Categories:
- Command lifecycle and orchestration:
  cancel/terminate semantics, lifecycle state machine (`queued/running/cancelled/completed/failed`), and fan-out multi-agent commands.
- Multi-command sessions:
  keep secure sessions open for command batches with per-command authz checks and stream isolation.
- Policy tooling:
  CLI for policy sign/verify/inspect, preflight validation, and key trust-chain diagnostics.
- Execution isolation profiles:
  configurable uid/gid drop, cwd/env allowlists, filesystem access restrictions, and hardened defaults per command class.
- Audit UX and forensics:
  searchable timeline views, execution provenance, and export paths for compliance/reporting.
- Documentation and operator DX:
  dedicated `docs/` structure, architecture diagrams, deployment playbooks, and troubleshooting runbooks.
- Test and release hardening:
  network fault-injection tests, migration tests, compatibility matrix tests, and staged rollout playbooks.


Milestones:
1. Milestone 1: Reliability foundations
   Add heartbeat/liveness checks, disconnect reason codes, relay-side limits, and baseline network/session metrics.
   Introduce PostgreSQL with initial schema for identities, agents, sessions, and command runs.
2. Milestone 2: Durable command execution
   Implement idempotency keys, resume tokens, and command lifecycle persistence.
   Add cancellation semantics end to end (client -> relay -> agent -> persisted outcome).
3. Milestone 3: Multiplexing and orchestration
   Add multi-command session multiplexing with flow control.
   Add queue/retry/scheduling tables and workers; introduce multi-agent fan-out execution primitives.
4. Milestone 4: Security and policy maturity
   Ship policy tooling (sign/verify/inspect), policy rollout tracking, and stronger execution isolation profiles.
   Add tamper-evident audit chain and compliance-oriented query surfaces.
5. Milestone 5: Operability and scale
   Add advanced observability/tracing, retention and partitioning strategy, backup/restore automation, and incident runbooks.
   Evaluate/phase QUIC transport support and finalize docs refactor for maintainable operator onboarding.