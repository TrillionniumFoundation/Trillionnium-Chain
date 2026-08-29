# G2B AgentTransactionV1 outer-wire candidate

Status: **MODULE_CLOSED_CANDIDATE only after exact-head Rust and independent-parser replay; no Gate promotion**

Owner: A12  
Package: `G2B_AGENT_MARKET_V1`  
Base: PR #32, `feature/chain-a11-g2a-da-fullrep-v2-20260829@2fb72d01e49350d3b5dad158a6eaada37c0794b5`.

## Objective

Define one bounded, deterministic and independently parseable outer carrier for the existing signed `KernelCommandV1` candidate. The carrier closes the repository-local wire ambiguity without claiming an accepted protocol object.

The exact frame is:

```text
magic[8] = TRNMATX1
wire_version:u16le = 1
flags:u16le = 0
context_digest[32]
sender_agent_id[32]
authorizing_key_id[32]
signer_key_id[32]
capability_present:u8 + capability_id[32]
session_present:u8 + session_key_grant_id[32]
live_capability_generation:u64le
session_generation:u64le
nonce_lane:u16le
operation_kind:u16le
nonce:u64le
expected_lane_version:u64le
valid_after_height:u64le
expires_after_height:u64le
command_length:u32le
payload_digest[32]
canonical_borsh_kernel_command[command_length]
wire_digest[32]
```

The fixed header is 294 bytes. The payload is bounded to 1 MiB. The payload and complete unsigned frame use separate ASCII-domain SHA-256 commitments.

## Canonical Rust path

`AgentTransactionV1::from_kernel_command` requires:

- schema and protocol version 1;
- non-empty bounded chain ID;
- exact operation-kind and operation-digest agreement;
- non-inverted validity interval;
- an exact 64-byte Ed25519 signature;
- canonical Borsh command bytes;
- bounded lengths and zero reserved flags.

`AgentTransactionV1::decode` rejects any non-canonical header, optional-ID representation, payload digest, wire digest, trailing bytes, truncation, version drift or header/payload disagreement. It then strict-decodes the inner command and requires byte-for-byte re-encoding equality.

## Independent parser

`conformance/agent-market/independent_agent_transaction_wire_v1.py` uses only the Python standard library. It does not import the Rust codec, the Python Agent/Market model, or generated protocol code. It parses the fixed carrier directly, recomputes both commitments and retains twelve negative mutants.

The Rust example `agent_transaction_wire_v1` emits the exact signed fixture consumed by the independent parser, so the replay is cross-language rather than two isolated self-tests.

## Existing kernel evidence now included in the package gate

The exact-head G2B replay also executes:

```bash
cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-agent-market-v1 --all-targets
cargo +1.95.0 clippy --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-poco-agent-market-v1 --all-targets -- -D warnings
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
```

This binds the already-present strict Ed25519 authorization, exact nonce/capability/session checks, SQLite atomic replay, finalized-block journal, sidecar rejection and fresh immutable readback into the A12 evidence path.

## Closed candidate gaps

```text
A12-AGENT-TRANSACTION-OUTER-WIRE-CANDIDATE
A12-INDEPENDENT-OUTER-WIRE-PARSER-CANDIDATE
A12-STRICT-ED25519-AUTHORIZATION-EVIDENCE
A12-DURABLE-SQLITE-REPLAY-EVIDENCE
A12-RUST-TEST-CLIPPY-FMT-EXACT-HEAD-GATE
```

## Remaining blockers

```text
accepted AgentTransactionV1 protocol authority
accepted A10/A12 wire digest and version
production controller/session/recovery key lifecycle
canonical application JMT and finalized Order proof
whole-store external anti-rollback
accepted A14/A15 cross-plane joins
normal node-process integration
independent reviewer acceptance
```

## Non-claims

```text
agent_transaction_wire_accepted=false
cryptographic_production_authority=false
global_state_authority=false
canonical_jmt_authority=false
order_finality_authority=false
node_integration=false
g2b_exit=false
production_candidate=false
production_consensus_activation=false
```
