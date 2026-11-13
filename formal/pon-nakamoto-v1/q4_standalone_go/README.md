# Q4 signed renewal — independent Go wire reference

This is a **research-only** byte/signature reference for existing Q4 revision9
atomic renewal (tag22). It does **not** implement a Node, own lease issuance,
submit a transaction, verify canonical chain membership, grant a current
withdrawal/FinalUse capability, change consensus, or certify production readiness.

## Local execution (Go standard library only)

From this directory run:

    GO111MODULE=off go test -count=1 main.go main_test.go
    GO111MODULE=off go test -race -count=10 main.go main_test.go

Observed locally on Go 1.23.2 linux/amd64 (2026-10-26):
5/5 distinct test functions PASS, repeated race-mode PASS.
This evidence is **not** Rust/native-node execution or third-party review.

The self-contained fixture uses deliberately public deterministic **test-only**
Ed25519 keys and independently constructed 64×64 field-matrix materials.
Its fixed canonical 1,187-byte signed PNX1/tag22 transaction has:

- SHA-256(raw transaction): 97dade3ee25e63c3a3413f5b1f108a6c6f8e9ebce1c717aaa757f08b5a4fefca
- PoN H("tx-id", raw): 5cec002e5e54493563850ffaf372a37b81f906f4ed5a11b44a2de84287706dd0
- Successor QDL2 lease ID: 89d88d5c24460e27278803c3d5db344dfcbc78dc398a92a331d4e7accccd1f50

These are research vectors, not a transaction admitted on a live Chain
or an externally authorized source.

## Independent checks

The Go reader reconstructs PoN domain-separated hashing, the exact 344-byte
QDL2 successor, 584-byte QWT1 material manifest, 684-byte source-signed QWA2
statement and 1,187-byte outer requester-signed PNX1. It checks:

- Strict sizes, little-endian integer fields, zero reserved bytes,
  bound network/parameters, real requester/source Ed25519 signatures.
- Lease generation, revision, requester/source/demand/DA identity,
  source sequence +1, old-to-successor overlap and actual containing height.
- Public field-element range, model/input/matrix-task hashes, layer/output
  meter, and the **previously admitted** task's immutable material bindings.
- Negative controls for **both** newly validly signed wrong-parent material,
  lost/changed sender signature, revoked predecessor, foreign context,
  replayed nonce, expired inclusion and malformed encodings.

**Important:** PriorTask is entirely caller-supplied in Go. Only the existing
authenticated native M02/M06/M07 owner may supply such trusted facts and
authorize an actual state transition. A forged prior snapshot can make the
research result self-consistent: this helper never issues an opaque verified
token. Go Ed25519 edge cases (weak keys/noncanonical signature encodings)
still require independent differential verification against Rust's strict
verifier; agreeing test fixture bytes alone is not the full verifier parity.

## Explicit non-claims / remaining P0-B exits

- These Go tests do not run W1, native fork choice, SQLite reorganization,
  retention replay, real network submission or independent withdrawal.
- There is no signing service, automatic renewal, dispatch/re-dispatch
  authorization, duplicate payment, storage proof or native production outbox.
- Existing q4_renewal_outbox_research.py remains a separate **untrusted**
  diagnostic; this Go helper does not upgrade it.
- Closure still requires actual Q4 owner/outbox integration, all-32-slot
  capacity and retention, revoked/expired sole lease, crash/lost ACK,
  authentic W1 Maintenance, independent native client confirmation,
  and multiple independently administered operators.

Original Rust contracts:
trillionnium/crates/trnm-protocol/src/qualified_work_task/lifecycle_v2.rs,
trillionnium/crates/trnm-protocol/src/qualified_work_task/lifecycle_v3.rs,
trillionnium/crates/trnm-protocol/src/pon_wire.rs,
trillionnium/crates/trnm-mvcc-fee/src/qualified_task_lifecycle.rs.

All original historical domains, signed bytes, profiles, activation settings,
budgets, and predecessor tests remain untouched by this research addition.
