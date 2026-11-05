# PQL1 — signed QTX1 fork-local state replay (HOLD / NO ACTIVATION)

Research-only continuation after PQN1 native QTX1 crypto conformance, stacked on
PR #424 (upstream research #399 → #405 → #406 → #408 → #413 → #417 → #419 → #424).
PQL1 adds no PoN consensus, no M02 fork choice, no production state, no block reward,
no credential custody, no Hepta Final-use and no mainnet/devnet activation.

## Purpose, source and trust

`formal/pon-nakamoto-v1/pq_branch_execution.py` reuses the exact inherited `pq_transaction`
QTX1 parser/preflight and `pq_envelope` TPQ1 OpenSSL ML-DSA-65 verifier. It does **not**
accept a caller-provided "signature valid" boolean. Each signed transfer is verified
against the account's fixed genesis signer key, exact network, generation, next nonce,
expiry, fee limit and available balance. The research genesis roster and block
logical timestamp come from the caller; no trusted network/genesis or block-time
consensus is supplied. The unit fee formula is a fixed test policy, not chain economics.

## Deterministic branch transition

- Each admitted child derives its own state from the indicated immutable parent;
  sibling forks never share mutable balance or nonce state.
- Exact canonical transaction framing: two-byte count, up to 16 transactions,
  four-byte length each, each bounded by QTX1 research maximum 8 KiB; no trailing bytes.
- Each QTX1 needs its own real ML-DSA-65 signature. Exact logical transaction identity
  is independent of signature randomness. No implicit account/signer registration.
- Sender nonce advances exactly once in the child branch; value is conserved between
  sender, recipient and the explicit test fee bucket. Overflow rejects atomically.
- SHA-384 domain-separated branch ID binds validated parent, height, time, ordered
  logical IDs and canonical resulting state root. No work proof/chainwork is minted.
- `observe_selected_tip()` accepts only a caller-chosen already verified branch as a
  **diagnostic observation**, using an expected-prior-tip CAS and monotonic generation.
  It does not decide which chain is heavier, valid under PoN, or finally confirmed.
- Original journal retains all conflicting forks; one SQLite IMMEDIATE transaction
  persists an entire child before acknowledge. Same logical block retransmission
  does not apply balances a second time. Crash after COMMIT before ACK is replay-safe.
- Cold open audits exact original genesis and full signed ancestry. Before each
  in-process write, validate frozen SQLite schema and re-execute the indicated parent
  ancestry to defeat post-open DDL or rehashed state substitution.

## Threat-derived recorded regression

`test_pq_branch_execution.py` uses new genuine ML-DSA-65 keys created by OpenSSL,
competing signed fork transactions, stale/changed keys/nonce/expiry/balances,
noncanonical bytes, altered signatures, bogus parent state root, injected trigger,
foreign genesis/symlink, cold full-history replay, and a real process cut *after*
durable COMMIT but before application ACK. Eight independent spawned OS processes
open the same WAL/FULL SQLite state and race the same transaction; the correct identity
is stored once, even if local retries observe the same block.

Reproduce in a complete checkout of the stacked research branch:

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_branch_execution.py
```

The recorded result is 16 PASS / 0 FAIL on one Linux x86_64 overlayfs container,
Python 3.13.5, OpenSSL 3.5.5 and SQLite 3.46.1. This is not physical disk-power-loss
qualification, independent operator acceptance, Rust M05/M06/M07 state integration,
or real WAN consensus. Observed task time and environment cannot substitute for
full-node TPS or formal PoN quantum hardness.

## Explicit remaining gates

1. M01 audited native **Rust** ML-DSA-65 provider and non-exportable key custody/HSM;
   the OpenSSL CLI fixture and standalone C verification are not the production path.
2. M00 activation profile and transaction/byte/fee/gas migration. Installed QTX1 is
   still rejected by the active 2048-byte transaction limit, and signatures enlarge blocks.
3. M02 actual native PoN header, target, quantum work-security, fork choice and proof
   admission; PQL1 must not select public history or authorize external effects.
4. M05/M06/M07/M08 atomic on-chain PQ account-state transition, old Ed25519 migration,
   independent revocation/effect journal, crash/power loss, deep reorg and verified sync.
5. M04/M09/M11/M15/Hepta real authenticated P2P, signed Cell release/retention,
   independent evaluators, export and withdrawal owner integration.
6. M17 independent external cryptographic review, WAN Sybil/eclipse/flood testing,
   sustained end-to-end throughput and native Rust product qualification.

**Machine production flags, W1/PNW1, chainwork, legacy signatures, keys, and deployed
network are unchanged. No test passes a production-eligibility or release-authority gate.**
