# PQL3 — fork-relative nonce projection and crash recovery (RESEARCH / HOLD_NO_GO)

Exact proposed parent: Chain PR #442 (`research/pq-genesis-nonce-liability-bridge-20261026`) at `6c63f18795e8937e7e8ea11b757fcdbd2ff1e59c`. Related independent, parallel native structural oracle: PR #445 at `02fac1a0f814600501036f0450d7876fd28cc59b`. This increment **does not merge either branch**, change `main`, replace PQL1, activate PQ signatures, emit Chainwork, decide fork choice, modify W1/PNW1 or update any production flags.

## Concrete blocker

PQL1 fixture initialization starts migrated accounts at `next_nonce=1` and has no historical Task/Reward/Quota/Escrow liabilities. Existing PQL2 builds bounded, non-authoritative bytes that preserve original floors and these liabilities, but has no crash/fork reference semantics. A future M05/M07/M08/M13 importer must not use PQL1 to accept PQG1. `pq_pql2_fork_recovery.py` adds a separate, **reference-only** SQLite fork history with externally supplied PQL2 pins and no actual spend.

## Boundary and exact bytes

`check_import` independently parses PQL2 v1: 5-byte magic/version, new-network32, profile32, original chain head32, withdrawal head32, expected PQG1 source digest48, projected genesis ID48, account count u16, exact 129-byte ordered account records (1–128), liabilities count u16, exact 81-byte ordered liabilities (0–256), followed by issued/quarantined/locked u64 values. PQL2 digest is `SHA384("TRNM/PQ/PQL2State/v1\\0" || BE64(len(PQL2)) || PQL2)` and MUST be caller pinned. It rejects ambiguous byte types, alternate magic, absent/reused PQ signers, zero original nonce/generation, generation overflow, invalid derived account addresses, unknown liability owner, duplicate liability, missing locked value, supply mismatch, reordered rows, excessive counts and damaged independently expected roots. This is structural validation of caller-provided data, **not** PQG1/ML-DSA cryptographic ownership or independently authenticated old-chain export.

`ResearchForkStore` preserves immutable imported account/status/balance/liabilities and stores fork-local only the nonce vector in `nodes`. Genesis contains all PQL2 nonce floors, not 1. Every hypothetical `simulate_append` creates a separate deterministic SHA-384 snapshot bound to its exact PQL2 root, parent snapshot ID, height, account index, operation ID and full nonce vector. It permits exactly +1 for migrated accounts and rejects any progression for quarantined/legacy-only identities. It models NO transfers, fees, task expiry, settlement, real signature verification, valid PoW, economic reward or actual operation dispatch; the method name intentionally includes `simulate`.

`simulate_choose_tip` accepts a caller-named existing snapshot under `BEGIN IMMEDIATE`/generation CAS. It does NOT calculate or prove chainwork, independently verify the proposed branch, or grant finality. A tip change increments local generation atomically, and old branch nodes remain available. Repeated calls with stale generation fail. `observe_irreversible_effect` is an append-only observation table distinct from fork-local nonces; it never grants Final-use or attempts to call a provider. Observations survive branch switches, while the branch's local nonce state may differ. All multi-row updates commit in one SQLite transaction, with WAL/FULL, before reporting an acknowledgement.

Cold open verifies exact SQLite table-only DDL (no foreign view/trigger/extra table), exact import/root identity, all branch parent/height/nonces/content hashes, the active generation and effect references in ONE pinned read snapshot. Existing database schemas are checked before PRAGMA WAL or writable initialization. The maximum retained research branch count is 32,768; this does not prove production storage compaction. Leaf symlink DB paths are rejected. SQLite sidecars/parent directories, real power-loss/whole-store rollback and cross-host trust are **not independently protected**.

## Reproduction and negatives

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql2_fork_recovery.py
```

The isolated 21 test methods cover entire-PQL2 mutation, attacker-rehashed bad nonce/status/balance/generation/locked accounting, all four liabilities, maximum 128-account/256-liability import, two forks/reorg, quarantine, exact retries, generation CAS, eight real independent processes competing for one publication, real process exit after durable append or publication but before ACK, cold readback, foreign DDL and post-open metadata substitution. Controlled in-memory development fixtures do **not** assert real signatures or independent source provenance.

An **intentional negative** replaces a fully committed DB with a self-consistent older snapshot: the local audit accepts it. This is an explicit **anti-rollback failure**, not an anti-rollback PASS. Independent non-rewindable state roots, trustworthy source operators and externally retained revocation/effect frontiers remain blocking requirements.

## Remaining production blockers

1. Independently admitted old-chain source history + complete liability/export authority, real strict Ed25519 and ML-DSA migration proof for **every** migrated owner, old-key exposure cut-off and trusted revocation/withdrawal owner.
2. Actual M00/M01/M05/M06/M07/M08/M13 audited Rust implementation with HSM-backed signer, native PQ QTX1 validation, authenticated chainwork/fork-choice, balances, rewards, expiry/compensation, incremental state, exact deep reorg and physical power-failure evidence; no PQL1 state reset.
3. Separate non-rewindable anti-rollback frontier across full DB rollback/clone, operator compromise and cross-host replay. A local SQLite WAL alone never closes this.
4. Deployed PQ M04/M09/M15 peer auth/Cell DA, independent operators and hostile WAN, real Hepta export/final-use integration, W1 quantum-effective security and external cryptographic acceptance.

**HOLD_NO_GO:** no product `VerifiedWork`, permission, asset, model release, Chainwork, finality, deployment or activation flag is produced by these tests. This increment documents reference behavior only.
