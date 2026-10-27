# PQ cross-branch exact-source composition — PQL7 research, HOLD_NO_GO

This additive integration uses [PR #465](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/465) as its frozen baseline. **It is NOT the native chain node**, does not update `main`, does not change the installed Ed25519/PNW1/W1 protocol or chainwork, and must NOT be automatically promoted or deployed.

## Source heads, not copied claims

| Scope | Upstream PR | Exact source SHA | Selected resolution |
|---|---:|---|---|
| PQL6 equivocation, PQL5 native, PQL4/PQL3 and canonical PQ research | 465 | `ddebbc701179b44794649df5e808874786e7390a` | existing foundation |
| Cell custody hardening, swarm, complete bundle publication | 474 | `c014bbbd604dad68f0a5d87a8f35a5d4fe5ce181` | import 18 new files; replace custody journal |
| Dual-signature migration owned durable journal | 475 | `6c9838a0b8813327936bd4509d81760c971d5bdd` | import 2 files; replace account migration journal |
| Fresh witness SQLite TEMP/ACK hardening | 476 | `f7b044f654b8865b41433dedeb2788f771aea572` | import 1 file; replace PQL5 quorum code/test |
| Native full-roster PQG1/PQS1 projection verification | 445 | `02fac1a0f814600501036f0450d7876fd28cc59b` | import 6 new files |
| Independent PQL3 native state projection verification | 447 | `5c39176168476de17606d991446b4305493ae918` | import 7 new files |

The exact source file Git object IDs are pinned in `config/pon/pq-cross-branch-corpus-v1.json`; any code-byte change requires repinning and **new** measured evidence. Existing experiment logs remain tied to their originally tested commits and are **not** current-source test results.

All four overlapping paths have a single explicit upstream choice. No original source is silently reimplemented. The paths are in the manifest's `overwrites` map.

## What this closes

- One auditable Git tree now contains real OpenSSL ML-DSA-65 + ML-KEM-768 research; QTX1 byte/nonce/reorg experiments; strict dual-possession genesis migration; signed Cell manifests/chunks, swarm and atomic bundle; native standalone verifier oracles; PQL3–PQL6 local witness/equivocation reference; and newest local journal hardening.
- An executable fail-closed source identity gate detects changed/removed/symlinked pinned source files, changed reference signatures, default chain activation, accidental transaction-limit promotion, unexpected overlay resolution and provenance omission.
- The integration tree establishes **only source composition** and planned acceptance inputs. It does not inherit historical PASS from the component branches.

## Run these checks on the exact combined checkout

```sh
python3 scripts/ci/check_pq_research_integration.py
python3 -m unittest -v scripts/ci/test_pq_research_integration.py
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_envelope.py test_pq_account_migration.py test_pq_migration_journal_owner.py
python3 -m unittest -v test_pq_cell_custody.py test_pq_cell_custody_journal_hardening.py test_pq_cell_swarm.py test_pq_cell_bundle_atomic.py
python3 -m unittest -v test_pq_pql5_quorum.py test_pq_pql6_equivocation.py
python3 -m unittest -v test_pq_import_projection_verify.py test_pql3_native_verify.py
```

These are **required future exact-tree checks**, not statements that they ran. Source-pin validation is independent of experiment runtime qualification. Native C/OpenSSL oracles and the original Rust suite need separately recorded exact-source compiler, sanitizer and fault evidence.

## Open security blockers (hard fail, not placeholders)

1. The installed mainline has classical Ed25519 wire and a 2048-byte transaction cap; ML-DSA-65 signature alone is 3309 bytes. No versioned production Rust M00/M01/M05/M06 gate, fee/verification gas or account migration exists.
2. The W1 expensive-invalid-proof asymmetry, Sybil-safe ingress and **quantum-effective** work hardness remain unqualified. Hash-based challenge binding is not a PoN security proof.
3. Local SQLite anti-rollback checkpoints and 2-of-3 signer receipts cannot resist shared administrator, compromised quorum or full disk rollback. Need independently administered monotonic anchors and governance.
4. The Cell swarm is a bounded loopback research path; production WAN P2P, storage availability under outages, repair, public authorization and true Hepta Final-use remain absent.
5. Independent crypto audit, public adversarial qualification, physical power-loss, long-term reorg and operator separation have not been performed.

Until all are independently closed, keep every production flag false, public mainnet disabled and research proofs incapable of minting VerifiedWork/Final-use.

## Additive native M00 TPQ1 preflight (same research branch)

`trillionnium/crates/trnm-protocol/src/pq_frame.rs` now holds a bounded, non-authoritative Rust parser for exact 176-byte TPQ1 statements plus 3309-byte signatures. It checks purpose, algorithm, reserved fields, caller-pinned network/context/key ID, generation, sequence, expiry, 64 MiB payload ceiling, SHA-384 domain-separated payload commitment and exact 3487-byte framing. Its return type is deliberately `UnverifiedPqFrame`, **not** a verified key/transaction/Chainwork/Final-use authority. It does not call OpenSSL or change the installed Ed25519 PoN format.

Five Rust regression tests are provided (full signed-statement byte mutation, legacy downgrade, zero-generation/nonces, stale/wrong payload and explicit non-verification of arbitrary signature bytes). The exact source has **not** been compiled or run with Rust in this tool environment; source/build qualification is still required.

Required command on an independently checked-out exact SHA:

```sh
cargo test --locked --manifest-path trillionnium/Cargo.toml -p trnm-protocol pq_frame
```

This is only a native M00 syntax boundary. Real ML-DSA verifier+key custody, transaction/state activation and quantum-effective PoN hardness remain hard NO_GO blockers.
