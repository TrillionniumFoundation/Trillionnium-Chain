# PQL11: fail-closed PQ corpus gate fixture and nested source coverage

Status: **RESEARCH ONLY / HOLD_NO_GO / DO NOT ACTIVATE**.

Frozen parent: PR #492 `668c41cead73ebef83212094d0c077ee788f1570` (stacked over #491 → #489 → #486 → #481 and upstream research). Main `9fedf7ecbbe07177069c030592b4e03dcffebb81` is unchanged. This change does not alter native Rust consensus, PoN W1/PNW1, installed Ed25519 transactions, Chainwork, 2048-byte transaction cap, model Final-use, post-quantum activation, or source signer authority.

## Independently reproduced negative cases

Two exact predecessor file blobs (`check_pq_research_integration.py` `c5cf49664bdb59d5f5f1fbd306280ad12568b5f2`; `test_pq_research_integration.py` `5153e8662d0f488814e53b53a7f1d262485d7ab0`) were reconstructed byte-for-byte from GitHub before execution.

1. The inherited test `REQUIRED` tuple contained the same `pqg_native_verify.c` twice. Its generated `required_paths` list therefore violated the checker's own duplicate rule. Running the exact original test and checker together gave **13 test methods; failures=13, errors=1** (multiple subtest failures) instead of a valid baseline. This is a *test fixture defect*, not evidence that Chain source blobs are wrong.
2. Removing just that fixture duplicate exposed a real bypass: the source scanner enumerated only immediate children of its three PQ source directories. An unpinned nested `src/pq_verifier/native.rs`, nested `src/core/pq_hidden_downgrade.rs`, and nested Python `pq_next/pq_hidden_downgrade.py` were not rejected. A nested symlink directory was also ignored. The augmented fixture failed **four targeted negative cases**, as expected before hardening.

## Minimal correction

- Remove the duplicate fixture entry, retain a regression showing an intentionally duplicated required path is rejected.
- Recursively enumerate `.py`, `.c` and `.rs` under the three previously approved PQ source roots; require an exact blob pin for files named `pq_*`, `pqg_*` or `pql*` **or lying beneath a PQ-named module directory** (e.g. `pq_verifier/native.rs`).
- Fail closed on nested directory/file symlinks and filesystem walk errors; no skipped unreadable subtree can yield a completeness result.
- Keep all prior exact Git blob checks, canonical path controls, explicit overwrite decisions, `HOLD_NO_GO` result and eight false activation/acceptance fields. This does NOT discover arbitrary cryptographic implementation files outside the three scoped roots or imply a secure source tree under hostile concurrent filesystem mutation.

## Actually executed qualification

Run with source/test bytes checked against the committed Git blobs:

```sh
cd scripts/ci
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_research_integration.py
```

**18 PASS / 0 failures / 0 errors** after correction on Python 3.13.5, Linux x86_64; includes valid research-only corpus, mismatched source hash, legacy activation, duplicate manifest/path, symlink, traversal, unpinned top-level and nested code, pinned nested code acceptance, unreadable directory injection, and overwrite refusal.

This is an actual *isolated* execution of the exact two research-gate Python files and synthetic corpus fixture. The entire 1,482-entry upstream Git tree was **not** materialized; `check_pq_research_integration.py` on a complete exact-head checkout, full Cargo/Rust native tests, cryptographic testing beyond inherited experiments, real WAN/HSM/physical power-loss, and independent security review remain **NOT_RUN** in this increment. Pin identities are only source identities and do not prove all runtime behavior.

## Remaining mandatory blockers

Audited Rust ML-DSA-65 signature authority and versioned TPQ1/QTX1 signer, nonce, fee, mempool, reorg/legacy-liability state; independently authenticated ML-KEM hybrid P2P and Hepta Cell export/Final-use; hardware-backed external antirollback under witness-majority compromise; W1 quantum-effective work/security and Sybil false-ticket verification costs; public multi-operator/physical failure/independent cryptographic acceptance. No consensus/main/activation change is permitted.
