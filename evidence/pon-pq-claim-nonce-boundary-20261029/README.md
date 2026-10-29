# Imported CLAIM nonce boundary

Base: `42ab57f1c5065d50f981cc337c417ef0ab7dc096` (PR #537), tree
`7720e95c8d362d2a4017b0cf801ef169f54862b0`.

## Defect and change

The current PQ State validator checked that a claimed imported account had key
authority, but did not require its nonce to have advanced beyond the externally
anchored source nonce. Starting from the output of a real dual-ML-DSA CLAIM,
retaining that authority and the claimed flag while reverting the nonce to zero
was accepted by the original validator. The new assertion fails against the
unchanged production source; the failure is retained in `claimed-nonce-red.log`.

Require `account.nonce > imported.original_nonce` for claimed imports. This is a
necessary invariant of the existing atomic CLAIM transition. No transaction
encoding, signed domain, State schema, nonce increment, trust anchor or key policy
changes. Unclaimed imports retain their exact original nonce rule.

The regression extends the existing migration test. It rejects nonces 0, 6 and
7 for a source nonce of 7 through both the State validator and ordinary M06 block
execution. The original successful CLAIM (nonce 8), subsequent cancellation
(nonce 9), locked provider account and reward maturation remain exercised.

## Local validation on the changed source

- Complete M06 library: 90 passed, 0 failed, six original ignored cost tests.
- PQ2 authority/capacity: two passed.
- PQ3 quota authority: eight passed.
- PQ4 task authority: nine passed.
- PQ5 task renewal: seventeen passed.
- 126 executed Rust tests passed overall. No original ignored test was enabled,
  relabelled or newly ignored.
- PQ readers: 49 passed; source integrity controls: 34 passed. These are synthetic
  reader/integrity controls and are not additional native product executions.
- Workspace formatting, embedded source inventory, full locked offline Cargo
  metadata (26 workspace members, 173 packages) and strict M06 Clippy including
  the four PQ integration targets passed.
- Compiler: rustc 1.96.0 (ac68faa20 2026-05-25). The existing hosted PQ gate pins
  rustc 1.95.0 and still needs its own exact-candidate run.
- All 1,768 non-evidence repository source files were matched against the remote
  Git blob inventory before editing. Only the two listed Rust files changed.

The initial formatting wrapper invocation failed because it selected a rustup
shim with an unwritable home; its observation is retained. Calling the installed
compiler's actual cargo-fmt/cargo-clippy binaries resolved the tooling path.
No source or acceptance condition was changed to bypass that error.

## Reproduction

```bash
bash scripts/project-preflight.sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml   -p trnm-mvcc-fee --lib   --test pq2_authority_capacity --test pq3_quota_authority   --test pq4_task_authority --test pq5_task_renewal -- --test-threads=2
python3 -m unittest discover -s scripts/ci -p 'test_native_pq*' -v
python3 -m unittest discover -s scripts/ci -p test_ci_source_integrity.py -v
```

## Scope

This is inconsistent-State rejection, not a demonstrated unsigned transaction
forgery or protection against restoring a complete old database. The added
assertions use the existing explicitly synthetic M06 checkpoint fixture; they
do not claim a new W1 proof. The original complete native Node 205-test gate and
three anchored migration tests have not been rerun on this changed candidate.
The prior trusted PQ registry and source finality/retirement remain external
premises. Production activation and whole-chain PQ qualification remain false.
