# x230 Chain PQ exact-inputs source recovery — HOLD

This folder preserves one **previously untracked Rust source file** found on the x230 operator host. It is research and provenance material, **not an active runtime integration**. No production or consensus qualification is implied, and this Draft PR must not be merged as a feature.

## Provenance and byte identity

- Repository of origin: `TrillionniumFoundation/Trillionnium-Chain`.
- Original worktree branch: `fix/chain-pq-full-20261103-4502`; original checked-out commit: `3f3a5c5017367eefc0970d512920a6eaa4a29c35`.
- Original relative source path: `trillionnium/crates/trnm-protocol/src/pon_wire/state_root_arithmetic/exact_inputs.rs`.
- Recovered file: `exact_inputs.rs`. Original size: **6,204 bytes**.
- Original **Git Blob SHA-1**: `8d6d8f64cc5789ac78bf4bf27bdafa228c9e2be5`.
- Original **SHA-256**: `04bc57b23bea70bb5889c0f5fd2882bfd9b682e169e578cb04da889b9d718957`.
- Before publication, GitHub's repository blob lookup returned 404 for that object. The published blob must be independently read back and match the original SHA. This check alone does not prove absence of a similar implementation under a different blob.

The source module is deliberately *not* copied into the active crate. Related local parent changes and other untracked Rust files were not silently transferred.

## Narrow, independently reproducible checks

On the mac operator host, using `rustc 1.95.0 (59807616e 2026-04-14)`:

```sh
cd qualification/pq-local-source-recovery-20261111
rustfmt --check exact_inputs.rs standalone_tests.rs
rustc --edition=2021 --test standalone_tests.rs -o standalone-tests
./standalone-tests --nocapture
```

Observed result: **four tests passed**, testing exact matching, nonmatching values, budget limits, shared-prefix rows, and binary byte payloads. The source SHA-256 was verified immediately before this run. The attached test harness SHA-256 was `bfb286f3499be29bfbfe6470e9ae0ce8cc30d5212ab704c16a48b80b7a47c341`. Basic local credential/private-key-pattern scanning found no hits in these two files.

## Unclosed blockers

1. Original worktree has 26 status entries including many tracked modifications and other untracked files. Their upstream mapping, security review and tests have **not** been completed.
2. x230 had no Cargo/rustfmt during the initial audit. **No integrated Cargo test, original host campaign, security proof or performance acceptance** was performed by this recovery.
3. The recovered dictionary is context-dependent: integration into the current parent module requires fresh compatibility review and independent whole-path tests. Its `MAX_BYTES` value bounds retained dictionary bytes, not peak process RSS.
4. PoN/W1/PQ system conclusions, external service, whole-chain post-quantum qualifications and all HOLD/FAIL/NOT_RUN receipts remain unchanged.

**Scope of this PR: exact-byte source custody and four standalone sanity tests only.**
