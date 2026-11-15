# Canonical ingress hex conversion on the current codec paths

Parent: `549c5a26616113c6aeee76a62f34dd780d729b75`. This adapts the narrow
[PR 708](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/708)
conversion idea to the current default, settings-selected and PacketCodecContext
paths. It does not copy the older ingress file or its historical qualification.

After the complete original lowercase-ASCII, even-length, 2,097,152-byte grammar
check, convert each already-validated pair directly. Preserve allocation after
validation, the 1,048,576-byte decoded bound, and the unchanged codec callback.
No work verification, context/configuration check, signature, Host check, deadline,
packet namespace or acceptance threshold is removed or cached.

## Actual checks

- Three new native tests pass: every ASCII pair (16,384 cases), Unicode and length
  boundaries, real packet/default/settings/context round trips, decoder-error
  equivalence, late-invalid input, and exactly-once/never-on-invalid callback checks.
- The complete `ingress::tests::` selection passes **54 / 0 / 1 existing ignored**.
  The three new tests are included in 54, not added again. Original Cargo profiles,
  Rust 1.95.0, locked dependencies and default features are retained. These are not
  all-feature PQ runtime tests or the complete Node/workspace runtime suite.
- Source pin/inventory checks pass (521 pins); 37 source-negative tests pass.
  Strict workspace/all-target/all-feature Clippy and final format/source checks
  are recorded in [the retained Clippy log](workspace-clippy.txt) and source binding. Clippy is not PQ runtime execution.
- Independent read-only review found no semantic regression in this narrow change.

Native output (terminal blank lines removed): [targeted](native-targeted.txt), [complete ingress selection](native-ingress.txt).
[Source/binary binding](verification.json) retains the exact ingress blob and ELF digest.
The first formatting command omitted `--all` and returned `Failed to find targets`;
no file changed. Corrected formatting completed before Node compilation; the final
source passed the original native test command. No Cargo profile was modified.

## Limited helper cost observation

[Harness](complete-helper-cost.rs), [all raw pairs](complete-helper-cost.txt),
[lossless rows and summary](cost-summary.json). The candidate function is copied
verbatim from the production source. Both the original hex 0.4.3 dependency and
harness were built with Rust 1.95.0 `-O`. Each measurement includes complete grammar
validation, allocation, conversion and destruction. Input/output equality is
checked before timing; eight alternating-order pairs are retained at each size.

Median paired fractions saved are 69.95% / 71.70% / 67.91% for decoded
128 / 4,096 / 1,048,576 bytes. **Two of eight largest-input pairs regress**
(pairs 1 and 6); no losing observations are removed or favorable reruns selected.
This small, noisy standalone experiment is not a nonregression gate, packet codec
benchmark, block p99, four-second confirmation, independent replay or WAN result.

## Reproduce

```
cargo +1.95.0 fmt --manifest-path trillionnium/Cargo.toml --all -- --check
cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked -p trnm-pon-node --lib packet_hex_decoder -- --nocapture
cargo +1.95.0 test --manifest-path trillionnium/Cargo.toml --locked -p trnm-pon-node --lib ingress::tests:: -- --test-threads=1
cargo +1.95.0 clippy --manifest-path trillionnium/Cargo.toml --locked --workspace --all-targets --all-features -- -D warnings
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_repository.py
```

For the helper-only comparison, compile the locked hex 0.4.3 `src/lib.rs` with
`rustc +1.95.0 --crate-name hex --edition=2018 --crate-type rlib -O --cfg 'feature="alloc"' --cfg 'feature="std"'`,
then compile the retained harness with `rustc +1.95.0 --edition=2021 -O --extern hex=<that rlib>`.
No native/service performance result is inherited from this harness or PR 708.
The original fixed-Host 4s/hostile-W1 business gate and every global qualification
remain open. No release, activation, merge into main or deployment is performed.
