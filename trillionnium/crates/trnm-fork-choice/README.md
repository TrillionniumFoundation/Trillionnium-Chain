# trnm-fork-choice

Owner: M02. Pure PoN branch-choice candidate; no node, network or consensus activation.

This crate selects among persisted branch tips by strictly greater cumulative
required work. It does not decode blocks, verify work, execute state, persist data or
decide production readiness. `BranchTip` has no public constructor: a future adapter
must pass crate-private marker evidence established by M01 (full header/work/signature
validation) and M09 (artifact availability). Caller-provided booleans and unsigned
records cannot manufacture an eligible branch.

```bash
cargo test --locked -p trnm-fork-choice --all-targets --all-features
```
