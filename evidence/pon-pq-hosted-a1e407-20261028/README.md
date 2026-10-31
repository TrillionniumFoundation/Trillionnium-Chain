# Exact published PQ source: independent hosted Cargo replay

## Executed source and result

Published source `a1e40747746772d1326bb3e656aec4ba10440147`, tree
`f90cd9f63fce5fb785061419c9cb12b57ae24873`, completed two independent hosted
research jobs. Both verified all 5,951 tracked entries / 783,702,659 bytes
before and after execution with the same source and tree identity.

The [quota run 40611087331](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40611087331),
job `122562500027`, executed actual locked Cargo builds and **164 passing tests**:
46 M00 and 88 M06 library tests, eight dual-authority quota tests, two retained
authority/capacity tests, five NPQ3 node tests, nine NPQ2 node tests and six PQ1
node tests. The two libraries retain their original eight ignored tests. All
30 integration tests executed with zero failures, ignored or filtered tests.
The actual NPQ3 node suite took 40.48 seconds; this is the hosted suite's
execution time, not the separate 186.72-second Cargo build-and-test phase.

The [accounts run 40611087354](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40611087354),
job `122562499938`, independently repeated the 151 retained account/profile
tests, with the same eight original library ignores and all 17 integration
tests executed. These are repeated observations of already counted methods,
not 151 additional distinct tests.

Both jobs passed locked Cargo graph resolution, repository-pinned Rust 1.95.0,
formatting and strict Clippy for M00, M06 and the node with `--all-targets`,
`--all-features` and `-D warnings`. This closes the earlier local
manual-component-link limitation for these selected targets. It does not
qualify every workspace package or the remaining PQ authority owners.

## Complete retained evidence and independent readback

The original archives are [quota.zip](quota.zip), artifact `12782843853`, and
[accounts.zip](accounts.zip), artifact `12783651937`. Their published sizes
and SHA-256 values were checked during acquisition. All 26 quota and 24 account
members passed CRC, size and SHA-256 readback. Every manifest-bound artifact
hash and all selected source-input hashes were independently checked again.
The original compressed executables were decompressed and their complete ELF
bytes matched the recorded size and SHA-256. No local recompilation is labelled
as execution of these hosted binaries.

The [independent result receipt](verified-readback.json),
[quota member manifest](quota-archive-readback.json),
[account member manifest](accounts-archive-readback.json),
[complete quota job log](quota-job.log.gz) and
[complete account job log](accounts-job.log.gz) retain the actual evidence.
The archives contain all per-command logs, phase observations and source
receipts. Phase wall times are observations on shared hosted machines, not
isolated CPU, global worst-case cost, physical energy or TPS measurements.

## Separate recent-batch source-binding failure and repair

The separate recent-batch run `40611087330` failed before executing its native
tests. Its actual source check succeeded, then the workflow compared the new PQ
`store.rs` against a pre-PQ blob pin. The [complete head job log](recent-job.log.gz)
and [all sixteen original pin comparisons](recent-source-pins-before.json)
remain as failed evidence. The later missing-log error followed that early
failure; it is not a successful test run.

The [material review](source-binding-material-review.json) records all four
changed source objects and their complete preserved patches. They cover
explicit PQ store/profile selection and timestamp propagation; the exact
selected authenticated packet decoder; an explicit Packet import in existing
tests; and PQ1 state validation before cached root arithmetic. The twelve
other pinned objects are unchanged. The legacy packet decoder is still the
legacy dispatch; unsupported PQ namespaces do not fall back to it.

Only those four reviewed hash literals are synchronized in the existing
workflow. All sixteen guards, every original command/assertion, both source
lanes, both architectures and all resource limits remain unchanged. Pin
agreement grants no runtime or capacity acceptance; the new source still has
to execute that original complete workflow independently.

## Scope remains explicit

These jobs cover the selected account, transfer, registration, rotation,
migration-claim and dual-signature quota paths. Other transaction authority
owners, transport/custody/History/Hepta permission paths, complete workspace
qualification, independent migration trust premises and production activation
remain open. `p1_complete=false` and `production_activation=false`.
