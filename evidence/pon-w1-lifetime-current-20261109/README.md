# Current W1 lifetime ledger observation, 2026-11-09

Status: **selected source identities and conditional arithmetic reproduced; security HOLD**. This successor is separate from the [original 2026-11-07 report](../pon-w1-lifetime-20261107/project-report.json). The historical report, its input and the fixed historical current-source observation profile retain their original bytes and rejection expectations.

## Exact source scope

The report's `selected_source_survey.base_commit` is [M8 `189b9b5959d836ef6ae96e14fb285948e4920aa9`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/189b9b5959d836ef6ae96e14fb285948e4920aa9), tree `35c9394cc41d4c8c5e555ba421311f0d5c1b1126`, whose parent is M7 `7ddfe2bfa480d1ebd91c07d03d56a963fff038c5`. Each of the 20 selected source pins was checked against that exact local Git object and the reviewed working bytes. The [ledger](../../scripts/w1_lifetime_ledger.py), controls and this successor report live in a later child of M8; the base field does not claim they were present in M8 or that a binary from the child has run. Full executed-source and binary identities require separate observations.

Only the lock entry changed within the 20-pin ledger roster. The selected `trillionnium/Cargo.lock` is 40,597 bytes, SHA256 `759c42c62d7b9a72d93c533039b5bf47f3508efabf1f1ee63f5eee59b9b9e55f`. The stale ledger declaration `3db3a086971106994f9e824df0bc64e8fa99cae22dc7bb8bd800643ee573b1ef` did not match M7's actual lock `f9e57d73899c5d9fabd4f5b4fedf45256b8db4efb448d15680d070bbcfcb30bd`. The original report instead records its own older lock `05cce83ab22c3085ff18ba8107b28bed70349fa56176784eab033897c282216c`; none of those historical values is relabelled as the new lock.

Compared with the original report, the successor also records the current
`store.rs` bytes and the two corresponding source-anchor locations. That store
pin was already present in the M7 ledger and is unchanged by this repair. All
differences between the two reports are confined to the selected source survey;
the lifetime arithmetic and independent acceptance objects are exactly equal.

The source survey still requires one locked `ml-dsa` version `0.1.1` with its `shake` dependency. Its current-source mapping, source anchors, bounded reads and three independent acceptance lines are unchanged. It does not execute the mapped Rust programs, establish exhaustive hash-use coverage, verify a receipt, or infer adversary query resources from native calls.

## Input, report and retained gates

[project-input.json](project-input.json) is an exact copy of the original unknown input, 6,107 bytes, SHA256 `a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89`. [project-report.json](project-report.json) is 31,311 bytes, SHA256 `8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0`. It retains null total lifetime queries, null project failure probability and target comparison, false qualification for all three security claims, and false production activation. All phases, shared-query budgets, all-null propagation, rational arithmetic, limits and failure-event treatment are unchanged. This report supplies no complete QROM, cheapest-legal-strategy or joint-consensus theorem.

The same 19 named ledger controls remain in the existing roster. Their source controls now also reject the actual earlier M7 lock, a changed lock byte sequence and a missing lock, and independently check all 20 selected pins against M8 Git blobs. Existing signature-source mutation, missing-source and symlink checks remain. The unknown-input control also compares the complete current report byte-for-byte. No test name, expected rejection, original service deadline, proof parameter or qualification threshold is removed or relaxed.

The [closure workflow](../../.github/workflows/pon-w1-qrom-closure.yml) reproduces and compares this successor report. It continues to require the complete original named roster and every required stage, with exact source observations before and after. A local report or test result cannot replace missing or failed hosted lanes.

```sh
python3 -B -m unittest discover -s scripts/ci -p 'test_w1_lifetime_ledger.py' -v
python3 -B scripts/w1_lifetime_ledger.py --input evidence/pon-w1-lifetime-current-20261109/project-input.json
```
