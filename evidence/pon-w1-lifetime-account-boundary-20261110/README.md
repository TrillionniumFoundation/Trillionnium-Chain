# W1 lifetime account-boundary source observation, 2026-11-10

Status: **selected source identities and conditional arithmetic only; security HOLD**.
This fixed successor is separate from the [2026-11-09 M8 observation](../pon-w1-lifetime-current-20261109/README.md)
and the [original report](../pon-w1-lifetime-20261107/project-report.json).
Neither historical directory is rewritten or relabelled as a new runtime cohort.

## Fixed source and retained failure

The selected source base is X `077ac4f33206de00a178553d9a0c729a20685088`.
The ledger's 20 selected source files were independently checked against those
Git objects. The current `store.rs` is 383,977 bytes, SHA-256
`d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca`.
The ledger and this fixture live in later commits; the source-base field does
not assert that the fixture or its test was present in X, or that a Rust binary
from a later commit was executed.

The ordinary ledger command actually returned security HOLD on source Y
`90ee47159e32e9014410a1823bed05d84c17b858`. Its recorded output is the exact bytes
of [project-report.json](project-report.json). On that same source, the existing
19-test ledger suite recorded one failure because its complete-report comparison
still selected the M8 report. That failed observation is retained separately;
this successor does not convert that run into a pass. The retained controls and
workflow must be rerun on the committed successor.

## Exactly seven reviewed differences

The new expected report was constructed from the old fixed report by the seven
literal updates below, then independently compared byte-for-byte with the
retained Y command output. Expected values were not obtained dynamically from
the implementation under test. All differences are within
`selected_source_survey`; every other field is equal, including the complete
`lifetime_ledger` and `independent_acceptance` objects.

| Field within `selected_source_survey` | M8 report | Account-boundary report |
| --- | --- | --- |
| `base_commit` | `189b9b5959d836ef6ae96e14fb285948e4920aa9` | `077ac4f33206de00a178553d9a0c729a20685088` |
| `observations.cumulative_weight.anchor_line` | `5142` | `5157` |
| `observations.cumulative_weight.sha256` | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` | `d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca` |
| `observations.native_work_verifier.anchor_line` | `1122` | `1124` |
| `observations.native_work_verifier.sha256` | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` | `d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca` |
| `sources[7].bytes` (`store.rs`) | `382866` | `383977` |
| `sources[7].sha256` (`store.rs`) | `108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554` | `d4623d65b74a5f7d875037dceeb1a9c3d2a4d957791d4b39514a14eb3a2b90ca` |

The preserved M8 report's SHA-256 is
`8ee20462d669a0e21b0fe964585f85fa2a49e7e58273459ab2501b4a2e39dfc0`.
The [unknown input](project-input.json) is an exact copy of the M8 input,
6,107 bytes, SHA-256
`a6e43a5c55e71154592a3489f566995e7961b91611e15d40a18a948a495f9f89`.
The current report is 31,311 bytes, SHA-256
`b050b861ec172305d708ba7c01ca47d547b1646cc3daee1d6aec9877d2cf3390`.

## Unchanged claims and stronger source controls

The same 19 named ledger controls and all their original arithmetic and
qualification assertions remain. The unknown-input test still compares the
entire expected report byte-for-byte, also pins the original M8 report hash,
and enforces exactly the seven fixed changes against that historical report.
The source test independently fixes X and the reviewed current store hash.
Changed or missing store bytes are rejected, and the actual earlier store bytes
are rejected using the M7 revision already required by the existing lock-file
negative control. The [closure workflow](../../.github/workflows/pon-w1-qrom-closure.yml)
retains its full-history checkout, all named controls, source guards and complete
`cmp`; it selects this current fixture without replacing either historical one.

The report keeps unknown lifetime bounds and project failure probability, null
project-target comparison, false qualification for all three independent claims,
and false production activation. Source consistency and conditional arithmetic
do not prove a QROM theorem, validate a native cohort, or grant whole-chain PQ,
resource-security, consensus or production qualification.

```sh
python3 -B -m unittest discover -s scripts/ci -p 'test_w1_lifetime_ledger.py' -v
python3 -B scripts/w1_lifetime_ledger.py --input evidence/pon-w1-lifetime-account-boundary-20261110/project-input.json
```
