# PQ owner composition: retained local evidence (2026-11-03)

## Decision

**HOLD / NO-GO for whole-chain PQ qualification.** This record documents a scoped implementation and actual local verification. It does not change the six-domain claim guard or activate a node or production deployment.

The runtime patch is commit `87ee23243dbfa97c9e6cb7681da6510be3715d05`, tree `eb6bfbec239c51aa278812e4b1e09e6b08527c02`. The containing follow-up adds only child-failure diagnostics, the corresponding exact source pin, and this evidence. `receipt.json` binds the tested source files by Git blob SHA-1 and SHA-256; it does not self-reference an unknown future commit.

## Runtime behavior

- A client remembers its last authenticated checkpoint. A later response must advance its sequence or repeat the exact same checkpoint. A regressing sequence or a different root at the same sequence closes that client. Advances made by other authorized clients remain valid.
- An active exclusive durable-witness owner remembers its committed head. Its current/CAS operations refuse storage that no longer matches that head.
- An uncertain local COMMIT fences that owner until explicit reopen. A successful CAS updates its known head.
- Registration and ordinary predecessor shapes are checked separately. Malformed local checkpoints refuse before signing or transport and do not poison an otherwise healthy client.

These enforce existing schema and wire invariants; no signed namespace, DDL, business budget or 250 ms exchange limit was changed. The root still covers only its original three PNQ2 tables. This does not expand the root to account balances, History or Hepta authorization/install state, or solve simultaneous cold rollback of an independent witness.

## Actual verification

| Check | Observed result | Evidence |
| --- | --- | --- |
| Existing 37 required controls plus six new controls | 42 passed; one failed due to an environment restriction; zero ignored | `receipt.json`, `native-first.log`, `live-admission.log` |
| Six added owner/client/predecessor regressions | All six passed | `native-first.log` |
| Independent-process combined regression | Failed; diagnostic rerun identifies `UnixListener::bind` returning `EPERM` before service ready | `native-combined-diagnostic.log` |
| Node library and tests, strict default-feature Clippy | Passed with `-D warnings` and an absolute Rust 1.95 compiler path | `clippy.log` |
| Source integration / claim guard / authority surface tests | 34 / 22 / 11 passed | `source-checks.json` and corresponding logs |
| Exact source corpus | 364 blobs checked; result intentionally remains HOLD / NO-GO | `source-contract.log` |
| Six-domain claim guard | Passes its refusal controls; all six domains remain unqualified | `claim-guard.log` |
| Distributed inventory, formatting, diff whitespace | Passed | `inventory.log`; local command receipts |
| Locked Cargo graph | Original 26 workspace members, 174 resolved packages; lockfile unchanged | `receipt.json` |

The first native filter reports 38 passes and one failure. One of those passes is the no-op child-process entry point and is deliberately not counted as a meaningful control: 37 meaningful witness passes plus five live-admission passes equals 42. The failed combined test is neither skipped nor converted into a pass. Its original generic failure and subsequent diagnostic failure are both retained. Only child stderr is surfaced by the diagnostic change, so a nested libtest summary cannot inflate the parent's count.

The native build used the original default canonical RustCrypto ML-DSA provider. It did not enable the optional OpenSSL differential feature. It also emitted `trnm SQLite I/O boundary UNQUALIFIED: RUSTC must be absolute`; that warning is retained. A later explicit-RUSTC Clippy pass does not retroactively qualify that optional boundary in the test binary. The original GitHub workflow retains its independent architecture/feature/merge matrix and all 43 mandatory controls.

This local checkout preserves the original Git tree and the complete locked Rust workspace, but does not materialize every historical large evidence blob. This record therefore does not assert the full historical artifact byte check or independent deployment acceptance.

## Remaining system work

Hepta's protected clock/frontier, ordinary consumer profile binding, schema separation, and exact Chain source pairing are recorded in the paired Hepta PR rather than being inferred from this component. End-to-end production owners, all-state migration and rollback policy, proof-system parameters, complete W1 quantum work economics, public confidential transport, original CPU/History/business budgets, and independent WAN/failure/migration evidence remain separately required. No all-chain PQ-128 statement follows from these component tests.
