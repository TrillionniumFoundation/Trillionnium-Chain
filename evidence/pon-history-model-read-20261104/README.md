# History and model-state reads: scoped implementation evidence

Implementation: [`54594c0c80c4684f3c3aaaec8f8a8db286d74d2d`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/54594c0c80c4684f3c3aaaec8f8a8db286d74d2d), tree `e9316f487342dc02da5e7accbdb1c15c4ebb791a`. Sole parent: `01627151f3ab50750eac2adeb46d8883a601265f`; the existing PR #688 integration lineage is preserved.

**The three implementation fixes are verified within the ordinary local scope below. Overall PoN qualification remains open.** This record grants no public-service, fastest-producer, future-model or independent-governance acceptance.

## Changes

- M06 uses ordered prefix ranges for model/state reads. It still snapshots the complete matching base rows, overlays current writes and compares complete keys and values during MVCC revalidation. Empty, nested, Unicode and absent prefixes retain their original meaning.
- History snapshots only the immutable packet Config across unlocked work. It no longer deep-copies initial State and bootstrap material at each page/packet. The original packet grammar, network/parameters, repeated profile checks, error order, full W1/M06 verification, completion identity, cancellation and all Host/request/CPU deadlines remain.
- The V2 work-cost command preserves the reader's semantic failure status: nonempty semantic alerts return 1 after emitting the complete JSON. Explicit requested acceptance-gate failures retain exit 2 priority; ordinary reporting does not acquire work-hardness authority.

Nine new regression selectors were added to existing M04/M06/M17 responsibilities and invariants. No new qualification gate, consensus rule, signed domain, stored schema or acceptance flag was introduced. The 384 existing corpus pins remain; nine values were refreshed for changed inputs, and the original inline store pin now binds the actual implementation.

## Actual verification

All native execution uses Rust 1.95.0, the repository's original profiles, the pinned OpenSSL 3.5.9 provider and one test thread. Compilation uses four build jobs. This is an isolated x86_64 Linux workspace, not a pinned production-hardware performance trial.

| Scope | Actual result |
| --- | --- |
| New ordered-prefix unit controls | 5 passed |
| Selected History codec, completion, original deadline and PQ packet controls | 4 passed |
| Existing model evolution, evaluation quorum, incremental execution and complete commitment groups | 4 + 2 + 8 + 16 = 30 passed |
| Unique selected native total | **39 passed, 0 failed, 0 ignored** |
| Complete work-cost report controls | 57 passed |
| Source-integrity controls | 34 passed |
| Applicability controls | 37 passed |
| Python total | **128 passed** |
| Full-workspace, all-targets, all-features strict Clippy | Passed with `-D warnings` |
| Workspace formatting, repository/links, 384 source pins, source inventory, locked Cargo graph | Passed |

Repeated earlier passes are retained but not added to those totals. The complete workspace native suite and original F0/pressure campaigns were not executed by this continuation. No latency, allocation-per-call or throughput speedup is asserted.

## Source and failed observations

`source-and-results.json` binds the actual results, complete source snapshot and final implementation tree. The initial final-validation sequence retained 7,987 files / 929,309,500 bytes unchanged and stopped on an out-of-date corpus pin for the newly updated workflow. All preceding native tests and strict Clippy passed. The follow-up changed only that metadata pin; it passed all six follow-up commands with unchanged files. All Rust code is identical across this metadata correction. The four model/MVCC integration groups also passed on the final formatted Rust bytes.

The complete source snapshot before and after the initial sequence is byte-identical; its payload is retained once. Applying the single recorded metadata delta reconstructs the final file-hash map. Every final tracked file was read and matched to the clean implementation commit before this evidence directory was added. Six executable identities were captured **after execution only**; binary bytes and pre-execution attestation are not claimed.

Earlier observations remain original: the new CLI regression first detected return 0 instead of 1; the first complete Python run lacked an existing sparse-checkout fixture; the first format check required two layout changes; repository checking rejected the old inline store pin; and the first final source-pin check rejected the old workflow pin. These failures are not rewritten into passes. The original fixture was restored byte-for-byte from Git.

Command arrays, exits, durations and raw logs are retained. Timings include ordinary build/load effects and are not benchmark evidence. The fixed provider receipt records its own narrower preparation and smoke-test scope.

## Remaining PoN obligations

The existing [frozen be0 service evidence](../pon-six-axis-continuation-20261104/README.md) remains source-bound: 0/6 at its scheduled four-second SLO. It is not a test result for this new implementation. [Issue #639](https://github.com/TrillionniumFoundation/Trillionnium-Chain/issues/639) requires its own complete-service evidence.

W1 correctness is separate from the cheapest legal producer's actual cost. No GPU/ASIC/quantum lower bound, hardware comparability or cost-amortization closure is supplied here. The model path still replays the actual candidate, parent and four controls under its existing controlled-data policy; faster lookup is not prospective generalization or external usefulness evidence. Developer keys and signatures do not demonstrate independent administration.

Use `sha256sum -c SHA256SUMS` from this directory to check retained artifact bytes. The manifest includes empty successful formatting logs as such; it does not execute archived code.
