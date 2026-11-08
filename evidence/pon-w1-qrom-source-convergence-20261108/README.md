# Versioned QROM source convergence after bb026697

## Decision and scope

**HOLD remains.** This change repairs two reproducibility failures on selected
research inputs. It does not establish a complete QROM theorem, independent
cryptographic review, a deployed lifetime budget, complete source/build/load
closure, consensus authority, or qualification of the new Rust entry points.

The selected current source is
`bb026697a972521009bc133ae6ed2b653e18e931`, tree
`18175756871bf341586fc37be1b17a00ef1dd099`. The fixed historical implementation
contract selects source `cb114b13bf848a77634e40a08b31b30c7c758e7b`.
The local validation here ran an explicitly recorded **uncommitted patch on bb**;
the retained before/after manifests identify the exact changed bytes. It is not a
clean-source hosted CI receipt, and bb's separate native results cannot be
transferred to the commit that incorporates this repair.

The original hosted failures remain in `42508015708.failed.log` (implementation)
and `42508015884.failed.log` (closure). They have not been rewritten as passes.
`baseline-bb026697-01/` retains a fresh local reproduction on clean bb before
these edits: the v1 implementation suite exited 1 and the v1 CLI exited 2;
the semantics and lifetime generators returned 0 but differed from their
historical comparison files. The command receipt, stdout/stderr and exact JSON
leaf differences are retained.

## Implementation mapping: exactly two changed inputs

The v1 implementation contract pins 16 selected project files. Fourteen remain
byte-identical. Only these two inputs changed:

| Selected input | Historical bytes / SHA-256 | bb bytes / SHA-256 |
| --- | --- | --- |
| `formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs` | 9233 / `07415e8e3bb53f3e81dd489e4ebda63368170efbe4a217ae6b0dd6cc0af14128` | 11172 / `5e102fcbe4881e3d163c7a8b65364304b14d080ae64f23b0d5032daa84208aa7` |
| `trillionnium/crates/trnm-protocol/src/pon_wire.rs` | 32354 / `be816ee5b209098fa790d6e190d1d9c659634ac22d58b95c83dc8b49899c70cd` | 32654 / `ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b` |

`reviewed-source.diff` is the actual historical-to-bb Git diff for these files
and the lockfile discussed below. `source-review.json` records the old/new
identities and the two exact reverse edits for each changed source file.

The verifier change adds `native_once` and its `--native-once` dispatch. The
new function reads the complete input and an independently supplied header,
requires their header bytes to match, checks the expected artifacts, calls
`v2::check_complete_relation` once, and invokes the existing public-statement
binding. Its output explicitly keeps parent eligibility and admission false.
Removing that exact added function and dispatch reproduces the complete
historical `main.rs` bytes. This is a limited byte projection; it does not
qualify the new entry point, its runtime, or a build using it.

The wire change extends tags 2 and 5 with funded-service reservation/decision
decoders, retaining the legacy 80-byte and 64-byte branches. Reversing those
two exact edits reproduces the historical complete file. The remaining header
encoding and work challenge bytes are unchanged. This check does not prove
the new funded-service decoders correct or qualify the full transaction path.

### Explicit version boundary

The active mapping is now
`scripts/w1_qrom_implementation_audit_v2.py` with
`config/pon/w1-qrom-implementation-v2.json`:

- Contract schema: `TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2`.
- Report schema: `TRNM-W1-QROM-IMPLEMENTATION-AUDIT2`.
- The v2 contract has its own complete SHA-256 pin, selected-source identity,
  exact 16-file roster, and four pinned historical inputs.
- The v1 engine, v1 contract, v1 81-name roster and historical report remain
  unchanged. The v1 engine continues to reject the changed current sources.
- The v2 driver compiles the exact SHA-pinned v1 engine bytes into an isolated
  module. It does not replace any v1 globals, import a cached engine, or permit
  an unreviewed path/hash fallback.
- The v2 driver explicitly composes the report using the immutable helper
  functions. It reproduces the reviewed byte projections and recomputes the
  selected control, receipt, transcript and parameter mapping.
- After removing exactly five provenance fields (`schema`, `contract_sha256`,
  `source_base_commit`, `generator_sha256`, `project_files`), canonical JSON
  bytes must equal the historical report. This preserves the distinction
  between `false` and `0`, `true` and `1`, and integers and floats.
- The v2 `source_review` output is separately versioned. The workflow requires
  its entire field set, value types and values, including all three new
  qualification flags being exactly `false`.

The source-transition contract is a selected-input mapping, not a complete
checkout, dependency graph or executable identity contract. The fixed saved
receipt and guest bytes are historical inputs; they are not new proof trials.

## Closure comparison: provenance changes remain visible

The old semantics report is retained at
`evidence/pon-w1-qrom-semantics-20261107/report.json`. Fresh bb generation changes
exactly one JSON leaf, `/provenance/lock_checks/2/sha256`, for
`formal/pon-nakamoto-v1/w1_zkvm/Cargo.lock`:

- Historical SHA: `af7ee60b8f9f95c200d3dddac41b70c037e2bb3395122fe67ab20885140f247f`.
- Current SHA: `ed6ea70f20cbe45bf0bdef7f841adbdaa7c3b2a9838ffdfed64fa88f129b707a`.

The actual lockfile diff adds `risc0-binfmt` and `sha2` dependencies to the
local `trnm-w1-zk-methods-v2` package. Removing precisely that package-record
change makes the parsed lockfiles identical. The audit still checks its six
fixed upstream archive identities; its `whole_cargo_graph_verified` value
remains false. No image, memory, AIR, parameter, qualification or other semantic
report field changed. This is not evidence of whole-graph build equivalence.

The old lifetime report is retained at
`evidence/pon-w1-lifetime-20261107/project-report.json`. Fresh generation changes
exactly seven JSON leaves, all provenance from the already-reviewed store pin
maintenance: the survey base commit, two store anchor lines and their source
hashes, and the store file size/hash record. The probability expressions,
budgets, assumptions and qualification values are unchanged.

The new exact generated baselines are `semantics-bb026697.json` and
`lifetime-bb026697.json`. The closure workflow still uses strict `cmp`; only the
two comparison destinations change to these versioned current baselines.
The five formal-bridge comparisons retain their original destinations and
remain exact. No provenance is stripped from workflow comparisons, and no
historical report is overwritten.

The unchanged lifetime ledger still pins 20 selected files, including the
unchanged v1 implementation engine. Its 19 controls run successfully within
the original 105-name closure roster. That selected survey does not suddenly
cover the new v2 entry point; the v2 contract and its own negative controls
provide the separate, explicitly bounded source mapping. Neither establishes
the all-domain lifetime theorem or actual global query budgets.

## Internal review corrections and fresh execution

The review was internal code review, not independent cryptographic review.
Both reported weaknesses were reproduced against the then-current patch
before correction:

1. Checking only the transition review hash let the report-scope gate accept
   promoted or absent new qualification fields. The preserved
   `review-counterexamples-v2-01/` run has 25 failing subtests covering the three
   flags, missing values, numeric aliases, provenance/count/path changes, and
   an extra field. The corrected gate checks exact fields, types and values.
2. Python dictionary equality treated boolean/integer and integer/float aliases
   as equal in historical semantic conservation. The preserved
   `review-counterexamples-v2-02/` run has three failing producer-regression
   subtests. The correction compares canonical JSON bytes. This was a guard
   against producer regressions; it was not an untrusted-file bypass of source
   SHA checks.

`validation-v2-01/` and `validation-v2-02/` retain their earlier exact source
manifests and outcomes. The final frozen-source local validation is
`validation-v2-03/`:

| Actual execution | Final result | Scope |
| --- | --- | --- |
| Original workflow's extracted named runner, explicit v2 roster | 84/84, no skip | Original 81 named methods plus three transition/history methods; original method names preserved. |
| Actual implementation CLI, unknown/hypothetical reports and extracted report-scope gate | Exit 0 | Unknowns and explicit qualification boundaries preserved. |
| Original closure runner and independent completion checker | 105/105, no skip | Exact original roster; includes the 19 lifetime-ledger methods. |
| Native C kernel controls within those 105 | 8/8 | Builds and executes the small C kernel; includes seven arithmetic known answers, zero-code commitment and malformed-input controls. These are not eight additional tests outside the 105. |
| Fresh semantics, lifetime and five formal-bridge reports | Seven exact `cmp` successes | No field normalization or tolerance. |
| Source before/after manifests | Equal | Same dirty patch and same input bytes during the local execution. |

The final raw command records preserve argv, timestamps, exit codes and log
hashes. The extracted workflow code is retained with the outputs. The validation
controller is also retained, so the declared source scope and output ownership
are reviewable. The reviewed source changes did not require a Rust rebuild in
this bounded mapping repair; none was represented as having occurred here.

## Remaining blockers

All original proof obligations stay unresolved, including complete relation
and compiler justification, all recursion-program semantics, RBR knowledge
soundness, Merkle extraction, sponge/domain and Fiat-Shamir mapping, challenge
sampling, adaptive composition, real lifetime quantum budgets, concrete enabled
feature/build semantics, quantum work/chain weight and owner authorization.
All proof, signature, production and consensus qualification flags remain false;
quantum security bits remain unknown. This evidence can close reproducibility
and fail-closed mapping defects, not any of those proof obligations.

No separate source's successful execution, no ignored static-consumer test,
no modeled budget and no other-head hosted result is used to change HOLD.
