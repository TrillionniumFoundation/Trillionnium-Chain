# Same-budget value-pool handoff

## Delivery and limits

The candidate changes exactly five tracked files against `bebb1f3289cd7050fefde89ea8f2cf33c6c37588`. The production change is confined to `trnm-protocol/src/pon_wire/state_root_arithmetic.rs`; the other four files are semantic regression controls. The code-only tree is `367bf61031f47fecc64123de644c3bf23b9d39b5`, and the complete patch SHA256 is `111bb65c0a066ea02a793f8138f5afabd7ad5cafbf79c171d04aafcbc827c3c1`. `source-freeze.json` lists each complete file SHA and blob identity.

No refs were pushed or committed. No manifest, workflow, profile, original CPU fixture, gate, Host checkpoint, SQL observation or default resource budget was changed. The two untracked `value_pool_component.rs` integration drivers are identical temporary measurement sources; exclude them from production integration. Their exact bytes are retained here for reproduction.

## Mathematical and accounting boundaries

A private immutable Arc owns one complete eligible plain-string encoding. Entries keep their complete key and original per-key key/leaf hashes. The private length/first-eight/last-eight index selects at most one allocation candidate; sharing still requires complete byte equality. A collision retains an independent fully charged allocation without replacing or extending the index bucket. It never supplies mathematical evidence or a leaf hash for another key.

All cold misses still run the original encoder and original hashes. All warm hits still require complete current canonical validation, exact key and full raw value equality. Validation/error precedence and the original wrapper are unchanged; no raw prehash/root constructor is exposed. Actual hashed rows and complete observed rows remain distinct under the existing v3 observation schema.

The original tree takes priority in the same retained pool. The builder does not credit an old value merely because it may be replaced. On successful finish, actual retained Arc allocation identities are charged once, only after an entry is accepted. Two equal-byte but independently allocated values are charged twice. Values kept solely by pending new keys survive old-entry removal and are charged in the new material. Error, abandoned builder and failed finish leave prior material/observation intact. The retained charge includes entry/key storage, the private value descriptor, boxed byte length, cached-charge storage and a conservative Arc header/alignment allowance. The 2 MiB bound is retained material accounting, not process RSS or a bound on all transient memory; the Node 16 MiB retained-charge limit remains unchanged.

## Functional verification

Original Rust 1.95.0 and the repository test profile were used, in an isolated target. Final source passed:

- Protocol arithmetic: 14 tests (9 existing plus 5 new).
- M06 root arithmetic: 9 tests (8 existing plus 1 new).
- Original M06 full-root arithmetic: 5 tests.
- Opaque-builder compile-fail doctest: 1 test.
- Node root arithmetic cache: 5 tests, no count increase.
- Node large-input cache: 2 tests, no count increase.
- Strict Clippy for protocol and M06, all targets, `-D warnings`.
- Rustfmt and tracked diff whitespace checks.

The first new Node count assertion incorrectly expected only the 2100 injected values; the original state also contains the string `model:current`. That failed run is preserved in `node-large-tests.log.before-count-fix`. The final assertion derives the complete eligible non-account plain-string set using independent serde encoding, and verifies the original model entry and all 2100 injected keys. It does not hardcode 2101, modify the fixture, or erase the failure. The final two Node controls passed.

Independent source review by state_history_audit found no blocker, including the final natural A/B/B collision-allocation test. This is not a claim that the final integrated workspace/CI has passed. Parent owns the broad wire test count adjustment from 22 to 27 ordinary passing tests (one ignored unchanged), source inventory/pins, combined integration and original gates. The M06 full-root selector stays at 5; Node counts are unchanged.

## Preregistered finite component campaign

The plan, identical driver, runner/analyzer, source trees and two distinct ELF identities were frozen before execution. Cargo artifact JSON confirms protocol opt-level 3, M06 opt-level 1 and driver opt-level 3, with debug assertions and overflow checks enabled. Five separately launched process pairs alternated AB/BA. Each process performed cold 1, warm 8, changed 1 and restored 1 for three cases and two actual public APIs, plus both prescribed failure cases for each API. All original encoding/derive work was inside the API timer; setup, independent original references, result validation/destruction and logging were outside and disclosed. Caller-thread CPU came from the existing Node rustix(time) dependency; no provider or manifest was added.

All 700 planned samples were retained: 660 successful computations and 40 expected errors. All 10 processes exited zero, with no timeout, unknown clock, missing sample, retry or exclusion. Complete input hashes, roots/errors against the independent original API and across variants, failed-input cache observations, exposed 2 MiB bounds, and before/after source/ELF identities passed. Private FullRootArithmetic charge is not publicly exposed and remains null in the measurement; it was not fabricated from another observer.

The preregistered statistic is the median of five paired candidate/baseline CPU ratios, with each warm value summing eight correlated calls. The repeated warm root ratio was 0.146361711 (85.36% less CPU under this rule); the complete M06 commitment ratio was 0.621036472 (37.90% less), including the original `encode_for_cache` and fallback work. All eight unique/collision cold/warm nonregression comparisons also passed their original 1.05 limit.

There is a material narrow margin: collision warm root was 1.049715288, just below 1.05. Its five paired ratios were 0.880399, 1.049715, 1.049754, 1.222894 and 0.868815. This campaign does not establish statistical independence, tail behavior or universal absence of regression. No extra runs or altered criterion were used to improve this result.

Repeated-state direct-root retained charge fell from 2,094,369 bytes / 445 retained strings to 455,566 bytes / all 2100 strings (459,720 bytes after the one-row change). Warm actual hashes fell from 1655 to 0; all 2100 current rows remained observed and compared. Unique/collision controls retain 438 entries rather than 445 because the new actual allocation descriptors/header are fully charged; this tradeoff is preserved in the data.

`benchmark-result.json` contains every paired comparison, changed/restored/error cost, setup, original artifacts and whole-process VmHWM; `measurements/` retains every raw stdout/stderr and execution receipt. `benchmark-result.md` is the compact table. The source-of-truth preregistration remains unchanged with `measurement_started: false`; actual execution lives in `measurements/execution.json`, not by rewriting the original plan.

This finite x86_64 component result does not close the original ARM CPU-quota failures, Host/checkpoint cost, 4-second service/import deadline or 30-second gate. The original ARM CPU profile must be rerun on the integrated candidate. The separate History importer hotspot remains repeated live Host checks within W1 progress, not this root-string workload.
