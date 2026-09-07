# Foundation operation contracts v1

Primary module: M17. Producers and consumers: M02, M03, M04, M08 and M15.
Status: candidate operation documentation; semantic and implementation acceptance
are not assessed. This is a technical contract, not another engineering plan.

## Scope and authority

`config/documentation-operations-v1.json` records individual existing operations
alongside the module navigation in `config/documentation-contracts-v1.json`.
It does not replace that registry, reassign packages, or claim an exhaustive
catalog of every enabled operation. Its historical source observation is
`d120c992a144c566a105277bdcbff420a33ccccd`; the checker derives the actual reviewed
HEAD, tree and input hashes at runtime. A source observation is not a current
test result or an accepted release.
The TC-advance and expected-ledger records were added after that historical
baseline; their actual implementation identity comes from the checked current
source and input hashes, not from the baseline commit.

Resolve `docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md` first. Frozen
`bft-v0`, candidate `pcc1` and `legacy-ledger-observation` remain distinct.
The two M15 records document inert legacy session stages, not the complete
PCC1 signing/finality lifecycles. M04's Prepared acknowledgement advances a
peer replay boundary; it grants neither vote nor finality authority.

## Operation record

Each operation contains the following explicit fields:

| Field | Meaning |
|---|---|
| ID, module, requirements, profile | Stable operation identity and its applicable requirement/profile scope |
| Implementation | Concrete package, source function and explicitly selected Cargo features |
| Normative clauses | Existing exact document headings and the applicable rule; lower contracts cannot override frozen bytes |
| Schema, domain, limit references | Concrete source selectors; no invented wire tags or guessed operational limits |
| State | Authenticated inputs, preconditions, accepted/rejected effects, uncertainty recovery and publication eligibility |
| Errors | Existing error reference, outcome class and interpretation; wrappers do not erase nested error distinctions |
| Producers and consumers | Cross-module obligations; primary code ownership remains the coverage registry's decision |
| Cases | Actual Rust source test, exact test filter, expected outcome and selected assertion fragments |
| Independent vectors | Explicitly open; source-generated fixtures are not independently authored expected bytes |
| Open requirements | Remaining scope, mapping, integration or external-evidence obligations |

The current cases establish reviewable starting points, not exhaustive error
precedence, every parser offset, independent byte conformance or deployment
qualification. An input that is unavailable locally must not be described as
Byzantine invalidity. A possibly applied operation requires exact authoritative
readback before retry. No unspecified error, codec or platform gets a default.

## Recorded boundaries

| Operation | Boundary |
|---|---|
| M02-OP-VOTE-BARRIER | Core persistence acknowledgement before requesting and releasing a verified vote signature |
| M02-OP-TIMEOUT-BARRIER | The same durable barrier for a local timeout; no finality prerequisite |
| M03-OP-SIGN-EXACT | Exact intent, durable signature, idempotent replay and external watermark reconciliation |
| M04-OP-PERSIST-INGRESS | Durable pending peer frame before downstream authority admission |
| M04-OP-ACK-PREPARED | Exact Prepared receipt before durable replay-floor advancement |
| M08-OP-COMMIT-STRICT | Strict oldest-target finality proof and both verification passes before application commit |
| M08-OP-READ-STRICT | Committed application readback; a prepared record cannot be promoted by a read |
| M15-OP-RECOVER-SESSION | Exact complete legacy coordinator receipt before local session readiness |
| M15-OP-ADVANCE-VERIFIED-FACT | Private verified fact bound to the recovered predecessor before local stage advance |
| M02-OP-TC-ADVANCE | Strict TC admission, both verification budgets and durable Safety readback before returning the next-view timer |
| M08-OP-RECOVER-EXPECTED-LEDGER | Complete history and caller-supplied exact source/target validation before repair or cleanup |
| M08-OP-APPEND-EXACT-LEDGER | Fenced durable append with exact-target retry and fresh convergence readback |

Real producer commissioning, device custody, independent rollback anchors,
transport interoperability, nonzero epochs and complete checkpoint/receipt
publication remain separately scoped requirements. A source test may use a
reference coordinator, injected signature producer or in-memory watermark;
its case description and operation gaps preserve that limitation.
The TC tests use four local host instances with real SQLite and Ed25519, fixture
custody and an in-memory watermark. The `recovery-process-test-support` feature
adds six userspace panic/drop cuts around signature-release and view-advance
persistence, plus metadata-tamper rejection after each write. These exercise
exact source/target recovery and timer suppression, not SIGKILL or power loss.
Ledger CLI expectations come from the existing
source/target checkpoint files; they are not newly authenticated or independently
retained by this code. Neither test supplies an independent rollback anchor or
physical failure evidence. A live ledger also pins the checkpoint and record
digest at its previously observed sequence: a higher head cannot legitimize a
coherently rewritten prefix. The positive extension case retains that prefix.
Full-history ledger scans and its existing capacity
bound are retained, not qualified as scalable by these changes.

## Checking and replay

The existing `scripts/ci/check_documentation_contracts_v1.py` loads both
registries. It checks closed field sets, IDs, module/requirement/profile links,
real package/features, exact document headings, source selectors, actual test
functions, exact Cargo filters and selected assertion fragments. Every referenced
file joins the existing HEAD/tree and input-digest binding. It never executes
commands stored or generated from the catalog.

Direct test feature gates must be explicitly selected in the case; ignored tests
and unsupported direct cfg expressions reject. This bounded lexical check does
not evaluate inherited module gates or the complete Cargo configuration. An
actual replay must execute at least one test; a zero-test filtered success is
not passing evidence.

Source and assertion checks are lexical. They do not parse Rust control flow,
prove that an assertion is reached, or establish behavioral equivalence. The
generated command uses `cargo test --locked --offline`, an explicit package and
library, integration-test or named-binary target, explicit features and `--exact`.
Inline `tests` modules are included in the filter. Run it from `trillionnium`; retain real
command status and raw output through the existing evidence process. The
documentation report leaves every Rust case as
`not-run-by-documentation-checker` even when the documentation test suite passes.

`python3 scripts/ci/test_documentation_contracts_v1.py` exercises the catalog's
false-pass controls without invoking Rust, changing sources or issuing review
acceptance. The full checker still requires a clean committed source and the
existing manifest pins; worktree tests do not satisfy those gates.

## Acceptance boundary

A checked operation record is not an independently accepted operation. This
catalog retains `operation_catalog_complete=false`, open independent vectors,
explicit open requirements, and `not-assessed` semantic/implementation status.
The checker reports counts of operations and source regression cases, not a
completion percentage. Qualified producer, consumer and specialist review uses
`docs/modules/TRNM_INDEPENDENT_REVIEW_V1.md` and the existing authenticated
external-evidence process. Neither an agent-generated JSON value nor a passing
documentation test may claim that acceptance, release or activation.
