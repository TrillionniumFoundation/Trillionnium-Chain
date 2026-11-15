# Complete-validation throughput continuation

This continuation starts from `362fbebe5027d731f16c88f710bfef7e922cd230`
on the existing integration PR #688. It preserves the original four-second,
F0, campaign, CPU, Host and independent-client verification gates.

## Changes and bounds

- Persistence merges two ordered borrowed State iterators. It still visits every
  union key and invokes each original checkpoint, compares canonical delta bytes,
  writes the same rows and completes the same transactional readback. The walk is
  O(N), with no temporary union tree or repeated per-key searches; it is not O(k).
- Generic History uses inline fixed-width record fields over the identical SQL
  CTE and full ancestry walk. It preserves type/width error precedence, all
  ancestor checks and cancellation. Indexed public/PQ History is a separate path.
- Explicit PQ caller authentication retains eight exact canonical ML-DSA public
  key expansions in the original intake epoch. Every signature is verified and
  every attempt remains charged. The retained material is not an authority or
  verification-result cache.
- Continuous public Submit reuses its already encoded immutable Packet when
  computing the scope digest. The later receiver, policy, nonce, CPU and final
  binding checks remain independent and in their original order.

The new differential controls cover original output bytes, ordered deltas,
absent/null values, SQL type and shape errors, foreign SQLite mutation, exact
SPKI/pin binding, fresh messages, invalid signatures, bounded churn and optional
material-lock contention/poison. Original tests remain.

## Measurements

The existing PQ Node workflow explicitly executes these ignored observations in
its original compiled test profile on head and actual merge for x64 and ARM:

```text
store::history_page::tests::inline_record_tests::history_inline_record_complete_call_cost
ingress::public_v3::pq_identity::verifier_cache::tests::pq_caller_authentication_complete_cost
```

The second selector requires `TRNM_PQ_AUTH_COST_DIRECTORY` to be a nonexistent
child directory; the existing workflow uses its retained command-record directory.
The state delta observation runs in the ordinary complete Node library suite.

Both observation arms use the same executable and exact inputs, retain original
validation/accounting, and alternate their order. No timing-ratio assertion grants
acceptance. Component timings exclude independent stages stated in each output;
none is a confirmed TPS, WAN capacity or release qualification.

## Initial failed attempt

The [first-attempt record](first-attempt.json) retains candidate `ed7d45a9`,
the actual ordered merge, failing jobs and the formatter's actual diff. Two
pre-existing inline source guards still pointed at the base store/History blobs.
The guards stopped recent-batch before native execution; the repository check
also rejects such drift. A separate original branch-encoding job reached rustfmt
and reported whitespace-only corrections in three new/modified files.

The correction updates the expected literal blobs to reviewed source, preserves
both comparisons and every original test, and applies the actual formatter output.
The initial failure is not replaced with a passing result.

Base preflight and two locked Linux metadata graphs ran before local executor
loss. New code is validated only by its own exact-source hosted outcomes. Until
those terminal records exist, new component/native/throughput outcomes remain
unverified. Original business failures and all existing HOLD exit conditions remain.

## Same-operation projection and shorter read critical section

The composed continuation preserves the concurrent W1/cache/cohort changes in
`bbcb3804576b9eb0b908eb3054bedccc189fb7ef`.

A cold complete-commitment calculation returns its already parsed account map
bound by a private lifetime-bearing object to the same immutable State. Only the
ordinary unscoped verifier consumes it. A complete-cache hit lends no map, and
readback-scoped verification keeps its existing path. Full current SQL graph
reads, comparison, aggregate checks and every progress callback still run.
Native differential controls count actual parser calls and visited State rows,
compare all cancellation points, mutate current SQL nodes after projection, and
check exact-state binding, malformed accounts and root-error precedence. An ABBA
observation includes the complete `verify_state_with_cache` call; it remains a
component observation, excluding Node admission, networking and confirmation.

Public History drops its Node guard only after the complete original indexed
read and next-ID checks. Owned Packet values plus the bounded immutable encoding
profile, context hashes, fixed tip and cursor are enough for grammar re-encoding,
hex and Page JSON. Original deadline/stop/CPU progress checks guard formatting.
A deterministic native test pauses formatting, commits a heavier fork through
the real Node writer, and compares the still-fixed-tip page with the held-owner
reference. Byte/error, fresh foreign corruption and cancellation controls remain.
The separate test-only SQL snapshot and authenticated PQ durable replay paths are
not promoted or changed by this response-formatting optimization.

Native compilation and exact-source outcomes for the full composition are
required before reporting any of the new controls or timing observations as PASS.


## Frozen hosted observations now read back

The [f35 component readback](measured-f35-components.json) binds all four lanes
of run [41752900431](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41752900431)
to `f35ee6dc61feaba7c68b16e1f9384b5c3794a976` / its actual ordered merge and
shared tree `87870eb9fc3d6477ee35e59334ccdbb669721777`. ZIP size/digest,
command-log digest and source identity were checked. The following head-lane
medians are milliseconds, with reference and candidate in the same binary:

| Actual component | x64 reference → candidate | ARM reference → candidate |
|---|---:|---:|
| Delta discovery, 65,536 keys / 2 changed | 18.139 → 1.204 | 22.085 → 1.297 |
| Complete state validation, 1,033 keys | 67.743 → 66.983 | 198.863 → 198.038 |
| Generic History complete call, height 257 | 5.344 → 5.313 | 9.283 → 9.183 |
| Complete PQ caller authentication, one warm key | 5.570 → 0.800 | 5.406 → 1.772 |
| Complete PQ caller authentication, 16-key churn | 5.543 → 5.888 | 5.407 → 5.408 |

The delta-discovery gain excludes roots, SQL, progress callbacks and confirmation.
Account parsing decreases from two passes to one, but the complete validation
benefit is small. The History effect is small and mixed; ARM height-one samples
regress. The x64 churn case regresses by approximately 6.2%. All these cases are
retained, with their actual sample counts and scopes. Three complete f35 Node
lanes passed; ARM head failed the then-existing ready-marker race. Passing cost
invocations do not erase that failed complete lane. These historical values are
not copied forward as measurements of later source.

The [44d3 service readback](measured-44d3-service.json) separately binds actual
F0, campaign, W1 pressure and regression outcomes to
`44d3def32f515b98fc41f074fe1b88e97f046191`, tree
`f3e07fc21a74e9a4367610ba10f5883213609320`:

- F0 is **1/6** confirmed in its original window and **0/6** under the unchanged
  supplemental four-second target measured from scheduled start. The latter is
  a separate SLO readback, not the original F0 native assertion. Two rounds are
  observed but unconfirmed; three are
  unobserved. The first confirmation is 27.298 seconds after its scheduled start.
- The original three-run campaign is **3/27**, with nine observed/unconfirmed and
  fifteen unobserved rounds. All three native invocations fail their original
  criteria; five hostile phases retain `PUBLIC_REQUEST_DEADLINE`.
- The original and fresh-challenge W1 pressure observations have zero pressure
  confirmations. A zero native exit from the original invariant probe still
  fails the wrapper's independent `CONFIRMATION_TARGET` acceptance check.
- The fixed public receiver and independent verifier share **0.25 CPU** and
  2 GiB. Throttled periods are observed. These are not unrestricted four-core
  machine measurements or WAN results.
- Baseline client graph verification takes 62 calls, approximately 17.94–18.31 s
  wall / 4.04–4.11 s calling-thread CPU. More than 82,900 fresh Host checkpoints
  occur per baseline. These nested stages must not be added. Actual SQLite
  `Transaction::commit` API intervals total only 17.7–96.2 ms in these campaign
  baselines; that API interval does not include all publication/readback work.
- Exact node decode material already hits 67,874 of 68,002 calls. All these
  service phases perform **zero PQ caller-authentication attempts**. More decode
  reuse or warm PQ authentication gains cannot explain away the service deficit.

The CI snapshots in that file are explicitly time-bound. The retained 05:54 UTC
snapshot has three terminal PQ lanes; the separate 06:04 UTC follow-up completes
all four. Each has 980 passed / 0 failed / 26 ignored and successful strict Node
`--lib --tests --all-features` Clippy. The [current four-lane component matrix](measured-44d3-components.json)
keeps the 44d3 paired measurements separate from f35 and all new local observations.
The original workspace CPU lanes compiled all workspace targets, then executed
50 named controls each. They did not execute every workspace test. The branch
encoding cargo module itself passed 6 controls / 2 ignored, but its stale
5-pass/1-ignored guard failed; concurrent commit `a10c3902` repairs only that
registration and its pin. Original service failures remain independent facts.

## Further complete-input materialization changes

The next composed source uses a private path/depth/digest subtree for complete
account-root calculation. It omits storage-record encoding and content-ID
calculation only where neither is used by the root. Actual stored `Node` records,
SQL graph reads, identity/shape checks and all original callbacks remain. Tests
compare with the retained record-building root and an independent full sparse
relation, including warm field changes, malformed internal shape and cancellation.

M06 can share a prior canonical map during unchanged checked-snapshot preparation
after a complete current-byte comparison, original budget/workspace accounting,
empty-delta tree validation and final expected-root comparison. An initial hint
is never accepted as unchanged State. A first mismatch immediately returns to the
original complete preparation, preserving late canonical-error priority. A late
mismatch can still cost an extra comparison; both mismatch locations are measured.
No database validity, stored row, graph or transaction verdict is cached.

The existing original-workspace CPU workflow requires all six new M06 controls
and all three new account-root controls by exact selector. The PQ component step
also explicitly executes both new ignored observations with its original profile,
source recorder and budgets. Full Node, strict Clippy, corruption/reorganization,
original Host, W1, F0 and independent-client confirmation gates remain required.
The new calculations still inspect complete input. They do not establish O(k)
execution, a stable independent read transaction, four-second acceptance or public
throughput. New-source local and hosted execution are recorded separately below.


## New local component evidence and retained regressions

The [local inventory](local-components/inventory.json) hashes the raw command
logs, paired observations and derived summaries. This is uncommitted component-
input evidence, not a frozen whole-source or public-service acceptance. The
account-root binary's optional SQLite I/O boundary was explicitly unqualified
because the initial local invocation bypassed the normal rustup environment.
The measured selectors exercise pure mathematics and never invoke that boundary.
Its status is recorded, not treated as qualified SQL execution. Subsequent
controlled storage integration is separate from these mathematical observations.

Six M06 controls pass within the retained `pon_commitment::` suite: **36 passed,
0 failed, 6 ignored**. The separate paired complete-binding observation executes
one exact ignored selector successfully. Three account-root differential controls
pass, and their separate exact ignored observation completes all 408 root
calculations with the expected independent roots. Root source fingerprints and
the test binary hash remain equal across that observation. Both code changes
also passed peer review for complete-input, error-order and authority boundaries.

| Paired complete component | Reference median | Candidate median | Scope / remaining cost |
|---|---:|---:|---|
| Unchanged binding, 128 keys / 64 B value | 0.107 ms | 0.063 ms | Complete current-byte comparison; cache eligible |
| Unchanged binding, 1,024 keys / 512 B value | 3.222 ms | 2.486 ms | Same existing cache/workspace ceilings |
| Unchanged binding, 4,096 keys / 512 B value | 18.705 ms | 13.578 ms | Still O(N), not a large-state full-root fallback result |
| First value mismatch, 4,096 keys | 18.337 ms | 19.938 ms | Early candidate miss then original complete validation |
| Last value mismatch, 4,096 keys | 15.585 ms | 28.051 ms | Approximately 80% slower; extra comparison remains |
| Account root, 1,024 accounts, warm | 1.658 ms | 0.637 ms | Private complete root mathematics only |
| Account root, 9,216 accounts, warm | 197.926 ms | 191.065 ms | Approximately 3.5% improvement beyond cache capacity |

M06 uses its original test opt-level 1; Node uses its original test opt-level 3.
Debug assertions and overflow checks remain enabled. State timing uses 12 samples
per arm, eight complete bindings and drops per sample. Account-root timing uses
ABBA/BAAB ordering, two independent caches per arm, two cold and 100 warm samples
per arm/size. Cold root samples show no clear gain. These are descriptive paired
observations on one shared environment, not independent-host confidence intervals
or p99 business latency. The two separate scopes cannot be added or multiplied
into a throughput claim.

The original state implementation's first-value miss regression is retained in
its initial raw log. The later early-miss change reduces that extra pass for early
mismatches but leaves late mismatches visible. A separate correction record fixes
the initial summary's base-commit/profile labels without changing the raw log.
All actual native service targets in the hosted readback remain failed; these
component results do not replace their required rerun on the new source.


## Local native integration with the original build fence

The [local validation record](local-validation.json) preserves exact command
output, component-input hashes, unchanged lockfile hashes, the later native test
binary identity and both qualified layout build outputs. Using the standard
pinned rustup launcher supplies the original compiler and normal loader context.
The runtime fence, source checks and native boundary were not edited to obtain
qualification. Earlier relative-compiler and incomplete-loader attempts remain
in the record with their actual unqualified status.

| Actual local execution | Passed | Failed | Ignored |
|---|---:|---:|---:|
| Complete M06 commitment module | 36 | 0 | 6 |
| Retained M06 commitment integration | 16 | 0 | 0 |
| Account archive and arithmetic, rebuilt native binary | 34 | 0 | 8 |
| Authenticated storage, including fresh SQL/corruption/recovery | 21 | 0 | 0 |
| Same-call current-account projection | 5 | 0 | 0 |
| SQLite transaction-scope controls | 13 | 0 | 0 |

Strict Clippy passes for both changed packages with `--lib --tests --all-features`
and `-D warnings`. The five retained source/negative-control suites execute 105
passing tests. The locked graph, unchanged lockfiles, formatting, all 389 pins,
301 required paths and generated source inventory also pass their checks.
Raw component logs retain their original bytes, including trailing blank lines.

These executions cover the changed algorithms and their relevant native entry
and storage boundaries. They are not execution of the complete Node suite on
this new source, the original fixed-Host service campaigns, an independent
operator test or a public throughput result. The existing head/actual-merge
workflows retain those original obligations and the failed historical reports.

## Parent readback and TCP-tail continuation: qualification remains open

The [parent-and-tail evidence index](parent-and-tail/README.md) records the next
continuation on b811. Its retained runtime changes are cancellation when additional
TCP input is observed after a complete request during Enqueue/Await, and
DirectAppend participation in the existing final-write transactional readback.
Complete State/W1 validation and final writer/generation checks remain; transaction
replacement follows the existing reorg scope-error escalation, so universal error
identity equivalence is not claimed. The two historical TCP runs and first append
controls keep their own source/ELF identities in that index.

The [parent-graph candidate](parent-and-tail/graph-candidate/README.md) is archived
and disabled after an unresolved physical-page ownership justification and a
10.79% small-account changed-state CPU regression. The independent
[M06 three-arm candidate](parent-and-tail/state/prefix-three-arm/README.md) is also
archived and disabled: its sole run passed sixteen of eighteen comparisons, but
two p95 regressions exceeded the original 10% rule. Defaults were restored and
negative samples retained. The [final CI wiring](parent-and-tail/ci-final/README.md)
declares 58 workspace selections; static wiring is not native execution. Final
default-source native qualification remains pending at this checkpoint and will
be recorded separately from these historical candidates.

The separate [clean b811 hosted readback](parent-and-tail/b811-hosted/README.md)
retains F0 1/6 and campaign 3/27 confirmations in their original windows, with
scheduled four-second results of 0/6 and 0/27. Baseline replay/commit deadlines
and the ROOT pressure phase with zero History/replay calls are distinct blocking
points. The [remaining conditions](parent-and-tail/README.md) preserve issue #639's
original four-second/16-worker gate, 4,105-block History, complete-state O(N) work,
and independent security/operator qualification. No full closure or activation
is inferred from this continuation.

### Final local composition after the concurrent History diagnostic

The subsequent [final native record](parent-and-tail/final-native/README.md)
supersedes the pending local-validation checkpoint above. It preserves the
concurrent `69d2e06c` diagnostic and binds 1,190 native inputs to manifest
`ccc0b180a702aa012bb24ca0541c9d91592239083c141e3a289f0345acf9df8c`.
Actual passing execution comprises 127 selected Node tests, the complete M06
library's 113 ordinary tests, and 13 original SQLite scope tests: 253 distinct
tests in total. The 58 workspace selections map to this execution as a subset.
Strict Clippy passes for the three components. Input and actual ELF hashes stay
unchanged before and after each recorded batch. The complete Node library and
the original head/actual-merge business gates are separate remaining obligations;
these local records do not supersede the failed b811 service observations.
