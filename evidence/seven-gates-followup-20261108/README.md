# Seven-gate source convergence follow-up

This is an evidence index under the sole
[development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It is not a second roadmap or a production authorization. **All seven gates
remain HOLD / NO-GO.**

## Exact source lineage

[source-inputs.json](source-inputs.json) retains the original `7e044b6` unified
candidate, the complete #807 and #809 heads, the reviewed local fixes, and the
new Hepta pair `36d5eff44f4071bb1f250b1c7706dc690cf0a875`. The Hepta candidate
is four commits ahead of `f1785ca`, zero behind, with that exact merge base.
Its HEPLCP02 initial request freezes the owner-selected evaluation profile;
an old HEPLCP01 checkpoint cannot supply that field retroactively.

The Chain integration preserves the original candidate and both Cell inputs
as ancestors. The `content_v2` and `custody` modules both remain present; the
original PQ source roster is retained and extended instead of replaced by the
smaller side-branch roster. Frozen-profile checkpoint joining, complete model
and environment version binding, custody continuation, fair discovery and
bounded working sets coexist in this source.

The final Chain commit is recorded by each external, post-freeze run. A source
file cannot embed its own commit identity. Read the actual `tested_commit` and
`tested_tree` in each original receipt; a later evidence-only commit does not
change those observations. No result of #807, #809, #5357, `c66ffbdc`, or a local
input commit is promoted into a final integration pass.

## Concrete fixes

### Preserve failed command and source observations

The original command recorder can retain `exit_code=0` with
`status=record_failed`: an actual child completed but changed tracked source.
The old qualification reader used the zero exit while ignoring that failure.
It could therefore call the normalized stage consistent and report an Unknown
effect as committed when the supplied query record referenced that receipt.

The reader now requires the existing successful terminal status, an observed
integer native exit, no recorder error, and both complete original source
observations. It enforces head/prospective-merge relationships and compares the
actual tested Chain commit and tree to the normalized source pair. Contradictory
source, collector, or command states cannot complete a stage or resolve an
Unknown external effect. The original recorder and its source verifier are
unchanged.

The [retained controls](command-binding-manifest.json) include the first
10-method campaign (nine counterexample failures), the second internal review's
source/schema counterexamples, and the corrected 13-method campaign. The
original 48 qualification methods, four recorder methods and 151 CI contract
methods remain present. The new tests are added to the live repository-truth
lane without replacing the archived 32-command or 17-command runners.

This is an internal consistency repair. `RAW_OUTCOME_UNVERIFIED`,
`result_payload_verified=false` and `effects_verified=false` remain. It does
not authenticate a supplied receipt, implement a complete native outcome
adapter, observe production-loaded bytes, or prove payment.

### Reject local prepare before claiming a native task

`NativeGenerationStoreV2::prepare` previously claimed the task in the native
owner before checking journal capacity, duplicate task, context and anchor
generation. A deterministic refusal could strand a task in a journal that
could not admit it.

The same predicate is now checked while holding the original SQLite Immediate
transaction, before the durable claim. Journal replay uses that same predicate.
The claim still precedes durable journal append: a storage failure after claim
retains the original journal's ownership and recovery obligation. It does not
permit a new journal or operation ID to redispatch an uncertain effect.

The [effects evidence](../effects-performance-20261108/README.md) retains the original controls and all interrupted attempts. Two original-implementation controls reproduced the side effect. The input
implementation's service library ran 70 tests successfully. Its new real-Node
control and broad Clippy attempts were interrupted by SIGKILL; one earlier
attempt exhausted disk space. Those attempts are not native Node passes and
must remain visible until a separate final-source run completes.

### Restore the W1 lifetime entry point on the integrated source

The [W1 source-convergence evidence](../w1-lifetime-source-convergence-20261108/README.md)
retains the original initialization failure with zero tests, the reviewed
`store.rs` change, and the corrected original 19-method campaign. Nineteen of
20 selected input files were unchanged; seven exact W1-facing expressions and
methods were compared before rebinding the one stale pin. Every selected file
has a tamper control. This does not establish equality of all runtime hash
counts, a cheapest legal strategy bound, or a quantum resource simulation.

## Preserved input validation and local resource refusal

The [Cell input manifest](cell-input-manifest.json) binds the complete raw archive
for `c66ffbdc`: 450 library tests, 34 integration tests and 12 doctests completed
with no failures, ignored tests or filtered tests. All 51 required new test names
were found exactly once. These are input-source observations; the final source
requires a new run. The archive retains dependency-cache refusals, Clippy SIGKILL
and disk exhaustion. A subsequent small SQLite environment probe confirmed the
original absolute compiler and loader environment; it is not a Node test pass.

The root integration
[local repository-check observation](local-repository-check-observation.json)
also records disk exhaustion while the repository mutant suite copied its
fixture. The structural report completed, but the whole command failed and is
not a successful repository gate. A fresh final-source run must complete in an
environment with sufficient space.

## Fresh observations on the frozen pair

The [Cell final-source record](final-source-cell/README.md) and
[Hepta final-source record](final-source-hepta/README.md) retain new executions
for Chain `bb026697a972521009bc133ae6ed2b653e18e931` and Hepta
`36d5eff44f4071bb1f250b1c7706dc690cf0a875`. They do not substitute the input
commits' results. Cell ran 496 native cases and the five named Python suites
ran 131 methods. Hepta ran the original 39+3 exact names with fresh JUnit IDs,
strict source observations and actual 8 GiB / 2 CPU readbacks.

The Hepta archive preserves build-01 exit 2, native-01 source refusal exit 99,
and the successful native-02 recovery. Only the supported Nextest output-store
location moved outside source; the original profile and ordinary 60-second
watchdog were unchanged. The reported 5,400-second supervisor request is not
asserted to equal systemd's observed infinite RuntimeMax. Actual executable and
provider load closure remains unproved. These local component rosters are
separate from the original 32-command and 17-command Chain campaigns.

## Original release inventory refusal remains visible

The original 32-command runner rejected its `release-all-targets` readback even
though Cargo exited 0 and its sole Unix libtest summary is 55 passed, with no
failures, ignores, measured cases or filtered cases. Its immutable predicate
requires exactly 52. The [roster conservation readback](release-roster-conservation/README.md)
proves all original 52 names appear exactly once and the additional three are
exactly the complete-content controls already present in `7e044b6`. The release
crate, original runner and old manifest are byte-identical between `7e044b6`
and the tested `bb026697` source. The 55-item observation is Unix-specific.

This readback does not alter the original runner or 52-item manifest and does
not relabel the original 32-command result PASS. Native test outcomes, the old
collector refusal and complete campaign outcomes are separate facts.

## Current research receipt reader

The [current process gate repair](research-ci-fix/README.md) preserves three
actual research CI failures at `bb026697`. It makes the transparent receipt
reader require the producer's version-3 cancellation/deadline semantics and
keeps version-2 records behind an explicit historical replay interface. The
original 23 report controls remain, with eight additive controls and all 58
original native cases retained. This later code change does not inherit a
native pass from `bb026697`; the original failed workflows remain failed.

## Complete original performance and CI failure records

The [performance archive index](performance-audit-bb026697/README.md), its
[original campaign audit](performance-audit-bb026697/original-campaign-run-42508015918/README.md),
and [CodeQL/W1 failure triage](ci-failure-triage-bb026697/README.md) preserve the
original ZIP bytes as well as source/resource/ELF identities and raw failures.
The [publication inventory](performance-audit-bb026697/publication-manifest.json)
binds 378 files plus itself, 115,336,172 bytes, including all six original ZIPs.
Audit-time paths and download descriptions inside those records remain
historical observations; the copies here are the complete published inventory.
No Actions expiration is used as permanent storage for the original ZIPs.
The [raw whitespace observation](performance-original-whitespace.json) retains
the whole staged diff check's nonzero result: original timestamp/log lines and
frozen audit files contain trailing whitespace or blank EOF lines. Their bytes
and inventory hashes are preserved. The separate non-evidence source check
passed; it is not presented as a whole-diff whitespace pass.

| Original run | Retained native or collector outcome | Acceptance boundary |
| --- | --- | --- |
| [Three-run campaign 42508015918](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015918) | Three native exits 101; nine phases fail; 3/27 slots confirmed in the original 30-second phase windows | Strict scheduled-offset four-second projection is 0/27; 9 observed failures and 15 unobserved slots remain in the denominator |
| [Single F0 42509669473](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42509669473) | Native exit 101; 0/6 strict four-second slots; 1 confirmation within 30 seconds, 2 observed failures, 3 unobserved slots | First confirmation took 22.602926924 seconds; finalization inherits the native failure while all three owned services are known empty |
| [W1 service 42508015817](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015817) | Head and prospective-merge service lanes fail; original invariant selector exits 0 but its business reader refuses `CONFIRMATION_TARGET`; fresh selector exits 101 | Each baseline reaches its own depth-six target; hostile confirmation fails with `PUBLIC_REQUEST_DEADLINE`; sources and workloads remain separate |
| [CodeQL export 42508015975](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42508015975) | Twenty-minute wait ends after 39 successful but empty upstream responses | No matching analysis or check is available to export; no 403 is claimed and local retained SARIF is not substituted |

All observations retain their original quarter-core Host, 2 GiB, swap-zero,
PID and confirmation contracts where applicable. Build success, completed
accounting, ACKs, packet exposure, cleanup and record integrity do not establish
qualified business goodput. Full-population tails and sustainable business TPS
remain unknown. The high-frequency History/Host checkpoint observations identify
a cost investigation path, not a proven speedup or permission to skip current
resource, cancellation or full-state checks.

## Acceptance boundaries

The [M15 feasibility record](m15-feasibility-bb026697/README.md) retains a
complete static-build tool manifest, including 142 provider headers and the
original provider receipt, accepted by the original input validator. Two
separate runtime prerequisites refused the actual desktop: the unchanged
namespace command exited 1 at `/proc/self/setgroups`, and the original protected
single-link runtime-file predicate refused the existing libc with link count 2.
The [complete archive](m15-feasibility-bb026697.tar.gz) and
[execution plan](m15-feasibility-bb026697/execution-plan.json) retain all commands,
inputs, source identities and failures. Static build and the ignored isolated
Node case remain unexecuted; no artifact digest, permission change, altered
namespace or debug substitute supplies a pass.

| Gate | What this source contributes | Evidence still required |
| --- | --- | --- |
| Source convergence | One explicit Chain lineage and a frozen HEPLCP02 Hepta pair; original failures and rosters retained | Complete source/build/provider/executed-file and model identity at the same tested pair |
| Consensus | Existing W1 relation and lifetime accounting are preserved | Legal algorithms, preprocessing/reuse, task selection, quantum resources, time/DAA/credit joint argument and native migration |
| Permissions and effects | Local prepare refuses before owner claim; failed readbacks cannot resolve Unknown | All actual entry-to-effect paths, current revocation, independent fresh recovery anchor and reorg/Unknown nonduplication |
| Hepta iteration | Frozen evaluation profile and checkpoint-to-original-use join | Real training, independent evaluation, legal NoUpdate, payment, cold fetch, install/load and next-task adoption in one iteration |
| Cell network | Complete model/environment version, custody, renewal/repair planning and bounded working set | Independent operators/fault domains, real funded effects, WAN cold recovery and actual device loading after author/provider loss |
| Performance | Original time, confirmation, resource and attack contracts remain unchanged | Same-resource honest/hostile campaign with qualified goodput, full cost breakdown and tail latency |
| Whole-chain PQ | Fixed source corpus and explicit refusal of unsupported claims | Eight actual interfaces, lifetime composition, critical unknowns and independent cryptographic/implementation review |

The original four-second deadline, depth-six confirmation and quarter-core
resource contract are not relaxed. Development compilation concurrency is not
that business resource profile. Local tests and one administrator's hosts do
not establish independent operators, independent evaluation or independent
review. No deployment, key rotation, root change or FinalUse grant is performed.
