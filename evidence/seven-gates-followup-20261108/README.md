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

## Acceptance boundaries

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
