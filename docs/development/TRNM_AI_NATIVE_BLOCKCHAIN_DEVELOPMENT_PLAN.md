# Trillionnium Chain Development Plan — PoN / Hepta-PoH revision

Plan ID: `trnm-chain-development-plan-v2` (stable registry identity; content revision 22).
Effective: 2026-09-28; priority implementation revision: 2026-10-25. Status: selected development direction; no runtime activation.
Canonical destination: `refs/heads/main`; continuation uses the current main lineage, not retired PR #194.
Current source/head/tree/base and prospective merge are derived at verification time.
Assessed legacy baseline: `c552c31c6d3c5ac47522a124e02c6b8bca4e23f2`, tree
`c37858e60146147eccf1a6fec6eff04d00a828a7`; this is provenance, not a live-head claim.

Machine implementation truth: [consensus-mainline.json](../../config/consensus-mainline.json).
Selected protocol and transition: [pon-nakamoto-v1.json](../../config/pon-nakamoto-v1.json).
Technical contract: [PoN specification](../protocol/pon-nakamoto-v1/README.md).
Module index: [M00-M17](../modules/README.md); [source registry](module-registry-v1.toml);
[source inventory](../../config/portability-inventory-v1.json); [release train](release-train-v1.toml);
[manifest](plan-manifest-v1.toml); [snapshot](CURRENT_SNAPSHOT_V1.json);
[applicability](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md).

## 0. One authority and explicit retirement

This is the one active engineering plan. It owns sequence, work boundaries and integration
policy; the protocol suite owns domain rules and the module guides own implementation
contracts. There is no parallel PoCO completion roadmap or separate Hepta blockchain.
Git history is the archive. The development directory retains one regular Markdown plan
and small machine-readable companions, not historical symlinks or dated parallel plans.

The user's revised consensus decision supersedes the earlier keep-BFT proposal:
PoCO-BFT is RETIRED AS DEVELOPMENT TARGET. PoN is a Nakamoto-style useful neural-work
chain: permissionless work competition, target/difficulty, independent block validation,
cumulative verified work, forks and probabilistic confirmations. Consumption-weighted
validators, stake/evaluator-vote fork choice, QC/TC locking, three-chain finality and
joint validator epochs do not belong in the new consensus profile.

Retired consensus code, binaries, protocol files, fixtures and legacy appendices are
now deleted from the active tree. Only explicitly inventoried portable components remain.
History is available from Git, not an active compatibility directory. No legacy runtime,
proof decoder or fallback remains in the workspace. Portable local monotonic stores do
not grant PoN branch/undo semantics. The later native development Node owns its own
explicit branch namespace and cannot silently import those portable stores.

No machine flag is promoted. The current implementation projection is:

    stage = invariant-driven-native-application-candidate
    production_candidate = false
    production_consensus_activation = false
    public_testnet_ready = false
    release_ready = false

The registry keeps full runtime acceptance, work-profile qualification, cryptographic
security, public-model efficacy and activation unaccepted. This does not deny the native
development code and controlled entrypoints below. Source work and documentation may proceed now;
release requires their own real evidence, not completion of the retired PoCO roadmap.

### Reconstruction and upgrade order

#### Pure PoN work-package execution — 2026-10-27

The isolated History owner reconstruction continuation is recorded in
[the exact-source candidate evidence](../../evidence/pon-history-owner-next-20261027/README.md).
It retains the original resource/deadline/large-parent controls. Full W1 can
protect only its original CPU operation; exclusive embedding may continue its
same stack without a Node mutex, while shared held phases remain nonwaiting.
The retained >8 MiB held-parent counterexample keeps WP2B on HOLD until actual
native evidence closes it. Recovered embedded source bytes are not the lost Git
commit objects, and local controls are not WAN acceptance.

The next original campaign placement separates the receiver/History verifier
under the fixed 25% public Host from the original 400% producer/controller and
attacker processes. The lifecycle broker conveys only process requests and real
reports. The original 3-by-3 workload, all honest requests and depletion
predicates remain intact; the new Host placement still requires actual hosted
execution. [Host/scalar applicability and delayed-debit counterexamples](../../evidence/pon-history-owner-next-20261027/HOST_BUDGET_APPLICABILITY.md)
explain why matching nominal quota and refill does not prove either depletion
or its impossibility. No new resource profile is activated by that analysis.

The frozen continuation now has full tracked-source and executable bindings:
original History 9/9, scalar 57/57, seven inactive pages, poisoned-registry
fencing and five actual SIGKILL cuts pass their stated local controls. Both
original 8,625,548-byte State backends still fail the unchanged CPU budget;
the latest total CPU costs are 2.772 s (Legacy) and 3.581 s (Authenticated).
Crash receipts explicitly retain unknown debt and refuse fresh credit; known
debt recovery and restored service remain incomplete. Final source `fe43f7c7f`
keeps the exact measured library ELF and a separately rebuilt phase broker;
all Node targets/features pass strict Clippy. The new fixed-Host campaign and
independent WAN gates remain unexecuted. Full original failures, streams and
denominators are in the linked candidate evidence; WP2B remains HOLD.

The user's seven work packages refine PN0–PN5, without creating another
roadmap or activating a fallback. Freeze the exact relation and adversary
freedoms in [pure PoN work/security model v1](../protocol/pon-nakamoto-v1/details/PURE_PON_WORK_SECURITY_MODEL_V1.md)
before comparing implementations. Original source inputs for this execution
are native #498 `4b6b8a91b6dfe41fbd7f40f40b359d535c2c4251`, PQ #495
`6f4b9cae0dafcb0e6bc171e2aa9b8f630e74eca6`, and DAA #487
`84a0c697a3178eaee31ff9f60851a42c479b73f9`. Their ancestry and actual integrated
tree must be recorded independently; the labels do not imply integration.

| Order / existing owner | Required concrete evidence | Exit criterion |
| --- | --- | --- |
| 1 / PN0, M00/M01/M02/M17 | Complete W1 relation, unique work identity, preprocessing/hardware/quantum/network assumptions and exact weight rule | Every freedom and unproved assumption explicit; pure PoN has no implicit fallback |
| 2A / PN1, M01/M02/M17 | Complete-relation cryptographic prototype, native equivalence, real prover/verifier cost, size and tails | Measured benefit over full W1 without omitted relations or proof-randomness tickets; a measured regression remains NO_GO |
| 2B / PN1/PN2, M03/M04/M07/M15 | Original hostile matrix and all honest requests, same CPU owner, short critical sections, real SIGKILL cuts and settlements | Honest service meets original depleted-budget targets; restart creates no credit; physical crash scope remains separate |
| 2C / PN1, M01/M02/M17 | Existing DAA, branch-local ASERT and fixed-p/variable-work models with counterexamples and resource assumptions | Analytic query-cost models never count as real quantum attacks or native admission |
| 3 / PN0/PN2, M01/M03/M04/M05/M08 | Versioned PQ wire plus real native crypto, accounts/migration/nonce/reorg and network authorization inventory | Every production authorization path has one reviewed policy; optional research adapters do not close migration |
| 4 / PN3, M09–M14 and original Hepta owners | Publisher-offline retrieval, complete actual model closure, original install/readback, future task comparison and no-update | Actual measured improvement or explicit no-benefit result; byte transport cannot grant install authority |
| 5 / PN5, M04/M09/M15/M17 and independent operators | Preregistered multi-day WAN evidence, administrator/failure domains, complete failed/timeout/resource/confirmation denominators | All frozen cohorts and safety/service thresholds met by at least three genuinely independent administrators over at least 72 hours |

Implement these as isolated, reviewable changes in the existing integration
lineage. Native tests, research mathematics, local process tests, model
experiments, hosted CI and independent WAN acceptance retain separate results.
Keep initial failures and unavailable tests. No optional test adapter, source
scan, SHA pin, document change or successful proof promotes readiness flags.

The [2026-10-27 execution record](../../evidence/pon-pure-workpackages-20261027/README.md)
retains the actual results: W1's complete-relation CPU proof attempt timed out
at 3,600 seconds without a receipt; original exhausted-budget/confirmation gates
remain unpassed; M06's detached prototype is isolated because autonomous bounded
reconciliation is still missing. Real ML-DSA-65 verification does not yet migrate
the native authorization owners. Real publisher-offline model retrieval and
comparison produced a legal no-update result, while original Hepta owner CI and
independent WAN exits remain separately unqualified. Pure PoN and all existing
production refusal flags remain unchanged.

The subsequent [native PQG1/QTX1 account owner](../security/PQ_NATIVE_ACCOUNT_OWNER_V1.md)
is an explicit transfer-only candidate under the original M06 and M15 owners.
It checks both migration signatures, preserves all nonce floors and all four
liability classes as locked records, and does not authorize mining by an account
roster. The [new source/measurement record](../../evidence/pon-pq-account-native-20261028/README.md)
retains its first compiler failure, failed initial Node fixtures and subsequent
exact-source observations. Public account registration/rotation, actual imported
liability settlement, task/Cell/Hepta authorization, physical rollback and WAN
acceptance remain separate unpassed gates; WP3 is not closed by a transfer slice.

The initial 2026-10-20 audit amendment uses Chain PR #323 commit
`9bd8b20da68f0dc199aab78c27644ed004af7411` (tree
`9a408fd7d9446dca3b319337f4a10078469df426`) against main
`9fedf7ecbbe07177069c030592b4e03dcffebb81`. These are the inspected inputs,
not a claim about a future live head or an execution receipt for these edits.
The paired Hepta PR #2559 input is
`443692c1c16a031fbde1ca3ddf5be99770667d81`; its workflow still pins Chain
`4a79d1f5b538041ae9824ba3dfb2fe7aa051d88c`, so it does not qualify this
Chain candidate. Hepta's V8 development amendment at PR #2930 commit
`e5e98bda42a3236a93d67cf4804f72c1e461d141` is a separate design input,
not integrated product evidence. Re-resolve all sources before execution.

Preserve the current work relation, branch/recovery engine, single durable
writer and Hepta's existing owners. Reconstruct the interfaces where measured
cost or missing authority prevents the product, rather than replace the whole
system or add another supervisor. The native revision15 evaluation quorum,
revision16 full-parent model update, pinned task windows and configured-peer
Cell pilot already exist; their controlled regressions are prerequisites to
extend, not missing features to implement again.

The following P0/P1/P2 labels prioritize remediation INSIDE PN0–PN6; they
create no second roadmap or module. P0 blocks the corresponding safety or real
product-loop claim, P1 closes state/resource/integration obligations, and P2
extends independently operated public service and measured capacity. A P2
release prerequisite is still mandatory. Hepta's existing P0–P8 roadmap labels
remain delivery phases, not these severity labels.

| Priority / existing phase | Accountable owners and interface delivery | Dependencies and acceptance |
| --- | --- | --- |
| P0 / PN0 first | M00/M15/M17 plus Hepta control.engineering/kernel.evidence: freeze source pair, applicable head/merge checks, security disposition and original failures. | Named unresolved finding owners and current source/config/binary identities; successful analysis or document checks do not clear failed security/native gates. |
| P0 / PN1 | M01/M02 own W1 validity/effective work; M03/M04/M15 own attempts and bounded ingress; M17 owns qualification. Deliver I01/I02 in the existing verifier/resource owners. | After PN0, retain three separate verdicts: statement correctness, computational qualification and honest service under the original attack envelope. No minimum-cost or public-service claim from parity, queues or one finite pass. |
| P1 / PN2 | M00/M06/M07/M08/M13 own versioned parent/witness execution, durable roots, undo/replay and migration; M05/M09 supply bounded transactions/data. Deliver I03–I05. | After PN0, iterate with PN1 accounting. Signed transitions beyond 65,536 accounts must use bounded W/proofs, conserve liabilities and recover from faults. Complete-State reference success alone cannot close PN2. |
| P0 / PN3 real model loop; P1 closure integration | M10/M11/M14/M15 and Hepta learning.operator/eval/artifacts/plasticity, neuron.runtime, inference owners and kernel.operations compose I06–I10. M09 supplies bytes, never install authority. | Controlled work may start after PN0 while PN1/PN2 remain visibly open; public acceptance requires both. Three real lineage cycles use actual installed-parent readback and next-task execution; no-update mechanical success and beneficial-release efficacy have different verdicts. |
| P1 / PN4 | M06/M07/M08/M09/M10/M11/M12 and Hepta kernel.operations own five funded budgets, byte-time duties and original-operation reconciliation through I05/I08/I10. | PN2 conservation and PN3 exact operation/release identities. Actual locks/debits/meters, Unknown resolution/refunds and reorg funding replacement prevent double payment or repeated effects; inventory is read-only evidence. |
| P2 / PN5 | M04/M09/M13/M14/M15/M17 and independent operators: bounded discovery, custody renewal/repair, complete-path performance and recovery. Extend I09 only through reviewed versioned contracts. | Joint PN1–PN4 acceptance; at least three independent administrators/failure domains and a preregistered 72-hour WAN campaign. Meet each cohort's service, release retrieval, repair and recovery objectives, not only an aggregate. |
| P2 / PN6 last | M00/M07/M08/M13/M15 and existing governed release/activation owners rehearse source-preserving migration. | All predecessor exits and explicit decisions hold on actual binaries/profiles. No automatic activation, replacement consensus or authority promotion follows from a document or merge. |

Section 6 is the executable work breakdown for these same PN0–PN6 stages;
section 4 assigns their interface owners. Design and controlled experiments can
overlap after PN0, but acceptance follows the dependencies above. Parameter
learning, structural Cell changes, executable code releases and consensus
upgrades have different admission owners; a parameter reward cannot authorize
the latter three. Do not create an additional global optimizer, operation
journal or parallel implementation plan.
PN1 public-service repair and PN2 storage engineering may iterate together on
one frozen workload; neither stage may declare the other's missing result passed.

The acceptance dependency is PN0 -> joint PN1/PN2 -> public PN3 -> PN4 ->
PN5 -> PN6. Controlled PN3 and configured-peer storage development may proceed
in parallel after PN0, with their scope explicit. Within PN3, I06 export and
I07 evaluation precede I08 exact task observation; I09 complete release fetch
precedes I10 local admission/install/readback. Reuse Hepta's existing
[global plan](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/c38e7727220f32c7410f59083c5ea7878bbae078/docs/DEVELOPMENT.md)
and work-package owners; Agentd composes calls and creates no second store.

### Audit contract refinement — 2026-10-25

This amendment refines the existing PN0–PN6 exits and I01–I10 interfaces. It
adds no phase, consensus selection, runtime API or acceptance flag. The inspected
inputs were Chain `ef2a6958a6f3d8fdfaea25fbc58fb1ecd188134c` and Hepta
`07731d314366bb9215753d23355b3ebf6449b32b`; they are audit provenance, not
future execution pins. PN0 must resolve the actual two heads, bases, merge
objects, configuration and binaries again before testing the delivered change.

The [original native campaign on that Chain source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40120511847)
passed its three declared runs. Read-only audit verified all 910 artifact-list
files / 328,625,725 bytes in artifact `12591401163` and recomputed its three
phase derivations: 189 submission observations, 27 confirmation rounds and
three distinct prepared business transactions per run. All six hostile phases
observed real depletion, while seven of eighteen hostile confirmation rounds
overlapped observed depletion. This finite same-host PASS coexists with earlier
FAILs; it proves neither continuous saturation nor work hardness, independent
WAN service or the new churn cohort below. A changed document is no new run.

| Existing phase / interface | Next accountable delivery and predecessor | Required exit evidence |
| --- | --- | --- |
| PN0 / all | M00/M15/M17 and Hepta engineering/evidence owners freeze one source-pair matrix and unresolved security disposition before execution. | Actual commands, raw inputs/results, source/tree/config/binary identities and applicable head/merge CI; queued or absent checks remain incomplete. |
| PN1 / I01–I02 | M01/M02 compare complete legal work and DAA assumptions; M03/M04/M15 exercise real paid verification, ROOT failures and identity-capacity churn. | Separate correctness, computational-cost and honest-service verdicts under the original budget; supplemental cohorts and their overlap requirements follow the admission contract. |
| PN2 / I03–I05 | M06/M07/M08/M13 profile and remove full-State/history hot-path dependence through the explicit bounded-parent profile, preserving one durable writer. | Same-root execution, conservation/reorg/crash/cold-readback plus cost curves over accounts, touched keys, history and conflicts; report the old full-read path separately. |
| PN3 / I06–I10 | Existing Hepta export/evaluation/selection/TaskFlow/loader/FinalUse owners compose the ordinary real-model caller; M09 supplies the complete selected closure. | Three actual predecessor-bound cycles and next-task readbacks; no-update mechanics, installation and three beneficial releases receive separate verdicts. |
| PN4 / I05/I08/I10 | M09/M12 and Hepta operations reconcile actual funding, byte-time/repair and original physical effects after PN2 conservation and PN3 identities. | Coin locks/debits and measured service are distinguished from local reservations; unknown effects, reorg funding loss and exhausted lifetime slots never become refunds or fresh dispatch. |
| PN5 / I02/I09 | M04/M09/M14/M17 extend the configured-peer complete-loader path with bounded discovery, independent custody and repair after joint PN1–PN4. | At least three independent administrators/failure domains and the existing at-least-72-hour WAN campaign, with every named load/fault cohort meeting its frozen objectives. |
| PN6 / all | Existing migration/release owners drain, reconcile and rehearse only after the preceding exits. | Source-preserving migration, cold verification, rollback/recovery and the specific governed decision; no document, merge or model reward activates consensus. |

For each row, register the existing callable or explicitly mark the proposed
seam unimplemented. Its request must bind the original operation, profile and
source context, parent/release/task identities as applicable, local generation,
original deadline and finite CPU/byte/disk/worker reservations. Its result must
name the same request, checked facts, actual charged costs, durable completion
or typed refusal, and the owner of unresolved effects. These are semantic
requirements, not a common replacement wire format. Busy, Unavailable,
Deadline and Unknown cannot be collapsed into Invalid or a success Boolean.
An Unknown is reconciled through its original operation before another effect.

The authoritative detail remains in [work cost and DAA](../protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md),
[admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md),
[performance](../protocol/pon-nakamoto-v1/details/PERFORMANCE_ACCEPTANCE.md),
[Hepta handoff](../protocol/pon-nakamoto-v1/details/HEPTA_HANDOFF.md) and
[Cell distribution](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md).
Hepta's existing global plan crosswalk owns the same local module deliveries;
its P0–P8 phases are not renamed. Keep bulk training, evaluation and weight
transfer outside ordering except for bytes required by the explicit work
relation. Consensus confirms commitments; model quality, durable availability
and local execution permission each require their own evidence.

### 2026-10-23 convergence checkpoint within PN0–PN6

This checkpoint continues the sequence and owners below; it creates no second
plan or activation authority. The integration includes the reviewed #328–#334
follow-ups in the existing #323 lineage. Historical failures and earlier
source identities remain intact. The [convergence evidence index](../../evidence/pon-upgrade-implementation-20261018/native-rounds/pn-convergence-20261023/SCOPE.md)
separates actual native observations, tested overlay hashes and still-open exits.
Exact final commits, actual GitHub merge refs and paired binary identities must
be read from their own receipts. A source check does not execute acceptance tests.

| Phase | Concrete acquired result | Remaining exit obligation |
| --- | --- | --- |
| PN0 | Fixed Chain `96a98a635def8c13b2d4f234aa1daee59c57afa0` and Hepta `3e9efb15faa261a4dc3ffc3205cd259aaee41a3f` passed five actual native pair selectors with source/binary receipts. The subsequent request-local parent-reuse overlay passed four new native regressions, seven original ROOT-cache cases, the original three-backend payment/reorg case, strict workspace/all-target/all-feature Clippy, formatting and source-integrity negative tests. | The new integrated heads and actual merge refs need their own clean-source, binary and paired receipts. Later Hepta owner and dependency changes are not covered by the old pair. Hosted checks and unresolved independent security disposition remain separate gates. |
| PN1 | The unchanged cache-OFF ROOT supplement actually ran at `96a98a6`: 24 hostile actors caused real paid-credit depletion; baseline completed 21 honest submits and three confirmations. Under attack the first honest confirmation round started and timed out, with zero confirmations; the other two rounds never started. No hostile ROOT packet entered live/cold state and the paid CPU ledger reconciled. | This is an observed honest-service FAIL, separate from the three original cheap-proof campaign FAILs that lacked depletion. Request-local parent reuse is a narrower repair, not a passing replay. Minimum legitimate-work cost, structured/hardware advantage, original-workload service qualification and independent reproduction remain open. |
| PN2 | The ordinary growth owner and cold-copy regressions retain their earlier 59-case scope. The explicit release boundary case at `96a98a6` passed: 65,520 genesis accounts grew to 65,552 through 34 signed transfers, two reopens and one reorg, with six working keys and a 3,722-byte witness. The original `rust-baseline` job now requires this nonzero ignored-selector execution and its native export in both source lanes. | The seeded boundary observation is neither growth from a small genesis nor public TPS. New-source release receipts, history/catchup, retained-history/resource curves, future-owner capacity, physical-fault limits and joint PN1/PN2 service qualification remain open. |
| PN3 | The ordinary neural entry composes original qualification replay, CURRENT selection, verified payload FD, Unix FinalUse and durable inference control. The old fixed pair's five native tests include live growth transport and restart/reorg. Retained real training has three lineage generations, two evaluated comparisons and zero beneficial comparisons. | The subsequent signed ordinary-owner path needs final-pair execution. Synthetic task authorization does not establish actual eligible CURRENT, independently authorized ordinary model consumption or a beneficial upgrade. Those real model exits remain required. |
| PN4 | Payment readback preserves the historical claim while reobserving current branch membership; the actual signed task/reorg regression passed on all three backends, without adding a payment, effect or journal mutation. | A local claim is not a chain funding lock. Complete byte-time retention, repair and reorg funding replacement, independently metered budgets and economic acceptance remain open. |
| PN5 | Existing finite configured-peer Cell/TCR1 evidence and fault regressions remain bound to their actual sources and unsuccessful overall handoff outcomes. | At least three independent operators/failure domains and the preregistered at-least-72-hour WAN experiment, including retrieval, repair and recovery cohorts, remain mandatory. |
| PN6 | Private-copy rehearsal verification and bounded descriptor/receipt reads passed 14 focused cases; three original cold-observer failures were reproduced before repair, then the combined growth suite passed 34 cases. | Cross-context compatibility, owner drain/reconciliation, operational migration/rollback, predecessor exits and the existing governed activation decision remain required. Production activation remains false. |

The PN1 accounting denominator is precise: paid mutation CPU equals actual
`attack_submit` plus `honest_submit` owner CPU. The original cheap-proof
campaign's 7.5–9.0 seconds per hostile phase include honest submits. Read CPU,
attacker construction and independent client import remain separate. Those
three campaign verdicts stay FAIL: 189/189 honest submission observations and
27/27 confirmations succeeded, but no hostile phase met depletion qualification.
They are not evidence of failed honest confirmation in those trials.

The separate ROOT supplement preserves its original work, actors, budgets,
deadlines and resource envelope, with the optional rejection cache off. Its
attack phase measured 9,399,693,107 ns paid CPU; balance identity closed with
zero live owners, booked reservations, unsettled known-live CPU and in-flight
mutation CPU at shutdown. Full W1 verification passed for 149 requests; this
does not mean 149 blocks were admitted. The native tip stayed at seed height
and no hostile packet appeared after cold reopen. The only started honest round
ran from approximately 1.00048 s to 30.01571 s with 15 unsuccessful/timed-out
submission attempts and zero confirmations. State correctness and accounting
closure do not erase this observed service failure or establish caller fairness.

The parent-reuse repair keeps a freshly checked parent only within the same
admission request and held owner. SQLite data-version and same-connection row
mutation epochs fence reuse; foreign commits force the original parent recheck.
Current clock/context checks and the second cancellation/CPU checkpoint remain.
It does not cache authority across callers, change W1/budgets/deadlines, enable
the optional ROOT cache or alter the nonpreemptible commit tail. Four new native
regressions and the seven original cache cases pass on the recorded overlay.
Their PASS does not certify the unchanged ROOT campaign on a later source.

The PN2 profile remains explicit: submit and exact status are paid operations;
head has fixed metadata and the original control output reserve, but waits for
the same owner. Admission reacquires that owner after typed W1 and rechecks
current clock/context/parent/epoch. Postcommit activation retains its charged,
O(reorg-depth), nonpreemptible tail. The cold interface keeps its exclusive lock
and O(H) audit cost; its local 8 GiB main-file copy ceiling is not a total
disk/CPU/device-latency bound. Source recovery logs require ordinary writer
recovery before retry. Neither path grants install or final-use authority;
maintenance retains `accepted_task=null`.

The mandatory-owner signed regression reached the 32-distinct-future-owner union
with 62 transactions, 37 working keys, 12,910 working bytes, 33 proof accounts and
a 64,551-byte packet. A new reward address was excluded while an existing miner
could continue; refunds and maturity later released the constraint. This is
entry exclusion below the other ceilings, not permanent halt. An authenticated,
versioned reservation/due-owner design and conservation/reorg/migration evidence
are needed before changing the rule; raising the cap or redirecting rewards is
not its repair. The read-only capacity report grants no admission authority.


### Audit remediation baseline and acceptance records

The 2026-10-22 audit inspected Chain `8d56f2f173d3e870846cf1129d48647f2b84540a`
and Hepta PoN `c38e7727220f32c7410f59083c5ea7878bbae078`. Hepta Cell
`710ab6863054cbf2927d1b4caa4300e71dcea60e` is a separate design/source input;
its code is not silently part of that PoN pair. These are audit provenance,
not pins for executing future candidates or proof of integration.

Current-source [original campaign 39776374954](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39776374954)
retains three failed trials: 189 block-submission observations and 27 confirmed
rounds, with equal receiver/client state, but no genuine depletion in any of
the six hostile phases. The original artifact `12424909281` has 914 ZIP members;
all 913 listed files were length/hash-checked. Its prepared business bytes
contain only three distinct transactions. This establishes neither continuous
attack pressure nor public TPS; it is not an observed honest-confirmation
failure. Earlier 6/18 overlap observations below belong to earlier sources.
Read-only flow reconciliation found all six hostile phases above the 100 ms
depletion threshold, including a conservative between-sample lower bound of
232.852451 ms in the lowest phase. Delivered hostile dispatch CPU was about
0.188–0.193 CPU-second/second for from-zero and 0.230–0.237 for late-product,
below the unchanged 0.25 refill. The preceding challenge limiter and cheap
rejection workload therefore matter; reducing a threshold or treating a
reservation as spent CPU would not qualify the original failed trials.

PN1 now reuses the existing valid-W1/false-State-root public replay regression
for an explicit opt-in, three-request component cost preflight. The additional
fixture fixes the original four blocks/1,024 signed seed transfers, h4 parent,
first business transaction (nonce 1025) and one M06 worker. It remakes W1 after
changing State root and sends the same body through three fresh public
handshakes. Work/M06 stages, actual owner plus scoped CPU, settled debit,
unchanged SQL/native state and cold reopen are checked, with a separate legal
acceptance control. The old eight-transaction/genesis/two-M06-worker regression
remains. Preparation, all actual search attempts, encoding and independent
verification costs are retained; preparation totals include nested components.
See [PN1 component cost boundary](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md#fixed-seed-root-rejection-component-cost).
This preflight does not measure sustained arrival rate, honest overlap or
burst depletion. A later explicitly supplemental cohort must first freeze its
real offered workload and independent honest window, retain the original
front-door limits/budgets and account actual producer costs. Original three-run
FAIL, work-profile qualification and activation flags remain unchanged.

PN1 supplemental code now extends the same phase/actor owner with one separate
valid-W1/false-root cohort: one 30-second baseline plus one 30-second pressure
phase, 24 separate producer processes and the fixed h4/1,024 signed seed.
Original caps, depletion arithmetic, t=1/5/9 schedule and three depth-six
confirmations remain. Exact-body receiver Admission/CPU observations and wholly
contained signature-verified client ROOT replies are separate requirements;
global paid settlement, 24 complete actor reports and exact live/cold State
readback are mandatory. The prepare/execute selector uses the existing source,
resource and bounded-process owners and freezes a read-only binary before any
single aggregate 400%/16-GiB user-service run. After source `c61e2112` and its
immutable release binary were frozen, one separately authorized cohort **FAILED**:
baseline 3/3 confirmations; pressure 2/3, with final h25 Submit `FRAME_DEADLINE`
and receiver h24/events24 after the fixed window. Genuine paid depletion,
593 signed ROOT replies, 24 complete actors, all hostile packets absent and
known whole-domain settlement of 9,396,951,692 ns were observed; they do not
replace the missing third confirmation. No retry occurred. The failure path
missed within-service final resource/source snapshots; independent post-failure
raw source/hash and process/cgroup cleanup checks remain separate evidence.
Original three-run/six-hostile FAIL, PN1/hardness and activation verdicts remain
unchanged. See the existing
[admission contract](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md#fixed-seed-root-supplemental-cohort).

The next M03/M06 component, composed by the existing M15 Node, is an explicit, default-off
`Node::enable_local_root_rejection_cache` API. Only the final mismatch after
actual M06 and task-output derivation may retain an exact encoded packet with
its checked immutable parent/root and local source/profile context. Every
replay still verifies complete Work, current context/eligibility, actual State,
root/account graph, owner/mining/continuous gates and cancellation, and pays
actual CPU. The volatile cache has 32 slots, a 2-MiB software-retention cap and
30-second monotonic TTL; unknown/backward time clears and disables it until
owner reopen. It retains no acceptance, generic ROOT, cancellation, Unknown or
local-integrity error. This component has no public CLI/service activation,
new lane, budget or wire/namespace change, and excludes the growth-reference
executor. Local component tests do not qualify nonce churn, the arithmetic
research profile or PN1; the failed original and supplemental campaigns remain
failed. See the existing
[bounded rejection component contract](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md#optional-bounded-final-root-rejection-component).

The same supplemental runner now uses execution-report namespace v2 to retain
independent binary, source and live-resource after-observations on ordinary
native failure. Missing after-evidence cannot pass or replace the primary error;
the cohort remains claimed once. Original inputs/criteria are unchanged, and the
old c61 failure and its missing records remain unchanged. These launcher controls
are not a new pressure result or final whole-unit resource settlement.

A separate current-source freeze `f7795a3d72bb59d9f0625186d301fc3ce0dc028e`
then passed the same one baseline/ROOT supplemental cohort, with the optional
cache still off and the original inputs/limits unchanged. All 24 actors and
21 business blocks completed; the three depth-six confirmations ended at
5.967304544, 16.120909061 and 26.006862713 seconds, each with contained numeric
depletion and signed ROOT replies. Paid/settled owner CPU was 9,403,286,579 ns,
with known zero scoped CPU. Hash readback covered 152 original files /
57,416,786 bytes; independent closed SQL copies agreed on all current State
rows, tip/root, height25/events25/blocks26 and hostile-ID absence. All three v2
after-checks passed, and all 26 observed processes/original cgroup were gone.
Current source includes scheduling/native-arithmetic changes, so this does not
attribute the improvement to the unused cache. The generic finite-phase flag
is still false; the separately frozen ROOT predicate alone passed. Capacity
exhaustion, nonce churn, cheapest-work hardness, original campaign failures,
deleted-unit final accounting and three real model upgrades remain open under
their existing PN1/PN3/PN4 owners. See the same
[supplemental admission contract](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md#fixed-seed-root-supplemental-cohort)
for source/binary/report pins and retained capture limitations.

The historical audit source `8d56f2f173d3e870846cf1129d48647f2b84540a`'s
[CodeQL check 119818040273](https://github.com/TrillionniumFoundation/Trillionnium-Chain/runs/119818040273)
reports failure with thirteen high annotations. Independent disposition is
required; the alert count is not thirteen independently confirmed exploits.
That check does not scan or qualify the later 8caf/f779 source heads.

Each PN exit retains source pair/profile, accountable owner, actual caller and
command, frozen workload/thresholds, raw outputs, missing observations and
PASS/FAIL/UNKNOWN/NOT_RUN per claim. Documentation verification only verifies
the amended contract. Use existing evidence owners and records; no new audit
journal, status registry or successful receipt is created by these edits.

- **P0 real-model acceptance:** actual pretrained encoder/model forward,
  training and post-install inference are measured through ordinary Hepta
  owners. Each of three cycles binds the actual installed parent, candidate,
  declared test dataset, controls and actual next use. Task/packet, candidate
  fetch and install receipts are required for steps actually executed. A valid
  no-update records its reason and marks unexecuted candidate publication,
  submission, fetch and installation steps NOT_APPLICABLE in the versioned
  campaign record; existing strict receipt schemas are not silently extended.
  It retains and revalidates the actual parent and unchanged generation, and
  proves next-task loaded-model readback without fabricated settlement/load
  receipts. Already admitted or Unknown effects still require reconciliation.
  No-update does not waive the separate successful cross-node I09/I10 cohort.
  Adopted updates create a fresh generation; rejected/no-gain candidates earn
  no improvement reward. Three installed improvements on declared tasks require
  three actual measured gains and next-task readbacks. A separate claim of
  improvement on future tasks requires its own prospective efficacy result.

Controlled engineering tests may use existing public or previously seen tasks.
An unseen future dataset or independent data custodian is not a prerequisite
for the three-round mechanism test. Record the exact task bytes, versions,
exposure/reuse, controls and budgets, and report measured results on that named
dataset. Actual training, cross-node loading, installed-parent lineage and
next-task execution remain required. Evidence for future generalization or
longitudinal efficacy is a separate claim, not inferred from this test.
- **P0 work acceptance:** I01 correctness, effective-work assumptions and I02
  original-budget honest completion are separately accepted. Valid-work,
  invalid-work and setup/amortization costs, attempts, target and hardware are
  comparable; all failed/saturation-insufficient trials remain visible.
- **P1 state acceptance:** fixed touched/mandatory W and declared history
  cohorts demonstrate bounded hot-path reads/proof bytes/RSS while permanent
  accounts grow beyond 65,536. Include omitted/wrong-parent range proofs,
  zero-balance nonce retention, liability conservation, deep reorg, disk-full,
  process cut, cold readback and isolated source-preserving migration. The
  source424 full-State 65,537-account result below is a reference observation.
- **P1/P2 storage acceptance:** first fetch one real selected release through
  existing TCM1/TCR1 into the safe loader and next task under origin loss.
  Full base/tokenizer/layout/runtime/router/member dependency closure belongs
  to the versioned release owner; a TCR1 member set alone does not prove it.
  Then qualify three independent complete replicas, renewal and repair within
  frozen byte/time/funding budgets, preserving every retained release's roots.
- **P2 capacity acceptance:** preregister offered load, unique confirmed
  goodput, p50/p95/p99, cold/warm load, CPU/RSS/VRAM, storage and recovery
  thresholds. Cell counts, shape-valid metrics, nominal 25.6 slots/s and a
  transport-only DAG comparison cannot satisfy whole-system performance.
  Compare new ordering architectures only if measured propagation/fork loss
  dominates after state, verifier and owner-conflict costs are addressed.


### Subsequent audit integration readback

At the subsequent GitHub readback, the original Chain integration branch had
advanced normally from `8d56f2f173d3e870846cf1129d48647f2b84540a` to
`cc9b599515eb5a9a895174c80220c32de12c6b4f`. Its ordered parents are the captured
`da09b195d4c022aecfcc0cb2c8f0dc8fc9b5de3f` and that original integration head.
PR #328 preserves those concurrent changes through an ordinary merge; the
paired Hepta integration branch was still `c38e7727220f32c7410f59083c5ea7878bbae078`.
Earlier uncommitted/UNKNOWN observations below retain their original cutoff;
they are not the current published branch identity or a passing final-source CI
result. Current head, target-base, prospective merge and cross-repository checks
must bind the resulting new source pair. The controlled neural campaigns,
arithmetic profile, growth, discovery, retention and funded-service components
in this integration retain their own explicit profiles and qualification limits.
No original failure or missing ordinary Hepta installation/readback is waived.

### 2026-10-22 17:48 UTC component checkpoint — final-source gates pending

This checkpoint freezes the results acquired by **2026-10-22 17:48:22 UTC**;
it makes no claim about a later job or commit. At the **17:42 UTC** source
observation, job `1a164b43c1b-1b6abb-3231` read Chain HEAD
`da09b195d4c022aecfcc0cb2c8f0dc8fc9b5de3f` and MERGE_HEAD
`8d56f2f173d3e870846cf1129d48647f2b84540a`. All **4,305 tracked file hashes**
matched the completed Python controls' source-after snapshot, with no intervening
change. The actual plan SHA-256 was
`3e803b580120f31f6c3a306016b52d4fc830061af433f23598f950e740ae69c0`.
Both integrations remained uncommitted. This document update is subsequent to
that source observation; it does not invent the future commit or tree.

| Acquired result at this checkpoint | Actual evidence | Scope that remains open |
| --- | --- | --- |
| Chain focused v2, job `1a163fcc788-1b6abb-30ed` | **35 PASS**: flow 10, completion 10, native-budget 7, work-arithmetic 5 and campaign-entry controls 3. The top-level **1 ignored worker** is `native_budget_abrupt_exit_worker`; a passing parent test explicitly invokes it with `--ignored --exact` in both reserved/intent phases and checks exit 86 and reopen. Scoped formatting changed only the two declared campaign files; the subsequent full fmt check and Node/Crypto all-target/all-feature strict Clippy passed. Source bytes were unchanged during the checks. | These are finite component controls. The worker's top-level ignored count is not a claim that it never executed. Original r13 diagnostic 4 remains **FAIL**; the complete new-profile pressure diagnostic has not run. |
| Recovered Python request, job `1a1640fdabf-1b6abb-30f4` | The original key `pn-recovered-python-controls-v1-20261022` resolved to a completed native run: **63/63** CI/catalog, **111/111** runtime and **5/5** explicit CPU tensor controls passed; source bytes were unchanged. | The previous startup timeout and scratch socket EPERM failures remain historical evidence. Five tiny constructed tensor controls are not a pretrained-model run, new training campaign, independent evaluation or installation qualification. |
| Hepta v1 failure and isolated tool repair | Job `1a163ff12c4-1b6abb-30ee` actually failed at fmt because `uv` was absent, without changing source; all three test groups were **NOT_RUN**. A separate local tool environment then installed the repository-pinned **uv 0.11.3**; workflow/project/lock inputs were unchanged and the existing frozen lock retained **ruff 0.15.13**. | Tool installation does not reclassify the failed v1 job or grant test/Windows acceptance. |
| Hepta scoped v2, job `1a164b1c9d4-1b6abb-3220` | `just fmt` returned **0**, with no source changes; features **1/1** and the operator package **24/24** passed, with no detected early-return markers. Core-cwd was executing when last observed. | **Overall terminal result remains UNKNOWN** at this cutoff. The original retries-zero, case-count and source guards remain; no Windows run, complete owner suite or final cross-repository verdict is inferred. |
| CodeQL evidence recovery | All **13/13** original check annotations have unique exact-content candidates in the captured same-HEAD Rust analysis. The complete ablation-v2 `run.json` was recovered and its SHA-256 verified as `1fa16b9a372199811eb2962d81568a23a2af06b8cfe1316005ac71f1efa213f7`; independent review of its full logs was still in progress. | The authoritative check-to-analysis/upload/result link remains unproved. Original check `119747556533` remains **FAILURE**; content candidates and causal model ablation do not close the security gate or change the official model. |

The acquired records include `OUT/recovered-chain-focused-v2/result.json`
(SHA-256 `61d7bdd38b8ccc8580866b7575a29f2dc8506a772e5c3b21d94d9408b24b6731`)
and `OUT/recovered-python-controls-v1/result.json`
(`927802e73b38df503ccc08c3e5faf6e28e75d00b227ecbdbaa884aabcbb3e083`).
These local receipts retain their own pre-commit source scope. After normal
commit, the actual clean head/tree must bind the pending diagnostic, original
five CI lanes, GSC2/PGH2 and final cross-repository source-head/actual-merge lanes;
none has a final-source passing result at this cutoff. Later outcomes belong in
their source-bound execution evidence, without attributing them to this earlier
checkpoint. The retained 32-task gen2/gen3 comparison is controlled synthetic
evaluation, with independent/prospective acceptance false. No PN0–PN6 exit rule,
original failure, deadline or qualification flag changes: **qualified = false**,
and production, public readiness, independent installation, reward and activation
remain unaccepted.


### 2026-10-22 recovered integration readback — uncommitted candidates

This subsection retains the **earlier recovery snapshot**, before the second
acquired terminal readback. Its unknown 30ed/30ee/Python outcomes and interrupted
connection describe that earlier observation; the 17:48 UTC checkpoint above
supersedes current status without deleting any original failure or receipt.

Connection recovery allowed the previously unknown merge and subsequent local
integration steps to be read back. At the latest acquired Git state, **neither
repository has a new merge commit**. Conflict resolution and patch application
establish edited candidates, not a clean final source pair or completed acceptance.
The last health request again timed out at the MCP boundary; do not infer current
connectivity or a pending job's result from its successful submission.

| Recovered operation | Actually acquired result | Remaining boundary |
| --- | --- | --- |
| Chain merge, job ending `30d5` | The actual Git merge returned **1**, with three conflicts: `scripts/ci/check_ci_contract.py`, `scripts/ci/ci_job.sh`, and `scripts/llm_runtime_pilot.py`. The wrapper's earlier successful exit did not mean the merge was conflict-free. Actual input HEAD was `da09b195d4c022aecfcc0cb2c8f0dc8fc9b5de3f`; MERGE_HEAD was `8d56f2f173d3e870846cf1129d48647f2b84540a`. | This resolves the old UNKNOWN merge observation. It does not create a commit or establish a final tree. |
| CI resolution, job ending `30e0` | The five-file CI integration resolution was applied. | Native application is now established; the earlier scratch controls remain separate from original five-lane execution. |
| Hepta merge, job ending `30e3` | The normal merge of the captured `c38e7727220f32c7410f59083c5ea7878bbae078` into the local fe3 lineage returned **0** without conflicts. | This is an uncommitted merge candidate. The earlier fe3 **305 PASS / 12 skipped** and Core **10 PASS / 2421 skipped** do not qualify the merged c38 source. |
| Exact repairs, job ending `30e5` | Pilot resolution SHA-256 `bb9789a726a23ada00ae32d5ee34e97700c3a121ffe1130493a478136abf4035`, the SQLite-prefix repair, the `05` campaign-entry patch, and Hepta's test-fixture candidate SHA-256 `797f5abfe2e0ee83af0ce29d8fe570d5b644cd41c0f6881f69f0513f31c90e8a` were applied; `diff --check` passed. Chain had **zero unresolved conflicts** at that readback. | Neither repository was committed. Applying a source repair or test fixture is not executing its regression or granting a qualification. |
| First Chain formatting check, job ending `30e8` | **FAILED** on formatting in the two Rust files touched by `05`; source bytes were unchanged and **no tests ran**. | Preserve this failed check. It neither establishes a semantic regression nor counts as passing focused tests. |
| Chain follow-up, job ending `30ed` | Scoped formatting for those two files and focused v2 checks were started. | **Terminal result not acquired.** Do not count formatting or any test as passed until the actual logs and source guards are read back. |
| Hepta follow-up, job ending `30ee` | `just fmt` and the selected features/operator/Core-cwd checks were started. | **Terminal result not acquired.** No Windows execution, complete owner suite or final cross-repository acceptance follows from this submission. |
| Python controls | The start call timed out without returning a job ID. | **Submission effect and terminal result are unknown.** Reconcile the original idempotency key; do not start a new key and silently duplicate the work. |

The next required readback is the existing focused jobs and Python submission,
followed by actual Git status, source hashes and any failed logs. A clean final
commit, normal PR head/base/actual-merge objects, all original five CI lanes,
source-bound GSC2 and PGH2, full applicable Hepta regressions and both final
cross-repository lanes remain unestablished. No deadline, retry rule, workload,
failure, source check or PN0–PN6 exit criterion is relaxed by this recovery.
The original r13 diagnostic 4 remains **FAIL** and the separate arithmetic
profile has no completed campaign verdict here. All production, independent
installation, reward, release and activation qualifications retain their
existing false/unaccepted values.


### 2026-10-22 local integration readback — da09 / fe3

This subsection retains the **pre-recovery checkpoint**. Its UNKNOWN merge,
not-started Hepta merge, prepared-only applications and unavailable route are
historical observations. The recovered-integration readback above supersedes
only their current execution status; prior failures and source-bound results remain.

This local readback continues the same PN0–PN6 sequence and leaves every original
exit criterion open. It supplements the retained published-source observations
below; it does not rebind their results to later source. The last confirmed clean
Chain commit is `da09b195d4c022aecfcc0cb2c8f0dc8fc9b5de3f`, tree
`171022d13b3ed4059a28c567351bf20256c0f7a5`. The last confirmed clean Hepta commit is
`fe3c92ce534d96bd4b1ab2b325f6cce21b162cac`, tree
`e661cb41366ec0b0240396ac7087aae92a2b9e88`; its local branch was observed without an upstream.
Neither identity is a claim about an unobserved later HEAD or final qualification.

The normal Chain merge of captured `8d56f2f173d3e870846cf1129d48647f2b84540a`
was submitted as job `1a163d5d679-1b6abb-30d5` with `--no-ff --no-commit`.
Its terminal result and the current HEAD, index and working tree are **UNKNOWN**.
The runtime subsequently returned `tunnel_client_not_connected`. Hepta's captured
`c38e7727220f32c7410f59083c5ea7878bbae078` merge has not started. Recovery must first
read the same job and actual Git state; do not repeat the merge with a new key,
reset the checkout or infer a clean merge from these prepared document bytes.

`OUT` denotes the local evidence root
`/home/qian-qi/work/pon-upgrade-implementation-20261018/pn-closure-20261022`.
The recovery bundle's `LOCAL_BLOCKERS_CHECKPOINT_ZH.md` and
`actual-native-checkpoint.json` retain the acquired process results and source
guards. Local locators are not newly published repository receipts.

#### Source-bound observations and unexecuted successors

| Scope | Actual result | Qualification boundary |
| --- | --- | --- |
| Hepta fe3 original owners | Job `1a163616e70-1b6abb-2fe8` completed **305 PASS / 12 skipped** for Agentd and infer-worker-host on the unchanged fe3 source. The separately resumed Core run, job ending `3029`, completed **10 PASS / 2421 skipped**, using the original offline, retries-zero transition selectors after a locked dependency fetch. | These are completed results, not still-running work. Core test time was 0.362 seconds, with 367.6596 seconds including compilation; its log SHA-256 is `2d1666ea967d82b2343e0cb04bac00e0c147d7b2359061cb4f76d0f79899ed84`. The original missing-`console v0.15.11` failure remains. Neither run covers later c38 cwd-feature/platform changes, all Core tests, Windows execution or the final cross-repository pair. |
| PN1 original r13 service | Diagnostic 4 on clean `4bff85ff435cda64a66b3b25d0fa8a0715e3a604` **FAILS**: baseline **3/3**, from-zero **1/3**, late-product **2/3** honest confirmation rounds. Original report SHA-256 is `97561cf3ab3d13b97c75f30483cb23d0355fc95e76177f72febe49a8572055e4`. | The original 2-second client, 10-second work deadline, 24 attackers and CPU envelope remain. A complete W1 followed by an unfinished admission can lose same-epoch completion priority on ordinary replay; the first observed packet9 admission error is unknown, while its seven later budget refusals are directly observed. The committed packet5 replay recovers correctly. No marker, cancellation rule, SQL/graph check or original failed verdict is removed. |
| da09 arithmetic profile | Actual native controls: **14** new arithmetic-cache tests, **13** retained facts tests, **10** retained completion tests, **5** explicit-entry/real-TCP tests, three separate retained raw/product/abandonment selectors with **1 PASS each**, and **2** churn controls. Formatting, the locked 25-member graph and Node + Crypto all-target/all-feature strict Clippy **PASS**. | This is an explicit new profile; default raw r13 remains unchanged. Its finite facts cache retains computed trace/product, not acceptance. The profile and client/cookie bindings remain separate; these component passes are not a full hostile-service campaign or a least-cost work bound. |
| Arithmetic churn | With **64 slots**, **65** cyclic challenge keys and **130** calls, the actual control executes **66,560 tiles** with **0 hits**. | Passing this negative control proves the expected attack behavior, not resilience under arbitrary key churn. The 4 MiB retained-object limit includes actual Vec capacity but is not a process-RSS bound. Trace-only facts can evict another challenge's product; a fixed 24-packet benefit cannot replace this boundary. |
| Prepared new-profile service entry | `05-arithmetic-campaign-entry.patch`, SHA-256 `56b6d6a55c5ceb04f006960add7d04acf04dee18101a072232580b9f783ee370`, adds a separate authenticated-v1 selector with matching server/client/attacker profile binding. | Its three finite Rust controls and complete campaign have **not run natively**. Original pressure, all time/CPU limits, confirmations and depletion conditions remain; the original r13 selector, reader and verdict are not replaced. |
| Prepared CI and catalog readers | The five-file CI integration candidate passed **58** scratch controls. The independent SQLite-prefix repair passed **15** controls after eight real producer/validator catalog counterexamples ran red. Their combined candidate then passed **63/63** scratch tests (unittest time 97.351 seconds; complete command 97.577 seconds), with unchanged source bytes. | These overlapping suites are not 73 distinct tests. Combined log SHA-256 is `e36e936462f1c9411de696336234b658dd53b9dbc8f768d63ac8a04916ab3278`. No native application or original five-lane run is established. All local runtime controls and upstream parent-step/strict CI checks remain; three-backend source recognition does not grant PGH2 historical-evidence qualification. |
| CodeQL causal experiment | Isolated ablation v2, job `1a163cec57f-1b6abb-30bf`, actually exited **0** in 396.211 seconds and reported `causal_model_reduction_observed=true`. It used a copied model with four identified rows removed; original models, query and baseline were integrity-checked. | The complete v2 run/CSV still awaits independent readback. Original check `119747556533` remains **FAILURE**; complete alert mapping and independent disposition remain open. This causal observation does not change the official model, dismiss alerts or pass the source security gate. |

The new arithmetic profile is
`14ada27ef062b1e510b7d7ab470e83157e58e7752b8f27a754f64dac614146e3`;
retained raw r13 is
`c110c3ccb1e229c3a85f4819b1e087fa819c865b50f8bd3ab78d3b8f45206cb2`.
The cache bounds and charged fallback do not change native state, funding, nonce,
target or completion checks. Cancellation cannot publish partial facts; bounded
comparison/publication after the final cooperative check is not a hard-real-time
zero-overrun guarantee. Entry/completion/churn evidence is retained under job
`1a163c74b03-1b6abb-30b4`; strict checks under `1a163cecee9-1b6abb-30c0` preserve
before/after source equality. Strict Clippy log SHA-256 is
`661804f10d577e9dbd4361d9e10700b9a4c811ea61760536f62c80b27281b494`.
Job `1a163d4ba2d-1b6abb-30d1` checked all eleven changed source files before
committing da09 and observing a clean working tree. Later source needs its own checks.

The CI candidate keeps pilot, parent-material, upstream parent-step and the four
local runtime suites in the existing lane. The catalog fix uses the exact
`sqlite_` prefix, preserving real SQLite internal objects while refusing actual
`sqliteX...` user tables, indexes, triggers and views. Earlier red observations,
schema/compilation failures and the original CI/security failures remain evidence.

#### Stage exits still open

| Stage | Retained progress and remaining original exit |
| --- | --- |
| PN0 | Recover the pending merge and establish the actual clean source pair, normal PR source/base/merge objects, original five CI lanes, applicable security disposition and fresh cross-repository head/merge executions. The prepared final runners have not run natively. c38's new cwd behavior and non-Unix refusal need their own regressions; functional Windows evidence requires real Windows. |
| PN1 | Retain diagnostic 4's service failure, the conditional completion-replay defect and the independent late-product throughput deficit. The explicit arithmetic profile still needs its own complete unchanged-envelope campaign, least-cost measurements and adversarial churn/service assessment. A proposed cross-request continuation contract is not implemented or used to pass r13. |
| PN2 | Retain the source-specific GSC2 complete-State readback and earlier PGH2 **65,520→65,552** signed growth/reopen/reorg result separately. Final-source GSC2 **65,537** and PGH2 export/bounded-I/O/recovery checks remain unexecuted; full-State roots do not become bounded witnesses. The local growth observation in section 6 remains unchanged. |
| PN3 | Local campaign 5 completed three real 10-step SmolLM2-135M/LoRA training and three inference phases, loading the inherited parent. The single frozen 32-task gen2/gen3 comparison is **16/32 for each**, **0 changed decisions**, **Ineligible**. Actual delivered-material owner publication/reopen and controlled load/query/unload do not supply independent efficacy, qualified installation or ordinary next-task product use. Preserve failed predecessors and false independence/product flags; do not resample the holdout to obtain a gain. |
| PN4 | Local accounting, funding/claim/effect and retry/reorg controls remain useful components. Six actual resource-supply chains, chain-backed future storage/service obligations and independent sustainable economics remain required. |
| PN5 | The controlled dev-v1 rendezvous/Cell mechanics and **107** M09 native tests retain their original source scope. Signed advertisements confer no possession, payment or installation authority. No three independent administrators/failure domains or frozen 72-hour WAN/repair qualification has been established. |
| PN6 | The six source-preserving rehearsal tests and inert exports remain component evidence. Final predecessor gates, actual migration/reconciliation and the independent governed release decision remain required; no activation occurred. |

All readiness, production, installation-independence and activation qualifications
retain their existing false/unaccepted values. This checkpoint changes no content
revision, protocol acceptance threshold or original failure. The local execution
route remains unavailable until its actual connection and pending state are read
back; neither a prepared patch nor a presumed alternative environment closes a gate.

### 2026-10-22 fixed-source follow-up

The following observations fix published Chain `42424a82ec605c35f3f1b91eb72e35b9debcc136`,
tree `145f0495eaa3f0ac32a39fcd18c54e65cae97c5e`, base
`9fedf7ecbbe07177069c030592b4e03dcffebb81`, and actual merge
`0f83ea57d6f3a5bd841c60129c7fbffd931dd77f`; paired Hepta is
`83b20a0f43d265a15216904c01194e8939647c65`, tree
`5adf37ed8686d0ea4c91ef3984283b8f4f04ee2c`, base
`75531105b27329abaeb955e77c2c04a6d14f3bcb`, actual merge
`44e863345e8f8438d6ec9f7550d794af4a6dffa4`. Both actual merges have
ordered base/head parents and the source tree. Future heads require their own
source and execution checks. The [fixed-source readback](../../evidence/pon-six-gate-closure-20261022/source-42424a-followup/readback.json)
and [lossless original observations](../../evidence/pon-six-gate-closure-20261022/source-42424a-followup/raw-evidence.gzip.json)
retain component identities and the original failures.

| Gate | Observed result and remaining boundary |
| --- | --- |
| PN0 | Source424 branch run `39748857377` passed all four head/actual-merge lanes: each has twelve actual protocol passes and one original ignored test. CodeQL check `119747556533` fails with thirteen high annotations; the [terminal export](../../evidence/pon-six-gate-closure-20261022/source-42424a-followup/security-terminal.gzip.json) retains all thirteen and 234 Rust API SARIF results, with the raw-upload completeness and annotation-to-analysis association unproved. The check completed before this Rust analysis was created. Internal source-flow review found eight synthetic fuzz `Vec.remove` locations and five numeric log sites, without a confirmed secret sink; independent security disposition is still required. Successful analysis jobs do not clear the gate. Hepta83's Windows ARM archive producer succeeds, while GNU archive and Windows boundary failures remain. Required CI, functional Windows isolation and security disposition stay open. |
| PN1 | Current campaign `39748857599`, job `119724041989`, artifact `12415988227` has all 911 ZIP members verified, including 910 manifest files/320,795,772 bytes. The original validation function via a complete read-only ZIP adapter and independent measurement audit pass: 189 submission observations, 27 confirmation rounds, three distinct transaction IDs, and only 6/18 hostile rounds with complete observed depletion overlap. Paid hostile CPU is 9.392823–9.399422 seconds per thirty-second phase. Minimum effective work cost, sustained saturation and public WAN service remain unproved. |
| PN2 | The unique source424 real signed case exited zero: four-account genesis plus 65,533 signed transfers, 65,537 accounts at height/generation257, before-publish cooperative interruption and two cold opens. The original official independent reader recomputes root `50ced4ab479eb469ba71586fc1d60ba31ea07a2fc91707b188db157e851094e5`; four full-byte source guards, binary identity and stable export hashes match. This is engineering factual readback only. The resource pause keeps the original qualification UNKNOWN; the first reader identity-change failure remains. Twenty-five non-account working keys coexist with a required complete State. Bounded proofs, source-preserving migration, storage sufficiency and physical-fault acceptance remain open. |
| PN3 | Source424 full real pilot still aborts its second loader phase on the original exit-observation recheck. The added controlled reason diagnostic changes no predicate. An explicit parent-step component now binds current source, the original plan, parent three pins, attempt, actual readback and completed candidate provenance. Its five actual tiny CPU tensor units cover absolute A/B replacement and refusal cases; no pretrained backbone, real training, Hepta installation or three-round loop ran on that new path. The original five-participant run and all resource criteria remain unchanged. |
| PN4 | Combined local source `ebc0076c84b9a7c15b4cc4fb87ee1d3971846022` passed seven native budget tests, forty-four scalar CPU tests, three public-target tests and full workspace/all-target/all-feature strict release Clippy. The bounded read-only inventory exposes existing pending/receipted operations without dispatch or payment authority. Mature mining rewards have already been credited and their reward rows removed; a second payment cannot be funded by that historical row. Actual M06 locks/debits, meters and reconciliation remain necessary. |
| PN5 | Three independent administrators, hosting providers and failure domains, preregistered WAN faults, repair and at least seventy-two hours of real operation are still missing. |

Within the same PN3/I10 prerequisite, M14's existing runtime now separates its
internal `decode_tokens` loop from the unchanged single-prompt wrapper. Already
encoded IDs use the original request/response domains, input128/output16 bounds,
fixed-count greedy rule and actual tensor dtype/device/shape checks. Caller-side
full-context compilation and actual loaded-attempt binding remain required.
Routing controls and opt-in tiny CPU tensor equivalence/refusal tests are not a
pretrained-model run, Hepta provider, held FinalUse or three-round/I10 result;
outer closure remains UNKNOWN. M14's existing inventory includes these controls.
The `a4533609` caller-growth red remains: copying after a length check was not a
hard bound. The snapshot now copies at most cap+1 and rechecks its own length;
growth beyond the cap refuses before validation/forward, with no truncation.

Within PN3, the existing [runtime component](../../scripts/llm_runtime_README.md)
adds the explicit `linux-owned-exit-terminal-subset-v3` observer and distinct
`llm-runtime-public-pilot-plan-v3` domain. It retains the complete initial V2
classification, all original FDs/identities and sticky refusal. Only a same-call
stable double frontier may record a strictly smaller set of unchanged zombie
tasks; removed tasks remain pending until the original owned-child terminal
wait4 proves group completion. Unknown/additional/reappearing tasks, changed
identity, running remaining tasks, malformed reads and unknown waits reject.
The original missing-sample 100ms deadline and wall/RSS caps do not change.
Strict-v1 remains the default and V2 behavior is retained. Schema/profile/source
bindings, parent-step dispatch, adversarial units and the real live-user-thread
refusal exercise this component boundary. They do not close PN3, convert prior
failed observations, establish a completed full pilot or replace the actual
cross-node three-round model/consumer/evaluation acceptance above.

The first fixed-environment V3 full model attempt on 2026-10-22 is FAIL.
Its first loader completed the actual pretrained model load and eight
forward/greedy-decode steps, then exited zero, but an ENOENT during the same-call
task frontier caused `rss-exit-cleanup-observation-unavailable`. Twenty-two
complete snapshots preceded the refusal: the last good two-task recheck was
64.536ms after the original missing sample, refusal ended at66.641ms, and a
later diagnostic showed one task at67.581ms. That later observation cannot
authorize a stable subset or prove timely terminal wait4, whose timestamp was
not captured. The stage took33.956s wall and37.340s exact-child CPU; sampled
peak RSS was1,073,172,480 bytes and waited peak was1,142,767,616 bytes. All twenty
original run/input/control files and hashes remain retained, and the earlier
V2 evidence was rechecked unchanged. No training, assessment, adoption or reward
ran. M17/M10 must close the incomplete-frontier observation through an explicit
reviewed source/profile and a fresh frozen experiment; a later diagnostic,
deadline extension or successful child exit cannot convert this failure.

The same PN3 M17/M10 runtime component now has the explicit worker-only
`linux-owned-exit-worker-pidfd-v4` / `llm-runtime-public-pilot-plan-v4` successor.
It retains strict-v1 as default and the frozen V2/V3 observer bytes. Full V2
initial qualification precedes binding every original nonleader's held kernel
thread pidfd to its task FD, starttime and namespace; acquisition changes or an
unavailable `PIDFD_THREAD` refuse. A later worker disappearance needs that
same held descriptor's actual terminal event. Interrupted frontiers then need
two new complete remaining frontiers in the same call, with matching names,
counts and original starttimes, all original predicates, and remaining Z tasks.
Each recapture consumes a newly proved original worker, at most the original
worker count. Previously observed illegal/unknown fields stay sticky. Leader
loss, unproved count mismatch, additions/reappearance, wrong FD/event and missing proof
refuse; no early-leader pidfd event or count-based inference supplies authority.
Own tiny-child tests confirmed worker-event/proc-disappearance separation from
group completion and the kernel's delayed early-leader event. Those observations
and adversarial units establish only this component boundary. Original held
FDs/reservations, missing-sample 100ms, wall/RSS caps and exact owned-child wait4
with valid resource receipt remain mandatory, with no zero-RSS insertion.
The V3 failure remains FAIL; a reviewed fresh-source full pilot and actual
three-round installed-parent/consumer execution remain open. The engineering
task set may be frozen public or previously seen data; report only that set's
actual performance, without claiming future-task generalization.

Independent review rejected initial V4 candidate `3052245` at the real wait4
boundary: reaped pidfd fdinfo Pid/NSpid become `-1`, so a post-reap live-identity
check falsely rejected completion. Preserve that failure. The corrected V4
keeps strict live-owner checks before reap and during every recheck, and checks
only original held PID/FD/token capabilities after the supervisor's exact owned
terminal wait4/resource receipt. A caller-supplied terminal flag cannot bypass
the live checks. Real own-child wait4 success and wrong-owner/replaced-FD cases,
plus synthetic unknown/wrong-wait refusal tests, cover this repair; no new full
model pilot or three-round acceptance follows from it.

The first full V4 `1cabbb1` real-model attempt is also FAIL. Its first loader
completed actual pretrained loading and eight forward/decode requests, exited
zero, and was genuinely reaped, but the supervisor refused
`exit-worker-frontier-change`. Fourteen complete snapshots ended with two tasks
at 77.997ms after the original gap. A newly observed original worker pidfd
terminal event at 82.285ms coincided with Threads=2 and one enumerated task;
strict refusal completed at 82.344ms. The later 87.258ms one-task/group-ready
diagnostic does not supply a complete same-call double frontier or prove
timely exact wait4; that terminal timestamp remains UNKNOWN. All 4,248 deployed
tracked source blobs were reverified unchanged, all original run/control bytes
and hashes remain retained, and later stages are NOT_RUN. No retry converts it.
The same M17/M10 component repairs only capture across a newly proved original
worker retirement: this `_names` call must add fresh bound terminal proof,
retain the leader in a strict subset and read the old count equal to the
complete committed active-set size at entry. That incomplete fragment may be
discarded through the existing bounded recapture; two new complete count/name
consistent remaining Z frontiers in the same call are still mandatory. Raw
count/names/proof context is retained. Repeated/previously retired proof,
intermediate or unexplained counts, new/reappeared tasks, leader loss and
already seen illegal fields remain sticky refusals. The original maximum
worker count, 100ms origin, resources, owned wait4 and post-reap capability
checks do not change. No new profile/schema, successful pilot or PN3 acceptance
is created by this repair; the retained `1cabbb1` outcome stays FAIL.

The separately frozen `9d9b2ac` actual full attempt remains FAIL. Both loaders
passed and the candidate completed ten training steps and saved a 933,544-byte
LoRA, but supervision refused `exit-worker-deadline`. Twenty-four complete
frontiers retained a zombie leader plus a running PF_EXITING/no-mm worker; the
last completed at 97.655707ms and rejection at 100.772941ms from the original
missing-RSS status sample. The present worker's thread-pidfd readiness, complete
failed-call frontier and exact cleanup wait4 time are UNKNOWN. Later four
control trains and five evaluations were NOT_RUN. This failure supplies no
three-round, installation, I10 or beneficial-release acceptance.

Within the same PN3/PN4 M14/M17 owner, the optional controlled kernel-spawn
slice extends the original `_Wait4Child`, never an external parent DTO or a
second supervisor. The tracked C helper makes the direct child with clone3
INTO_CGROUP/PIDFD and an async-safe exec gate; the original Python owner alone
does membership admission, signaling, exact wait4 and cleanup. M14's portability
inventory now names its C/FFI sources. Internal explicit source compilation and
sealed-memfd loading bind actual library bytes and all reused parsers; source
guard checks C without extension exemptions. A typed live operation capability
requires exact unit InvocationID/MainPID, supervisor membership, cgroup2 mount,
operation/ancestor held-FD and name/inode identity, finite unchanged 8/16GiB,
400%-CPU, zero-swap and 256-task limits and no tighter ancestor. There is no
serialized grant, fallback, new CLI/profile, old-100ms relaxation or change to
the public root 2GiB profile. Existing public/seen tasks remain usable for
engineering, with only their observed dataset results reported.

The first outside-subtree clone3 EACCES cohort and the later delegated-service
cohort remain FAIL: the latter proved its own native birth-placement/pidfd/
membership/wait4/operation-empty primitive, but lost the unit ControlGroup path
before authoritative whole-unit reconciliation. Neither result qualifies this
new source. Unit-stop InvocationID authority, escape/shared-page accounting,
ancestor expenses, ordinary Hepta operation/FinalUse integration and complete
outer closure remain open under existing PN3/PN4 owners. Raw cgroup charge is
never RSS or released credit. Every new controlled result is deliberately
failed pending outer reconciliation, with reservation RETAINED; no refund,
installation or adoption authority is emitted. Local native refusal and
synthetic-capability real wait4 tests are not model/cgroup qualification. The
source `cc9b599` inherited-runtime and neural-read adapters use the unchanged
ordinary supervise call and gain no kernel capability automatically; preserve
their separate source-bound campaign evidence and V2/V3/V4 semantics when
integrating this additive optional path.

Independent review rejected initial controlled spawn source `ce4ae661` for the
post-clone tuple/field-handoff exception gap; retain that rejection. This same
M14 owner now binds its native result slots and prebuilt cleanup exception
before clone, and constructor/monitoring share cleanup. Any post-clone signal
or allocation failure must resolve the original pidfd/exact wait4 or explicitly
retain that owner and reservation. A native close-and-clear primitive prevents
pending signals from leaving stale slots that could close reused descriptors.
The 21 real tiny-child fault cases use synthetic native outputs; persistent
allocation and exact gate/pidfd-number reuse tests cover cleanup, not cgroup
placement, whole-unit closure, model acceptance or I10.

The same M14 capability now provides explicit descriptor closure only before
spawn, or after an actual native refusal proves all child slots untouched.
One fixed strong Native slot retains its open capability. Native memfd closure
refuses while that slot is occupied; eligible cap closure resolves its original
ancestor descriptors first. Consumed/unknown child or outer state always
refuses close and retains the same owner. Native errno/close-and-clear slots
survive signals/allocation failures without closing reused FD numbers. This
does not stop a unit, refund a grant, complete FinalUse or qualify a model.
Independent review rejected initial close source `6e0e064b` for deterministic
acquire/acquire and close/acquire races; retain both failures. A fixed creating
process/Thread identity refuses foreign operations before IO/FD/slot mutation.
Review then rejected `445fdda6` for the native Lock.acquire-to-Python-local
exception window; preserve that deterministic opcode fault injection. The new
controlled helper explicitly requires CPython 3.12.3's
[native BEFORE_WITH](https://github.com/python/cpython/blob/v3.12.3/Python/bytecodes.c#L2316)
and exact C RLock. Public wrappers enter the native lock directly and reject
recursion count above one inside the protected block; no generator acquisition
wrapper or Python acquired flag remains. Unsupported ABI, including 3.14,
refuses before source IO/compiler/memfd; ordinary default supervision is unchanged.
Owner-thread lifetime remains required, and constructor cleanup reuses its held
lock. These controls close only local ownership windows, not the unit envelope
or FinalUse; prior 3.14 runs retain their old-source scope.

The delegated-unit failure still blocks outer reconciliation. Upstream
systemd255 [SERVICE_EXITED pruning](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/service.c#L1263)
and [inactive-unit pruning](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/unit.c#L2757)
can remove the cgroup before final property readback. Its
[accounting getters](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/core/cgroup.c#L4065)
may return last cached values. Neither finite properties nor preheld directory
FDs prove final raw accounting. The old cohort lacks the post-main InvocationID
and accounting properties; preserve FAIL. An external controller with an
explicit original-unit lifetime/final-data protocol remains required under
the existing PN3/PN4 owners. No outer success path is supplied by this slice.

The next M14/I10 slice implements controlled aggregate mechanics v2 through
the same runtime's explicit `_aggregate_operation`; supplying it together with
the old capability refuses. A stable delegated U keeps an external original
wait4 owner in finite `controller`; its birth-bound Python supervisor and every
payload participant (model, trainer, verifier and descendants) belong to one
fresh manual aggregate leaf, with zero allowed subgroups. The inner model wait4
owner remains unchanged. Held mount/boot/InvocationID/path/inode/source/ancestor
identities and actual controller limits bind the mechanics; U's original
16GiB/400%/256 envelope is not increased. A memory plus controller memory must fit
the parent before IO/registration, and A CPU/tasks equal U minus the strictly
positive controller share. Actual fields must match this partition; a 16GiB A
refuses. Source `686442fc` incorrectly accepted overcommitted declared budgets;
preserve its ordinary-FD red. U has exactly the two known leaves, depth1 and
descendants2, with no internal payload or dying groups. Acquisition changes no
parent configuration and V2 supplies no capacity grant. This trusted same-admin boundary
does not isolate hostile same-UID migration or external service dispatch.
The checked budget is privately copied before IO; retain the `2478cef6`
ordinary-FD caller-mutation red. Acquisition still assumes trusted preparation,
not general leak freedom at every open-to-Python-slot async exception boundary.

The original direct-owned supervisor's exact wait4 plus empty/no-dying aggregate,
zero memory.current/swap.current and unchanged limits/identity can produce only
a private raw post-terminal observation. The owner rechecks after collecting
memory.peak/events/cpu.stat and requires two matching raw snapshots without
retry; nonzero charge or any unknown retains the original
owner and descriptors. No group deletion, cached-final substitute, grant refund
or whole-unit equivalence is supplied, even after that fact. Original d50 FAIL,
old profiles/100ms/default RSS/public 2GiB and outer UNKNOWN remain. The one actual
tiny `ea2434d5` attempt failed at initial aggregate acquisition with
`aggregate-counter-format`, before runtime clone3/supervisor/payload. Its original
offending filename/raw was not retained and the stopped group was collected;
that exact input remains unknown. A separate later read of existing 4060 groups
found the official Linux
[`core_sched.force_idle_usec`](https://github.com/torvalds/linux/blob/v7.0/kernel/cgroup/rstat.c#L703)
key, which the old underscore-only parser deterministically rejects. The parser
now permits only that exact additional dotted key, retaining duplicate, u64,
field/read bounds and every empty/zero-charge/identity predicate. Parse failures
carry an immutable bounded original filename/raw/reason tuple, without an owner
or authority; callers must retain it in their existing first-failure record,
without another read. Non-ABI parser/ordinary-file controls run separately from
the CPython 3.12.3 native owner tests. This repair does not identify the old exact
input, retry the attempt or qualify aggregate birth placement or a model.
The later actual tiny `3eb2b52a` on source `51146530` passed the parser but
refused initial acquisition with `aggregate-not-fresh`, before any runtime
child or model. Its stopped unit supplied 17 retained evidence files; the
original initial counter text was not exported, so the particular nonzero
field remains unknown. Initial freshness now uses the same bounded immutable
counter diagnostic for the first failed `memory.peak`, `cpu.stat` or
`memory.events` predicate, in the original short-circuit order and without
another read. All zero, empty, identity and cleanup requirements remain.
The outer C first-failure exporter must explicitly allow that exact reason;
an unknown reason cannot silently become diagnostic evidence. Synthetic
ordinary-FD controls preserve refusal, first raw bytes and no-child cleanup;
they do not qualify an actual group. Do not rerun `3eb2b52a`, reset counters,
delete/reclaim A, subtract a baseline or infer a release from collection.
The later single `1c1b674c` on source `ad644fe3` retained the exact initial
`cpu.stat`: `nr_periods 2`, with all usage, user, system, nice, forced-idle,
throttling and burst fields zero. It failed before a runtime child or model;
source identity held and administrative stop/collection did not release the
reservation. Linux [bandwidth statistics](https://origin.kernel.org/doc/html/v5.19/scheduler/sched-bwc.html#statistics)
define `nr_periods` as elapsed enforcement intervals. The
[cgroup v2 interface](https://docs.kernel.org/admin-guide/cgroup-v2.html#cpu-interface-files)
separates usage from bandwidth counters; the upstream 7.0.14
[period timer](https://github.com/gregkh/linux/blob/v7.0.14/kernel/sched/fair.c)
increments intervals before its idle check. Only that exact key in initial
`cpu.stat` may now be nonzero. All actual usage, throttling, burst, forced-idle,
unknown counters and every other freshness predicate still require zero; raw
inputs and parser bounds remain. No counter reset, baseline subtraction,
budget/deadline change or new actual group/model qualification follows. The
old failed candidates remain retained and must not be retried.
The single `e2cc9b11` on source `24a1e86b` acquired A and recorded both owned
`wait4` exits at zero plus all three complete FIFO frames and EOF. Terminal
observation still failed with `KernelBudgetError`; its exact fixed reason was
not exported. Later forensic `memory.current` reads were 290816 and 286720,
with zero processes/population/dying state, and do not identify the original
failure. No private terminal fact, release or refund followed administrative
collection. The original tiny catch now retains only a prebound known code from
an exact one-string `KernelBudgetError`, while original memory current/swap
zero failures retain their first bounded raw text with exact two-file pairing.
Unknown codes/types, extra arguments and unrelated filenames refuse projection;
optional diagnostic faults cannot bypass the original pidfd close. No new reads,
zero/equality changes, waiting loop, budget or deadline changes are introduced.
Pending charge drain remains a separate PN4 matter; empty groups need not reach
zero charge within eight seconds. The used nonce is retained and never retried.
The original wait4 owner's aggregate terminal-error path retains only this
existing typed immutable counter tuple, with pre-clone type bindings and no
exception/traceback/capability references. Projection faults cannot replace the
original refusal or skip the original pidfd-close path; ordinary owned-FD tests
cover MemoryError/KeyboardInterrupt. This is diagnostic evidence only. Prepared
`7abd4172` stays NOT_RUN because A still writes log/JSON file pages; finite
evidence transport remains a separate source change and does not guarantee zero
charge or authorize operation release, Store/FinalUse use or a model.
The private pipe ownership prelude retains the original16 ancestor slots plus
two native-populated FIFO slots, with same-owner/nochild-or-actual-refusal gates,
native identities/errno, endpoint direction and actual source binding. Original
C spawn text stays unchanged. The separate source-bound tiny framing prelude
now bounds three ordered schema-checked records to 64KiB/frame, 256KiB total and
4KiB/read. Before serialization, a bounded complete-envelope traversal includes
keys/punctuation/Unicode escape costs and256-bit integer limits; oversized
65KiB leaf/key controls refuse before the serializer. Incremental private
dict/list capture shares one total budget; all subsequent schema/serialization
reads use that captured graph. Caller changes after capture cannot enlarge the
output; capture-time dict mutation refuses and growing lists/aliases stay
bounded. This does not claim an atomic caller-state or native observation.
The borrowed nonblocking
stdout writer keeps one supplied absolute
deadline at most8s ahead at construction. The private tiny path binds it to the
original C8s owner/start, drains4KiB/pass and gives A the original2s writer path
without mkdir/open/save. Original exact wait4/identity must precede final EOF/
native read-slot close, which precede both original raw snapshots. Typed tiny
terminal KI/MI/projection faults preserve original pidfd cleanup; partial/
unknown remains RETAINED, not release. Tests use ordinary real children with
synthetic native birth/limits/raw; they do not qualify a valid unit or model.
This interface grants no budget authority. Pure parsing
and small ordinary-FIFO child controls cover
malformed/truncated/extra frames, backpressure and deadline refusal. Actual
valid-unit verification and original Store/FinalUse closure remain open.
The later `83ca245b` tiny observation on source `90232d41` completed both
original wait4 exits and three FIFO records, but its first terminal read found
`memory.current=159744` and permanently retained the reservation. Later
same-held-group diagnostic reads found 4096 then 0; those late observations do not
repair the failed capability, and their complete counter vectors differ.
The PN4 successor reconciles kernel charge teardown only inside the first live
tiny terminal transition, using the already-configured original absolute 8s
deadline. Only exact memory/swap charge-retained errors may wait, at most 801 reconciliation
attempts plus the unchanged final snapshot with sleeps bounded by 10ms and remaining time. Format, identity, process,
descendant and snapshot-equality failures remain immediate sticky failures.
The original deadline is checked before and after every wait and observation;
the final held pidfd/wait4 checks, exact-zero memory and swap, and two equal
complete raw vectors still precede private fact publication before that deadline.
Blocking system observation retains its original two-second call timeout, so a
failed observation or cleanup can return after eight seconds; such a tail never
publishes a timely fact. No counter reset, reclaim,
limit change, new budget or retry of a failed capability is allowed. Non-tiny
terminal paths do not wait. Existing owned-process CI now runs 59 original plus 7
new controls on exact CPython 3.12.3 for source and prospective merge, requiring
all 66 successes, zero skips and zero expected failures. These ordinary-child/synthetic-counter controls
do not establish a real aggregate pass, outer reconciliation, resource refund,
Store/FinalUse authorization or any model upgrade round.
The subsequent [single controlled observation](../../evidence/pon-upgrade-implementation-20261018/native-rounds/aggregate-charge-wait-20261023/SCOPE.md)
on exact source `ec0f58d3` completed its original outer terminal observation in
3.080 seconds under that unchanged eight-second deadline. Exact owned wait4,
three FIFO records and EOF, true zero memory/swap charge and the original equal
complete snapshot assertion produced the private mechanics fact. The inside
controller took 5.321 seconds; the overlapping durations are not additive. All 24
collected files and 18 source pins matched independent remote readback. This
closes that tiny terminal charge-drain reproduction only. The original outer
reconciliation and consumed-capability close still refuse release: UNKNOWN and
RETAINED, no manual aggregate deletion, no refund, no model load or upgrade round.
Post-native Python exception injection does not claim native-internal
signal interruption; SIGUSR1 tests prove guard reentry refusal. Ordinary FD
controls do not qualify a valid unit or prove that C-created pipe pages charge C.
The next dependency remains the existing Hepta
kernel.operations Store's CPU destination/independent FinalUse/terminal release
protocol; this module adds no second manager or journal and no I10/model result.

The ordinary merge with source `8caf5387` retains the inherited runtime and
persistent neural-read worker, its default held-pidfd/irreversible-exit helpers,
all explicit V2–V4 source-bound paths and the controlled native owner. Explicit
profiles cannot fall through to default reconciliation; their 100ms ceilings
remain. The default waits for proved kernel cleanup only within the original
absolute phase wall budget and still requires exact wait4/resources. Campaign5
and its 16/32 equal gen2/gen3/zero-changed-decision Ineligible result keep their
original source scope. This merge adds no model, cgroup, FinalUse or I10 result.

The existing [Cell/native handoff script](../../scripts/run_llm_cell_native_handoff.py)
implements controlled dependency transport and byte readback, but its native
Hepta consumer and owner-receipt contract are not shipped. Inspection of Hepta
`deaf31954d53fa8eba543525221c34f9b1b3d1b6`, primary
`061f14c8f4722506b38a39ff3921b6bd42b8c8aa` and PoN base
`c38e7727220f32c7410f59083c5ea7878bbae078` finds no matching consumer.
After the unchanged original transfer deadline, readbacks and finite producer
drain, this script records consumer UNAVAILABLE and receipt UNVERIFIED, keeps
the top-level result failed and invokes no unknown native command. The retained
absolute-path arguments cannot enable that absent consumer. A missing report
already failed closed; the removed arbitrary-JSON success branch could instead
promote a mocked child exit0 with a failed or unrelated JSON report. The red/green
controls use mocked orchestration and small real file hashes, not actual model
execution or a real model failure. They preserve the original late-readback
failure and do not close the real caller, load-attempt binding, resource,
FinalUse, three-cycle next-task readback or I10 obligations.

The same PN1/PN2/I05 M09 cache path now uses fresh TCL4/schema4 with immutable
logical bytes, chunk/manifest rows and an explicit main-database image/file-length
cap. `--cache-max-bytes`, `--cache-max-chunks`, `--cache-max-manifests` and
`--cache-max-db-bytes` are mandatory for all six Cell writer commands, discovery
fetch and the existing handoff script. The same exact configuration covers every
producer/consumer member; each writer reapplies and reads back SQLite's
connection-local `max_page_count`, using fixed 4096-byte pages. The image cap is
4096-aligned, from 256KiB to 2TiB. Existing read-only entries audit persisted caps,
page size/count and file length. TCL1/TCL2/TCL3/foreign databases, oversized images or tail
padding are refused without migration, truncation or quota reset. Cold catalog
validation still requires all 14 exact objects and only the two automatic PK
indexes; reserved prefixes cannot hide an object.

The new actual controls observe native SQLite FULL/13 with unused logical
allowance, complete eight-chunk transaction rollback and exact cold readback,
two real writer connections and a fresh reopen that cannot renew the cap,
unchanged old TCL2 bytes, and the original allowed 8 x 4MiB batch. Existing logical
quota, catalog, corrupt-cache, release, read-only and deadline assertions remain.
An initial WAL control failed because identical UPSERTs generated no new pages;
the retained correction holds a real reader while writing distinct small chunks.
Its WAL exceeded the 256KiB main-image cap while main pages and logical usage
remained bounded. That complete original TCL3 control and its greater-than
assertion remain in an explicitly test-only historical fixture; no production
TCL3 reader/writer or fallback remains.

The TCL4 increment keeps admission in the original `CellStoreV1`. Initialization,
manifest/chunk writes, the original eight-chunk batch and corrupt-cache deletion
share one persistent zero-byte OS writer-lock identity. A complete TRUNCATE
checkpoint and actual zero-length WAL are required before another write; a held
reader refuses the new batch before mutation. Lock contention and SQLite share
the original single five-second budget. Every connection disables automatic and
close-time checkpoints and dirty-page spill, retaining `synchronous=FULL`.
Complete cold schema/configuration/counter audit precedes any writable checkpoint:
the original cold-catalog no-rewrite assertion caught and now prevents a real
ordering defect. Process-crash recovery, two independent CLI writers and exact
same-operation retry are actual controls, not only mocked lock observations.

For immutable main-image cap C, the supported locked SQLite 3.46.0 writer protocol
derives WAL length `32 + (C/4096 + 16) * 4120` and a separate SHM length
`32768 * (1 + ceil((C/4096 + 16)/4096))`. The additional frames conservatively
cover the bundled backend's maximum FULL-sector padding. This bound requires
empty-WAL admission and one spill-free original-owner transaction; changing the
backend/VFS requires new qualification. Existing oversized sidecars are rejected,
while after-commit checks are invariant diagnostics, not preventive quotas.
Because closing does not checkpoint, committed WAL can remain: copying only the
main DB is not a complete cold export. Retain/recover the coherent namespace or
reconstruct this disposable cache through the existing pinned fetch owner.

This bounds supported cache-writer DB images and WAL/SHM logical file lengths,
not allocated blocks, backing reservation or total disk peaks. Initialization's
rollback journal, SQLite TEMP/memory, caller output and retention metadata/WAL
remain open, together with global ledger roots, funded I05 duties, native model
consumption, installation and three-cycle acceptance. Arbitrary direct SQL,
custom VFS and adversarial namespace replacement are outside this owner protocol;
there is no claimed OS-wide quota. Checkpoint thresholds and journal-size
retention are not peak limits. Cache
admission/deletion never changes M12 funding or paid obligations. No 35-second
aggregate handoff or original 8-second owner window is extended by this slice.

The optional scalar-credit freshness observation reads the original watermark
and projects the original refill arithmetic without changing the clock, credit,
owner or depletion predicate. Its added sampler contention and complete-path
cost still need an actual new-source campaign. No old campaign result is
transferred to that sampler. Complete-State growth is still a reference oracle:
the authenticated COW owner and compact executor retain their own 65,536 caps
and require explicit bounded-parent, proof-overlay and recovery integration.
No PN0–PN5 exit or production/readiness flag changes in this follow-up.

### Earlier 2026-10-22 checkpoint: source871 / sourceCB

This earlier independently read published source was Chain PR #323 head
`87126992dd5634348cc1a788442126997b28c624`, tree
`579771a4735f58c9d3391edc76e1d7552bb9a606`, base/main
`9fedf7ecbbe07177069c030592b4e03dcffebb81`, and actual merge
`b388ad9a4fc955d5584ea344c0081bec2204c571`. Hepta PR #2559 head is
`cb481bb06d2e048d9cb4d6356cf78682ea620fb2`, tree
`239f6b9fb0125ca7b376ee6b7eec8d5fce2456d4`, stacked base
`75531105b27329abaeb955e77c2c04a6d14f3bcb`, and actual merge
`ab4c32eae71f0d282c6980fdd033853d5311ea5c`. Actual merge parents were
read in ordered base/head form and both merge trees equal their source trees.
These are measured source identities, not mutable latest-head aliases.
Hepta's schema 4 preserves `accepted_task`; legacy schema 3 remains readable
but cannot satisfy the independently pinned task-acceptance comparison.
Current full Rust run `39743869108`, paired run `39743737810` and Chain
required run `39739585771` still need complete terminal acceptance.

The [paired run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39727952205)
completed successfully on four Linux lanes and both Windows ledger lanes.
Each Linux lane's 107 execution receipts, source tuple, log hashes and actual
backend envelopes were independently read back. Installation, independence and
activation qualifications remain false. This run does not certify later local
growth, budget, observer or Windows boundary changes. A separately source-built,
GNU-time-measured complete repository-truth execution on exact Chain `1131d067`
finished in about 630 seconds with exit 0; retain the earlier failed execution
and do not transfer this pass to the new integration. Required baseline and
priority jobs still queued are pending, not passes.

The [source-bound CI/security readback](../../evidence/pon-six-gate-closure-20261022/ci-security-before.json)
and [18-finding source review](../../evidence/pon-six-gate-closure-20261022/codeql-current-readback.json)
retain the published `1131d067` security gate failure (one critical, 17 high) separately from
successful analysis/export. The exported branch SARIF has 224 results, a different
scope. The 18 candidate exporter matches have no independently proved mapping;
their acceptance remains unknown/null. Source review does not dismiss alerts or
replace independent security acceptance. New source requires new scanning.

Original [native campaign run `39718009547`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39718009547)
on Chain `5eb30bdedba2bb4933f5c97211426fc2df21bb7c` failed all three complete trials.
All nine phases confirmed their three scheduled rounds and retained equal
receiver/client state. In all six hostile phases the original genuine-depletion
condition was false: measured mutation CPU was below the original available
credit/refill envelope. This is insufficient demonstrated pressure, not an
observed honest-confirmation failure. Keep the original workload, predicate and
failed artifact; no aggregate success, reduced refill or fabricated depletion
may convert it into acceptance. A separate valid-W1/late-state-root depletion
control retains its own inputs and cannot replace this campaign's verdict.

The predecessor [original-policy campaign `39727391523`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39727391523)
on published `1131d067` completed successfully and passed strict raw-artifact
readback: 189 submissions and 27 confirmed rounds across nine phases. Only 10
of the 18 hostile-phase honest rounds overlap observed genuine CPU depletion;
this is not all-round or continuous saturation. Preserve the original budgets,
workload, denominators and failed predecessor. This result does not close the
cheapest-work assumptions or public service under a sufficiently delivered
attack envelope.

The [Windows deletion-boundary run `39727952366`](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39727952366)
on `097d9713` passed all four native NT probes on both source and merge lanes,
but failed the broad-identity and restricted-process deletion boundaries:
the outside parent granted `FILE_DELETE_CHILD` (64), and outside files and
directories were actually deleted. Locally integrated successor repairs make
managed launches that claim this isolation fail closed with a typed error
before side effects. They preserve the original `097d9713` positive tests and
gates; fail-closed refusal does not qualify functional Windows isolation.

| Gate | This increment's executable boundary | Full exit still required |
| --- | --- | --- |
| PN0 | Chain `ef2a6958` passes its fourteen baseline execution jobs and current CodeQL; aggregation and priority CI remain queued. Hepta `07731d31` pins that source and `81d9d829`, passes fourteen exact static checks and 865 Python controls, and starts original full CI on source and actual preview. Both ARM diagnostic lanes pass fourteen of sixteen original/additive groups, but broad-identity deletion and the missing production legacy route still fail. Historical CodeQL findings and earlier native failures remain retained at their own sources. | Applicable final head/merge CI, independent security disposition, functional Windows isolation and fresh cross-repository execution. Matching trees or partial passes do not waive the two native failures. |
| PN1 | Current original-policy campaign `39739585823` passed full original-artifact readback: 189 submissions, 27 confirmations and 6/18 hostile honest rounds overlapping genuine CPU depletion. | Cheapest-adversary assumptions and actual public service under a declared, sufficiently delivered attack envelope. |
| PN2 | Published revision17 GSC2 native complete-State reference and required 65,537-account signed-transaction/recovery test; the unique published-source local long run stopped at its original shared-disk safety boundary, last logged 57,348 accounts at height 224. No final 65,537 export or successful libtest result exists. | Terminal signed-boundary/recovery/readback evidence, bounded working-state/proof validation and source-preserving migration. Complete-State reference roots are not bounded witnesses. |
| PN3 | Source `ef2a6958` completes all twelve strict-v1 real 135M five-control phases; candidate and strongest control each score 1/2, so gain is zero and no adoption/reward follows. Three real parameter generations load their predecessors and execute direct next tasks. On Hepta `07731d31`, original artifact publication/recovery and signed read/unload pass, including actual loading of peer-fetched upstream weights; its comparison timeout remains retained. The bounded parallel-start successor `43ad626b` actually passes all three original native cases on the local ROG host; the complete comparison takes 13.651s within its unchanged 60s limit, with all 32 tasks, 64 forwards, 66 signed/control records, exact cold reopen and both original unloads. Its original decision is still Ineligible; no CURRENT installation follows. The offline 4060 rerun remains pending, and earlier unknown-RSS/transfer failures remain retained. | Bind an actual initial neural parent through original selector/CURRENT without treating an unselected trained child or Qualification receipt as an eligible SystemLongitudinal release; then three-round ordinary next-task closure through existing ledger, evaluation, selection and complete-release owners. Existing public/seen tasks remain valid for engineering acceptance. Three parameter generations or one peer-loaded forward do not qualify three installed improvements. |
| PN4 | [Separate finite lane budgets](specs/pon/REWARD_BUDGETS_V1.md) now have native local obligation persistence; six component tests passed again on the integrated native source, including abrupt-exit recovery. | Native debit/escrow locks, actual resource-owner measurement and dispatch, funded storage/service obligations and independent economic review. Local records do not lock chain funds or pay rewards. |
| PN5 | Preserve the preregistration and independent-custody requirements below. | Three independently administered operators, accessible existing nodes and a complete frozen 72-hour WAN campaign. |

The [current original CI logs](../../evidence/pon-six-gate-closure-20261022/current-871269-ci/branch-encoding-original-failures.json)
retain all four failures in branch-encoding run `39739585740`. Each lane
successfully executed 12 protocol tests with zero failures and one ignored;
the shell still required the predecessor count of 11. The successor changes
only that exact count to 12. Rust source, selectors, ignored-test execution,
resource/time budgets and source checks remain unchanged; the four original
logs prove the corrected count matches, not that later workflow steps passed.

In original-integration run `39921443580`, branch-encoding jobs
[120307385007](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39921443580/job/120307385007)
and [120307384981](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39921443580/job/120307384981)
executed the complete authenticated-migration selection: all original 29 members
and six added cold-snapshot/file-read controls passed, with zero failures or
ignored tests. Both jobs then failed because the shell still required 29 passes.
The successor requires exactly 35 while retaining the original complete Cargo
command, selector, pipefail, zero-failure/zero-ignore checks, source guards and
all other workflow assertions. The two failed jobs remain failed observations;
replaying their logs checks this count repair, not a new native execution,
subsequent workflow steps, final-source CI or production qualification.

The [current security export](../../evidence/pon-six-gate-closure-20261022/current-871269-ci/security-export-exact-source.json)
retains check `119708392458`, all 13 API-exposed annotations and the exact-source
exporter metadata. The 234 Rust SARIF results have a different scope; neither
old findings disappearing from this check nor source review proves remediation.
The [current complete campaign readback](../../evidence/pon-six-gate-closure-20261022/current-871269-ci/campaign-full-artifact-readback.json)
verified all 910 original files (320,779,809 bytes), including retained native
binary and databases. Its three controlled same-host runs meet the original
finite policy, with only six of eighteen hostile honest rounds overlapping
observed depletion. This is neither continuous saturation nor minimum attack
cost, WAN availability or sustainable public-network throughput.

The [long native growth failure](../../evidence/pon-six-gate-closure-20261022/current-871269-ci/native-growth-failure-summary.json)
retains the original 3,821.7-second shared-disk interruption. Available space
fell to 237,518,848 bytes below the unchanged 300MB protection; the wrapper
stopped the group and then exited before native wait/result accounting. The
pinned native process subsequently disappeared. Its direct terminal status is
unknown, not inferred from the wrapper's exit 1. All partial DB/WAL/SHM bytes,
original runner/observer logs and hashes remain; the partial database was not
SQL seeded, reopened or converted into a successful replacement. The actual
after-stop full raw source check passed on unchanged `8712699`; the original
before-launch guard was metadata only and is not retroactively upgraded.
No successful native checker, independent final export reader, physical-fault
or whole-PN2 acceptance is claimed.

The available hosted CI uses the existing `ubuntu-24.04` and `ubuntu-24.04-arm`
labels. Queue metadata does not establish dedicated-cloud terminal access or
prove an organization-wide runner-capacity cause. Real public model materials
and a working local CPU loader are now available. No three independently
controlled operators or qualified 72-hour WAN campaign have been established;
local processes and additional development keys cannot supply that evidence.
The integrated native source passes full strict Clippy and four independent growth-root vector tests, three small signed growth/recovery tests, six local budget tests and the original native model-release integration test. The required long signed growth gate remains incomplete after the resource stop; current-pair CI still needs complete terminal evidence.
No PN0–PN6 stage is closed by this checkpoint and no readiness flag changes.

Every performance/iteration report must retain the following distinct quantities.
Unknown or unexecuted stages are null with a reason, never copied from an earlier
stage. Timed-out, rejected, reorged and withdrawn attempts remain in their original
cohort; repeated polls and duplicate deliveries do not create additional successes.

| Quantity | Required denominator or identity |
| --- | --- |
| Unique valid transaction confirmation TPS | Distinct transaction identities on the observed active chain under the stated confirmation policy, divided by real campaign wall time including the stated drain. Logical block spacing and internal queue counts are separate. |
| Proof verification and state-commit rates | Actual proofs, valid/invalid/cancelled outcomes, and completed state commits, with elapsed time, shared CPU ownership and durable write costs. |
| Candidate-to-install p50/p95/p99 | Original candidate submission to verified actual model installation, with sample count, unresolved/failed fraction, clock source and observation window. Do not report only surviving fast candidates. |
| Installed and subsequently qualified updates | Distinct neuron lineage transitions with real installation and the predeclared follow-up task/cost/safety result. Replica installations and repeated readbacks cannot multiply one learned update. |
| Honest-user completion during attack | Completed authorized honest requests divided by all offered honest requests in the same attack interval, preserving Busy, timeout, revocation and unknown outcomes. |
| Loss/reorg/restart/new-node cost | Actual bytes, wall/CPU time, peak memory, disk growth and recovered tip/model/operation identities for each named failure. A process restart does not stand for physical power loss. |

The local continuation retains this order. Its
[native architecture comparison contract](../protocol/pon-nakamoto-v1/details/ARCHITECTURE_COMPARISON_V1.md)
compares serial, concurrent and signed-reference-DAG dissemination through the
same unchanged PoN application and independent depth/work confirmation owners.
The separate consensus-assumption matrix identifies the additional Conflux,
Narwhal/Bullshark, Mysticeti and Prism implementation obligations. A native
dissemination result is not an implementation or security qualification of those
consensus protocols. Failed runs, cold acquisition, disk synchronization, client
verification and recovery remain part of the evidence; no faster phase alone
selects a successor protocol. Final source and result receipts are required
after the applicable implementation tracks converge.

A DAG candidate must account for total ordering, execution conflicts, withheld data,
equivocation, admission economics and reorganization/confirmation semantics. A BFT
candidate must separately define committee admission, rotation, Byzantine bound and
finality. Neither may inherit this profile's work/fork-choice/confirmation claims.
A serialization improvement, a faster query, or a simulated block schedule is not a
DAG/BFT throughput result. No new protocol profile or readiness flag follows from this
continuation alone.

### Current native development contracts

The [checked applicability registry](../../config/pon/applicability-v1.json) and
[canonical procedure/profile table](../architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md#current-applicability-and-evidence-classes)
separate current source bindings from local execution, historical receipts, hosted-head
checks, prospective-merge checks and external acceptance. This plan records no current
PR pass: derive exact candidate/base/merge identities and retrieve their actual CI results.

The 2026-10-22 PN0 repair retains the failed `d78744b` hosted Rust baseline
(run `39785191834`, job `119846398662`): its signed 65,537-account test passed,
but the independent reader refused because a `mode=ro` SQLite connection
created an empty WAL. The reader now treats an absent WAL and exactly zero
WAL bytes alike while pinning the complete main database, every nonempty WAL
and the original receipt. It still reads committed WAL content; `immutable=1`
would skip that content and is not used. The same exported database passes
the repaired mathematical readback; empty-WAL lifecycle, WAL-only nonce
tampering and changes during readback have explicit controls. This checker
repair does not supply current-head CI, bounded-state or work qualification.

#### Priority implementation revision: capacity, work, model evidence and engineering

The current generated [implementation/profile view](../architecture/CURRENT_IMPLEMENTATION.md)
comes from the existing registries and is checked for drift. It is not another plan,
a runtime test result or a declaration of independent acceptance. The package graph
remains 25 packages and 39 responsibilities; explicit native development ownership now
includes W1 verification, operation-local M05 signature facts and incremental M06
prefixes, bounded history projection, and the explicit revision13 empirical scorer /
revision14 composition successor with an independent arithmetic/state comparison.
The explicit [revision15 evaluation quorum](../protocol/pon-nakamoto-v1/details/NATIVE_EVALUATION_QUORUM_V2.md)
composes with those model profiles: it freezes the controlled non-author roster
and threshold, counts matching actual reveals, and rechecks objective conflicts
at adoption. It grants no work weight, consensus finality, operator independence
or Hepta installation authority.
Package and procedure counts do not measure scientific acceptance.

The 2026-10-19 increment adds the explicitly selected
[model evolution V5 / revision16](specs/pon/MODEL_EVOLUTION_V5.md) to those same
owners. Its signed ILF3/tag24 transaction loads the actual complete current ILM3
parent and can jointly change base, router and expert matrices, plus a nonempty
three-slot enable mask. This removes the zero-router reachability restriction
for the new family. It is a bounded graph, not arbitrary Hepta topology. Native
candidate/evaluation/tag8 adoption tests reach a successor parent and refuse a
neutral next update; model scores still confer no chainwork. Historical ILF2,
ILM2 and revision15 vectors, domains and stores keep their exact identities.

V5 optionally accepts [owner-pinned task windows](specs/pon/MODEL_TASK_WINDOWS_V1.md)
through the ordinary Node CLI and Config/Settings constructors. The full input
file digest, separately pinned signer, canonical source snapshot/content hashes,
complete task roots and ordered activation schedule bind the pre-genesis context.
The submission round selects the same fixed window for the actual parent,
candidate and every retained control; an author cannot substitute a preferred
root. Two six-text controlled fixtures exercise real new payloads, activation,
native adoption and independent feature/score computation. These are source and
protocol controls, not an independent prospective data campaign. Changing the
manifest after genesis requires a new context; live data governance and custody
are still separate work. The original no-window V5 context remains distinct.

The separate M09 [cell byte pilot](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md)
provides an actual `trnm-cell` pack/serve/fetch/verify route. A caller-pinned TCM1
manifest binds the family, dependencies, complete payload and ordered chunks.
Finite configured TCP peers, a separate disposable SQLite cache, hash-checked
repair and complete no-replace materialization are exercised with real loopback
connections, origin removal, two suppliers, corruption, partial downloads,
exhausted connection budgets and a byte-dripping peer. This grants neither model
loading/installation nor CURRENT/FinalUse authority. Independent storage owners,
WAN delivery, public discovery, private transport and long-term replica renewal
require their own observations. The merged explicit development
[rendezvous](specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md) and
[native-funded retention](specs/pon/CELL_RETENTION_V1.md) remain separate scoped
components, with no independent custody or public-network qualification.

The explicit configured-peer bounded serving option now shares an actual-write
budget across at most four read-only workers with no application waiting queue.
Overload consumes the original connection limit; partial failed writes are
charged, and shutdown/error paths join admitted workers. The default serial
route is preserved. This is PN3/PN5 transport engineering, not public fairness,
complete model loading or independent custody acceptance.
Merged discovery shares the client's original connection/response/deadline
reservation; bounded serving still reads only the disposable cache. Actual
discovery/retention databases are rejected as cache namespaces. Neither this
merge nor its local transport regressions rerun or qualify earlier model cohorts.

A2026-10-22 controlled three-host cohort transferred eight pinned public
SmolLM2-135M-Instruct material files,271,178,816 payload bytes in266 chunks.
The debug build failed the original120s verification deadline after all chunks
were present; its exact failing verification stage and CPU cause remain unknown.
A release-preparation attempt failed the binary SHA gate before network activity
because a concurrent local test rebuild changed the distribution path. Both
failures are retained. A fresh cold-cache attempt with the immutable release
binary completed A-to-B fetch in36.691s and, after A stopped normally, B-to-C in
37.966s, under the unchanged120s/512MiB payload/1GiB response budgets. Independent
release verification took4.723s/5.391s. All eight materialized files matched their
pins and passed the runtime material verifier. Each server completed275 requests
and wrote271,192,859 application bytes including a nine-byte final control reply.
This closes only the controlled public-material transport/source-loss byte
subitem. The operators share administration; semantic release closure, I10
installation, independent custody and PN5 remain open. The subsequent full model
pilot failed its exit-observation gate and grants no model-loop acceptance.

The additive TCR1 whole-release route pins an owner-supplied release manifest and
digest, checks all member manifests before payload download, and shares one
deadline, connection count and actual response-byte budget across every cell.
Complete cache readback precedes create-only publication of the release marker.
That marker records fetched bytes; it does not grant model installation,
retention or finality authority. Local blocking filesystem I/O remains cooperative.

All three new applicability rows are source bindings with no invented execution
receipt. Package ownership remains 25 packages and 39 procedures. Controlled
native regression results do not promote runtime, scientific, product or
production acceptance, and old evidence receipts are not repinned to this source.

This revision preserves full header/challenge binding, parent-derived difficulty,
required-work fork choice, complete proof verification before the private verified
work type, ordered application execution, the single durable writer and the separation
between reorganizable branch state and irreversible local operation facts. Model
scores do not change chainwork. Earlier failures and zero rewards remain retained.

| Priority | Implemented development boundary | Required acceptance still separate |
| --- | --- | --- |
| P0 capacity | [Continuity revision12](../protocol/pon-nakamoto-v1/details/CONTINUITY_V1.md) reserves absent mandatory recipients, future archives and unfilled reward slots before admitting state growth. Actual65,536-key fixtures cover continuation and cleanup-dependent entry through reorganization/reopen. The [account archive](../protocol/pon-nakamoto-v1/details/ACCOUNT_ARCHIVE_PROTOTYPE_V1.md) now constructs canonical AAM1 multiproofs directly from persistent Patricia nodes and uses them for actual complete-state mandatory/successor execution. Its signed41-account fixture reduces339,357 expanded bytes to2,251 compact bytes, independently replayed from full State. A fresh [native authenticated backend](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md) now writes account COW nodes and exact final state commitments in the actual Node transaction; explicit source-preserving migration replays every retained branch and preserves local facts. | Default consensus/root and65,536-key limit retain their meanings. Full non-account input, witness discovery, full State reconstruction and pre-COMMIT readback remain. Compact encoding is not a whole-block time or RAM bound. The separate [complete monetary range relation](../protocol/pon-nakamoto-v1/details/MONETARY_OBLIGATION_RANGES_V1.md) authenticates all task/quota/release/reward rows, including future and zero liabilities, before their actual M06 discovery. It retains a checked complete parent and other non-account reference rules. Public proof availability, disk/version ownership and growth pricing remain open. |
| P0 work cost | [W1 comparison](../protocol/pon-nakamoto-v1/details/W1_IMPLEMENTATION_COMPARISON.md) retains four complete producer experiments, including eight fixed-maintenance producers and the explicit five-producer zero-locality v2 with charged setup and balanced order. The new zero integer-paired candidate computes all original prefixes with152,832 integer/field multiplications per challenge; its33-bit paired products require actual timing against the previous blocked-zero and general paired implementations. A separate native late-rejection diagnostic now measures real Accepted/Transcript/Product outcomes on the same winning proof across production, scalar and limb kernels; four task classes, two targets and nine samples retain full acquisition and failed-search costs. Existing-proof mutation costs and progress probes have separate denominators. | Finite same-source x64/ARM64 observations do not prove cheapest-adversary cost, energy cost, task equivalence or hardness. The diagnostic uses general PreparedTask acquisition and does not claim the cheapest Product forgery. Unlimited preprocessing, other legal structures and physical hardware remain explicit research assumptions. |
| P0 work availability | Revision12 commits a separate immutable maintenance material/identity, zero useful-output credit and an explicit Node/CLI choice; optional signed V4 tasks retain expiry/revocation. | Availability is not computational qualification. Owner-side grants/withdrawals still fence local operations. There is no fabricated indefinite lease or automatic fallback. |
| P1 verification | Current production W1 verification retains transposition, exact modulus folding and tiled hash updates. An explicit limb research verifier shares the same grammar, checks, error order and cancellation points while replacing transcript dot-product accumulation; the independent scalar reference remains. Actual late-rejection observations and three-kernel equivalence/fuzz checks cover the changed path. | All458,752 field scalar products and complete transcript replay remain. No timing winner is declared by source code. A succinct new proof relationship requires a separate version, security argument and independent review. |
| P1 state/history | [Resource bounds](../protocol/pon-nakamoto-v1/details/HISTORY_STATE_RESOURCE_BOUNDS_V1.md) retain checked ancestor batches and bounded History pages; [pool prefixes](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md#same-block-incremental-m06-prefix) reuse operation-local M05 facts and successful M06 suffixes. The explicit native backend now merges changed account paths before writing each final subtree; intermediate uncommitted roots no longer leave permanent nodes. Borrowed account decoding, cached SQL statements and one-pass leaf decoding preserve complete checks. Complete-state root encoding now streams one canonical value at a time into the original sparse-tree relation, removing the second whole encoded-payload map while retaining the full grammar pass and hash-path sorting. Actual native snapshot/prefix staging now discards a cache encoding upon a current-state key/payload/workspace bound failure, continues full canonical validation, and materializes required differences only after the full root; the complete parent State and operation-local parent bytes remain. Live KV copies are dimension/type checked before owned decoding in both backends, without changing wire limits or final integrity checks. Both storage modes verify affected rows and final actual state/events/cursor and ancestry before COMMIT, including late activation writes. Native proof queries reject invalid dimensions before storage and support cancellation through state replay and actual proof construction. Explicit migration uses a pending-fenced atomic no-replace target publication and final disk readback. | Full-state reads/root construction, non-account scans, historical confirmation and mandatory retained-node verification remain. Extra commit readbacks have real cost. Physical global retention, bounded complete-state reconstruction and reader/writer separation remain open. |
| P1 model | [Model evidence revision13](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_EVIDENCE_V3.md) keeps its exact rules. The explicit [revision14 composition successor](../protocol/pon-nakamoto-v1/details/NATIVE_MODEL_COMPOSITION_V4.md) checks exact common-parent sums, exact cancellation, strongest-component superiority and positive leave-one-out weights. Independent Python arithmetic, lineage, complete stored-record and payout comparisons use actual native observations from the existing lifecycle tests. The explicit [offline window-history contract](../protocol/pon-nakamoto-v1/details/MODEL_OPERATIONS_ACCEPTANCE_V1.md#explicit-continuation-across-reported-evaluation-windows) binds a fixed prior-history anchor, rejects reuse of previously contacted evaluation prompts/groups, retains negative gates and reserves completed-record capacity. Its explicit [pre-disclosure V2 successor](../protocol/pon-nakamoto-v1/details/MODEL_OPERATIONS_ACCEPTANCE_V1.md#explicit-pre-disclosure-exposure-continuation-v2) consumes declared exposure in a pending transition before evaluation, retains aborts and malformed-result exposure, and reserves both terminal shapes; the existing evaluator owner must durably CAS the returned pin before disclosure. | Reported window continuity does not prove historical execution, hidden-window completeness, trusted pin storage or real future-task custody. The corpus is historical/public and saturates at25/25. Independent implementation agreement, exact derivation and retrospective ablation do not prove training causality, future efficacy or Shapley fairness. Hidden common control, general-model correctness and public evaluation governance remain unaccepted. |
| P1 public service | Existing V3 service/queue and protected transport tests remain actual bounded native campaigns; each mixed-service/restart report must keep errors, timeout outcomes and honest-service gaps. | Independent operators, WAN/partition campaigns and long-running public service targets require actual external operation. Local tests cannot set those flags. |
| P2 errors | [Typed local errors](../protocol/pon-nakamoto-v1/details/INTERNAL_ERROR_IDENTITY.md) separate local identity/cause and actual retained-data provenance from human text and authenticated remote refusal. Real retained header/KV/reorg/replay failures stop the owner while peer lookalikes, cancellation and clock deferral retain their original behavior. Public-client recovery and failed-phase accounting use typed local stages while retaining exact JSON labels. Completed local replay rows missing retained responses and failed conditional journal writes now carry local-structure origin; caller frame/ACK refusals retain typed nonfatal causes. | Remaining formatted legacy diagnostics still explicitly remain Unclassified; each added origin boundary requires concrete native tests. |
| P2 CI/docs | [Execution contract](../architecture/CI_EXECUTION_CONTRACT.md) retains the five required head names and exact prospective-merge lanes. Existing workspace runs export actual native SQLite, source/target migration, signed AAM1, complete obligation ranges and raw zero-prefix fixtures for independent readers. The storage reader reconstructs every retained ancestry row from parent walks. Each Rust lane explicitly runs the authenticated65,536-key capacity fixture and paired complete-account verification observation in release; their ignored markers in ordinary debug tests cannot substitute for these required executions. Coverage-guided targets include actual compact/range execution and three W1 kernels. The same two cost jobs and comparison retain four producer suites plus the separate legal/late-rejection suite, bound to one source/run/attempt and real architecture. | Hosted jobs must actually execute on the final source. Local preflight, source wiring, finite fuzz and artifact consistency do not establish independent operators, worst-case complexity, security acceptance or production qualification. |

The account archive and model-window history are explicit research/offline boundaries in the
applicability registry, not new active consensus revisions. The archive preserves every
account nonce and fails on unavailable data. Its original checked execution wrapper requires
the complete State and authenticates original-parent point access before ordinary ordered
account reads; an omitted proof cannot use the complete State as a fallback. The separate
authenticated-state companion binds complete account and non-account commitments plus
funds/count aggregates to a checked full parent. It reconstructs mandatory execution from
the complete authenticated non-account partition, merges original-parent account proofs
for prologue and final changes, and compares the result with a full rebuild. This is an
explicit reference-backed research relation, not a partial-State production backend.
The non-account witness and full reference still scale with State. Execution derives a
complete conservative account-access bound from parent keys, actual transactions and miner;
the original standalone point-query API retains its32-account limit. The new AAM1 relation
uses one canonical nonempty shared frontier and verifies exact account presence/nonce before
reusing changed paths; zero-query proofs grant zero account accesses. Its conservative full
encoding bound is7,561,821 bytes, separate from its actual small signed fixture measurements.
The original durable research archive remains independently selected. The new native backend
has an explicit startup choice and source-preserving migration under a fresh stored schema.
Migration keeps every old local-fact table, pending reorganization and source directory;
external owner modes require their own migration relation. Witness availability, disk/version
ownership, proof availability, growth pricing and the ledger capacity limit remain separate work.
The explicit monetary range companion builds a new operation-local ordered index from the
checked complete parent; it proves complete prefix intervals, not just valid membership.
Future and zero obligations remain disclosed before M06 uses those rows for expiry, reward
maturity and parent capacity responsibility. Other rules and successor capacity retain
complete-State checks, so this is not a partial-State or constant-cost execution claim.

All incompatible consensus rules require fresh explicit profile/context selection.
The old revision3/6/7/8/9/10/11/12/13/14/15 vectors and namespaces retain their meaning. The
combined continuity-task12/model13 context has a separate native regression through
306 actually mined/admitted heights, archive reservation conversion, native rewards,
source/retention cleanup and cold reopens. Its source-bound execution remains a
development conformance result, separate from the full-capacity fixture and external
acceptance. Revision14 uses fresh configuration, model-evidence/source domains and
an explicit composition record embedded in the existing bounded release. It is
selected explicitly, can coexist with task12, and never silently upgrades model13.
Transaction tags, wire error codes and the default branch SQLite schema retain their
meaning. The explicitly selected authenticated backend has a fresh schema identity;
its opener rejects the old namespace and the old opener rejects the new one. Migration
never converts an existing directory in place or silently grants external owner authority.

For every delivered source, execute the existing complete Cargo graph/lock/fmt/test/
Clippy gates, protocol bridges, negative repository/evidence checks and actual fuzz.
Measure release binaries only after freezing source and without concurrent builds;
retain exact commands, toolchain, binary hashes, inputs, failures and environment.
A hosted head check and a prospective merge check must name their own exact commits.
Neither results from this prose nor from the generated navigation table.

#### Retained four-priority development scope

These changes continue this plan and its existing module owners; no acceptance axis
is promoted by implementation or by adding a diagnostic checker.

1. **Applicability and evidence consistency:** the checked registry above joins all
   module documents, actual source owners, controlled entrypoints and test selectors.
   M05 explicit reconciliation and M06 native execution/deltas are mapped to the Node
   owner; the39 responsibilities also bind revision11 factor admission and public V3
   resource-r9 to their exact source/tests, without granting execution evidence.
   Historical receipts and exact current delivery checks remain separate.
2. **Work security diagnostics:** the [proposed local diagnostic profile](../../config/pon/work-security-acceptance-v1.json)
   and [work report contract](../protocol/pon-nakamoto-v1/details/WORK_PROFILE.md)
   bind cost classes, setup amortization, rejection amplification and scoped hostile
   service observations. Its thresholds are proposed screening policy, not
   preregistered scientific acceptance, consensus parameters or a hardness proof.
3. **Conservative execution/resource improvements:** the [local pool contract](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md)
   reuses one checked actual parent within a pool operation and one mandatory
   prologue, then executes only the newly accepted M06 suffix. Successful M05 main
   signatures can be reused only within that immutable operation; every full-prefix
   state-dependent gate, complete output root and operation-boundary reread remains.
   [Derived commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
   changes retain complete-root authority and bounded fallback. Incremental M06
   execution does not establish SQL isolation, persistent-root authority or measured
   endpoint TPS.
   The [sync evaluation fixture](../protocol/pon-nakamoto-v1/details/SYNC_EVALUATION_OBSERVATION_V1.md)
   now checks explicit64+64+64+49 page-budget resume over all241 retirement successors,
   with separate original120-second listeners and durable ancestry/cursor assertions.
   It preserves the prior single-transfer timeout, and does not certify uninterrupted
   delivery within one lease or inherit old fixture/CI execution results.
4. **Model and operations evidence:** the [reported-acceptance sidecar](../protocol/pon-nakamoto-v1/details/MODEL_OPERATIONS_ACCEPTANCE_V1.md)
   joins a pinned run plan, strongest-control gain, adversarial probes, reported
   consumer uses and material/retention obligations. Supplied-record consistency
   does not prove future-task custody, consent, independent operation, real serving
   or physical retention; those external obligations remain unaccepted.

[Source-bound local observation package](../../evidence/pon-four-priority-audit-v1/README.md)
retains the measured `3c63c836` work-cost diagnostic (expected exit 2) and scoped
M06 preview timings; it promotes no acceptance or end-to-end throughput claim.

New local checker results apply only to the source and environment actually tested.
Full Rust qualification, exact committed-head/prospective-merge CI, physical-host
measurements and independent model/security acceptance require their own retained
observations; this section declares none of them passed. Earlier failed campaigns
and their source identities remain unchanged.

The following contracts describe the current candidate under M05/M06/M15 ownership.
Older evidence and historical sections below retain their original source and profile.
Their presence does not make an earlier absence claim the current API specification.

| Boundary | Current explicit contract | Remaining acceptance boundary |
| --- | --- | --- |
| Retained signed transactions | [Local pool](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md), [cache V2](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_CACHE_V2.md) | Logical cache bounds do not bound physical chain/SQLite/WAL growth or operator tombstone lifetime. |
| Continuous native work | [Wall-clock mining](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md) | Preparation, one transcript, native commit and diagnostic sinks remain nonpreemptive. |
| Parent task and execution state | [Operation-local actual parent](../modules/M06_EXECUTION_TECHNICAL_SPEC_V1.md) | One operation can reuse its first checked full parent read; new operations and admission re-entry still read actual state. The checked derived cache may retain up to the existing 65,536-key protocol limit under 8 MiB payload/512 MiB workspace-charge ceilings, with complete-root fallback when a selected cache budget is exceeded. Protocol overflow still rejects. This adds no authority cache, SQL isolation guarantee, throughput claim or work qualification. |
| Guest transaction intake | [Public V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md) | Resource tickets and separate read queues do not certify hostile-load fairness. |
| Protected proof transport | [Admission security](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md) | A zero-capacity Hello handoff preserves original deadlines and three socket workers. Its new explicit transport digest requires same-profile peers. A finite regression does not prove public scheduling or availability. |
| Atomic task renewal | [V3 exact inclusion](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md), [fresh V4 overlap](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md) | Source/requester signatures and actual task availability remain required; no automatic qualification or indefinite lease. |
| Long retained history | [Native ancestry index](../protocol/pon-nakamoto-v1/details/NATIVE_ANCESTRY_INDEX.md) | Local derived index integrity is not a remote ancestry certificate; receivers still verify full packets. |
| Explicit neighbor following | [Pinned peer polling](../protocol/pon-nakamoto-v1/details/PINNED_PEER_POLLING.md) | Paid Head/History and fixed cursors do not supply discovery, gossip, independent operators or eclipse resistance. |

Same-administrator Tailscale campaigns and task-owned delayed/interrupted TCP
proxies are simulation evidence. Record actual direct/DERP routes, every failed
attempt, native inclusion and stopped-store verification; do not promote independent
operators, prospective model tasks, computational hardness or public readiness from them.

The immutable `fefe235bdb25bd18a8b48876c2114448da0a4a86` near-limit
normal-load attempt requested 262 blocks of 250 transfers, followed by six drain
blocks, at 10-second live pacing. It failed with
`ADMISSION_BUSY_READ_ONLY_RESERVED` on the next submission after 116 completed
blocks: 29,000 transactions were accepted and 27,500 confirmed. The producer had
29,277 state keys and the validator 29,027; their heads differed. This was an actual
service failure before budget exhaustion, not a passed maximum-state acceptance.
The failed source predates the bounded repeated Hello handoff opportunities described
in the current admission contract. Those opportunities and larger optional derived-cache budgets require a
fresh committed-source rerun of that unchanged load and independent complete
reference replay. The earlier passed 16,411-key case remains scoped to its original
source. Reaching 65,536 keys, rejecting 65,537 without changing parent state, large
payload/workspace cases and hostile availability remain separate obligations.

## 1. Product mission: shared intelligence from real work

Every Hepta node can learn compatible small-model parameters from authorized real tasks.
It can publish a bounded parameter update, obtain independent out-of-node validation,
contribute to a reproducible shared model, and receive rewards for measured adopted
value. The public model is available without a model-use fee under its accepted public
policy; funded network resources provide a bounded free hosted-inference tier.

    real tasks -> local adaptation -> public parameter contribution
       -> independent evaluation -> expert/router composition
       -> whole-model evaluation -> shared model release
       -> contribution reward + free basic consumption -> new authorized experience

This is not only an inference marketplace. Upload counts, trained parameters, issued
coins, hashes, self-evaluations and seven local processes are not closed-loop evidence.
A new independent consumer must benefit from the composed release in a future task
window and be able to feed its own authorized learning into the next generation.

## 2. Consensus and learning architecture

### 2.1 The PoW-like ledger

Use one native event/effect consensus core. It receives bounded verified inputs and
returns effects; it performs no network, database, private-key, unbounded proof generation
or model call. Replace the active decision rules with the PoN block/target/chainwork
state machine. Keep reusable codecs, strict crypto, bounded adapters, transaction
accounting and storage identity checks only where their meaning actually matches.

Fresh work binds the exact parent, complete header template, producer/payout and
neural-task context. A qualified expensive attempt produces a canonical output; a
threshold predicate determines a winning attempt. Proof randomness and cheap metadata
changes cannot produce extra lottery trials. A node chooses the fully valid branch
with maximum cumulative required work, not maximum height or maximum model accuracy.
The precise candidate arithmetic, target adjustment and time rules are in CONSENSUS.

An old fine-tuned model may earn a model-contribution reward. It is not fresh consensus
work. The target work primitive is challenge-bound verifiable linear algebra arising
from adapter/head/router training or evaluation. The exact experimental transcript primitive, numeric/byte registry and two-language
vectors are implemented in W1/L1. Anti-shortcut security, cheap-forgery admission,
public-network efficiency and independent verification remain unqualified. No
quality threshold, training log, TEE quote or proof-of-execution is silently substituted
for computational hardness. No pure-hash or old-BFT automatic fallback is authorized.

### 2.2 Executable application boundary

The mainline is a dedicated AI-work/model/service chain with twelve original closed
application commands and explicit profile-gated native extensions. Signed task13,
evaluation14..17, lifecycle18..21, and the revision8
[V3 atomic renewal22](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V3.md)
and revision9 [V4 signed overlap](../protocol/pon-nakamoto-v1/details/QUALIFIED_TASK_LIFECYCLE_V4.md)
have distinct context and gate rules; V3/V4 refuse standalone19. V3 requires the exact
containing height; V4 permits delayed inclusion while both signed authority windows
remain valid. The explicit revision11
[integer factor candidate23](../protocol/pon-nakamoto-v1/details/NATIVE_INTEGER_FACTOR_CANDIDATE_V2.md)
adds `M10.SubmitFactorContribution`, bringing the current typed responsibility
inventory to39 across the same18 modules,25 packages and17 normal dependency edges.
It loads the actual complete ILM2 parent and reuses bounded integer BA computation;
old tag6/model/task contexts do not silently select this profile. Historical twelve-command
parity and transfer benchmarks retain their original scope. This is not an arbitrary user-contract VM. No EVM, Move or WASM backend is
selected. Fees and performance evidence apply to the named closed commands. A future
VM decision needs explicit bytecode safety, deterministic metering, ABI, storage,
upgrade/reorg semantics, tooling and module ownership; it cannot arrive through an
unknown transaction tag or model artifact. See the application-scope section of
[LEDGER_WIRE](../protocol/pon-nakamoto-v1/details/LEDGER_WIRE.md).

### 2.3 Shared model structure

Use a common immutable base, organ/domain adapters, Cell/expert deltas, learned router
and typed composition graph. Parameters carry exact compatibility-family identities.
Local optima are candidates, not automatic global optima. Train/calibrate routing and
connectors under a fixed budget, evaluate the complete composition, and periodically
distill into a cheaper public base. Keep sparse full releases and compact deployment
profiles distinct and reproducible. Count shared weights once.

Heterogeneous backbones/tokenizers cannot be merged by tensor position. They require
versioned ports or evaluated distillation. An arbitrary collection of remote APIs is
not called one parameterized large model unless its complete architecture, model bytes,
routing and output semantics can be reproduced. Cell depth is not transformer depth.

The global control plane remains advisory and outside ledger authority.

### 2.4 Local Hepta sovereignty

Hepta training/artifact/evaluation/plasticity owners remain authoritative for their
facts. Neuron/Intuition/inference execute admitted models; kernel.operations owns
intents/outboxes/reconciliation; memory.federation remains read-only. The chain adapter
submits idempotent business operations and verifies PoN inclusion/confirmation proofs.
It cannot mint a local final-use token, share private memories by default, become a
second trainer/store or override revocation. The four existing NDU subject levels are
unchanged; a mandatory fifth global optimizer is not introduced.

### 2.5 Four-layer boundary convergence

This is an implementation boundary within the existing plan, not a fifth optimizer,
a replacement learning journal, a protocol activation or a new module registry.
The current PoN and disabled release-finality candidate keep distinct contexts.

| Layer | Existing owners and accepted input | Output and forbidden authority transfer |
| --- | --- | --- |
| Compute and contribution | Hepta learning.operator / learning.plasticity; Chain M01/M02 checked work and M10 contribution lifecycle | Exact work statements and proposed parameter bytes. Correct execution is not efficacy, ownership, permission or additional evaluator-weighted chainwork. |
| Artifacts and evaluation | Hepta learning.artifacts / learning.eval; Chain M09 availability and M11 bounded evidence | Pinned artifacts, compatible lineage and scoped evaluation. A hash is not custody; a signature is not independent control or future utility. Bulk model bytes stay outside the hot ordering path unless the explicit proof relation requires them. |
| Public coordination and release | Chain M02/M05-M08/M10-M12, with separately selected release-finality reference | Inclusion/confirmation, release commitments and settlement. No receipt changes Hepta CURRENT, mints FinalUse, silently adopts a committee, or reinterprets PoN history as deterministic finality. |
| Local use and effects | Existing Hepta artifact CURRENT, independent selection, kernel.operations and outer FinalUse owner | A locally admitted generation and scoped effect. Local resources, compatibility, withdrawal or authority may refuse a globally recorded candidate. Irreversible effects are reconciled, not erased by chain reorganization. |

The existing experimental native composition package now exposes a bounded, read-only
[native V2 certificate reader](../../trillionnium/crates/trnm-pon-node/src/release_finality.rs).
Its caller must independently pin canonical committee and context bytes. It
verifies both actual signed quorum bodies, strict Ed25519 keys/signatures, the
actual membership/quorum inequalities and the complete statement identity.
Its artifact commitment retains the V2 domain; it is not a TCR1 release ID.
This adds no voting, durable locks, pacemaker, storage lease, installation or
FinalUse owner. The disabled finality configuration and native-runtime integration
claims remain unchanged. Native corpus checks and explicit cross-language controls
compare the unchanged Python reader without making Python a runtime dependency.

Preserve strict signed-byte agreement and bind the actual two-repository
source/merge matrix. Then use the unchanged W1 cost
collectors at equal targets, charging structured preparation, maintenance, lost
attempts and false-ticket rejection separately. This work creates no public-service
or cheapest-adversary qualification. Controlled/offline learning may proceed while
PoN security remains open, but every generation uses its actually installed parent,
untouched evaluation materials, genuine control separation and lawful no-update.

State and artifact expansion retain complete checks, the single durable writer,
branch-local rollback and irreversible local facts. Measure state/history growth,
full disk/WAL allocation, cold recovery and missing artifacts before selecting a
storage successor. Compare serial, concurrent and DAG candidates only on the same
business workload and explicit security assumptions, including confirmed goodput,
tail latency, failures and recovery. A propagation microbenchmark cannot select a
new consensus or authorize a model. The reconstruction and upgrade order above remains.

## 3. Eighteen long-lived modules, reused ownership

There remain 18 long-lived modules. Current crate ownership is preserved; changed
responsibilities are explicit targets, not evidence that existing crates implement them.

| Module | Selected PoN responsibility |
|---|---|
| M00 | New work/header/contribution/release codecs, parameters, registries and version dispatch |
| M01 | Work/statement verification, identity and capability crypto; no vote weights |
| M02 | Header validity, target, cumulative work, fork choice and branch transition decisions |
| M03 | Mining/effect identity, bounded work-attempt lifecycle, durable publication and local fencing |
| M04 | Open bounded header/body/proof/parameter gossip, retrieval and eclipse resistance |
| M05 | Reorg-aware mempool, nonce/reservation and contribution transaction admission |
| M06 | Deterministic branch execution, workload metering and reversible application deltas |
| M07 | Branch roots, undo/replay, model/escrow state and descriptor-bound storage |
| M08 | Confirmation policy, reorg coordination and effect-aware recovery |
| M09 | Public parameter/evidence availability, replication, repair and bounded retention |
| M10 | Parameter contribution, evaluation job, composition and model-release lifecycle |
| M11 | Objective verification, independent evaluation and typed challenge/adoption decisions |
| M12 | Mining maturity, marginal-contribution rewards, serving payments and free-use budgets |
| M13 | Work-verified sync/light clients, deep reorg replay and fresh-instance PoCO migration |
| M14 | Honest included/confirmed/reorged APIs, model discovery/download and free inference |
| M15 | One ordinary PoN node composition, Hepta adapter and versioned deployment |
| M16 | Advisory routing/resource/composition proposals; no fork or authority decisions |
| M17 | Work-security, model-efficacy, reorg, economic and independently retained evidence |

Dependencies remain primitives -> contracts -> pure cores -> bounded adapters -> node
composition. No new global supervisor, parallel task ledger, PoN-owned learning database,
second body registry or all-module runtime is introduced. Actual Cargo edges/SCCs remain
source facts; a target diagram is not permission to falsify current dependency evidence.

## 4. Interfaces, persistence and reorganization

Separate ParameterContribution, WorkCertificate, EvaluationReceipt, CompositionCandidate,
GlobalModelRelease, ContributionAllocation and PublicInferenceBudget. Each has one
schema owner, versioned meaning, exact parent/attempt/nonce/profile binding and bounded
codec. Public constructors, booleans and unsigned JSON cannot manufacture verified facts.

Maintain a Node Commit Ledger-style coordinator and PinnedSqliteNamespace protection,
but do not reuse monotonic BFT-finalized state as a reorg implementation. PoN requires
new branch/undo schemas: durable intent -> detach -> attach -> root/readback -> atomic
active-generation publish -> indexed remove/add acknowledgement. Deep valid reorgs
trigger verified replay when undo was pruned; a local retention threshold is not finality.

Chain-derived balances, nonces, task entitlement, model-release pointers and reward
maturity can roll back. Local effect entry, provider receipt and revocation/anti-rollback
frontier cannot. A vanished confirmed lease does not authorize executing the same real
API action again. Reconcile orphaned effects under explicit risk/compensation rules.
Model adoption uses fresh local generations and preserves which historical model made
each recorded decision. Never reexecute history using current weights.

### Required interface deliveries for PN1–PN5

The following are target contracts inside the existing owners. Row labels are
review references, not newly registered procedures or claims of exported Rust
types. Reuse existing checked types where applicable; any new wire/schema/domain
needs its own bounded codec, namespace, independent vectors and source binding
before it becomes callable. Do not turn these rows into permissive JSON adapters.

| Ref / phase | Producer -> consumer and owner | Required input -> checked result; failure boundary |
| --- | --- | --- |
| I01 / PN1 | M03 producer -> M01 verifier -> M02 fork choice | Exact profile/parameters, header/challenge, task and canonical W1 bytes -> private verified-work fact and required-work increment. Preliminary ticket success, evaluator score and claimed CPU never manufacture this fact. |
| I02 / PN1 | M04 ingress + M15 host -> existing scoped resource owner | One operation identity, lane capability, absolute deadline and CPU/byte/worker reservations -> admitted work or Busy/Unavailable. Settle actual worker CPU once, including cancellation, late failure and Unknown; duplicate identities do not gain fresh budgets. Invalid is reserved for checked invalid content. |
| I03 / PN2 | M00 context + M07 verified parent -> M06 execution | Versioned parent commitment with account root/count/balance, bounded non-account root/count/liabilities and supply -> private bound parent. A claimed aggregate or cached block id cannot replace authentication. |
| I04 / PN2 | M09 archive/producer -> M06/M07 | Exact parent, canonical touched-account multiproof, complete mandatory/range inputs and proof-byte budget -> checked transition, child root and reversible delta. Missing data is Unavailable; authenticated absence is distinct; no partial transition may commit. |
| I05 / PN2/PN4 | M07/M08/M13 -> M09 retention owner | Required roots, acknowledged obligations, byte reservation and retention/recovery endpoints -> durable storage responsibility. Provider receipt is not proof of possession forever, chain validity or finality; GC must preserve reachable roots and mandatory duties. |
| I06 / PN3 | Hepta artifact/export owner -> M10/M11 | Actual installed parent, candidate manifest/bytes, consent/export and current withdrawal scope -> scoped publication/evaluation input. ArtifactOwnerService publication with DENY_ALL does not authorize redistribution. |
| I07 / PN3 | M10 candidate + declared dataset -> M11/Hepta evaluator and selector | Frozen parent/candidate/control identities, test-data/exposure/reuse scope, total budgets and decision rule -> gain/no-gain/invalid/unknown evidence on those tasks. Existing public or previously seen data is valid for controlled engineering tests. Evaluation quorum is an application policy, never ledger work or local installation authority. |
| I08 / PN3 | M14 packet-status -> existing Hepta TaskFlow coordinator | Already durable exact packet/effect bytes -> schema-4 storage/active-ancestry/depth/work observation plus exact accepted-task binding when present. Legacy schema 3 cannot satisfy task acceptance. Match task, owner, provider, output and generation; local absence never proves global NotDispatched. |
| I09 / PN3/PN5 | M10 release owner -> M09 fetch -> existing Hepta loader | Selected release dependency closure and pinned TCM1 identities, finite peers, original deadline and resource budget -> freshly verified complete bytes and provenance. Manifest ID, payload SHA256 and any external CID retain their distinct algorithms/domains. Download success grants no CURRENT/FinalUse authority. |
| I10 / PN3 | Existing Hepta selection/artifact/resource/FinalUse owners -> neuron runtime | Current signed artifact/withdrawal head, compatible verified bytes, local generation, explicit chain confirmation policy and real resource admission -> fresh local installation and actual inference readback. Reorg or withdrawal fences further use; durable external effects are reconciled under their original identity. |

Dependency details and negative schedules live in the existing
[work](../protocol/pon-nakamoto-v1/NEURAL_WORK.md),
[admission](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md),
[permanent storage](specs/pon/PERMANENT_ACCOUNT_STORAGE_BOUNDARY.md),
[Hepta handoff](../protocol/pon-nakamoto-v1/details/HEPTA_HANDOFF.md) and
[Cell distribution](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md) contracts.
They share this sequence and must not become separate roadmaps.

## 5. Reward and free-use rules

Keep mining reward, model-contribution reward and serving/storage/evaluation compensation
separate. A finite release budget unlocks only under preregistered whole-model improvement
rules; zero credible improvement pays zero. Attribute within the locked budget using
bounded ablation/sampling, with uncertainty, duplicate lineage and complementary bundles
handled explicitly. Splitting a root contribution across cells/accounts cannot increase
its total budget. No automatic perpetual lineage royalty or validator weight is minted.

Hosted free inference is sponsored and rate/queue/quota bounded. Token issuance is not
GPU supply; report funding and resource units separately. Service permission, local
learning, parameter export and public redistribution are distinct permissions. Parameter
publication does not prove privacy and cannot promise recall of every downloaded copy.
Genesis economics, emission/maturity/fees and public-tier budgets require explicit
parameters and independent economic review before activation; no invented launch numbers.

## 6. One executable convergence sequence

### PN0 — Contract and source alignment

Owners: M00/M15/M17, with the actual upstream Hepta owners. Entry: inspect the
candidate and base without changing deployed services or another repository.

1. Derive exact Chain and Hepta head/tree/base, prospective merges, binaries,
   target/profile/genesis/namespace and hardware/configuration. Update the
   owning paired workflow only when that upstream change is authorized; until
   then record the stale pin as a blocked pair, not a passed test.
2. Reproduce relevant source, dependency, signed-reader and negative-integrity
   gates. Review current security alerts by rule, path, data flow, affected base,
   exploit preconditions, owner and fix/disposition evidence. A successful scan,
   changed-file truncation warning or historical alert count is not triage.
3. Preserve original campaign inputs and all failed/censored observations.
   The source494 public campaign failed 0/3 rounds in all three modes; source
   df6 improved baseline to 2/3 while both hostile modes stayed 0/3. The 9bd
   successor's original-budget campaign is pending, not inferred from its cache
   and import regressions. See the existing performance acceptance contract.

The 2026-10-24 local CI repair keeps the original lane commands and assertions.
Ordinary evidence-test children bind only their own checkout's script directory,
including prospective merges, instead of inheriting a stale head's `PYTHONPATH`.
The durable-schema reader requires the current legacy/authenticated openers'
literal `false` growth-observation argument; changed backend, mode and rebinding
mutants still reject. The shared funding fixture reads the real account's next
nonce before each unchanged funding transaction. The merged runtime group executes
the original 269 cases plus both source-path controls: 264 pass and the seven
existing opt-in model cases remain unexecuted. Both the isolated-interpreter decoy
control and the cloned head/prospective-merge poisoned-path control remain. The
concurrent PID fixture reads actual procfs names from the pidfd namespace metadata.
All 44 external-reader cases and five real storage-service cases pass locally.
The concurrent cloud build-input workflow is retained without certifying its
resource bounds or execution. Current hosted head/merge checks,
fresh CodeQL disposition and native/model acceptance remain separate open gates.

The same PN0 CI boundary now partitions the unchanged local `rust-baseline`
commands into required runtime and quality workers for both candidate and actual
prospective merge. Each worker retains 180 minutes; the original required check
names run fail-closed fan-in after every outcome. Both current-run/current-attempt
receipts, exact source before/after and executed command hashes must agree, and
both jobs must succeed. Runtime retains the workspace, signed oracles and four
exact ignored native controls; quality retains formatting, supply-chain, docs and
strict Clippy. No test, native deadline or assertion is removed. This addresses
observed scheduler cancellation after successful capacity/growth controls; fresh
hosted execution of the new scheduling remains pending.

The earlier published Hepta owner-native source was `394d1c75` and its actual
original-base preview is `1dddb018`, with parents `[c38e7727, 394d1c75]` and the
verified merge tree. Its existing full native workflow and Windows diagnostics
are requested, not passing evidence. The ordinary Linux suite passed 1,042 cases
with 17 separately accounted inherited qualifications; 832 Python controls and
six V8 tests against the original checksum-verified sandbox artifact also pass.
The existing Windows workflow retains both x64 lanes and adds both ARM64 lanes.
All fifteen receipts require their exact named cases and one complete summary;
compiler host, Windows architecture and the fixed runner/target pair must agree.
A wrong test, duplicate result or green total cannot replace an original red.
Both actual ARM diagnostic lanes pass all four original stage, four
primary-owner, five security, four principal and four volume cases. The full
library still reports 14 passes and 23 owner failures; FinalUse and Registry
owners still fail. The two compilation errors are repaired: all nine sandbox
groups actually execute on both ARM lanes. The original full-restriction
candidate, partial-delete regression, four mechanism probes and eight ACL
controls pass. The broad-identity regression still observes parent DELETE_CHILD
permission, and legacy execution still refuses its missing qualified producer.
The same-call diagnostic binds the common initial ancestor failure to the actual
volume-root TrustedInstaller SID; no private-store owner policy is changed by
that observation. Preserve the earlier nine NOT_RUN outcomes and both current
failed lanes in [the original diagnostic run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40117218852).
x64 and full current-pair native acceptance remain required.

The subsequent published source `07731d31` and actual original-base preview
`ccff5bed` retain all native gates. Both ARM diagnostic lanes pass the original
private-state, FinalUse, Registry, owner-lock and held-RX controls; both still fail
the original broad-identity deletion and guarded legacy execution regressions.
Their complete native workflow runs
[source](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40177457993)
and [actual preview](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/40178472384)
then fail all four ARM test shards. The source executes 18,491 tests: 18,113 pass,
343 fail and 35 time out. The original partition filters are separate from these
378 actual failures. No passing build or diagnostic receipt closes that gate.
Within this same PN0 item, Hepta now has local successor repairs for held writable
Windows directory synchronization and typed native-TLS negotiation fallback,
including actual certificate-denial controls. Their scoped Linux packages pass
39 and 100 tests respectively; source checking is not native Windows execution.
The fresh managed-runner original process/token proof remains only a launch
prerequisite. Its complete qualified production route and the original deletion
assertions remain required, without a test-only bypass or longer limits.
See the same [Hepta development obligations](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/394d1c7559513f4c28930b4bb1425ff383350ddc/docs/DEVELOPMENT.md).

Exit: one reproducible source-pair/configuration inventory and per-gate results
with unresolved items assigned. Block dependent acceptance on required failures;
continue scoped repair and offline research. Do not rerun historical cleanup or
restore retired code. Register actual new objects/errors/vectors only with their
implementation; this documentation amendment adds no runtime maturity claim.

### PN1 — Qualify real neural work

Owners: M01/M02/M03/M04/M15/M17. Entry: PN0 inputs fixed. Deliver I01/I02
as separate correctness, resource and public-service contracts.

1. Keep W1's current arithmetic and full statement binding. Freeze task classes,
   target, setup/amortization horizon, maintenance choice and attacker hardware
   assumptions. Compare the best implemented general, zero, low-rank, sparse,
   preprocessed and ticket-passing false-transcript producers at equal targets.
   Include preparation, every unsuccessful attempt, winning work, full receiver
   rejection and useful-output rate. Do not mix main's microbenchmark ratio with
   the candidate's fuller-cost ratio or call either a lower-bound proof.
2. Explain the security bound in effective qualified work, including the admitted
   structured/hardware advantage and work concentration; machine or key count is
   not adversarial work fraction. Independent review must state which hardness,
   lottery and preprocessing assumptions remain. An unsupported assumption keeps
   work qualification open even if the finite availability test passes.
3. Join the actual paid and public ingress paths to the same scoped accounting.
   Account for decode, state access, verification, all workers, commit and client
   confirmation separately. Preserve recovery capability separation, finite
   retries, original deadlines and first-error behavior. Unknown/cancelled jobs
   retain consumed credit and require original-operation reconciliation.
4. Rerun the unchanged public campaign: 1,024 signed seed transfers, four seed
   blocks, 21 business blocks, three 30-second rounds in each baseline/from-zero/
   late-product mode, 0/24/24 attackers, two workers, 2 CPU-second burst,
   0.25 CPU-second/second refill and 100 ms start reservation. Require 3/3 timely
   independently imported confirmations in each mode; repeat the complete frozen
   campaign three times with all failures retained. This is a finite development
   regression under that attack envelope, not universal public fairness.
5. After preserving that result, execute the separately preregistered I02
   capacity/churn supplement: actually produce at least 4,097 distinct complete
   work identities, cross the current 4,096-entry scheduling boundary, and keep
   fresh identities arriving during honest confirmation. Report table occupancy,
   new/repeated identities, real construction cost and ordinary-path fallbacks.
   Direct table injection is a component test, not this cohort. Retain the
   original service CPU/worker/deadline/confirmation limits; declare offered load,
   total duration and honest schedule before construction, never after a failure.
6. Qualify timestamp/DAA effects with the actual work model and legal clocks,
   oscillating effective hashrate, withholding and partitions. An easier target
   still contributes less required work. A proposed DAA or work relation change
   requires explicit version/domain/migration review and new independent vectors;
   queue repair or a different PoW paper cannot qualify the unchanged relation.

Exit: separate work-security and honest-service verdicts with raw denominators,
assumptions and independent reproduction. Queue cleanup or ACK alone cannot pass.
A failed work relation needs an explicitly versioned reviewed successor, fresh
context and new vectors. No automatic hash-only, TEE, evaluator-vote or old BFT
fallback; no new model improvement is required for every maintenance block.

### PN2 — Native PoN chain and recovery

Owners: M00/M05/M06/M07/M08/M09/M13/M15. Entry: PN0, frozen I03–I05 and
PN1 accounting; PN1/PN2 implementation may iterate before joint acceptance.
Keep required-target/chainwork, DAA/time boundaries, fork eligibility and
partition/reorg regressions in the existing consensus owner throughout this work.

**Local implementation observation, 2026-10-22.** The explicitly selected
[permanent-account growth v2](../protocol/pon-nakamoto-v1/details/NATIVE_ACCOUNT_GROWTH_V2.md)
now connects the original-parent AAM1 proof, bounded complete working partition,
shared signature/nonce/fee/mandatory M06 rules and actual SQLite COW/delta/branch
publication through the existing Node. PGH2/PNP2, network, parameters, genesis
and storage schema have separate identities. The old full-State profile and cap
retain their meanings. Zero-balance leaves keep their nonces; cold open replays
retained branches and audits the retained COW graph before publishing the new
backend's explicit local storage epoch.

The earlier release-mode native scale run passed in 216.25 seconds: 65,520
explicit genesis accounts became 65,552 through actual signed transitions,
with 34 transfers, two cold reopens and one heavier-fork reorganization. Its
first growth block used 35 proof accounts, six working keys and 417 additional
COW nodes. The separate four-owner query used 59 point reads and a 3,722-byte
multiproof; those are not whole-block admission costs. This run predates the
optional SQLite evidence export and final combined source. The original log
remains evidence; the final create-only scale export and exact source/binary/merge
qualification remain outstanding at this checkpoint. No million-account,
public-ingress, unlimited-retention or throughput qualification follows.

The original authenticated-v1 hot path still performs complete-State/account
checks and tip-to-genesis history checks at admission and activation. Consecutive
heights through H therefore incur O(H²) cumulative history reads despite
exact-input arithmetic caches. Fixed-snapshot parent/header/record reuse may
reduce constant costs only while preserving all current error, clock, owner,
cancellation and final writeback semantics. This increment adds no cross-snapshot
validity cache and removes no integrity check. Nested native stage CPU observations
must be read separately from PN1's real total budget and honest-completion result.

1. First measure complete-State encoding, actual SQL/graph reads, history seals,
   proof collection, execution, lock wait, durable commit and client import.
   Retain 9bd's exact-byte arithmetic reuse and final integrity fences. Batching
   and pipeline improvements must preserve roots, errors, cancellation and
   one-writer atomicity; O(state)/O(history) paths remain explicitly disclosed.
2. Install a separately selected growth profile, using the existing research
   `GrowthStateCommitmentV2` and `growth_profile_binding_v2` only after complete
   parameter/header/challenge/namespace dispatch and independent vectors exist.
   Authenticate permanent account root/count/balance and bounded non-account
   liabilities. Verify original-parent touched-account proofs and complete
   mandatory recipient/range coverage before optional transactions. Preserve
   zero-balance existence, nonces, conservation and old-profile replay exactly.
3. Target block validation of O(W log A + bounded non-account/range input),
   where A is permanent accounts and W is all touched/mandatory accounts. Freeze
   numeric ceilings and require transaction bytes + W1 + witnesses to fit the
   selected packet budget. No per-request full-history walk in the new hot path.
   Replace full-read trust with explicit verified persistent roots, transactional
   generation fences, authenticated pages and cold integrity audit; never just
   skip the old pre-COMMIT/final reorg checks under their old root meaning.
4. Commit block, child roots, COW nodes, deltas, root references, reservations
   and active-generation publication through the existing durable owner.
   Retain roots for forks, pending reorg/recovery and acknowledged duties; GC
   needs reachability. A pruned deep valid fork uses verified resync, not invented
   finality. Export/migration verifies the complete source and publishes an
   isolated destination only after readback; source remains recoverable.

I03/I04 implemented subitem: the existing M07 native AAM1 query can now supply
its opaque checkpoint directly to M06's compact complete-State reference adapter,
without a separate AccountArchive. The same parent/context, witness budgets,
mandatory/successor checks and cancellation order remain. The signed native
differential suite covers zero balances/nonces, refunds and maturity; previews
cannot publish SQL or active state. This does not connect witnesses to Packet or
native admission, select GSC2, remove complete-State scans, or relax any 65,536
legacy cap. Bounded witness discovery/working input, durable deltas/root retention,
migration and fault/scaling acceptance in I03–I05 remain open; PN2 stays unqualified.

PN2 cold-journal subitem: the original growth Node's cold-open read transaction
now streams every event twice. The first pass preserves the prior complete
SQL-type-error priority; the second checks every genesis-to-active journal edge
with scalar generation/ordinal state. Two actual row cursors then compare the
latest steps/events and original reorg singleton, including both EOFs. Existing
hot reorg cancellation and publication remain unchanged. This removes the
all-events and last-generation event vectors while adding one O(E) read pass;
the 33-byte stored-hash copy bound and two retained event rows do not bound
SQLite pages, RSS or the rest of cold open. Blocks, checked roots/COW aggregates,
fork paths, DB/WAL and historical obligations still require their original
verification and I05 retention/resource ownership. No root is pruned, no local
history threshold becomes finality, and PN2 remains unqualified. Actual native
differential checks pass on 73 events and a 49-step reorg, including 27 SQLite
corruptions and the original late-type-error priority. The retained growth suite
passes 17 tests with the original 65,536-account release case ignored under the
existing serial CI setting. An earlier default-parallel run's `WRITER_BUSY`
failure remains recorded separately; its cause is not established by the later
serial pass. These results do not close global root/disk retention.

I04 producer subitem: the existing M07 owner can now issue an explicit opaque
historical account-query pin after the same complete-State validation, then
produce AAM1 from real Patricia paths without replaying State on each repeated
query. Each query rereads exact record/block/context bindings and fails on missing
or damaged tree bytes. This is fixed-root content access, not a fresh KV/history
audit, active-state entitlement, retention promise or executable bounded parent.
The original strict query, cold open, native execution/commit/reorg and all caps
retain their checks. See the existing [native storage contract](../protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md#explicit-historical-account-query-pins).

The separately selected native growth backend already binds its private audited
parent aggregate and complete bounded working partition to the actual header,
then shares M06 with proved touched accounts; the complete-State compact reference
above does not replace that path. Its activation now propagates cancellation
through ancestor reads, ordered journal writes and streamed exact journal readback.
The original cancellation error and whole-transaction rollback remain. Duplicate
journal vectors are removed, while the two fork paths, cold retained-history audit
and permanent root retention still grow. No public PNP2 admission, global disk
bound, source-preserving activation migration or final-source scaling acceptance
is supplied by this increment.

Its original-parent proof verification and both proof-derived successor root
computations now propagate the same original control error through existing
multiproof progress boundaries. M06's public interface and successful second
successor recomputation remain unchanged; a private single-error owner bridges
its string-only commitment result. Real signed small fixtures must reject early,
hash-stage and final-output cancellation without publishing any child or changing
any native table, then admit and cold-open normally with the same owner. These
boundaries do not make a single hash operation preemptible or close the remaining
PN2 qualification and retention items above.

The same explicit growth admission callback now reaches full W1 replay through
the existing typed verifier, preserving original control sources and `WORK:*`
invalidity. Failed or cancelled work cannot publish a child or reuse success.
Public PNP2 intake remains dependent on the shared original CPU/deadline/resource
owner and joint PN1/PN2 qualification. Global I05 bounds remain open: the inert
migration reservation and the separate M09 Cell arena are not ledger-root or WAL
quotas, and a SQLite page-exhaustion rollback test supplies no retention policy.

The existing Hepta bounded-state dependency also retains the real 1,000-cycle
SQLite and process-reopen workloads. After earlier 600.030-second SQLite
timeouts, the original four explicit qualifications pass at `df1b0c7f`: SQLite
in 554.851 seconds, 1,000 actual child-process cycles in 467.420 seconds and both
original crash probes. All 279 ordinary memory cases pass. The implementation
reuses only the same freshly verified journal within one read or the original
write transaction, retains live lease/state/digest/witness checks and borrows
five actual row texts. No cross-call cache, workload reduction, deadline change,
event deletion or new authority is introduced. This closes that finite controlled
timeout. The separate `0ca2b9dd` count-capacity repair reads at most 4,097 rows
and still rejects oversize state, and refuses a new 4,097th event in the original
write transaction before insertion. Three actual cold/full/idempotent/no-rewrite
controls and 282 memory cases pass; the combined `cd30140a` source passes 1,045
ordinary cases. The final published `394d1c75` combination also executes all four
original qualifications: SQLite1,000 in549.305s, actual process1,000 in470.916s,
KG crash recovery in0.122s and writer crash/reopen in0.131s. The original600s
test ceiling,30s child ceiling, workloads and assertions remain unchanged.
These finite results do not close per-row byte costs, global I05
retention, Windows execution, real-model or public throughput acceptance. The
existing PN2 owners retain those obligations.

Exit: actual signed native transitions cross 65,536 permanent accounts with
bounded W and working partition; small-state complete/reference differential
execution agrees. Pass zero-balance/re-entry/nonce, wrong-parent/omitted/extra
proof, mandatory maturity/refund/expiry, deep-fork/reopen, disk-full, provider-loss,
process-cut and cold-recovery schedules. Measure increasing A and retained history
at fixed W, including real proof/disk/RSS costs. A 65,537-leaf archive-only test,
larger cache, deleted zero accounts or a raised old key cap cannot pass.

### PN3 — One real parameter-to-public-model product loop

Owners: M09/M10/M11/M14/M15 and existing Hepta learning, artifact, selector,
TaskFlow, resource and FinalUse owners. Entry: PN0 source pair and I06–I10
bound; public claims additionally require PN1/PN2. Controlled product work may
proceed with those failures visible.

1. Start with one real compatible pretrained Encoder and bounded Cell heads or
   small adapter model through the ordinary neuron runtime. Record actual forward,
   training and post-install inference calls and hashes. A trait, fixed head,
   tabular scorer, declared Cell count or public 25-row ceiling is not this path.
   Use Hepta's shared Encoder and scoped immutable feature snapshot owners;
   feature reuse binds input, preprocessing, model, scope and local generation.
   The current ILM3/ILF3 family cannot admit arbitrary neural weights. Deliver
   an explicit M10/M11 artifact/release/evaluation profile with bounded codecs
   and stated independent-custodian trust before claiming native model admission;
   PoN orders commitments/settlement, not every validator's full LLM evaluation.
   Freeze evaluator admission/roster/epoch, conflict and Sybil assumptions, quorum
   fault bound, missing-reveal and appeal rules before outcomes. The controlled
   revision15 native-score threshold is not a private-evaluation safety theorem.
2. Freeze the named test dataset, source/time/exposure and reuse, consent,
   scoring rule, minimum useful gain, safety/retention limits and equal total
   train/evaluate/serve budgets. Existing public or previously seen tasks are
   admissible for the controlled engineering loop; unseen data and independent
   data custody are not entry conditions. Evaluate
   actual installed parent, frozen base, best single, simple/pooled merge and
   applicable routed/composition controls. Adoption needs the preregistered
   uncertainty-adjusted gain over the actual parent, the declared strong-control
   criterion and retention/safety/cost limits; correct for repeated candidate
   selection when claiming statistical efficacy. Claims about unseen future
   tasks separately require suitable prospective evidence and sample/power
   justification. V16 owner-pinned pre-genesis task
   windows are an existing replay input, not live future-data governance.
3. Run candidate -> authorized export -> independent evaluation/selection ->
   exact durable TaskFlow submission -> current chain observation/confirmation ->
   pinned release-closure download -> existing loader/resource/FinalUse admission
   -> fresh CURRENT generation -> actual next-task readback. Keep schema-4
   accepted-task binding and model-output/effect-packet digest domains distinct.
   The coordinator composes owners and creates neither new authority nor journal.
4. Integrate the existing configured-peer Cell pilot first. Release selection
   freezes base/tokenizer/runtime/layout/router/required-Cell closure and versions.
   Fetch missing chunks from finite peers with the original budget/deadline;
   verify full payload and dependencies before loader entry. Public discovery,
   independent replication/repair and private transport mature at PN5.

The PN3 receipt must join each round's actual predecessor load, authorized task
episode, dataset/export scope, train/control/evaluation calls, selected release,
exact TaskFlow operation/packet and schema-4 observation, closure fetch, loader
admission, installed generation and ordinary next-task loaded hashes/output.
Round two and three obtain their parent from that runtime readback, never from
the previous candidate filename. A no-update keeps and actually executes the
old parent; it cannot supply an installation or beneficial-release count.
Bind the safe loader to the complete base/tokenizer/runtime/router/Cell closure,
not merely a TCR1 member set. The existing Hepta operation owner reconciles
lost/unknown effects; this receipt creates no new issuer or learning journal.
Three no-update cycles do not waive the separate successful cross-node I09/I10
cohort with actual compatible installation and ordinary next-task readback.

The controlled 135M five-control observation in the inspected Hepta source
reports zero gain against the strongest control and no ordinary installation
or three-round closure. Preserve that result. Require frozen matched training
and evaluation costs, whole-composition safety/noninferiority and raw per-task
results for any successor; public/seen engineering tasks remain permitted,
while future-generalization claims need separate prospective evidence.

The current [controlled TCL4 relay](../../evidence/pon-upgrade-implementation-20261018/native-rounds/cell-tcl4-release-three-host-20261024/SCOPE.md)
passes the configured-peer transport subitem using the complete271MB public
material set,266 chunks and the same four finite persisted cache limits on
three actual tailnet hosts. Release transfers finish in33.255s and38.782s under
the unchanged120s windows; origin loss precedes the replica-to-consumer hop.
The development-build120s verification failure remains recorded separately.
This supplies byte/dependency readback only; real loader entry, installation,
next-task use, funded retention and three beneficial upgrades remain open.

Exit: at least three consecutive real lineage cycles, each using the actually
installed predecessor (or retaining it on a valid no-update), plus an independent
consumer's authorized next task. Bind each decision to exact bytes, evidence,
installation/readback and subsequent named-task results. Test lost ACK,
duplicate call, withheld Cell, bad shape/loader, author loss, stale/reorged task,
withdrawal during download/install and restart at each owner boundary. Keep local
effects/revocations monotonic. Mechanical completion and efficacy are separate:
three no-update cycles can pass safe loop behavior, never a claim of three
improvements. Three installed improvements on the declared tasks require three
separately measured gains under the frozen rule; public or previously seen
tasks remain valid engineering inputs. A claim of sustained improvement on
future tasks separately requires prospective qualification. No-gain yields
zero adoption/reward, not a manufactured success.

### PN4 — Rewards, reorg liabilities and free service

Owners: M09/M10/M11/M12 with M07/M08 and existing local effect owners.
Entry: PN2 conservation and PN3 exact operation/release identities.

**P0 native owner prerequisite, fresh namespace interface.** The existing
runtime owner now has a separate preparatory
[HostScopeAdmission](../../scripts/llm_runtime_host_scope.py) interface, with
[bounded manager transport](../../scripts/llm_runtime_host_scope_io.py).
It issues the actual `StartTransientUnit` request for the original caller O;
it does not execute that request at import or during the fixture tests.
The manager owns fresh scope S. O creates H only below S's original held FD.
O moves S -> H, enables S's controllers only after S is empty, creates
`H/observer`, moves there and enables H's controllers only after H is empty.
S has the manager's 17GiB/500%/272-task ceiling; H has the same resource ceiling
and real depth2/descendants4 bounds. H contains observer O (1GiB/100%/16) and
operation U (16GiB/400%/256, depth1/descendants2); U contains controller C
(128MiB/100%/16) and aggregate A (8GiB/300%/240), both bounded leaves.
These engineering ceilings are nested, not additional supply or funding.
S's topology controls are not part of systemd255's delegated-file allowlist;
the interface neither writes them nor claims a kernel topology bound on S.
Exact observed S-only-H topology and hard H bounds are separate predicates.

The original PID/thread/starttime, boot, namespace handles, manager unique name,
original invocation, mount, directory FDs, source bytes, limits and ancestor
ceilings are retained and checked. Existing groups are never adopted. Any
unknown manager outcome or later mismatch is sticky; the original owner and
FDs remain held. No stop/delete/reset/second request converts it to success.
Moving O does not move previously charged pages, as specified by the
[kernel memory-ownership contract](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory-ownership).
Consequently this is only a fresh namespace/subsequent-charge boundary; O's
complete RSS, original host baseline funding and physical resource return
remain open. Compatible ancestor ceilings are not reservations or CPU service.

The twenty-nine local controls retain all twenty-two preceding controls and use real bounded transport subprocesses, the original
source-built native close-and-clear slots and
ordinary temporary-FD layout fixtures with a mock manager. The retained-owner
regression adds an immutable copy of every native slot value and signature;
controlled bookkeeping mutations around real owned FDs must be detected without
changing the original assertions. A separate read-only
query checked real `busctl` method/property response shapes against the existing
manager. Those controls create no native scope. A separate
[first native attempt on exact378](../../evidence/pon-upgrade-implementation-20261018/native-rounds/host-namespace-pristine-failure-20261023/SCOPE.md)
reached `host-operation-not-pristine` in its one original admission and remains
UNKNOWN. Its twelve exports preserve original owner/job/invocation, six stored
group identities and sixteen owned slots; the old unit/cap is never reused.
The old guard did not identify the failing role/counter, so no charge or kernel
bookkeeping is exempted and no root cause is asserted. The diagnostic successor
captures role/field and the same first returned raw value without rereading,
reordering or weakening any original short-circuit empty/zero predicate.
An immutable first-failure tuple retains the complete bounded raw; exception
messages expose its length/hash and explicitly mark any raw suffix omitted to
fit the existing probe's4096-character diagnostic limit. Ordinary-file counter,
read-order, first-value and sticky-owner controls do not qualify native pristine.
Actual exit status stays UNKNOWN and whole-probe completion remains NOT_PROVEN;
the ordinary-exit intent and missing PID are not settlement or resource-return
proof. Another fresh native request requires independent review and a new GO.

**P0 phase correction, same original owner (preparation slice only).** The next
[exact-e6 native observation](../../evidence/pon-upgrade-implementation-20261018/native-rounds/host-memcg-phase-boundary-20261023/SCOPE.md)
captured `operation.memory.current=258048\n` at the first failed read, without
rereading. It remains UNKNOWN. Official Linux7 and Ubuntu7.0-38 source select the
parent active memcg while allocating accounted child-memcg statistics: creating
C/A below U can charge U even while O runs in observer and before C/A task birth.
The exact byte decomposition and deployed HWE source/config identity are not
proved. These are real U expenses, neither a deductible baseline nor exempt
bookkeeping. The original complete-layout `admit` path and all seven pristine
zero/empty requirements remain unchanged in meaning and remain unqualified.

M14/M17's existing `HostScopeAdmission`, manager/FD owner and limits now expose
`prepare_fresh_host_leaf()` -> same original owner -> `admit_fresh_leaf()` ->
private `_FreshULeafFact` -> `consume_fresh_leaf(fact)` once. No caller supplies a
leaf/pristine claim. The actual registered topology is only S/H/observer/U; the
unchanged guard runs on U before any C/A directory exists. The fact is bound to
that original owner, source, fresh generation, PID, manager unit/invocation and
held U identity; it cannot be copied/serialized or used by another owner. The
consume operation rechecks the actual facts, returns no authority and transitions
to LEAF_PROOF_CONSUMED; any ambiguity becomes sticky UNKNOWN_RETAINED with the
original slots held. It creates no child, operation grant, new owner or journal.
Factory owner/generation faults close before effects; cleanup failure returns
the same owner through `KernelOwnedCloseRequired`. All old22 plus seven new
ordinary-FD/mock-manager controls pass locally; none is
native admission or resource-return qualification.

The same staged owner now exposes `prepare_fresh_child_groups()` only after
LEAF_PROOF_CONSUMED. It creates C then A with create-only relative mkdir, holds
their actual FDs and configures/readbacks the original C128MiB/100%/16 and
A8GiB/300%/240 ceilings under U16GiB/400%/256. Each intermediate topology is
checked with the same original manager/invocation, PID/thread/source, held
identities and ancestor ceilings. U's actual current and historical peak must
fit its full memory ceiling, with zero swap/tasks/CPU usage and memory events;
no child metadata is subtracted or exempted. Only newly created C/A use the
unchanged seven pristine predicates. U is never called pristine after birth of
its child groups. `verify_child_preparation()` reads the dedicated completed
phase; successful preparation returns None and keeps `_ready=False`. This narrow
staged API is not the still-absent controller process/spawn authority protected
by the original controls, and existing production adapters cannot consume it as
ready. Partial creation/configuration or any later uncertainty keeps the original
cap, first error, attempted role and held slots in UNKNOWN_RETAINED; it performs
no close, removal, retry or adoption. A subsequent controlled empty-group
preparation observation is recorded below; native C/A process birth remains
NOT_RUN.

One controlled Linux experiment on source `03b67a955b8fcb6b6c920be584eaad5c0a71d34d`
now preserves [the exact source and raw exports](../../evidence/pon-upgrade-implementation-20261018/native-rounds/host-child-groups-preparation-20261024/SCOPE.md).
The same original owner consumed its fresh fact and prepared the six held
groups with the original limits. Pre-child U satisfied all original pristine
requirements; afterward full U `memory.current=352256` and `memory.peak=524288`
include the child metadata without subtraction or reset. Empty C/A retained
zero memory, tasks and CPU usage; operation memory events were zero. Exactly
one launcher and twelve readonly exports ran. The final export classified
`CHILD_GROUPS_OBSERVED_ONLY`; early samples lacked the not-yet-written ending
record, so the original conservative aggregate remains UNKNOWN. Both results
and every export are retained. This is an executed empty-group preparation on
that pinned source, not qualification of the later combined candidate,
controller/worker birth, whole-U retirement, refund or model acceptance.

The old aggregate constructor requires a service with the current C in its
controller subgroup; this scope's original O remains in H/observer. It cannot
be passed to that constructor or cast to a KernelBudget/Qualified fact. Actual
O-parent wait4(C), C-parent wait4(A), evidence binding/drain, ordered retirement,
whole-U terminal accounting, original baseline funding and settlement remain
OPEN. The source controls use ordinary files/FDs and a mock manager, including
modeled positive U metadata charges; they are not new kernel measurements.

The next internal C-mechanics slice retains the same original O and held C
FD through a private `_HostControllerOperation` binding. The unchanged clone3
ABI, four persistent native handoff slots, exec-error pipe, pidfd and exact
`_Wait4Child` wait4/rusage owner are reused through a dedicated internal type
selector; neither the old aggregate constructor nor a caller boolean opens it.
The original namespace owner still exposes no spawn/terminal/refund factory.
There is no CLI or public acquisition function: the existing Hepta funded
registration and sealed FinalUse/opaque grant producer must gate a future real
entry. Missing that producer remains a production blocker, not a successful
stub or a new Python funding/signature issuer.

C running/exit observations validate the original manager, O identity/observer
membership, retained six groups, exact limits/topology and unchanged pristine A.
U/C actual current and historical peak stay charged in full; retained peak/CPU
meters cannot rewind. No counters are reset or metadata subtracted. An exact
owned wait4 of C before the same supplied absolute eight-second cutoff can
record C's process exit plus raw U/C meters only; it cannot prove whole-U empty,
retire C/A or refund a reservation. The existing aggregate evidence-pipe and
framing controls remain unchanged; a real scope-C-to-A transport/owner binding
is still required before any complete O/C/A execution entry can be exposed.
Local controls use ordinary files/mock namespace observations and a real direct
ordinary wait4 child. They do not execute native clone3 into C, prove kernel
placement, grant FinalUse or count toward three real-model upgrades.

The subsequent private `_AggregateLaunch` supplies a fixed native C body, rather
than executing Python inside C. Original O still owns the same C clone3 handoff,
four persistent slots and exact `_Wait4Child`; native C uses its held A FD with
the unchanged spawn ABI and itself exact-waits A. Before A birth, C retains only
stdio, held A and its fixed receipt pipe; inherited O/ancestor/funding handles
are closed, and A/receipt handles are CLOEXEC. The same absolute monotonic
eight-second cutoff crosses both births and O's receipt read without renewal.
O reads one bounded 64-byte C record only after its separate exact wait4(C),
then retains actual U/C/A counters, including nonzero residual charges and all
historical meters. Pipe EOF is not proof that a payload executed. Seventeen new
controls cover the private binding, sticky refusals, original deadline, actual
native wait4 subroutines and actual exec handle closure; successful native
cgroup C/A birth is NOT_RUN. This handoff adds no public entry, FinalUse/funding issuer,
whole-U terminal or refund; production funded entry, A→C retirement
and raw U zero before the original cutoff remain OPEN.

The same launch installs a private retention-only C-wait role on original O's
`_Wait4Child` before native entry or any G write. Rollback, finish, direct signals
and pidfd-close paths cannot kill C or discard its original pidfd, including
after G raises a pending exception or the original eight seconds expire. Even
timely C/A exit does not release that handle before the still-open retirement
protocol. Native C likewise retains its original A slots and waits in its same
bounded process after an unresolved wait/poll/kill error; late A exit cannot
renew or unlock UNKNOWN. An actual terminal wait4 is kept distinct from invalid
rusage. Real ordinary-child fault controls exercise both owners and exact
test-only cleanup; none qualifies cgroup birth, retirement or model release.

Before that launch can create its native receipt pipe or C, the original host
module installs one fixed process-lifetime strong root for the same cap, bound
to the real O PID and concrete Thread. Losing all caller references and garbage
collection cannot discard the original C/A wait-owner graph or its held FDs.
Existing-root checks reject a second host preparation or aggregate before new
native/manager/pipe IO. The root exposes retrieval only on the same PID/Thread;
UNKNOWN and even a normal C receipt cannot clear it. The existing C-only path
does not install this C/A root. A real ordinary pending-G control drops every
caller reference, collects garbage and checks the exact retained slots/FDs;
test isolation clears its mock root only after exact C→A and O→C cleanup.
This retention root does not retire C/A, prove raw U zero or release funding.

That same rooted launch now predeclares a single native retirement preparation
slot before its receipt pipe or C/A birth. It allocates a fixed 1MiB stack plus
two protected pages and creates one native thread in original O/observer under
the unchanged observer 1GiB/100%/16-task total ceilings. Native PID/TID, exact
held observer identity, current thread membership, actual stack address and
the same absolute cutoff are bound before readiness. This is bounded use of
the existing ceilings, not physical funding or a claim that task headroom is a
reservation. Preparation alone grants no effect authority. Its one
preborn worker waits to the original monotonic cutoff without a qualified request; expiry/refusal retains
the stack, original root and fixed state, with no later worker, queue or retry.
Nine real native controls run in O's existing read-only cgroup, checking actual
thread membership, both guard maps, duplicate refusal, cutoff and preparation
faults, including a worker still blocked past the cutoff; the existing namespace
controls explicitly model this new transport.
They do not qualify fresh observer placement, C/A retirement or raw U zero.

Native snapshots acquire the initialization publication before reading any
ordinary owner/output fields; EMPTY/OWNED refuse without inspecting them.
Preparation claims the fixed slot before scanning its output and refuses an
occupied slot before caller-buffer reads. A nonzero first output consumes the
same failed slot without reset. Four additional controls pause initialization
and protect the original output page, retaining the original nine preparation
assertions and cutoff; neither refusal path may race the owner's snapshot.
The first `9cf5de77` preparation retained eighteen real TSAN warnings. Its
`01c65582` successor passes the unchanged TSAN driver with11,263 competing
calls per thread and no warnings; the same four new controls actually fail
against the old C source and pass on the fix. Independent159/159 controls and
the full952-case repository-truth job pass with zero skips. These results close
the two identified publication races, not native C/A birth or retirement.

The original private controller now admits one child-retirement effect only
from its internally retained exact O→C/C→A terminal fact, after repeating every
original live identity/limit/history and zero-population check. The same preborn
worker consumes a release-published fixed payload and removes A then C through
the original U FD and exact held name/inode checks, closing each original slot
and finally the original C pidfd. Each irreversible step records actual progress;
error, blocking or late completion retains the root and every remaining slot,
without retry/reentry or a renewed deadline. A same-O retain-only native latch
registers UNKNOWN on the same fixed atomic word as each of the five steps
(A unlink, A close, C unlink, C close, original C pidfd close). Each step has
one strong CAS against its exact predecessor. Cancellation first forbids a new
commit; a step that commits first may finish only that step and records its
actual progress, while subsequent steps and remaining FDs stay retained. The
original first error survives even a failure of the latch. This linearization
does not preempt a committed syscall or guarantee when the scheduler enters it;
the original absolute eight-second checks still reject late success. Private
snapshot layout2 assigns word23 to last committed step0..5 plus sticky STOP
(0x80000000), source-bound to a fresh prepared owner with no old-root adoption.
Four additional controls cover all five before/after-commit orders, a late
committed step, and strict layout/phase rejection; retained f69 with only
test synchronization pauses fails all five before-commit effect assertions.
A sticky pre-entry marker forbids
live verifier scans while those arrays may be closing. A separate strict phase
verifier accepts only complete native progress, original identity/quiescence and
unchanged U history; it reports unlink/close facts, never Whole-U or resource
return. Ten real own-directory controls (explicit test-only filesystem wrapper)
and seven modeled exact-terminal/phase controls do not qualify real cgroup
retirement. The original preparation observation helper rereads its same buffer
after actual thread disappearance for its unchanged finished==1 assertion;
the prior cached-snapshot race and a deterministic old-helper failure are kept.
Linux has no unlinkat expected-inode argument: this remains the existing trusted
administrator namespace scope, not hostile same-UID rename isolation. Actual
cgroup retirement, U dying/current zero and funded entry remain OPEN.

The same original launch also predeclares one private raw-U readback slot before
its pipe/C/A effects. After complete exact child retirement, its no-argument
owner call consumes that slot once and repeats the complete retirement-phase
source/identity/limits/history verifier for every observation. At most801 reads
use the original absolute cutoff, with at most10ms between positive current or
dying observations; this is no additional window or helper. Two consecutive
complete raw-U zero observations are required: current/swap/pids/procs/populated,
descendants and all dying counters. U's own `nr_subsys_*` counts remain intact;
historical peak/CPU are monotonic, never reset or subtracted. Missing/malformed
fields, drift, cancellation, late reads or exhaustion retain UNKNOWN and every
remaining original FD/root, with no reentry. Success reports only
`raw_u_zero_observed`; Whole-U, funded return, authorization and refund remain
false. The acceptance check also rechecks sticky failure/closed state and the
same held U/deadline after parsing, including cancellation during the second
zero read. The single retained observation is an immutable nine-item snapshot;
mutating a normal returned DTO cannot expand the process-lifetime root. Fifteen
modeled held-directory/clock controls exercise this boundary;
they are not native cgroup qualification or a claim of bounded syscall latency.

The [2026-10-25 actual controlled evidence](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/SCOPE.md)
now includes fresh `/bin/true` C/A birth, both exact waits and native retirement
on `6a96dd94` and `ec6868da`, with progress31 and step5. The latter original
raw-U observation fails its original start+8s cutoff and keeps the same owner,
root and handles. Only a separate post-deadline diagnostic reports remaining
kernel charge4,096 with zero processes/descendants/dying; it is not a terminal
receipt. Native child retirement is therefore observed in this controlled
scope, while raw-U zero, funded entry and whole-unit return remain blockers. A separately reviewed
fresh fixed `/bin/true` diagnostic pins only its new owner and descendants to one
allowed CPU. Within the same original start+8s window, the unchanged sampler
observes raw U zero in 12 samples, while retaining the original owner and all
Whole-U/funding/refund flags as false. The earlier multi-CPU failure is preserved.
This is a scheduling diagnostic, not a product policy, a uniquely proved kernel
cause or closure of multi-CPU physical return and bounded retained-state gates.

The same controlled original-model cases are then run from one frozen Hepta
`b27a2f5e` archive on both hosts. The local ROG passes all three; its full
comparison takes13.129 seconds. The restored4060 passes artifact publication
and signed read/unload, but fails the comparison at41.219 seconds after its
first query becomes Indeterminate and the candidate worker encounters
BrokenPipe at response send. Its original retry refuses existing output. The
actual control has only three records per phase, not66. Preserve both hosts'
[exact outcomes](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/integrated-b27-original-native.json);
no unique first-query cause, initial neural-parent load or installed upgrade is
proved. The owning Hepta prerequisite now validates canonical positive-zero
initial bytes and exposes only non-installing selected material with original
selector expiry, known revocation and fresh CURRENT checks. Actual main-weight
measurement, ordinary task context, eligible child selection and subsequent
CURRENT/cold-reopen composition remain the next PN3 dependencies.
No old Unknown owner is cleaned or reused to obtain these results.

The existing PN4 dependency and acceptance sequence is:

| Stage / owner | Interface and required evidence | Status / exit |
| --- | --- | --- |
| Fresh leaf / M14/M17 | Same original owner; exact topology/limits/source/generation and original seven-zero guard before C/A | Preparation and one-shot consumption implemented; new native qualification OPEN |
| C/A preparation and birth / same owner, Hepta kernel.operations | Consume the same fact once, then create exact bounded C/A; charge all child bookkeeping to U's 16GiB; original native birth/pidfd/wait4 binding | Two actual fresh controlled empty-payload runs observe birth and exact waits; funded/native model and whole-U qualification remain OPEN |
| Running and quiescing / same original O | Monotonic existing operation/effect identity; authoritative original C and A exits plus zero leaf populations/descendants | Observed only for the named controlled empty payload; never call running U pristine or generalize to the model/funded route |
| Normal retirement / same original O | Only after both exits are known, retire A then C once using original parent FD/name/inode, then native close-and-clear of those original held slots | Native child retirement observed on the named controlled sources; no full raw-U return. Unknown/partial removal retains remaining slots, never retries or reuses names |
| Whole-U terminal / original evidence-pipe and aggregate owners | Retain U/S/H/observer; actual U descendants0/dying0/current0/swap0, exact identity/limits and unchanged historical meters before original cutoff | OPEN; no charge/peak reset or baseline subtraction |
| FinalUse and I05/I10 settlement / existing effect owners | Original authoritative terminal identity and budget/funding evidence, then existing AuthBus reconciliation | OPEN; no new journal or refund path |

The eight-second fact cutoff is the original supervise start plus8s, never a new
retirement window. Historical peak/CPU remain recorded; peak0 is a fresh-leaf
prebirth condition, not a resettable terminal meter. Kernel CSS teardown/charge
drain can remain pending past the cutoff: that result is UNKNOWN_RETAINED, with
no terminal receipt, new entry or refund. Linux7 `rmdir` can block in-kernel;
synchronous remove/poll code cannot promise an eight-second return. The private
native asynchronous effect above occupies at most one bounded slot permanently
owned by original O. On timeout it retains the slot/handles,
forbids reentry and grants no refund; timely observer return does not prove the
effect finished. Actual controlled empty-payload birth/retirement does not supply
the original guardian lifetime/budget, funded model entry or whole-U terminal
evidence; those remain explicit PN4 blockers. No additional native side effects
are authorized by these tests.

Native S/H qualification,
original C birth/pidfd/wait4, whole-U zero-charge terminal capture inside the
unchanged original eight-second deadline, FinalUse entry and AuthBus settlement
remain required in that order. This interface exposes no spawn, terminal,
settlement, refund or model-install operation. The original sixty-six aggregate
and charge-wait assertions remain unchanged. Fallible signature reads retain the
already opened FD in the original native slot; close-and-clear is one unchanged
source-built C call. Partial close faults keep that slot, and constructor cleanup
failure returns the same owner through `KernelOwnedCloseRequired`. The generic
`os.open` to Python-slot acquisition boundary is still trusted preparation,
without a general asynchronous-signal leak-freedom qualification.

Deliver separate finite mining, contribution, evaluation, byte-retention/repair
and inference budgets. Reserve storage capacity and mandatory successor duties
before acknowledgement. Price actual byte-time, transfer, evaluation and service
units; signatures and token issuance do not create disks or GPU supply. Contribution
credit follows the frozen whole-model rule with uncertainty and duplicate/bundle
controls, never chainwork. A failed or no-gain candidate consumes only its explicitly
authorized evaluation resources and receives zero model-improvement payout.

Exit: escrow and monetary invariants hold through split/replayed contributions,
orphaned adoption, maturity/expiry/refund, interrupted repair, full storage and
lost ACK after external success. Reconcile the original effect identity without
rewinding the local log. A new consumer receives measured sponsored basic use
within published quotas and real funding; exhausted funding returns a bounded
service outcome. Retention expiry cannot erase account nonces or acknowledged
duties. Economic/security review remains separate from unit conservation.

### PN5 — Independent system acceptance (the G5 release boundary)

Owners: M04/M09/M13/M14/M15/M17 with independent operators and data evaluators.
Entry: joint PN1–PN4 acceptance on the current pair; explicit tested work/network/
storage trust assumptions. Independent means separate administrators/custody and
failure domains, not extra processes or keys controlled by one operator.

Deliver bounded discovery and authenticated/confidential transport where required,
provider expiry, chunk scheduling, replica repair and verified sync. The initial
development DA objective is three complete replicas across three independent
failure domains; loss of one must leave retrieval from the other two and repair
to three within a preregistered repair deadline and byte/funding budget. This is
a new test objective, not the current pilot's guarantee or a production SLA.
Erasure coding is a later separately specified option with decode/repair costs.

Exit: run at least a 72-hour frozen WAN campaign with at least three independent
operators, reporting all load/fault cohorts, partitions/heal, eclipse attempts,
proof floods, churn, origin loss, disk-full, restart, separately identified power
loss, deep reorg and new-node sync. Freeze offered load, attack budget, confirmation
policy, latency/completion objectives, storage/repair deadlines and tail sample
requirements before the run. Report unique confirmed TPS, candidate-to-install
tails/failures, subsequently qualified updates, honest completion and full
recovery costs. Missing/undersampled tails remain unaccepted. Every threshold
must pass in its named cohort; a strong aggregate cannot hide an attack failure.
The duration/operator count are minimum development coverage, not sufficient
production security. Exact-head and applicable merge evidence remain distinct.

Only after measurement shows propagation/stale forks dominate, compare the current
chain with Conflux/GHAST, GHOSTDAG or Prism under the same W1, execution, availability
and total resource assumptions. A reference-DAG transport comparison is not those
consensus implementations. Any successor must specify ordering before post-state
roots, conflict/reward treatment, withheld data, reorg and client confirmation;
it cannot inherit another chain's safety bound or add references to old headers
silently. State I/O or verifier amplification is repaired in its owner first.

### PN6 — Migration and governed deployment

Owners: M00/M07/M08/M13/M15 and the existing release/activation authority.
Entry: accepted PN0–PN5 evidence on the exact proposed binaries and contexts.

**Materialized rehearsal observation, 2026-10-22.** The existing Node now exposes
`rehearse_growth_migration_v2` and an independent READ_ONLY cold verifier for
quiescent legacy/authenticated sources. Native job `1a16282a4b9-1b6abb-2da2`
exited 0 with all six rehearsal tests passing and exported both actual source
formats under `pn6-growth-rehearsal-candidates` in the local execution root.
The exact log locator, test coverage and flags are recorded in the
[growth profile observations](../protocol/pon-nakamoto-v1/details/NATIVE_ACCOUNT_GROWTH_V2.md#observed-development-runs--2026-10-22).
This batch has no final combined-source manifest; later source changes still
require their own applicable qualification.

The archive preserves every retained original-schema branch, signed transaction,
state/delta root, local replay/outbox/pool record and reorganization fact. The
candidate checkpoint retains the original height, nonces and monetary duties,
with actual COW nodes and complete unchanged working rows. Readback independently
reexecutes the old history and audits the new checkpoint; failed pending stages
remain visible, and publication never replaces an existing destination.

This candidate schema cannot admit or activate blocks. `migration_executed`,
`old_work_promoted`, `consensus_activation`, `production_enabled` and
`external_journals_imported` remain false. External M09/M12 effects and revocation
history are not copied or reset. Executable cross-context work/evaluation rules,
external-owner drain/reconciliation, independent PN0–PN5 acceptance and the actual
governed release decision are still required. Source preservation and six passing
local tests do not close those requirements or grant activation authority.

Rehearse drain/reconciliation, full source verification, isolated destination
publication, cold readback and abort/recovery with all obligations and old-profile
history retained. Use fresh genesis, profile/domain and storage identities for
changed relations. No old proof or work weight is silently promoted and no
cross-network double-spend protection is invented. A rollback selects a newly
authorized local generation; it does not restore an old revocation frontier or
overwrite signed history. Document irreversible external outcomes explicitly.

Exit: independent acceptance and the actual governed release decision authorize
the specific migration/activation. Development selection, source merge, document
checks and model publication keep all production/activation flags false.

## 7. Qualification and evidence commands

Run project preflight before edits/commit/push. On a committed, unchanged checkout:

```bash
bash scripts/project-preflight.sh --audit
python3 scripts/ci/check_repository.py
python3 scripts/ci/test_repository.py
python3 formal/pon-nakamoto-v1/test_reference.py
bash scripts/ci/check_canonical_development_plan.sh
cargo test --locked --workspace --all-targets --all-features --manifest-path trillionnium/Cargo.toml
```

The new reference tests are arithmetic/state examples, never a neural miner, work proof,
Rust node or deployment certificate. Retained component regression tests remain required and are not evidence of PoN completion.
Run the affected Rust package tests, strict Clippy/fmt and applicable build-closure,
security and supply-chain checks for actual implementation changes.

Preserve exact source/tree/base/binary/profile/configuration, raw failing and successful
logs, hardware, actual invocation path and independent review. Current candidate identity
comes from Git/CI, not branch prose. Derive source and document fingerprints from the actual checked-out tree, never evidence outcomes. No self-approval, unrelated protection change,
force push, deployment or performance/efficacy claims arise from this refactor.

## 8. Completion definition

The direction is complete only when a real local-task update becomes a verified useful
part of a reproducible shared model, a new user obtains funded free basic use, the
contributor receives exactly the allowed reward, and the new PoN chain safely handles
work competition and reorg under its qualified assumptions. This document does not
assert any of those experiments ran. Open work-profile and implementation obligations
remain named in the machine contract and domain acceptance specification.


## 9. Active-tree cleanup boundary

`config/portability-inventory-v1.json` is the actual retained-package/owner inventory.
All old protocol and runtime trees are absent; Git history is the archive. Deployed
state, keys and services were not touched. Portable domains and schemas are fresh-only.
Local monotonic application stores are NOT yet authoritative branch-aware chain storage.
Storage/evaluator thresholds are application trust contracts, not ledger voting power.

## 10. Current convergence, not a count of documents or tests

The authoritative invariants are `config/pon/invariants-v2.json`. Each names its claim,
owner/scope, atomic boundary, adversarial schedule, exact test selectors and remaining
assumptions. All eighteen module contracts refer to their own failure modes. A registry
checker proves that these bindings exist; a separate exact-source receipt proves which
selectors actually ran. Neither mechanism supplies independent scientific authority.

| Priority / workstream | Actual implemented boundary | Concrete next acceptance requirement |
|---|---|---|
| P0 work and public admission | Exact experimental transcript and complete production transcript verification with an explicit scalar reference; a mismatching final digest skips product corrections after the complete transcript replay, while matching digests still require exact product verification; native PreparedTask removes avoidable repeated product work; paired valid-producer costs and bounded development ingress retain open hostile-proof/Sybil qualification | Implement/reproduce adversarial shortcuts and same-target costs; join ordinary public ingress and demonstrate honest service under stated sustained attack. No queue count grants work hardness. |
| P0 one native node | Native development CLI owns work/target decisions, branch persistence/reorg, receiver sync/confirmation an allowlisted signed private-development ingress with durable inbound replay/client outbox, and explicit public-development-v2 resource-ticket intake with bounded Head/History and no durable guest authority; original M00/M01/M06 are reused | The explicitly enabled [local queued owner](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md) provides bounded durable groups, typed M05 checks/M06 preview and branch/restart reconciliation; its explicit wall-clock miner, fresh V4 signed-overlap renewal, paid V3 transaction intake and operator-pinned peer following share one native owner; qualify measured sustained operation, open public discovery/gossip plus confidentiality, interruptible native work and ordinary Hepta/resource/effect integration. Both transport profiles remain development candidates; public-v2 resource bounds and local conformance do not grant public-service or complete product acceptance. |
| P1 long-lived state and confirmation | Native branch/delta/checkpoint persistence, receiver verification and exact signed-request replay/outbox state coexist with the independent reference oracle; root maps/history scans still incur full-size costs | Persistent incremental authenticated roots and real WAN/open-peer integration; the controlled receiver is full-verifying, not succinct or globally fresh. Verify deep history without treating private authentication, transport budgets or retention as finality. |
| P1 independent model value | E3 seals actual parent/candidate/strong controls/calibration/partitions; explicit revision11 factor admission loads the complete current parent and rejects exact same-context BA copies; no-gain remains zero adoption and reward | Authorized new tasks, independent source/evaluation/withdrawal owners, untouched future windows and budget-matched strong controls. Retrospective splits or configured identities do not satisfy independence. |
| P1 real resources and failures | Closed service receipt, finite quota/reward conservation and same-admin process/host fault observations | Real storage/serving obligations and funding, target-side effect reconciliation, independent operators, physical power loss and hostile public network. No chain undo may repeat a physical action. |
| P2 end-to-end capacity | Source-bound worker/session comparisons plus real native CLI, process-cut and loopback socket regressions; no sustained public capacity claim | Same profile, source, state size and load through submission, inclusion and client-verified depth/work confirmation, with latency tails, hotspot degradation, resources and attack availability. Executor speed alone is not TPS. |

Existing capacity/initialization/revoke-entry/admit-before-activate counterexample fixes
remain regression obligations in the current owners; they are not new missing features.
P0 work research and native integration may proceed concurrently, but neither grants the
other's acceptance. The five documentation corrections are implemented through current
revision applicability, procedure-level maturity/evidence, exact M08 phase contracts and
explicit application scope; their completion is not completion of this table.

Do not repeat already accepted component work under a new parallel engine. The source
inventory remains the sole native package/owner list; proof, execution, chain state,
model quality, local permission and actual effect entry remain different facts. A
published Hepta learning artifact does not automatically authorize public redistribution:
its publication receipt carries DENY_ALL authority, and actual export/withdrawal and
final-use decisions belong to existing independently configured owners.

## 11. Current model and consent increment

The [E3 contract](../protocol/pon-nakamoto-v1/details/EVALUATION_BUNDLE.md) gives the
exact immutable evaluation object, limits, control materialization, source-group policy,
producer write boundary, evaluator replay and consumer expectations. Existing
`model_loop.py`, `learning_cycles.py` and `settle_model.py` consume it directly. No new
trainer, artifact registry, global optimizer or parallel economic ledger is added.

A reference file, task file or score report changed after sealing must fail under the
caller's admitted hash. Calibration chooses the strongest deployable control using the
same equal-group principle as evaluation. Both positive mean gain and the corrected
sign-direction test are required. The settlement producer recomputes the original
calibration and evaluation; rehashing both summary and evaluator files cannot grant
reward. Full service expectations include returned output, units and provider nonce.

Three actual optimization attempts must each start from the actually admitted public
artifact. No-update, weaker-than-control and zero-reward outcomes remain visible. The
current public-source corpus is retrospective; three disjoint file pools or a caller's
future flag are not three independently improving prospective generations. Public
parameters change only after current independently admitted evidence and owner approval,
not because the experiment was scheduled to run three times.

## 12. Evidence and remaining authority

[Procedure-level evidence navigation](../modules/README.md#responsibility-and-evidence)
reads immutable package identities and reports subject-byte equality, the complete
recorded runtime and exact observed/unobserved selectors separately. Reusable package
presence is not ordinary product integration. Empty entrypoints and unobserved campaigns
remain explicit; no mandatory paragraph length, heading total or test-count gate is added.


`evidence/pon-v1`, `pon-v3` and `pon-v4` retain their exact historical source, failures,
workload, filesystem and host scope. The historical verifier checks those bytes and
results without promoting them to a changed current binary. Current model execution
requires its own current-source receipt; source equality and empirical effectiveness
are separate checks. Runtime changes must never be hidden by repinning old reports.

New measurements report input composition and conflicts, submitted/executed/included/
client-confirmed stages separately, proof cost, wall time, RSS, model load and actual
resource use. Unmeasured VRAM/inclusion/confirmation remains null. Native component
throughput is not chain TPS, and same-administrator physical machines are not independent
consensus actors. Root README remains blank by owner decision.

Squash merges may leave measured source commits outside main's ancestry. The evidence
preparation tool fetches only declared exact objects from this repository, verifies
their trees and never moves a branch or grants acceptance. A missing source object is
an error, not permission to copy current results into historical evidence.

Still unaccepted: cost-hardness and public hostile-proof fairness; complete public native host, continuous miner/mempool lifecycle
and ordinary Hepta owner/resource integration; independent attestors/custodians;
untouched future tasks; sustained long-term DA/state growth; actual physical power loss
and public network security. Highest repository privilege does not manufacture those
facts. Continue their implementations and falsifiable experiments on this lineage;
production remains disabled until the corresponding evidence exists.

[The retained E3 model execution receipt](../../evidence/pon-evaluation-bundle-v1/README.md)
records its exact-source native and logical regressions, locked evaluation replay, three
no-update optimization attempts and nine same-input results on three owned hosts.
It does not cover the subsequently added client runtime or replace independently
administered future tasks and public work qualification.

[The receiver-verified client receipt](../../evidence/pon-client-confirmation-v1/README.md)
records new clean-source full regression and both reference and explicit native compute
client configurations, including complete-ancestry clock reobservation. The same
responsibility reporter resolves its measured source and exact selectors. No model
training/host campaign was rerun for that receipt. Its retained initial failure exposed
an omitted-source hole in historical component checking: the original measured runtime
inventory must come from the measured Git tree, not an editable receipt. Publication
checker tests are separate from runtime qualification; local callbacks inside a test
are not independent test cases. Original successful and failed logs remain immutable.

## 13. Native session, bounded confirmation and new-source qualification

Continue the same canonical PR #204 lineage. Existing five applicability/evidence/M08/
responsibility/application-scope corrections are preserved, not counted as new runtime.
Recovered local work is integrated only after source comparison and byte-preservation.

In the historical session path, M06 exposes an optional private native compute session
with a compressed in-memory incremental commitment. Within that path M07/M08 reference
SQLite remains the sole durable owner. The subsequent native CLI has its own fresh
M07/M08 namespace, not a second writer of the reference store. Strict predecessor bytes, sequence, delta, output,
backend selection and lost-reply handling prevent reuse of an unknown cache as authority.
Early work prechecks reject malformed input before branch-state reconstruction but do not
qualify cheap forged tickets or adversarial work hardness. The receiver can check a bounded
batch of distinct transaction confirmations with one complete-ancestry clock observation.

Qualify on a clean committed source, including all existing native tests, client/reference/
explicit-native/session backends, old evidence integrity and newly added counterexamples.
Run same-source paired execution costs and an actual work/persistence/receiver-confirmation
campaign into new paths. Report logical-clock/no-pacing and local-controller limitations;
no executor improvement becomes public TPS, independent consensus or full-node completion.
Historical E3/model/client reports retain their original source and outcomes. The new
current receipt must cover changed runtime; no old receipt is repinned or silently waived.

All six P0/P1/P2 tracks above retain their missing real boundaries: adversarial work/public
admission, ordinary native node, persistent state/WAN sync, authorized independent future
model efficacy, funded DA/effects/physical faults, and sustained public confirmed capacity.
No new VM, EVM, consensus fallback, learning owner, live service or production flag is added.

[The historical native-session and receiver receipt](../../evidence/pon-native-session-v1/README.md)
supplies its original exact-source regression and controlled pipeline observations.
Native-node changes require a new native-node receipt; old E3/client/session packages
are historical, not current-runtime coverage.
The retained selected-matrix pass is accompanied by the later actual expiry-receipt and
maximum-budget failures, their fixes and a complete clean-source rerun. An incremental
in-memory tree is not persistent native storage, and locally verified confirmation
under a logical clock is not public WAN throughput or deterministic finality.

The [historical session-source work-cost collection](../../evidence/pon-native-session-v1/work-cost/README.md)
was rebuilt and executed on its named clean source after the prior cost gate rejected
stale inputs. Current and historical verification remain separate required checks.
The [retained publication failures](../../evidence/pon-native-session-v1/publication-failures/README.md)
also record globally ignored raw logs; the delivery checker now requires actual Git
coverage for in-repository receipts. None of these repairs changes work qualification,
production flags, original model observations or the missing ordinary native host.


The same native development composition now supplies bounded ordinary CLI/socket batch
confirmation, cancellable read traversal and an explicit allowlisted signed private-
development transport. Inbound replay reservation and signed response retention survive
restart; the client commits one exact signed wire before I/O and retries only those bytes.
Opened-descriptor checks protect key/roster inputs and authentication options are confined
to network commands. These facts close a controlled request/replay gap, not confidentiality,
open peer discovery, Sybil fairness, independent administration or target-side physical
exactly-once effects. Fixed-dataset value and elementary accuracy upper-bound statements
are recomputed by the existing evaluation/settlement workers; they do not qualify
prospective learning or general circuit optimization. Record this changed source in a new
native-node receipt rather than repinning session evidence. Public P2P/work admission,
continuous mining/mempool scheduling, native persistent incremental state, revision3
evaluation-order economics and genuine Hepta/model/resource integration remain separate
unfinished implementation/acceptance work on these existing owners.

The current [native-node receipt](../../evidence/pon-native-node-v1/README.md) binds the clean runtime, actual native CLI replay, both work-cost targets and a separate recomputed model-value experiment. Hosted candidate/merge checks remain fresh delivery observations, not part of old runtime receipts.

## Complete-evaluator successor and alternative valid-work producer

Continue PR #204 and the same native M11/M06/M15 owners. The default revision3 and all
prior evidence remain unchanged. An explicitly selected fresh revision4 development
context binds `closed-round-all-eligible-min-v1`: every eligible genesis attestor except
the exact author must submit before the minimum score closes. Missing/zero evidence
cannot unlock adoption or reward; existing signed expiry bounds withheld candidates.
This removes prefix-arrival selection for this complete-set rule, not evaluator trust,
withholding, functional-copy attribution or the need for a public dispute profile.
Ordinary native CLI mining, reopen, heavier-fork removal and reexecution are exercised
with the same signed transactions and independently computed state. No old database is
migrated, production enabled or authenticated public ingress inferred.

The existing M01 PreparedTask producer now uses exact bounded field reduction,
transposition and batched transcript hashing. It must produce byte-identical work under
the unchanged verifier. Account preprocessing and same-target winners, full verification
and forged-ticket rejection separately. An observed cheaper valid miner tightens the
actual cost question; it does not qualify the work profile or supply a lower bound.

New runtime needs its own clean-source qualification and cost records. Old node/model/
host evidence remains historical. No new training, funded GPU serving, independently
administered future-task acceptance, continuous public miner or persistent authenticated
state is claimed by the closed-round or arithmetic changes. Their existing P0/P1/P2
workstreams remain implementation and external-acceptance obligations, not paper gates.


The [closed-round/producer receipt](../../evidence/pon-closed-round-v1/README.md)
retains the explicit revision4 selection, complete eligible-set aggregation, ordinary
native CLI/reorg tests, exact optimized producer, and new same-target cost collection.
It preserves revision3 defaults and all historical artifacts. Source qualification,
independent model value, public work safety and production activation remain separate;
the remaining work stays in the existing convergence table, not a new roadmap.

## Six-finding convergence continuation

The [current entrypoint and acceptance contract](../protocol/pon-nakamoto-v1/details/PUBLIC_READINESS.md)
maps the six audit findings onto executable development interfaces and remaining public
gates. This continuation stays on the existing native candidate; no acceptance flag is
promoted. The implemented additions are a negotiated connection-local proof-admission
challenge, explicit signed-task revision5 registration/material/parent eligibility,
branch-relative arithmetic-output counting, bounded integer-adapter attribution and
off-chain evaluation lifecycle, and a durable TCP/client-confirmation campaign. The
original work verifier, chainwork and revision3/default bytes remain unchanged.

The signed-task testing context has16 public fixture demands, a public source seed,
a fixed withdrawal frontier and1000-block bootstrap lifetime. It is intentionally not
an exclusive production source, real task marketplace, live revoke or indefinite
maintenance policy. The attribution profile establishes exact BA identity and finite
candidate-set objectives, not generic neuron equivalence, independent future efficacy
or global neural-circuit optimum. Public evaluator governance remains a separate owner responsibility. The explicit
native-public-evaluation-dev-v1 successor implements frozen commit/reveal phases,
mandatory deadline closure, signature-conflict evidence, bounded archive appeals and
existing funded release/reward gating. Its heights and branch state are native; its
development identities and signed scores remain unqualified for independent governance
and objective ML quality. Historical revision4 and default revision3 keep their bytes.
An actual complete-round counterexample exposed the previous single-value storage
limit: a late reveal conflict and the third appeal exceeded4096 bytes and rejected.
Storage revision2 separates bounded records, commits a fresh network/parameter context,
and tests all16 appeals, late conflicts, archive-only continuation, reopen and cleanup.
Preserve the failed candidate and its original execution record.

The explicit signed-task-lifecycle-dev-v2 revision7 adds native requester lease
open/renew/revoke and source registration under distinct signing/parameter domains.
Renewal keeps the admitted material and one-output meter; revoked parent state refuses
subsequent work. Generation-safe bounded slots retain source sequence and availability
windows. Actual Node tests cover signed transactions, valid PNW1 packets, durable reopen
and heavier-fork replacement. Development authorities and cost-class1 remain unqualified
for genuine demand, remote availability or cheapest-miner hardness.

The pinned SmolLM2-135M CPU/rank4 LoRA family has actual material loading, training and
all four required controls in an isolated LAN runtime. The tiny public same-operator
fixture gives zero gain against the strongest control. An explicit cross-context bridge
binds the raw artifact and original observation to native revision7, completes the native
commit/reveal round at score0 and refuses adoption/reward; it claims no native ML proof.
The [bridge input/output boundary](../../scripts/llm_runtime_README.md#native-negative-bridge-input-and-public-output)
requires matching canonical contract digests and projects public receipts through an
explicit typed field allowlist. Raw external metadata stays private; canary rejection
and non-echo regressions do not qualify model efficacy or the public security gate.
The separate distributed caller assigns producer, authenticated validator and full-sync
confirmer to three OS processes with three owners. Each verifies native work and state;
matching signed receipts do not attest physical placement or independent operation.

Priority remains P0 qualified cheapest-miner work cost and sustained hostile intake,
then P1 actual target-model efficacy/poisoning/deployment costs, independent evaluation
governance, useful-output efficiency and steady end-to-end state/history/network load.
Keep failed experiments and all attempt/validator costs. Live wall time and descriptive
latencies do not supply a hardness theorem, independent operators or public fairness.
The new clean-source qualification runner captures the full native/reference regression
and additional campaigns; historical receipts stay bound to their original source.

The [six-finding local qualification](../../evidence/pon-public-readiness-v1/README.md)
records clean implementation c2b1ca2 with cryptography50.0.2/OpenSSL4.0.3, all 15
qualification commands and the nested 48-command native/reference regression. Four live
transfer workloads confirm 20,480 transactions through two durable owners; protected
socket phases preserve reported high-level attempt outcomes and retry-inclusive elapsed
times, without individual reconnect attribution.
Actual transcript, signature, confirmation and closed SQLite replay passed. The 29
source-preparation and 20 evidence negative tests passed. First-run missing-corpus failure,
predecessor traffic-accounting/caller costs, the prior publication CI selector failure,
D publication historical-test setup failure and E launch/Python-path failure
are retained without relabelling their source or tool environment. This evidence does not
close the public gates above or qualify the later lifecycle, evaluation, model and
distributed additions. Each successor requires its own source-bound observations;
independent work-cost and model-benefit obligations remain open. Child Python is explicitly bound to the observer environment and its actual
executable/dependencies are checked against both qualification layers. Preserve the
measured Git source history when publishing or merging evidence.


The explicit [operator actors development profile](../protocol/pon-nakamoto-v1/details/OPERATOR_ACTORS_V1.md)
adds canonical public genesis actors/allocations and source/requester offline approvals
without implicit DEV signing in Node Settings. M05 still validates the native nonce/fee
and parent-admitted task; M06 commits the selected roster/material under a fresh N/P/G;
M15 composes public-only normal startup and explicit offline prepare/sign/finalize.
Actual local native/CLI regressions do not prove random keys, independent custody,
truthful demand, data retention, cheapest-miner hardness or public governance. All
acceptance flags remain false, and historical constructors/golden bytes stay unchanged.

The retained [public V2](../protocol/pon-nakamoto-v1/details/PUBLIC_INTAKE_V2.md)
contract selects resource revision r2. [V3](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md)
revision r3 introduced retention of paid canonical requests within the same bounded
connection while its original worker channel is Full, attempting enqueue in
connection-ID order without increasing queues, grants or absolute deadlines.
Revision r5 introduced the local mutation-thread CPU account retained by the
current r9 source. This account reserves local actual mutation-thread CPU
before native dispatch, charges its total once and records disjoint full-work and
remaining dispatch intervals. One service-epoch account spans caller identities;
measured debt stops new starts, and unavailable accounting disables future
mutation starts while preserving already completed native outcomes. Original
read reservations remain. Two nonpreemptive calls may exceed their reservations;
individual CPU, Node lock occupancy, honest fairness and Head SLA are not bounded
by this local account. It is a development resource policy, not ticket cost or
hardness calibration, host-global governance or public qualification.

The retained V3 resource r7 source retains complete M05 cooperative Work
replay and adds M06 observations before/after envelope preparation and canonical
apply, around staged root/output, and before/during uncommitted persistence.
The shared observer uses the original public stop/cancellation flags and absolute
deadline. All scoped workers join before return; cancellation is a separate local
error, discards staged output and cannot trigger commitment fallback. A precommit
error rolls back the uncommitted transaction; no added postcommit fence replaces
original durable success or activation. Ordinary no-cancellation wrappers preserve
complete Work/State, ordered receipts, roots, nonce rules and error precedence.
Individual signatures, State clone/mandatory/apply internals, encoding/root,
history and SQLite remain nonpreemptive; the Pool bundle path retains its original
stage fences. No request CPU-second cap, anonymous fairness or physical preemption
is claimed. The [V3 contract](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md)
records the original r7 cooperative scope and the current r10 digest separately;
historical r5/r6 results keep their original policy and scope.

The isolated V3 resource r8 candidate additionally debits every actual scoped
M06 worker interval for the request, including cancellation, panic unwind,
partial spawn and defensive retries. All joins precede checked closure counts.
Outer dispatch O plus scoped C is charged once; M05 W remains nested in O, and
the original metrics fields decompose W and O-W+C while the optional dispatch
observer remains O. PoolBundle forwards the collector through the existing
workers1 full-prefix execution, which has no scoped child intervals. Unknown
clocks/counts/arithmetic disable new mutation starts without refunding unknown
work or replacing native durable success. No State/Output/metrics schema, cap,
identity privilege, deep-stage preemption or fairness qualification is added;
startup/teardown and post-sample bookkeeping are outside these measured intervals.
Fresh qualification/captures are required and historical r7 results remain r7.

The isolated V3 resource r9 source candidate adds immediate debit of actual
same-thread CPU increments at existing owner/scoped progress boundaries. The
request-local live stamps are separate from original full interval stamps; after
all joins, settlement debits only full O+C minus already charged CPU and returns
the unchanged100ms reserve once. Unknown clocks/overflow/poisoned bookkeeping
immediately deny future mutations, and live budget debt causes cooperative
cancellation. Native durable results and signed ACKs survive final accounting
failure/debt; no fence is added after commit. The explicit controlled Pool path
checks complete fixed-workers1 prefixes and precommit persistence, propagates
Cancelled instead of classifying it Blocked, and preserves already committed
reconciliation. Ordinary wrappers remain no-op and all M05/M06 arithmetic, State,
receipts, root and wire bytes remain unchanged. No accounting lock spans math,
join or SQL. The original2s credit/.25 CPU-second refill/100ms reserve/2workers,
35 resource constants, metrics schema and read reservations remain. Signatures,
deep roots and SQLite are still nonpreemptive, so this is not a hard per-request
CPU cap, independent fairness, cheapest-miner bound or public-service acceptance.
The first r9 focused run failed: Node tests returned113 passed,2 failed and1
ignored. A precommit scoped-child clock fault was wrongly expected to ACK, and
the test/document policy hashes did not match the complete signed descriptor.
The successor preserves that actual failure and fixes only those expectations,
precommit no-persistence checks and applicability navigation. The descriptor and
production behavior remain unchanged. Its corrected tests have not executed;
Root alone formats/builds/tests it before exact committed-source qualification.
Historical r8 source receipts and all earlier failures keep their original scope.

The opt-in [public Submit recovery client](../protocol/pon-nakamoto-v1/details/PUBLIC_SUBMIT_RECOVERY_V1.md)
also handles a signed `PUBLIC_MUTATION_CPU_BUDGET` refusal within its existing
absolute deadline, RPC and Submit-attempt limits. It first checks exact packet
membership through locally admitted bytes and a stable signed Head/History/Head
view; an absent packet may be retried within those same limits. A membership
result keeps the refused Submit reply and does not invent a server ACK.
Budget retries after verified absence divide the remaining original deadline
among the remaining Submit opportunities and membership work; ordinary EOF/read
retries retain the short pause. Neither schedule adds a call or a deadline.
Accounting unavailability, invalid signatures and permanent errors remain immediate failures.
This client behavior does not establish service fairness for fresh anonymous writes;
actual pressure and end-to-end acceptance remain separate gates.

The Linux [M10 bounded adapter runner](../modules/M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md)
installs process child adoption before spawn within the original request deadline.
It pins the process-group leader while killing the owned group and reaping only
actual adopted descendants whose parent, group and start time match a held pidfd.
Descendants and the leader share the original one-second cleanup deadline; the
leader is reaped last. Unrelated direct children remain available to their owners.
The focused source completed all342 retained Worker tests and3 new nested/concurrent
ownership controls, strict Clippy and an independently waiting outer owner with
zero adopted descendants. The previous whole-qualification outer failure remains
retained without a proved PID-to-test mapping. The combined committed source still
requires complete qualification; other adapter paths, credential/group escapes
and host failures are outside this bounded runner's Linux guarantee.

The [local Pool owner](../protocol/pon-nakamoto-v1/details/LOCAL_MEMPOOL_LIFECYCLE.md)
now shares one freshly reconstructed, checked immutable parent within one submit
operation. Every separate operation rereads actual KV; full growing-prefix M05/M06
execution, roots, receipts, SQL fences and failed-bundle rollback remain required.
All14 focused Pool controls passed. A finite36-operation/18-pair experiment closed
228 complete prefix comparisons and36 same-packet `FUNDS`/SQL rollback controls.
Five of six conditions improved in descriptive wall/CPU medians;1000 funded
accounts with12 retained groups regressed from140.562 to172.387ms wall median,
with two of three pairs slower. This tradeoff is retained explicitly; three pairs
on a shared host do not establish universal speedup or public-service capacity.
Full qualification on the combined committed source remains required.

Within the existing totals it reserves read-body and control-output capacity, separates
paid mutation/read grants and read challenge tokens, retains grants through native work
and output, and checks disconnect/expiry fences between complete stages. EOF, including
a write-half-close, cancels the request; clients keep both halves open until the reply.
New resource digests reject old cookies without fallback. These component controls do
not establish anonymous scheduling, remove full-verifier cost amplification or qualify
independent public hostile service. The separate connection-work-v1 transport now gives
its original socket/deadlines an at most2ms zero-capacity handoff opportunity and up to512
Busy attempts within its existing absolute5s budget, under a fresh profile digest.

The same [continuous miner](../protocol/pon-nakamoto-v1/details/CONTINUOUS_MINING_V1.md)
checks cooperative stop/deadline fences after owner/parent observation, actual pool
selection, miner binding and preparation, and before and after postsearch revalidation.
Selection already performs full M05/M06 under the uninterrupted owner; its immediately
duplicated presearch preview is removed only for the locally owned batch. Public mutable
batch validation, postsearch validation, native admission and durable activation remain
complete. Stage timing names and nonpreemptive overruns are specified explicitly.
Actual SQLite-blocked stopping and injected native failure controls retain state and
queue invariants; failed predecessor observations remain bound to their source.

The [M06 derived commitment](../protocol/pon-nakamoto-v1/details/DERIVED_STATE_COMMITMENT.md)
preflights ordered differences without cloning payloads, selects resource or excessive
delta fallback before building the public change vector, and computes the complete
original root before fallback materialization. Complete delta bytes and root authority
remain unchanged. The65536-key disjoint-state control has131072 changes; it is a finite
component resource/root equivalence control, not a native reachable workload or public
availability certificate. Cache budgets are separate from canonical-state limits and
do not bound all required canonical/delta allocations or allocator RSS.

The [V1 evaluation observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_OBSERVATION_V1.md)
and its CLI check actual candidate membership, frozen rounds, active generation and
installed confirmation policy through a complete ancestry bounded at4096 blocks.
The separate [V2 round observer](../protocol/pon-nakamoto-v1/details/EVALUATION_CONFIRMED_ROUND_OBSERVATION_V2.md)
checks a complete bounded round window at later chain heights, actual reverse deltas and
parent roots, and cross-checks the existing ancestry index. Its base anchor, earlier
global confirmation and earlier clock history are explicitly unevaluated. A private
typed local observation is neither a public session receipt nor adoption/reward
authority. Reorg invalidation, public operation consumption and independent evaluator
governance remain in the existing convergence requirements.

The independent [checkpoint tile material replay](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_MATERIAL_V1.md)
checks complete original checkpoint bytes, actual tensor coordinates, original input
bits and exact integer quantization against all derived A/B values, under a new
closed descriptor/policy domain. Its private checked result binds the unchanged
crypto source/context manifest; actual native parent slot eligibility, withdrawal,
replay and output consumption remain with the existing owner. The library alone adds no
task selector, State, ledger wire or signed source authority. The explicit revision10
[checkpoint tile task selector](../protocol/pon-nakamoto-v1/details/CHECKPOINT_TILE_TASK_V1.md)
commits a context-free policy and new operator specification before deriving fresh
N/P/G. Settings construction and every Node open replay complete original materials;
Config policy construction alone does not. Only the installed Maintenance/output0
relation is selected; original parent/source eligibility and native execution remain required.
Full-file membership and material density do not qualify cheapest-miner hardness,
true demand, full-model execution, marginal contribution or independent custody.

Public sync can explicitly request the [same-owner evaluation observation](../protocol/pon-nakamoto-v1/details/SYNC_EVALUATION_OBSERVATION_V1.md)
after its complete actual work/state sync succeeds. Partial sync cannot create a
phase result. Observation failures retain and report the already completed sync
fact; omission preserves the previous result fields. This composes existing owners
without new evaluation RPC, guest permission, durable schema or decoded observation
authority. Applications consuming observations still need their own durable effect
identity and reorg/retirement rules; native evaluation transactions continue to use
the actual roster, current State, branch heights and funded conditions.

The isolated public V3 r3 localhost successor completed three10s phases with
180/180 honest Submit/Head/History requests. Cached invalid800 attempts produced
792 duplicate-content refusals and8 Product rejections; distinct-fork800 produced
799 Product rejections and1 paid-grant client refusal. Queue refusals were0;
71 Full polls were not71 failed requests. Original independently coded scalar/State/
ordered-receipt replay checked the anchor,20 linear successors and one separate
valid fork template (22 packets). Each closed service store contains genesis and
21 linear packets, giving66 stored rows including3 genesis; the fork is not in
those stores. Its product-only mutation was refused as PRODUCT.
The original1c observation (9 of20 honest Submit accepted,7 queue refusals,788 duplicate-content
and6 Product rejections) remains a retained failure/saturation observation.
These component results do not qualify the newly combined source, WAN/SLA,
anonymous fairness, model efficacy, useful task demand, mining hardness or public
readiness. General functional-copy attribution and independent evaluation/source
budgets remain open; all six public acceptance gates remain false.


The restricted-owner-node-v1 source candidate composes the existing packet Work,
State and durable branch owner with a new protected operator grant domain. Two
outside pinned roles authorize an exact full packet, actual parent, full lease,
material catalog and registered task/class reservation. The private owner journal
retains reservations and monotonically anchored views across failed Work, restart
and branch reorganization; no automatic refund or migration exists. The CLI uses
one protected opener for server, sync and local mutation, and legacy openers refuse
required-policy stores. Pool preview/mining are explicitly held by this first core;
normal Pool support must be restored by a separately reviewed typed operation scope.
This paragraph describes unexecuted source: candidate compilation, tests, full new
qualification and actual legitimate two-stage packet admission remain pending.
CPU/DA/funding reservations are signed declarations, not per-operation measured CPU,
proof of balances, source independence, model origin, task hardness or fair access.
The existing request CPU owner remains responsible for its unchanged O+C sampler;
all six public scientific gates remain false. This is an opt-in local service mode
with fresh durable namespaces, not a new PNW1/PNX consensus version or permissionless
reward qualification. Continuous miner/view-refresh integration remains pending.

The restricted-owner-node-v2 Pool source successor starts from the Root-formatted
v1 files pinned by the closed e5fc6a45 format receipt. It defines a separate
POOL-GRANT1 domain for exact enable, reconcile and ordered ordinary-bundle commands,
not a proof-task substitute. Each expensive operation reserves one outside-fixed
operation before actual parent State reconstruction. Every old retained group
requires its original durable admission reservation and a separately signed current
retained-group permission; the full prefix still executes M05 and M06 from the
same reconstructed original parent, with both original SQL generation fences.
The r9 ExecutionControl worker accountant is preserved. CPU/DA/funding reservation
amounts still describe operator declarations; no new actual CPU-class meter or
balance proof is claimed. Fresh v2 namespace/journal/Work signing domain refuses v1
stores, with no automatic migration or discarded journal history.

A trusted typed refresh entry accepts only two externally fixed original keys,
the same source/context namespace and a linked next latest view. It authenticates
all new finite Pool grants and full six-file catalog before fsyncing the new journal
anchor, then cancels old in-flight capabilities through an epoch fence. Stop/reopen
uses the same protected CLI loader and monotonic journal. There is no anonymous
reload RPC, startup list is not permanent authority, and neither old packet view
nor new incoming bundle alone authorizes old prefix transactions. History/recovery
reads keep the original complete checks; uncommitted reservations never refund.
Mining-batch/validate/prune remain explicit purpose HOLD until independently
specified exact grants are implemented. All source2 compilation, real new Node
admission, Pool normal-load and scientific qualification are pending Root execution;
original core1 tests cannot authorize this successor. Permissionless reward,
source truth, physical costs, useful demand, hardness and fairness remain false.

Pool source-only successor 4 retains the immutable successor 3. Restricted enable metadata uses the permission-captured parent/generation at its SQL fence; the existing unrestricted branch is unchanged. A new local SQL fence test definition covers intervening parent/generation changes. The real Work reservation test has a fixed eight-timestamp positive-nonce fixture and fails on exhaustion, preserving the original positive-nonce admission rule. These source fixes have no author Cargo, test, Native, Work/State, SQL, signing or network execution; new qualification remains pending.

Pool compiler repair successor 6 retains the original failed Pool5 build receipt. Three new Pool identity hex decodes now explicitly map malformed input into the existing Node Error type; no global error conversion or validation rule changes. Root preflight precedes the edits. New full build, tests, Clippy and Native admission remain pending; prior core1 qualification does not qualify this successor.

Pool compiler repair successor 7 retains both original failed build receipts. The new mempool error mapping now names crate::Error explicitly; the original Error type and all validation rules remain unchanged. Root preflight precedes the edits. New full build, tests, Clippy and Native admission remain pending; prior core1 qualification does not qualify this successor.

Pool compiler repair successor 8 retains the original release-build PASS and test-compilation FAIL of successor 7. Two test-only imports name the existing PoolLimits type and PermissionsExt trait explicitly; no production or validation code changes. Root preflight precedes the edits. New full build, tests, Clippy and Native admission remain pending; prior core1 qualification does not qualify this successor.

Shared CPU source candidate: original r9 scalar budget/live owner/scoped implementation moves into ingress/public_v3/scalar_cpu.rs with exact arithmetic inverse and unchanged Public dispatch settlement/tests/policy constants. PublicServer exposes an opaque same-Arc domain; new actual owner/scoped metering API is available for the separately guarded mining successor. Domain metering is not task permission. Six meaningful new test definitions are unexecuted; build/Native/public readiness remain pending Root. Original full CPU+worker accounting and residual-only settlement, unknown-clock refusal, exact resource constants and deep-stage nonpreemption remain unchanged. No frozen/Root worktree edits or dependency changes.

Navigation: [shared CPU domain source scope](../protocol/pon-nakamoto-v1/details/RESTRICTED_MINING_CPU_DOMAIN_V1.md). Root alone executes any qualification; Pool7 failed test-import compile and Pool8 source-only repairs remain separately preserved.


Shared CPU5 basis is now actually qualified and committed by Root: 315 passed,
zero failed, 12 ignored, release build and strict Clippy, original source controls
and inventory, commit fa77a4bec0af1a8a2412f6b73eea68782e1d9e22/tree
dda23bbd7e8215a2ef53b9c31b0de230f49a2fc9. The earlier Pool/CPU compiler and
inventory failures remain historical failures. That qualification applies to the
3344-source basis, never to the following new mode3 candidate.

Restricted finite mining mode3 is a source-only successor from those exact
Root-formatted 18 owned files and the full 3344 map. It separates TaskView,
StartupCatalog, unchanged ParentReconcile, Search, WinnerValidation and Activate
from packet and Pool domains. Full material signatures, original task lease,
positive finite nonce window, exact ordinary-byte allowlist/ordered digest and
original-parent M06 remain mandatory. A complete Root-protected local controller
keeps one actual Node and shared CPU epoch across linked signed next views. It
retains every started proof including failed and cancelled-after-proof nonces.
A held-directory fault sink survives initialization failure or unwind without
changing original Native results. Unknown/faulted journal recovery is HOLD;
claims survive crashes without automatic refund. Any failed persistence is an
explicit error, not evidence of a durable fault marker.

Mode3's 256 total journal claims and 32 finite controller steps support only a
short bounded end-to-end experiment. Startup consumes two distinct claims and
each successful Search/Validation/Activate chain consumes three more. This does
not qualify the original 241-block/8193-input continuous normal campaign. No
reset, rotation, erased claims or shortened workload may inherit that acceptance.
Automatic Pool selection/status/prune, generic maintenance mining and anonymous
continuous issuance are HOLD in mode3. The existing mode2 Pool implementation is
unchanged. Signed CPU/material/DA/funding reservations remain operator
declarations; actual CPU accounting enforces the original service domain, not
physical class costs, verified balances, hard preemption or anonymous fairness.
All new source/binary/Native/full-reference/SQL/network/scientific actual refs are
pending Root execution. Only Root applies, formats, builds, signs and runs.

Navigation: [finite mode3 interface and acceptance](../protocol/pon-nakamoto-v1/details/RESTRICTED_OWNER_FINITE_MINING_MODE3.md).


### Qualified retained-budget Mode4 limited scope and Mode5 successor

The Mode4 commit 8abfd3457e59d965e95cfdd820ad3ee30b210121 / tree eb2de4bf6dedc60dcd72945d0d0eb8c440d9dc1c has actual Root qualification: 378 passed, zero failed, twelve ignored, all retained 27 Mode3 and 36 Mode4 definitions, strict Clippy, complete 3365-source equality and five successful CI jobs. The original 50 metadata negatives and navigation checks also passed. Qualification receipt ce320ffa4e502e0d3af359e1a4904af271300804087ad483f7f38d40ff4672f7 and commit binding 15c1da5b5353a5559469c84febed3084b79379e4881a690c6b1875ce51adbeca identify that exact limited source. Earlier fixture/lint failures remain historical evidence and do not inherit these results.

The separate actual five-stage before-key/short Native experiment closed with receipt 831b4ae06af6557a0ce36c833cb4b815a57ef158cfcfbba6c168399eb9411c2c. It retained four actual nonce trials, one complete Work verification, two original M06 executions and both stores' complete typed SQL comparisons, including producer EOF and zero-credit cold reopen. This limited cycle does not qualify automatic PoolPush, changing leases, old serve--mine, the original 8193 campaign, full whole/104 or anonymous network readiness. Its operator declarations do not prove source truth, balances, class cost, usefulness or fairness.

The fresh Mode5 SOURCE candidate extends that exact formatted basis with distinct Pool operation purposes, original admission and ordered-prefix witnesses, two-phase lease reconciliation, and explicit known SIGKILL process residual settlement before restart authorization. The new service remains externally authorized by the same operator. All task/class/global allocations and measured CPU remain append-only and non-refundable; original full Work, M06, wire, scalar CPU constants and SQL fences remain mandatory. The original 8193 inputs, queue/conflict/status behavior, depth six, height-ten owned kill/reopen, resource boundaries and complete three-store oracle are unchanged acceptance requirements. New compilation, keys, signatures, Node binary, original normal traffic, recovery, full-reference/SQL and whole/104 actual references are None/HOLD until Root's actual closure. There is no source-only PASS or acceptance inherited from Mode4.

Navigation: [qualified Mode4 limited entry](../protocol/pon-nakamoto-v1/details/RESTRICTED_OWNER_CONTINUOUS_MODE4.md); [Mode5 exact Pool, lease and recovery acceptance](../protocol/pon-nakamoto-v1/details/RESTRICTED_OWNER_CONTINUOUS_MODE5.md).


## Directed architecture boundary continuation — 2026-10-08

This continues the same PN0–PN6 sequence and existing owners; it is not a
parallel plan, new supervisor, trainer, journal, registry or deployment.

The Hepta continuation joins the existing bounded process exchange to current
height/work/effect-bound observations. Its next sealed-image increment uses
existing provider byte-identity primitives and the same final-use/TaskFlow host.
An executable-byte identity is not data-export, installation or effect authority.
The chain's observed generation and Hepta's final-use generation are different
namespaces and must never be compared by integer equality. Downstream adoption
still requires the independently current local withdrawal/selection/resource
checks, not just a retained successful chain observation.

The native growth reservation owner now reads bounded receipt bytes through a
held target directory and checked nonblocking/no-follow file descriptors. It
checks actual opened file identities and rereads the current pathname identities
before returning. A successful initial reservation syncs the parent directory as
well as files and the target. A failed reservation retains the uncertain target
for exact reconciliation; it never recursively deletes a potentially substituted
path. The new readback bound is64KiB and is not a new ledger capacity. This does
not implement native execution beyond65,536 total keys or grant sufficient storage
for the1,000,000-account research relation. That actual growth transition remains
an explicit new profile/genesis/store implementation and replay obligation.

The existing model-window owner gains an explicitly selected V2 consumer-decision
relation: score improvement and adoption authority are separate. A candidate may
improve the declared metric while remaining unadopted for a signed safety,
consent, resource or selection hold. Fresh receipt/attestation/result domains bind
the typed reason and exact owner-decision evidence identity. V1 shapes and domains
remain unchanged. These are supplied-record/signature contracts; the ordinary
Hepta installation/consumption path has not been executed by those fixtures.

| Upgrade subject | Existing authoritative boundary | Insufficient evidence |
|---|---|---|
| Model parameter bytes | Current artifact, evaluation, selection, withdrawal, final-use and resource owners | Better score, chain inclusion or a publication receipt alone |
| Neuron topology or executable code | Existing runtime/release and capability owners, compatibility and recovery validation | A parameter-adoption grant or model vote |
| Consensus rule, verifier or state root | Explicit protocol release, new activation context and applicable migration/replay | Model quality, claimed compute or local code replacement |

Exact source tests and independent operation remain distinct. The retained x64/ARM
cost jobs use same-target valid, false-transcript and late-product inputs and retain
setup/search/failure denominators. An additional local replay of their exact x64
binary remains a binary replay, not a fresh build, CPU/energy measurement, public
service qualification or independent operator campaign. Sustained service evidence
with no observed budget depletion cannot be promoted to saturation acceptance.
WAN partition/heal, full disk, unavailable materials, cold recovery, physical loss
and long-run client-confirmed tail latency require actual scoped observations.
No new document, reader pass or signature changes any production/release flag.

## Cloud implementation and adversarial observations — 2026-10-13

This historical source continuation implements the retained interfaces below. Its component
observations do not close the final-source or independent-operator requirements.
The active consensus remains PoN Nakamoto. No BFT committee, finality certificate,
GHAST rule, DAG fork choice or consensus activation is introduced.

The paired Hepta source now requires the original ProductEvaluationRunner and its
sealed qualification, an actually synchronized immutable qualification file, the
same evaluator's signature over the exact candidate and predecessor bytes, and
the independent selector before published model installation. The ordinary CLI
reconstructs that path from independently pinned raw materials. It cannot decode
a caller-supplied opaque qualification or substitute a signed arbitrary metric.
Restart replay requires the already recorded holdout plan, original writer fence
and exact retained CAS anchor; it cannot consume a new holdout or take over its
writer. CURRENT readers use the original named owner's observation fence and
settled durable ACK. Unknown, revocation and failed currentness checks deny use.
Launch generations remain separate from model generations. A signed recovery
decision can explicitly abandon a Prepared intent whose effect remains Unknown;
it preserves that uncertainty and does not manufacture a release result.

The bounded three-generation study performed actual fits, product qualification,
installation and inference on fresh arithmetic instruction-selection tasks.
Independent child processes held seven role keys and future task materials.
An independent reader verified 53,432 distinct instances and eleven observed
windows. Each new candidate improved the declared task distribution against its
actually installed predecessor; a fourth fit with equal behavior was lawfully
rejected, and durable withdrawal closed cached consumption. The original IPS
bound uses the final sealed window, measured uniform four-action logging and the
unchanged acceptance thresholds. The measured whole native run used 74.06 seconds
wall time, 75.70 seconds waited-child CPU and 231.50 MB retained storage. Its
270.75 MB memory observation is the maximum single waited-process high-water
mark, not simultaneous process-tree RSS. The actual binary uses the unoptimized
test profile; whole-run cost includes the adversarial controls and excludes
compilation, the external reader, energy and financial charges. These are controlled tabular learning
observations under one administrator, not three neural-network generations,
multi-host governance, long-horizon distribution drift or general model efficacy.
Two raw configuration reconstructions do not qualify two full daemon restarts.
The original Agentd socket test still fails because this cloud host denies
AF_UNIX bind; its assertion and failure are retained.

The second independent-process hostile campaign retained the original two
attack modes, 24 clients per mode, target, eight-bit admission policy, two workers,
2 CPU-second burst, 0.25 CPU-second/second refill and 100 ms start reservation.
All hostile actors completed and services closed normally. Baseline business
completed all three rounds at depth six with required verified work. Both hostile
phases actually depleted the metered CPU flow around 3.4 seconds; neither
completed the honest confirmation round. The supported caller-local two-second
deadline expired during solution-body response/dispatch and retries, before any
History confirmation request. Some accepted packets were only acknowledged on a
later duplicate retry. This is a retained bounded-liveness failure, not a passing
saturation result. The ordinary client's thirty-second overall profile was not
measured by that experiment. Passive CPU-flow diagnostics do not change credit,
reservation, continuation, settlement, signing or consensus rules. No deadline,
work target or gate is relaxed to convert the failure into acceptance.

Source review located repeated historical-parent State reconstruction before W1
verification as an actionable cost candidate. The bounded successor reuses only
the original opaque CheckedCommitment tree arithmetic material, indexed by block
and the root freshly read from SQL. It retains at most eight entries, 2 MiB of
canonical payload and 16 MiB of conservative additional material charge. The
original 512 MiB per-call arithmetic workspace bound is separate; these charges
are not a whole-process RSS bound. Each use still reads and reconstructs the
actual snapshot/deltas, checks canonical values, all before/after transitions,
current records/roots and continuity, and performs the original final writer
validation. It never returns a cached State or eligibility verdict. Misses and
over-budget material use the original calculation; uncertain/root failures clear
the material. The existing active-cache observation schema is unchanged. Its
benefit and the original two-second hostile confirmation requirement must be
measured on the new exact source, rather than inferred from reduced tree work.

The read-side experiment preserves the single writer and final revalidation of
every used on-disk fact, including committed foreign writes followed by restore.
Initial measured owner-lock time improved while complete first-body and short-tail
requests regressed by about 79% and 138%. One retained cost run has an incomplete
final baseline tail and is not a complete acceptance receipt. A subsequent complete
ABBA experiment retained all 256 nonce samples and 384 paired reader observations,
matching the native stream to the parent's bounded pipe capture and verifying
the final synchronized files and source hashes. Both reader arms used the same
prepared-statement optimization. Whole first-body median still regressed from
1.514 to 2.723 ms; p95 rose from 1.942 to 4.338 ms. Its owner-lock median fell from
1.391 to 0.588 ms. Whole short-tail median regressed from 0.630 to 1.388 ms.
Lock duration alone is therefore not a throughput result.

Skipping speculative work for repeated senders preserved full canonical ordered
execution, state, receipts, errors and cancellation controls, but did not establish
a stable whole-operation improvement: the complete mixed workload median changed
from 16.067 to 16.181 ms, p95 from 21.454 to 19.479 ms and maximum from 24.792 to
77.109 ms. The unchanged same-sender control also shifted by about nine percent,
so a faster percentile alone cannot be attributed to the new scheduler. Neither
the snapshot reader nor the repeated-sender scheduler is selected as a production
default. Their explicit test research and source-bound negative results remain
available. The ordinary held-owner read path, canonical execution and original
integrity checks are preserved; a request capacity refusal remains distinct from
local corruption. Storage observations include all retained branches, jump
indexes, deltas and cold recovery: at 512 blocks the measured directory retained
31,379,488 bytes and cold recovery took 6.523 ms. No pruning or permanent
bounded-disk claim follows from that finite experiment.

The fixed native dissemination comparison exercises serial delivery, concurrent
delivery and a signed-reference DAG through unchanged full Work/State validation
and depth/work confirmation. The DAG did not consistently outperform ordinary
concurrent delivery across disjoint and conflicting business. This supplies no
reason to replace consensus. Conflux, DAG-BFT and parallel-chain designs retain
the distinct safety, data availability, admission and recovery obligations in
the architecture comparison contract. Complete baselines and actual native
source/merge pairs must still bind the final combined source; missing native
ARM64 execution cannot be replaced by cross-compilation or an x64 observation.

Native malformed-input ordering now uses one allocation-free PNW1 encoding
precheck in common packet admission and the continuous owner's earlier actual
task-binding path. Both reject malformed magic or noncanonical A/B/C fields
before task lookup reconstructs the parent State. Owner authorization, exact
duplicate handling and bounded header/ancestry checks retain their original
order. Original full Work verification, cancellation, paid CPU settlement,
durable recovery and final writer validation remain required. The standalone
verifier's target/task/error order is unchanged. The new regression selectors
and precise native-versus-Ledger scope are in the existing
[admission security contract](../protocol/pon-nakamoto-v1/details/ADMISSION_SECURITY.md).
Exact-source and prospective-merge CI must validate this change; source fixes
do not replace a measured hostile public-service campaign or the unresolved
work-hardness and independently governed model-evolution qualifications.

The `6724ed1905e11d30775738ad0eb84b53d1d9ea97` hosted Rust baseline and
prospective-merge jobs each retained 625 passing tests and two failing ingress
ordering tests. Both failures reproduce on that source: the pending-activation
metadata probe incorrectly emitted `BeforeParentBinding` even when no recovery
was pending. It did not reconstruct parent State. The repair keeps that probe
before ordinary readiness checks and preserves its request cancellation and CPU
checkpoint, while reserving the execution-stage callback for actual parent
binding. The original bad-statement, false-transcript, valid-retry, SQL-tamper
and cancelled-reorganization recovery assertions remain unchanged. This is an
ingress control-flow correction; it does not alter proof acceptance or replace
the original failed native service campaign.

The first CI run for this encoding-precheck source stopped before native recent-
batch tests because its reviewed store blob guard still named the preceding
implementation. The successor pins the actual reviewed `store.rs` blob
`663f57cd025637cbbaa50200d7179448a94d6ba6`; all nine file guards, ordered source/
merge checks and native test requirements remain enforced. The original
[failed run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39102102704)
is retained. Its missing native logs cannot qualify this successor; the new
exact-source and actual-merge runs must execute the original acceptance suite.

## Bounded I/O corrections — 2026-10-20

This continuation starts from PR #323 commit
`f1bea3d31ab0d537957399a45cc4361e59e74e08`. It repairs the existing PN2
reservation owner and PN3/PN5 Cell transport; it does not change the PN0–PN6
acceptance sequence or create another integration candidate into main.

Growth storage creation now resolves each ancestor through no-follow directory
descriptors, creates the target relative to its held parent, and binds the first
observed target inode and effective UID before changing permissions. Reservation
and receipt creation, allocation and synchronization use those held objects.
Final readback also binds the original opened files: replacing a file or directory
with equal bytes cannot qualify the live reservation. Deterministic regressions
exercise ancestor replacement, symlink and real-directory replacement before
permission changes, and replacement after descriptors have been retained. They
check that decoy contents and permissions are unchanged and uncertain targets
remain available for reconciliation.

The guarantee covers these pathname redirection windows. It is not isolation
from another process with the same UID before the first observation after
`mkdirat`, nor a promise that a pathname cannot change after return. The actual
native reservation/reopen regression remains required in addition to the small
filesystem fault fixtures. No new growth profile, native admission beyond
65,536 accounts, storage sufficiency, model efficacy or public-service
qualification follows from this repair. Exact-source test and cloud CI results
must be attached to the successor commit rather than inherited from the parent.

The existing [Cell fetcher](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md)
now reserves a shared response-byte allowance before each socket read. Actual
headers, manifests and rejected or truncated bodies consume that allowance;
unused reservations are returned within the original absolute deadline.
Successful reports and budget-exhaustion errors retain the actual received
response count. Verified newly cached payload remains `downloaded_bytes`, and
a complete verified cache can serve a zero-response-budget fetch. The counter
does not cover outgoing requests, TCP/IP overhead or retransmissions. This
bounded configured-peer repair does not qualify discovery, independent custody,
WAN availability, storage obligations or actual Hepta model installation.

Seven additional test/example files now name their account sequence helper
arguments `account_sequence`, following the existing
[fixture naming contract](specs/pon/ACCOUNT_SEQUENCE_TEST_HELPERS.md).
The eleven parameter renames preserve `Envelope.nonce`, fixture values,
signatures and assertions. They address the observed parameter-name heuristic;
other hard-coded-value and logging findings still need their own evidence.
No CodeQL query, gate or alert disposition is changed. The parent security check
reported 225 findings but exposed only 100 annotations, so neither this correction
nor that partial classification certifies closure of the complete security gate.

## Native cloud follow-up — 2026-10-21

The bounded I/O correction was published to the existing PR #323 as
`064cce1d4b5c27d843864536b9b157a11df2be66`, with tree
`4e0948859584b17a14d99c8e5a195603b5d6d6eb`. Its
[CodeQL run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39521908005)
reported 145 findings: 124 critical and 21 high, compared with the parent's
204 critical and 21 high. The 80 fewer critical findings do not close the
remaining security gate. No alert is dismissed and no query is disabled.
The separate read-only analysis export waits for the existing CodeQL check
on the exact PR source, retains every available matching analysis/category
through complete API pagination, and records the API-provided SARIF subsets
and metadata. Source drift, incomplete scans, processing errors and denied
access fail the export. Export completion is not a security-gate pass, and
the returned subsets are not the full original SARIF uploads or the complete
history of branch alerts.

Two existing acceptance workflows stopped on stale source/test-count guards.
The recent-batch guard now binds the actual reviewed
`native_authenticated_tests.rs` blob
`6b304bc0fe5bb8b48e0cd2c377b120f4ceb2291d`. The branch-encoding guard now
requires all 21 authenticated-migration tests, including the added reservation
race controls. The preceding x64 and ARM64 executions already ran those 21
tests successfully; their subsequent count-check failures remain failures.
All source guards and exact-source/prospective-merge lanes are retained.

The four accepted-task observation scenarios now each execute against both
`legacy-v2` and `authenticated-v1`, through the real node/CLI, reopen, reorg,
ambiguous-task and corrupt-store paths. The scoped native regression passed
all four tests, covering eight backend executions. This expands backend
coverage; it does not establish actual model installation or independent
operator agreement.

The new original-native-campaign workflow runs the existing release-profile
`separate_process_work_and_signed_confirmation_campaign` on a fresh x64 cloud
runner. It schedules three complete observations, retaining every failure and
partial result, with the original seed workload, 30-second phases and 0/24/24
attacker counts. The service must expose the declared cgroup CPU/memory ceilings
and nice value; unavailable or weaker resource controls fail without an
unrestricted fallback. Exact tracked source, compiler profile, executable hash,
raw reports, child logs and resource observations are retained. The workflow is
an execution entry point, not a passing campaign receipt. It covers the source
head only and does not substitute for ARM64, prospective-merge, WAN, independent
custody, work-hardness or complete Hepta model-evolution qualification.

### Observed cloud results and analysis-reference correction

The follow-up source was published as
`00733fb34b0cd8007862de373176c3dca4534805`, tree
`7c8289f5efe1d1dc543b68d85305e08d9cfa9064`. Both the
[recent-batch run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39524527808)
and the
[branch-encoding run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39524527849)
passed all four x64/ARM64 source-head and actual-merge lanes. This closes the
stale guards for that source; it does not qualify a later source or another gate.

The [original campaign run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39524527820)
built the optimized release executable and completed all three planned attempts
in 98.32, 99.28 and 98.50 seconds. All three attempts failed the original finite
experiment assertion. Each retained a complete report with unchanged source,
binary and actual resource ceilings, and none reached the outer timeout.
In all nine measured phases, the receiver accepted the 21 honest blocks, the
independent client completed all three depth-six confirmations inside the
original window, and receiver/client states agreed. The latest confirmation
was at 12.27 seconds. Hostile phases retained actual rejected full work during
every honest round, all 24 actors completed, and observations were complete.

The unmet condition was actual paid-credit depletion, not honest confirmation.
All three from-zero phases and the first late-product phase failed that condition.
The from-zero minimum observed remaining paid credit was approximately
419, 439 and 411 ms, above the unchanged 100 ms start reservation. Their total
metered mutation CPU was approximately 8.37, 8.39 and 8.44 seconds over the
30-second windows. The existing challenge admission bound and cheaper early
transcript rejection limited the pressure reaching the paid CPU domain. These
observations support timely honest service under this exact fixed load, but
cannot certify service under depleted credit. The failed original assertion,
thresholds, attacker load and deadlines are retained; no artificial slowdown,
smaller credit budget or promoted partial result substitutes for saturation.

The same source's CodeQL check reported 143 findings, comprising 122 critical
and 21 high. Its completed Rust upload identified `refs/pull/323/head`; the first
read-only exporter queried only `refs/pull/323/merge`. The corrected exporter
retrieves every analysis page for the PR and accepts only its two exact PR refs.
A head-ref analysis must bind the frozen head SHA. A merge-ref analysis records
whether its actual commit is that head or the separately verified prospective
merge; these are never interchangeable source claims. Historical SHAs are
retained in raw pages but cannot satisfy completion. Offline regressions cover
both refs, pagination, wrong bindings, intermediate missing configurations,
source drift, denied access and unstable exports. The original failed export
and vulnerability gate remain distinct from this retrieval repair.

The paired Hepta witness recovery correction is published on its existing
PR #2559 as `0ef0e9280e8caec3fdd63761462621848761e7df`. Its
[native Windows run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39524912633)
passed six witness and nine evaluated-shadow tests in each of the source-head
and actual-base-merge lanes. The actual merge parents were
`75531105b27329abaeb955e77c2c04a6d14f3bcb` and that Hepta head; this is the
existing integration-stack base, not a claim of qualification against Hepta main.
Both lanes retained identical before/after tracked bytes and zero test/logging
exit codes. The four original Windows lock-conflict fixtures exercised their
real reopen and fault paths. This closes that Windows verification scope, not
the independent model-evolution or WAN acceptance gates.

### Authenticated remote diagnostic display

Review of the retained logging findings also identified a separate concrete
CLI display boundary: authenticated push/sync responses can carry an arbitrary
peer-supplied error string. Signature verification authenticates that source;
it does not make newline, carriage return or terminal escape bytes safe for
direct stderr display. The final CLI error renderer now escapes Unicode Cc
control characters before printing one diagnostic line. Ordinary Unicode,
quotes, literal backslashes and fixed error codes are preserved. The underlying
typed error, its raw diagnostic, protocol bytes, signature verification and
exit code remain unchanged.

Three actual native CLI unit tests passed, including all 65 C0/DEL/C1 control
characters, a multiline/terminal-control canary and ordinary Unicode/type
preservation. Independent source review confirmed both authenticated response
paths reach the repaired sink. This is a log-integrity repair, not proof that
the remaining CodeQL logging findings are private-key disclosures or resolved.
Those findings still require their exact-source analysis and data-flow review.

### Exact-source security evidence

The reference correction was published as
`9e29c21e62a76031851d58495fb39eeba346dc40`, tree
`c62730226cc533da12ba08a1f278ad40faec9fcf`. Its
[read-only export](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39526601044)
completed after all three actual CodeQL language analyses. The artifact retains
the matching Python, Actions and Rust API-provided SARIF subsets, their metadata,
all polling pages and both source observations. Every selected analysis binds
`refs/pull/323/head` to that exact head. The separately verified actual merge
`5276486e60e255b878bf877b74a37e0c5e4c1dd7` is recorded but has no independently
selected merge-source analysis in this export. The artifact digest and both
internal file manifests were verified on download.

Python and Actions returned zero results. Rust returned 414 analysis results:
392 hard-coded-cryptographic-value and 22 cleartext-logging findings. These
API analysis results have a different scope from the completed PR security
check's 142 findings, comprising 121 critical and 21 high. Neither the successful
export nor the difference in these counts closes the security gate. Public
account replay sequences, deterministic protocol/security vectors and actual
secret-bearing flows require distinct source-level review; changing test values,
disabling queries or dismissing findings is not part of this correction.

The read-only exporter also retains the existing CodeQL check's API-exposed
annotations, with raw pagination and before/after bindings to its exact check,
source, application and same-repository PR head/base. Annotations have no stable
API ID; repeated locations and messages remain distinct. All 14 offline export
regressions passed, including a denied later page, changed source/endpoint,
count drift and the distinction between 100 reported annotations and 142 gate
alerts. The actual preceding check metadata has that limited shape. No complete
gate-to-alert mapping, newly downloaded annotation body or resolved alert is
claimed from those offline controls, and no workflow permission is expanded.

The complete source review mapped 175 unique analysis findings to 32 public
account-sequence functions in 25 source/test/example files. Those parameters now
use `account_sequence`, including the owner/provider sequences committed into task
IDs and the verified archive sequence-query argument. Inverse identifier mapping and independent diff review preserve the original
code tokens, literal values, signed transaction fields, cryptographic domains
and assertions; formatting only adds line breaks and optional trailing commas.
Operation/transport replay nonces, PoW counters, commitment salts, actual keys
and golden vectors retain their original semantics. This is the existing fixture
naming contract, not a subtraction of 175 from the PR gate or a future scan result.

Review of the 22 logging findings identified 14 ordinary vector mutations that
the analysis treated as log sinks, seven public test/observation values and one
runtime JSON stdout sink. The runtime finding is the `Ok(value)` branch, with
paths from public account data and from `secret_identity` through result/control
flow. Its recorded path does not establish serialization of the private key:
`DevelopmentIdentity` exposes neither `Serialize` nor `Debug`, and the inspected
key validation failures do not include the key bytes. This source classification
does not dismiss an alert or resolve the security gate. The separate stderr
control-character repair above must not be reported as closure of this stdout
finding.

### Completed native Hepta pair for the preceding source

All four x64/ARM64 source-head and actual-base-merge Linux lanes in the
[Hepta pair run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39524912633)
completed successfully. Each retained 99 passing execution receipts, including
six witness-recovery tests, nine evaluated-shadow tests and the explicitly
ignored real Chain submit/reconcile/confirm/reorg test. The latter executed both
`legacy-v2` and `authenticated-v1`, preserving lost-ACK reconciliation and the
terminal acknowledgement across reorganization. Both before/after source checks
were clean in every lane.

These results bind Hepta `0ef0e9280e8caec3fdd63761462621848761e7df`, its actual
integration-stack merge `69adeb54b9acc2e10c116df1ee17b365e0bb79a8`, Chain
`00733fb34b0cd8007862de373176c3dca4534805` and the Chain merge
`bb12346c5b53cb13526335b04078b1b8bc954a90`. They do not qualify a newer source,
Hepta main, actual model installation, independent operators or public activation.

### Observer registration and measurement coverage

The [original campaign on the analysis-export source](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39526601026)
again completed three full attempts. All 189 honest submissions succeeded, all
27 signed confirmation rounds completed inside their windows, and receiver/client
states agreed. Every hostile phase still failed the unchanged credit-depletion
requirement. In addition, the third late-product phase retained only 3,421 of
3,422 accepted connection observations, with one omission and one measurement
failure below the 16,384-record capacity. These are separate failed conditions.

The retained flow identities reconcile paid debit, final settled CPU and service
mutation CPU, with no remaining live owner, unsettled known CPU or clock failure.
The depletion predicate uses paid credit including booked start reservations;
stored admission credit is a separate quantity. Adjacent cumulative debit/discard
observations also bound paid credit between samples, excluding missed depletion
for these failed phases. The corresponding W1, CPU-accounting, challenge,
dispatch, Node-admission and campaign sources did not change between `00733fb`
and `9e29c21`; their different measured CPU costs cannot be attributed to a code
change between those two sources. Both original attack classes reject inside W1,
before full M06 execution. A valid-W1, false-state-root input would exercise a
different, heavier admission path and requires its own measured experiment and
producer/replay cost accounting. It cannot retrospectively satisfy the original
fixed-input depletion requirement.

The matching registration failure path held the complete registry mutex while a
live snapshot read every record, while new connections used `try_lock` on that
registry and permanently omitted a record on contention. The missing connection
was between IDs 609 and 611 near the second round's live snapshot; the exact
timestamp of the missing record was not captured. A deterministic native test
held the first record's task lock until the snapshot had entered that record,
then registered a second connection. It failed on the original implementation
with `live snapshot omitted another connection`; the original source hash,
executable hash and failed test log are retained.

Registration now reserves an individual slot from a checked, non-wrapping
accepted-connection counter and publishes that slot once. A snapshot does not
hold a registry-wide lock. The existing capacity, omission and overflow semantics,
per-record row/task locks and explicit capture failures are preserved. This
eliminates the demonstrated registry contention path; it does not promise that
all live per-record observation races disappear or give observations authority.

The snapshot's shared coverage predicate also rejects nonzero omissions or
measurement failures, counter overflow, an accepted/retained count mismatch,
and incomplete or failed retained rows. The CLI and all five native qualification
predicates use that same check after their existing joins. Previously a poisoned
row could be omitted while every retained row remained complete, allowing the
multiprocess predicate to miss the failure. The new real row-poison control
retains one healthy record and rejects that incomplete coverage. Concurrent
registration and saturation controls retain their exact denominators and verify
that existing records are not overwritten.

The recent-batch workflow retains its reviewed source guard with the actual
updated `public_v3_multiprocess.rs` blob
`5597af0007e175eaa1d732b57b0b173443236313`. This change strengthens measurement
integrity only. The original campaign workload, CPU budget, deadline, depletion
threshold and business requirements remain unchanged, and its old failures do
not become successful observations.

The repaired observation module passed all 13 actual native tests, with zero
failures and zero ignored tests. The deterministic registration regression first
failed on the preceding implementation and then passed with the slot registry.
The real row-poison and concurrent-capacity controls passed in the same module
run. Both raw logs and the corresponding source and executable digests are
retained. These local results do not substitute for the original full campaign
or final-source hosted qualification.

All four native request-accounting integration tests also passed, with zero
failures or ignored tests. They exercise real TCP requests, partial EOF, exact
frame accounting, observation capacity loss and honest reads. Their two actual
depletion controls use explicitly trusted local replay work before public
service/recovery; they do not bypass or qualify the separate per-request public
challenge saturation campaign.

Both scoped CLI process regressions passed on the final Rust source. The normal
service join exported complete coverage with the same public context; actual
capacity loss remained explicitly incomplete, and a process killed before join
left no completion report. Each selector executed one native test, with zero
failures or ignored tests.

The complete locked workspace passed strict Clippy with all targets and features
and warnings denied. Final Rust formatting and diff whitespace checks also passed;
all 20 reviewed workflow source-blob guards still match. Cargo graph, lockfile,
consensus domains, serialized packet formats, service budgets and readiness flags
remain unchanged. Hosted head/merge results still have to identify the published
successor; this local verification does not promote the unresolved gates.

### Hosted observer result and remaining exact security findings

The observer correction was published as
`594536f75038f5154829eee1bdff5701249e2eac`, tree
`002a878e937155119c9eb83df2496f01bf22cc9d`. Its actual prospective merge
`dee1a1aaf445b182ae2b8404efc07c46bb47340c` has the verified ordered base/head
parents and that same tree. The
[unchanged original campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39538607709)
completed all three attempts in 97.15, 97.14 and 97.11 seconds. All nine phases
retained every accepted connection exactly once, with no omission, measurement
failure, incomplete record or unclosed observed task. The 189 honest submissions
and 27 independent confirmation rounds succeeded within their original windows,
and every receiver/client state comparison passed. This is hosted evidence for
the repaired observation scope; it does not claim races are impossible in every
future execution.

All six hostile phases still failed the original paid-credit-depletion and
depletion-overlap requirements. Their minimum observed paid credit was
1.2075--1.2414 seconds for from-zero and 0.9214--0.9467 seconds for late-product,
above the unchanged 100 ms threshold. The other original phase predicates passed.
Final paid-debit identities reconciled, all live owners and reservations closed,
and the actual four-CPU/16-GiB resource ceilings, priority and original input
profile were retained. No CPU throttling or out-of-memory event was recorded.
The original campaign therefore remains failed; timely honest service without
depletion is not saturation qualification.

The same candidate's
[security evidence export](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/39538607567)
completed with stable before/after source and check identities. All three
selected analyses bind the exact PR head. Rust contains 239 full-analysis
results, comprising 217 hard-coded-value and 22 logging findings; Python and
Actions contain none. The actual PR gate independently reports 51 findings:
30 critical and 21 high. This is a measured reduction from the preceding gate's
142, not a deduction from the earlier 175-result source review.

All 51 API-visible annotations were retained, matching their reported count.
Forty-seven have exact exposed path/span/title/message matches to one SARIF
result each. Four multiline logging annotations omit column information; each
has one match on all exposed fields, while the unavailable columns remain
explicitly unverified. Raw responses and both manifests are retained. The
exporter's generic complete-gate-mapping flag remains false and its successful
retrieval does not change the failed security gate.

Fourteen critical annotations identify three test helpers for authenticated peer
frames. Production replay admission requires each public frame sequence to be
the checked successor of the last acknowledged sequence; it is not a random
encryption nonce. Those helper parameters now say `frame_sequence`, preserving
all literal values, actual protocol fields, signatures, replay checks and test
assertions. The reviewed recent-batch source guard is updated to the resulting
`store.rs` blob `2feb579d1907f688234fbee34874bb558a8956bf`. This clarifies the
fixture interface; a later actual scan is required before claiming a changed
gate count.

The remaining critical findings concern fifteen fixed public operation-ID
fixtures and one intentionally fixed W1 false-trace challenge. Their actual
protocol fields and research inputs remain unchanged. The twenty-one PR logging
annotations concern fourteen ordinary vector mutation/index sites and seven
test diagnostic sites, which remain distinct from the runtime stdout finding
present only in the full analysis. Source review and false-positive evidence do
not dismiss findings, remove assertions or grant security-gate acceptance.

The paired Hepta workflow published as
`9d9b9a669c25ef4145b13642504c970389ca6e03` used this Chain head and its verified
merge. Its [native pair run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39539710569)
finished all six lanes. Both Windows lanes passed six witness and nine evaluated
shadow tests. All four x64/ARM64 Linux head/merge lanes passed the ten study-reader
controls and then failed the actual compile-only command: the wrapper injected
`--no-fail-fast` into `--no-run`, a combination rejected by native nextest. The
study did not execute; each Linux lane retained 90 successful execution receipts
and the failed build receipt rather than a three-generation pass.

Hepta successor `acbae58fd8ff380f78cae644c3a7d601b7654b28`, tree
`0f87f3835af04267279e8c93285948fcc8efb488`, repairs that wrapper argument
interaction and adds all twelve real native wrapper controls to each Linux
lane. Its actual merge `d3e585ea7b9b4c04a98fe7d268ad1d96f372d1e9` preserves
the existing integration base and has the same tree. The
[successor run](https://github.com/TrillionniumFoundation/hepta-private-ci/actions/runs/39543970250)
must establish its own source-specific results. The original study, role custody,
data, thresholds and 600-second owner remain unchanged. Any eventual study pass
is scoped to controlled local tabular learning, not actual neural generations,
PoN/TaskFlow model installation, independent operation or public activation.

### Valid-work state-root refusal and complete Cell deadline

A new ordinary protected-v3 regression submits the same complete packet three
times with a newly acquired, strictly verified W1 proof and an intentionally wrong
state root. The eight transaction signatures remain valid. Each request reaches
full Work acceptance and actual M06 admission refusal, returns signed `ROOT`,
does not run SubmitResult and settles its owner plus scoped-worker CPU charge.
The three measured debits in the local run were 20,209,865, 11,565,557 and
27,392,977 ns; their sum exactly matched the service's 59,168,399 ns settled
charge. These are observations from one execution, not throughput or attacker
cost bounds. Complete request coverage, per-call settled identities, unchanged
native stats/state and absence of the rejected packet are checked directly.

The service is joined and its sole Node owner dropped before actual cold reopen.
The first reopen retains the original mempool context and unchanged state. A
second ordinary service epoch accepts the independently constructed correct
packet, after which another cold reopen verifies the exact state and stored
packet bytes. The first attempted regression failed because its test setup
omitted the service's required mempool initialization; all four requests failed
before dispatch. That failed observation is retained. The corrected setup uses
the original campaign's existing PoolLimits before its baseline snapshots, and
the two reopens only inspect persisted context rather than re-enabling it. The
corrected native selector passed once with zero failed or ignored tests.

All 1,194 original campaign lines and their inputs remain byte-identical. This
additional case does not replace the original false-W1 hostile traffic or grant
its missing depletion qualification. The recent-batch workflow binds the new
integration-test blob `c94eea8c3498775f9a9cb1f861b3502669c1bae1`, and all four
priority service-model lanes explicitly execute the new selector and retain
its actual receipt. Work-hardness, original campaign, depletion and activation
qualification remain false.

The M09 Cell CLI previously finished the bounded fetch and then invoked a
separate materialization without the original deadline. It now calls
`fetch_cell_to_file`, passing one unchanged absolute deadline through network
retrieval, complete verification, final write and the pre-publication checkpoint.
The additive `materialize_until` API rechecks original cached payload bytes;
the existing no-deadline materialization API remains available to explicit
callers. That deadline-only increment preserved protocol bytes, manifest/cache
schemas, limits and CLI report fields. The later TCL3 image and current TCL4 WAL-admission increments
is specified above and in the same Cell contract. Checks are cooperative: filesystem calls cannot be preempted,
and a complete file is not deleted after publication because subsequent I/O
takes time. The exact boundary is documented in
[CELL_P2P_V1](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md).

The twelve retained Cell tests and four additional deadline/publication controls
passed as sixteen actual native tests, with zero failures or ignored tests. One
negative control performs real network retrieval and file synchronization,
compares the original and received `Instant`, then pauses at the test-only
publication hook until that same deadline expires. It requires no final file
and no leaked temporary file; a later explicit cache-only operation succeeds.
The clock is not replaced. Corrupt-cache, wrong-complete-digest, existing-output
and success controls retain exact byte comparisons. The first temporary result
observer incorrectly expected seventeen tests and failed after native libtest
had already passed sixteen; that observer error and original log are retained.
The corrected observer reuses the unchanged-source native result without
claiming another test execution.

A separately built CLI packed and transferred 131,328 bytes in nine chunks over
ten actual loopback connections, verified the complete SHA256, rejected an
existing output without modifying it, and produced a second complete file from
cache with zero response bytes and zero network attempts. The finite server
exited normally. These local byte/resource results do not implement the absent
neural loader, complete model-release closure, WAN discovery, independent
custody or replica economics.

The priority, baseline and Hepta pair workflow concurrency groups now retain
an already running candidate while its successor waits. Their source checks
continue to bind frozen event head/base/merge identities, never a mutable live
PR head. Trigger, job, source checks, runtime owners and time limits are
unchanged. GitHub's ordinary pending-slot behavior can replace an older pending
candidate when another arrives; no result is claimed for an unexecuted version,
and an earlier successful candidate cannot qualify a later source.

The final Rust source passed locked, offline, complete-workspace strict Clippy
with all targets and features and warnings denied in 98.47 seconds. Formatting,
the three changed workflows' actionlint checks, all twenty source-blob guards
and the exact twenty-five-package locked Cargo graph also passed. Source digests
before and after the native tests and Clippy are retained. These checks do not
grant production, model-efficacy, independent-security or release acceptance.

### Reconstructed Host-only follow-up, 2026-10-27

After a temporary-workspace loss, the narrow inactive implicit-slice repair was
reconstructed over the unchanged `ac469237` candidate. Its [evidence](../../evidence/pon-reconstructed-host-fix-20261027/README.md)
retains the source boundary, fresh Python controls and missing hosted-run gate.
No native owner, work relation, resource ceiling or activation policy changes.
The previous local commit identity and its lost records are not reconstructed
as an allegedly identical successful publication.

### Actual reversible components, 2026-10-28

The pure-PoN quantum work package now has [explicit reversible arithmetic and
SHA-256 components](../../formal/pon-nakamoto-v1/REVERSIBLE_COMPONENTS.md), including
exported gate lists, strict artifact reopen, nonzero-output execution and actual
scratch cleanup checks. The original full W1 relation, work identity and chain
weight are unchanged. The observation records gate counts and logical resources
for these components only. It does not supply the coherent rejection sampler,
whole matrix/prefix memory schedule, complete phase oracle, physical machine
or quantum proof-system soundness. Existing DAA rate experiments remain
conditional models; no simulated rate is relabelled as a quantum attack or
used to grant pure-PoN security acceptance.

### Exact native build preparation outside the public Host quota, 2026-10-28

The original `73ffdd94` protocol-contract execution passed the actual Host
checks but exhausted its 900-second build deadline before any native test ran.
Its [preserved evidence and follow-up boundary](../../evidence/pon-host-build-separation-20261028/README.md)
separate that compilation failure from the distinct multi-process campaign's
public-Host membership refusal. The CI controller now runs the exact build-only
command once as ordinary preparation, preserving its whole CPU/resource/failure
receipt. It then invokes the unchanged original runner in the fixed 25% CPU,
2 GiB, swap-free Host parent. That runner repeats its original source build and
all original native tests, with unchanged deadlines and report predicates.
Source identities and executable digests must join across both stages. No
downloaded executable or earlier source can satisfy this preparation, and a
successful build alone grants no test or service acceptance. Pinned OpenSSL
build inputs are explicitly preserved across the unprivileged process boundary.
The new controller receipt uses its own v2 schema; separate preparation and
build-to-execution binding receipts use new v1 namespaces. Hosted execution on
the resulting source must establish its own result.

### Actual integrated-work-package evidence, 2026-10-28

The [actual fc23 Host observations](../../evidence/pon-fc23-native-host-20261028/README.md)
now establish preparation/execution source and ELF identity in four hosted
lanes. Every original inner build and all five named native tests ran, but all
four original pressure-confirmation gates failed. All 28 signed submissions
were timely; incomplete History replay prevented confirmation. No actual CPU
credit exhaustion occurred in those windows. The original raw reports, binaries,
databases, requests, timeouts and macOS cleanup failure remain retained.

The [original Cell/Hepta observations](../../evidence/pon-cell-hepta-readback-20261028/README.md)
establish actual publisher-offline replica acquisition, original artifact-owner
publication/recovery, controlled neural FinalUse and frozen-task comparison on
Hepta `50f4fe80` paired with Chain `73ffdd94`, including both actual merge lanes.
Each lane executed the same 32 controlled queries: baseline and candidate were
both correct on 16, and every final choice was unchanged. The original runner
returned Ineligible and the adoption decision remains no-update. Source and
merge repetitions are not 64 independent tasks. All production-installation,
ordinary-context, independent-efficacy and public-reward flags remain false.
The later receipt export preserves original bytes without qualifying a new
source or rerunning the model.

The [native PQ authorization inventory](../../evidence/pon-pq-authorization-inventory-20261028/README.md)
records the actual QTX1 and TPQ1/PNQ1/PNP1 paths, classical profiles and the still
unmigrated owners. Exact e642 Clippy succeeded, but the interrupted post-fix
native qualification has no completion receipt. Static binding repairs and
newly written controls do not become runtime acceptance. The full account,
task, Cell, Operator and Hepta migration remains open.

The [independent hardened W1 verifier](../../evidence/pon-w1-verifier-hardening-20261028/README.md)
accepts an actual saved lift receipt and rejects the identical control-ID
mutation accepted by the older verifier. This is a specific metadata-binding
fix, not evidence of arbitrary W1 forgery or quantum proof soundness. The full
W1 proof experiment remains bound to its original guest/session/source and
separate time budget. Integrating its source does not inherit the frozen
experiment's qualification or turn a prefix into a complete succinct proof.

The combined candidate retains the pure-PoN work relation and weight. It does
not activate a network or complete the independent 72-hour, multi-administrator
WAN gate. Each combined-source build, runtime and service result must be recorded
under its own identity before any of those gates can change.

### 2026-10-28: preserve r14 startup failure and repair exact historical readback

Integrated head `8a35529679c3d176fd7586ab1ecf4e004f25af79` reached the
original hosted campaign, but `load_profiles()` still required r13 while the
native resource configuration had advanced to r14. Run `40614503458` failed
before compilation or any native phase. The [retained startup failure and reader
repair](../../evidence/pon-r14-reader-repair-20261028/README.md) preserves its
original artifact, log and exact source. It grants zero service or pressure
acceptance credit.

The Python reader now validates exact r10–r14 raw history, current r14 arithmetic
and separate historical r13 arithmetic against their respective hashes and
bases. It does not change resource numbers, phase lengths, confirmations,
depletion predicates or Rust behavior. The related 31 Python controls pass,
including historical relabeling and mixed-generation rejection. The workflow
executes these checks before native preparation. New native results remain
required; old failed, skipped and unavailable observations remain failures or
unknowns under their original source identities.

### 2026-10-28: preserve e25 startup refusals and pin the launcher context

The r14 repair allowed the [next original release campaign](../../evidence/pon-e25-phase-startup-20261028/README.md)
to compile its real test ELF successfully. All three predeclared runs then
failed at all nine phase launches, before Host setup or service measurement.
The original error combined cwd and non-root checks; it does not establish
which condition failed. The Rust launcher lacked an explicit repository cwd.
The candidate pins only that Python child's directory, retains both checks and
all resource/permission limits, and reports the two refusals distinctly.
Eleven phase-host Python controls pass, including wrong-directory and root
refusal before provisioning. Native fixed-Host/depletion acceptance is open.

The recent-batch workflow keeps its original source and test gates while
explicitly repinning five reviewed blobs; all 16 guards and every original
selector/count remain. New native execution is still required. The
[frozen W1 source bundles](../../evidence/pon-w1-source-closure-20261028/README.md)
are now included as actual bytes with a publicly reachable prerequisite; the
earlier e25 observation that they were not yet present remains retained.


### 2026-10-28 UTC — exact denominator maintenance and source qualification

The original e25 workflow failures are retained. Reviewed Linux-only owned-reserve selectors increased from seven to nine, and migration selectors from 35 to 36; CI now requires the exact new counts while retaining every selector, zero-failure/zero-ignore condition, resource budget and confirmation denominator. The source/old/new selector review is in [the count evidence](../../evidence/pon-ci-exact-count-review-20261028/README.md). No new runtime acceptance is inferred from changing the literals.

The clean committed startup repair 4370f250 and published tree-equivalent 131f673d passed strict full-workspace Clippy, 11 phase-host controls, 34 source-integrity controls and the 25-package/971-Rust-file/1,342-link repository check. These exact-source records and actual merge-parent checks are in [the source qualification evidence](../../evidence/pon-integrated-source-qualification-20261028/README.md). W1, sustained paid-depletion service, full PQ authorization, real model efficacy and independent WAN remain separately gated.

## 2026-10-28 complete W1 Succinct observation — benefit gate remains failed

Frozen guest/prover source `64be7c4ad51d432e7736ad135476262e23e968f5` now has an actual full 59-segment Succinct receipt, independently accepted by the original SDK 3.0.3 and hardened SDK 3.0.6 (`dd4fb0a65a734bdccac23a061dc0d6c72b69188f`) full gates. The exact original W1 relation, task/target/ordered transcript/product and original work ID remain bound; proof randomness adds zero tickets. The 318-byte PNH1 header, 49,188-byte PNW1 witness and 16,818-byte journal are retained.

The final receipt is 256,886 bytes, 5.2225 times the native witness. On the same frozen input, 1,000 native full-replay measurements have median 0.5543925 ms and sample p99 0.841684 ms. The hardened verifier's 100 decode-and-verify measurements have median 16.660953 ms and sample p99 21.576132 ms, 30.0526 times the native median. Exactly 24 controls (one positive, 23 negatives) matched the expected outcomes with zero PANIC. This is one independent proof, not a prover-p99 or production-tail measurement. The full-relation prototype is completed; work package 2A still FAILS the actual-benefit gate. No production proof path, consensus weight or fallback is added.

Original 90-minute timeout return124 is retained. The independently declared continuation's outer supervisor was interrupted; its exit status and wait4 terminal receipt remain UNKNOWN. The same existing prover continued, observed by a newly declared observer after a 282.650989-second sampling gap, with zero new time budget and the original compression/total deadlines. Fresh gates completed 1,318.132983 seconds after the original continuation start. The combined actual CPU lower bound is 41,887.285978 seconds; recorded controller/prior/continuation wall accounting is 6,712.315070 seconds including 700.173346 seconds of coordinated pause. This is not isolated prover latency or exact interrupted-process CPU settlement. Post-gate source verification checked 5,502 tracked entries / 706,320,655 bytes on the original clean source.

See `evidence/pon-w1-complete-succinct-20261028/README.md` and `final-readback.json`. The independently hash-checked complete raw archive has 923 payload members / 925 total members, 65,349,319 bytes, SHA-256 `5a888ab56f0a656ac26df5caf79a6c46c71b1e53110d189ca1a951591ddb5ac4`. Full source recovery bundles are separately published. Transparent-STARK wording, component soundness calculators and these real proofs do not establish full post-quantum chain security, complete QROM soundness, useful-work hardness or independent WAN acceptance.


### 2026-10-28 UTC — Host/refill reachability and remaining acceptance

The published fixed Host has 0.25 core total CPU while the paid mutation bucket refills at 0.25 CPU seconds per wall second. The [cross-work-package review](../../evidence/pon-workpackage-cross-review-20261028/README.md) retains exact source, timely-accounting assumptions and delayed-settlement counterexamples. This is a reason to inspect real debit/refill/discard and confirmation overlap; it is not a native attack or a proof that depletion cannot occur. No original profile, budget, work identity or passing threshold was changed. The actual 131f native campaign remains its own required observation.

The [W1 packaging process correction](../../evidence/pon-w1-packaging-audit-20261028/README.md) preserves an evidence-branch preflight failure and the subsequent allowed-branch successful preflight. Runtime proof evidence is not relabelled as evidence-commit execution.


### 2026-10-28 UTC — original 131f service outcome and remaining backend contract

The [original 131f campaign and read-only backend review](../../evidence/pon-131f-native-and-pq-readback-20261028/README.md) now contain all three native repetitions. The startup repair worked: all nine Host receipts pass, with no startup errors. All nine service phases fail, including the baselines. There are 0/27 scheduled confirmations, nine observed failed rounds, and 18 unobserved rounds. Sixty-three of 189 planned business packets were issued and timely acknowledged. History network acknowledgements are 24/24, but local imports are 15/24 successful; all nine failures are PUBLIC_REQUEST_DEADLINE. Six attack phases paid real CPU but none reached paid-credit depletion. This is not sustained-overlap service acceptance or a restart test.

The observed account-graph verification intervals dominate native verify-state cost, while receiver and client ledgers remain distinct. This supports a bounded incremental-state/snapshot design investigation; it does not yet establish a particular lock or a safe consensus-preserving optimization. No budget, deadline, work relation or original denominator was weakened.

The hosted PQ compile failures expose an unbound backend contract; runtime fixture failures occur at the independent CLI call before strict DER decoding. Local explicit-3.5.9 Clippy success does not qualify the hosted backend. Original runtime failures, missing diagnostics and the earlier automatic interruption of native validation remain open. No optional feature was skipped or classic fallback introduced.

The [fuzz lock consistency repair](../../evidence/pon-fuzz-lock-consistency-20261028/README.md) adds only two existing path dependencies' zeroize edges. Locked metadata and public dependency download now succeed locally; the original offline missing-source failure is retained. This is no native/fuzz/advisory acceptance claim. The full project remains HOLD/NO_GO pending the original work-package gates.

### 2026-10-28 UTC — r8 History boundaries and explicit PQ provider

The [History checkpoint candidate](../../evidence/pon-history-checkpoint-r8-20261028/README.md)
removes three adjacent duplicate checks while retaining every original full
state/account/root validation and resource-first checkpoint. Its original native
groups record 72 passes, no failures and four original ignored cases; a separate
explicit slow depletion run executes actual W1 and preserves the debt/reopen
fence. The seven-page private comparison retains identical packet identities
and tips but is not a fixed-Host service or throughput acceptance result.
The [exact historical reader repair](../../evidence/pon-legacy-reader-pq-layout-r8-20261028/README.md)
retains both the original three-variant store contract and current cfg-gated
four-variant PQ contract with exact schema vectors, 50 passing reader controls
and 34 source-integrity controls. Neither result erases the original 0/27
confirmation or 0/6 attack-depletion outcomes.

The [explicit PQ provider contract](../../evidence/pon-pq-backend-contract-20261028-r8/README.md)
binds five protocol oracles and their original fixtures to the same declared
OpenSSL installation as native Rust, without system-PATH selection. Bounded
offline runs pass eight original synthetic M06 account tests and 72 original
real-crypto protocol tests. Dirty source digests, original budgets, full logs
and process results are retained. Thirteen backend controls include 48 provider
alias refusals. The authorization inventory and whole-chain acceptance flags
remain unchanged. These observations neither qualify an unexecuted successor
nor complete Cell/task/Operator/Hepta authorization migration.

The [isolated W1 batch source](../../evidence/pon-w1-batch-source-20261028-r8/README.md)
requires every complete leaf proof and original work identity, rejects duplicate
work and verifies the exact aggregate image and empty assumptions. It supplies
no extra tickets or production acceptance. The measured single complete W1
proof still fails byte and verifier-cost benefit gates. A new batch guest,
actual aggregate proofs, total-cost measurements and enough distinct paid leaf
proofs remain separately required observations.

### 2026-10-28 UTC — actual PQ post-intent counterexample and secure compiler acquisition

The [exact native PQ readback](../../evidence/pon-pq-native-readback-20261028-r8/README.md)
retains the original eleven Node/M06 tests passing on `e7ab8cce` and strict full
workspace/all-targets/all-features Clippy, locked metadata and formatting passing
on `e3afbbf4`. Those source-specific results do not cover the later scheduling
regression. The first new test attempt failed macro compilation; its complete
cost and error remain recorded. The corrected test on clean
`6762be6bad760d17c6cbb50ff7f8b1928c6284df` then genuinely failed at runtime.

All five predeclared real signed socket calls were observed. The original
production PQ listener's ten-second deadline elapsed after a genuine durable
reorg intent. A valid native ML-DSA signed failure was retained, but the intent
remained pending and all three honest followups failed. Cold reopen activated
the retained valid target; peer operation records and sequence/revocation
ledgers remained equal to the live observation. This is a local scheduling-cut
liveness/recovery counterexample, not a signature forgery or physical kill.
The repair must retain every original request, State and nonce check, use local
typed cancellation identities that cannot be parsed from remote strings, and
obtain separate actual before/after results. Full migration and public/WAN
qualification remain false.

The [official RISC0 compiler acquisition](../../evidence/pon-w1-rust1911-acquisition-20261028-r8/README.md)
preserves the original patched guest dependency graph after rejecting an unsafe
MSRV-only downgrade. Official Rust 1.91.1 was downloaded once, authenticated by
its exact release size/SHA, fully inventoried and installed in an isolated
explicitly selected toolchain. Its actual RV32IM target metadata matches the
expected target. Acquisition and compiler metadata checks are complete; SDK
build/runtime compatibility, real batch proofs, soundness assumptions and
measured benefit remain separate gates. No work relation, weight or fallback
was added by this toolchain change.

### 2026-10-28 UTC — actual local PQ cancellation repair and full paired readback

The [local cancellation source review](../../evidence/pon-pq-local-origin-source-review-20261028-r8/README.md)
adds three local-only typed error identities. Generic parsing of remote error
strings cannot construct those identities. The existing deadline, expiry and
revocation order, every original wire/state/nonce check and all 138 previous
wire error mappings remain unchanged. This limits pending-intent cleanup to
locally established cancellation authority.

The [actual repaired native observation](../../evidence/pon-pq-local-origin-runtime-20261028-r8/README.md)
is bound to source `990aeb651f793ca44bf94b074356be06e58e75c1` and tree
`91b8178b05d867f063ce21264043c2a49fcc6e41`. All ten PQ network and ten error
origin tests pass, with no failures or ignored tests and every original test
retained. Both the unchanged ten-second deadline test and the genuine signed
expiry test retain all five scheduled socket calls and succeed on all three
honest followups. Fifteen injected local/remote-origin controls and six actual
signed/forged socket calls also pass. The injected cases do not establish a
concurrent durable operator revocation, which the current serialized production
listener does not expose. The original baseline failure remains retained.

The bounded qualification consumes 525.349589 seconds wall and 508.373779
captured child CPU seconds, including compilation, strict workspace/all-targets/
all-features Clippy and the original tests. Its 41 observed PID/birth identities
are all terminal. The three regression attempts together retain 960.152845
seconds wall and 933.875773 captured CPU seconds; this does not erase earlier
PQ experiments or source/evidence costs. Full production authorization migration,
paid hostile public service, physical power loss and WAN acceptance remain open.

The [complete paired Hepta 682 readback](../../evidence/pon-hepta-682-pair-host-readback-r8-20261028/README.md)
contains 3,769 client calls, 3,633 receiver records and all 256 original wrapper
records across four Linux jobs. The exact source remains Chain `131f673d` and
its original merge `66634191`, not this later integrated candidate. All five
original named native selectors pass in each lane, while every pressure service
gate fails. Only 3/8 scheduled confirmations meet the unchanged four-second
deadline, including 0/4 pressure confirmations; all 56 business submissions
receive timely signed acknowledgements. Eight sustained phases reach 0/8 real
credit-depletion outcomes. Their full-W1 refusals never reach M06 admission.
These results require a separately identified late-root/controller-placement
experiment; they do not authorize changing the original profile or its outcome.

The [batch guest/host build](../../evidence/pon-w1-batch-build-20261028-r8/README.md)
uses the actual official compiler and unchanged independent locks. Its real
308,184-byte guest and original build costs are retained. The [staged batch
source](../../evidence/pon-w1-staged-source-20261028-r8/README.md) requires an
actual conditional receipt, real final-verifier rejection, and real typed
resolution of the same already-verified original leaf. Build and source checks
do not replace those cryptographic observations or establish proof benefit.

The [separate fixed-Host ROOT F0 reconstruction](../security/PUBLIC_V3_FIXED_HOST_ROOT_EXPERIMENT_R10.md)
recovers nine earlier Python/workflow files but identifies its missing Rust as new
source. The old phase, ROOT supplement and launcher whitelist remain unchanged.
The separate route requires a live private controller capability, 24 distinct
actual child identities, the original complete W1/M06/state/depletion checks,
six planned confirmations and 42 business exposures. Its additional four-second
SLO starts at scheduled times 1/5/9 and includes queue and observer costs. Both
immediate and always-finalizer cleanup require exact invocation/boot/PID-birth
and cgroup identity; an unknown controller cannot yield a final all-empty claim.
The original 0.25-core/2-GiB Host and paid bucket are unchanged. This source
candidate still requires native formatting, locked graph/Clippy, five native
source controls and a real hosted run. Source fixtures do not close service,
restart credit or WAN. F1 is not implemented; no throughput gain or production
activation is inferred.

The [R11 controller-resource correction](../../evidence/pon-f0-controller-resources-r11-20261028/README.md)
retains a real parser counterexample on clean `ca4fcb`: the old two F0 readers
accepted missing controller counters with all 24 external-actor RSS values
unknown. The five original native controls and 61 Python controls did not
cover that condition. A separate mandatory whole-controller-cgroup gate now
binds raw CPU/current-memory/lifetime-peak readings before launch, at actual
actor readiness and after reaping to the original controller capability and
complete Child-derived manifest. It preserves the old null RSS diagnostics,
pressure samples, public Host, paid bucket, work, SLO and all denominators.
The native total, readers and finalizer must refuse missing or drifting resource
identities/counters. Five original native selectors remain, with two new counter
controls; static acceptance alone cannot close the native or actual Host gate.

## 2026-10-28 recovered W1 staged host: typed negative-control repair

The [reconstructed typed-control source](../../evidence/pon-w1-staged-typed-source-20261028-r10/README.md)
replaces two invalid Debug-text prefix checks with the pinned verifier's exact
error variant and both independently bound claim digests. All existing inner
STARK, complete-claim, metadata, one-real-assumption and actual resolve checks
remain. The only host-lock change is a direct edge to the already pinned
`risc0-zkp 3.0.5`; the guest lock, relation, guest and WorkID are unchanged.
Python public-byte and graph checks do not qualify compilation or a proof run.
The missing unpublished repair and proof artifacts are not assigned to this
new source identity. Exact native qualification and a fresh bounded proof run
remain required, and one-leaf calibration cannot establish the batch benefit,
prover tail, full authorization, quantum soundness or WAN acceptance gates.
