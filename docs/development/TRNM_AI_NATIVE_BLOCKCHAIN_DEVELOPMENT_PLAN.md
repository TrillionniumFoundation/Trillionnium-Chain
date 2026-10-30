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

Latest owner-recovery checkpoint: [2026-10-30 continuation](#pn-owner-recovery-continuation--2026-10-30-utc).

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

### Pure PoN six-item implementation — 2026-10-27

The user's six-item authorization continues PN1 and PN3 inside this plan. Pure
PoN is mandatory: this increment adds no stake vote, committee fork choice,
independent hashcash gate or permissive fallback. The integration input is Chain
`c96022b897c1235fdbdbfcfa32764403511c6aab`; the paired Hepta input is
`e1537d7deea32f29ec9612c0a7b90655b14aa904`. The continuing Chain review is
[PR #499](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/499),
targeting the existing audit integration branch. Neither those pins nor this
section imply that a later source has passed its required checks.

| Priority / owner | Concrete increment | Remaining veto condition |
| --- | --- | --- |
| P0 / M01 complete W1 | The independent [PWG1/PWJ1 relation](../protocol/pon-nakamoto-v1/details/W1_COMPLETE_RELATION_RESEARCH.md) binds all 318 header bytes, canonical PNW1, task/target, all noise, all 512 trace tiles and the corrected product. Differential tests compare native kernels and mutations. | Local execution is not a transferable computational proof. A real pinned proof, complete journal binding and bounded rejection still need their own evidence; proving only the final product is insufficient. |
| P0 / M03/M04/M15 adversarial cost | The [pure public profile](../protocol/pon-nakamoto-v1/details/PURE_PON_PUBLIC_BOOTSTRAP_V1.md) has no caller nonce search and retains the original shared budgets. A fixed exact-public-product fact rejects wrong C before replay; [native campaigns](../protocol/pon-nakamoto-v1/details/PURE_PON_COST_CAMPAIGNS_V1.md) retain unique invalid traces, honest calls and cold reopens. | A correct C with a false trace still reaches full native W1 replay. Therefore the no-full-replay bad-certificate requirement is not closed by this filter or by a finite service pass. Reactor CPU, arbitrary hostile scheduling and WAN fairness remain separate. |
| P0 / M01/M02 work cost | The fixed matrix offers all 12 current producer strategies, nine input classes, cold/reused preparation, paired complete streams, multiple horizons and two targets. Every miss and unsupported constructor remains in the denominator/report. | Finite software observations do not prove a minimum physical cost, non-amortization, task-selection safety, accelerator parity or quantum mining assumptions. Structural task availability is not useful-demand registration. |
| P1 / M02/M03 public task supply | A fresh node can derive or fetch the exact public genesis maintenance bundle and mine through the actual native producer without pre-existing balance or private provider credentials. | Maintenance remains maintenance: useful-output credit is zero. This does not demonstrate sustained beneficial neural-task supply or model-quality gain. |
| P1 / M00/M01/M15 PQ path | [Native ML-DSA-65](../protocol/pon-nakamoto-v1/details/PQ_NATIVE_AUTHORIZATION_V1.md), 210 pinned Wycheproof vectors, independent OpenSSL fixtures, and a separate durable TPQ1 authorization owner replace the syntax-only research seam. | PNX1, ordinary transport, other authorization owners and the work-proof security parameters have not become post-quantum through this helper. A new signature namespace cannot clear the whole-chain gate. |
| P1 / PN3 and existing Hepta owners | The paired work implements an ordinary initial-model CognitiveRanker path and a separately identified public initial genesis v2 because the old pinned contract bytes cannot be reproduced from the published closure. | v1 pins and evaluated-child qualification remain strict. Cold installation, actual ordinary reads, three real training rounds, matched controls and beneficial accepted releases require distinct actual outcomes. |

The [first integration observations](../../evidence/pon-pure-integration-20261027/first-ci-failure.json)
retain the initial native/fuzz lock mismatch rather than relabel it. The
[local first-check manifest](../../evidence/pon-pure-integration-20261027/local-first-checks/manifest.json)
also retains the sparse-checkout link failure, offline dependency-cache miss and
strict Clippy failure, alongside successful checks. Each source identity belongs
to its own observation. The focused native workflow runs exact candidate source
and preserves failures; it does not replace the original required head/merge,
cross-architecture, original-pressure or long-capacity lanes. All acceptance and
activation flags remain unchanged.

### Pure PoN admission / DAA continuation — 2026-10-28

The user's two-item continuation starts at `0d02a946c9126c5dbdad41edd770c81eda07a96e`
inside PN1/I01-I02. The [technical attachment](../protocol/pon-nakamoto-v1/details/PURE_PON_ADMISSION_DAA_V2.md)
specifies a fresh explicit pure-v2 transport, same-account cross-listener FIFO,
same-epoch bounded arithmetic facts, and a separate real complete-statement
transparent certificate verifier research API. Existing pure-v1/r13 protocols,
native W1 authority, CPU/byte/deadline limits and all acceptance flags remain.
There is no added Hashcash or other PoW gate. FIFO after bounded intake is not
unrestricted Sybil fairness; fresh-challenge attacks remain real work.

The supplemental fixed 24-actor/three-30-second campaign requires receiver-side
work, actual shared CPU depletion and honest round overlap, plus true 64-slot
capacity churn. Its reader preserves valid failed observations and refuses
unearned finite qualification. The [two retained local observations](../../evidence/pon-pure-admission-daa-v2-local/README.md)
both failed honest service: respectively 3/2/3 and 3/3/2 completed rounds across
the three phases. Their raw reports and telemetry defects remain archived.
The final collector obtains real height by active tip, records generation
separately and checks fresh paid-credit depletion. Its corrected stored evidence
uses a new v3 namespace; the transport remains pure-v2. The original campaign
source, workload, limits and historical failures remain unchanged. Final exact
head CI must supply the corrected campaign's own observation.

A subsequent exact-head check at `c2364a5` returned 180 runtime tests passed
and one original timed-close assertion failed; its complete raw record is
retained with the local observations. A reachable baseline gap omitted expiry
counters when the original deadline elapsed inside a stage check. The narrow
correction requires both a typed time error and an actually elapsed original
deadline, preserving the old TCP conditions, all limits and wire identities.
Two deterministic boundary controls plus the original TCP case passed locally;
this diagnostic correction neither replaces prior failures nor qualifies service.
The c2364a5 exact-head x64 and ARM64 CI observations separately passed all nine
confirmation rounds each; four of six hostile rounds per architecture also
contained fresh paid-depletion observations. Their unchanged raw inputs were
independently reread with identical v3 verdicts. These are finite observations
under the 4-CPU / 16-GiB / nice-10 experimental envelope, not evidence for the
fixed public kernel parent or for the later timed-close correction.

At exact head `75d52b6`, x64 qualified all nine rounds. ARM64 passed the six
native gates and reported nine rounds, but the independent reader correctly
failed a call that entered 102,720 ns after the original phase cutoff. Both
artifacts and source-specific verdicts are retained in the evidence index.
The forward collector checks the captured call start before invoking the API,
conservatively anchors its absolute deadline, and uses one captured start to
gate sampler entry. It retains every actually issued call and late result.
The v3 schema and reader rules stay unchanged; a seventh mandatory native
gate covers this entry boundary. The original ARM failure remains failed and
the successor requires its own exact-source observations.

The conditional PoN DAA model includes task/solver costs, witness/publication
latency, producer rate changes, hidden branches and full-cost quantum hypotheses,
with native integer-rule vectors and a real PNW1 confirmation/reorg/reopen test.
It changes no consensus DAA and supplies no economic exploit or chain-security
probability. Transparent proof production, worst-case public proof rejection,
arbitrary-Sybil honest service, physical work/quantum costs and independent
security acceptance remain OPEN. Final source/merge CI and actual native
campaigns must supply their own receipts; this section grants no release or
activation authority.

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
implements controlled dependency transport and byte readback. Its default route
continues to refuse an unavailable native consumer and unverified owner receipt.
The earlier inspection, before the additive controlled profile below, covered Hepta
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

The additive `--controlled-consumer-profile smollm-signed-read-v1` remains in
this PN3/I09 work package. M09 exports the original eleven TCM1 manifests and
one TCR1 release; `llm_cell_release.py` adds a create-only declaration capped
at 64 KiB. Hepta's owning inference module must reconstruct those original
wire bytes from all actual received payloads, join the original six executable
source pins and full model/profile/parent identities, then use the existing
signed load/query/unload owner. Declaration and readback parsing do not grant
selection, CURRENT installation, ordinary-task qualification or reward.
The original transfer and readback budget stays 35 seconds; model compilation
and the explicitly selected original native case are separate observations.
The default refusal remains unchanged, and even a controlled positive keeps
the overall handoff failed because I10 selected installation is unavailable.
The bounded/duplicate-key/typed-readback refusal and retained deadline controls
are parser evidence. The later [source-bound controlled observation](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/i09-eleven-material-controlled-20261026.json)
on Chain `915f933c` / Hepta `da4a920` fetches all eleven model-data objects
(272,190,131 payload bytes / 269 chunks) from one loopback peer. Transfer and
final readback take 3.240547 seconds within the original 35 seconds; the original
signed native load/query/denied-query/terminal-unload case passes in 10.133 seconds.
Three authorizer binding calls yield two durable nonce claims. The overall
handoff remains failed/exit1 at I10 selected-installation UNAVAILABLE. CURRENT,
ordinary-task use, three installed-parent upgrades, funded Whole-U return,
runtime dependency closure, durable repair and independent WAN custody remain open.

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

The local Hepta `01f2757d` checkpoint separates the four-file opaque prepared
process/pipe/ConPTY owner prerequisite from the subsequent terminal observer.
Security-authority retains the exact token, root proof, capability, desktop and
Job owners; this reviewed source slice is not compiled or natively qualified.
The retained six-file terminal candidate still has an open failure-custody
dependency. PN4's original controlled session must own one fixed attempt slot
before birth, retain the original child and resources through fallible readiness
and terminal publication, and forbid another birth while Pending or Unknown.
The current standalone test has no such longer-lived caller transfer. A stop
request, Err-drop or late cleanup cannot establish an observed exit or release.
Keep the same absolute eight seconds, actual exit0/7/259 and reduced-rights
sticky-refusal assertions, plus all original Windows native groups and deletion
failures. No fresh cleanup window, detached reaper or second registry closes it.

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

**Finite observation, 2026-10-25; PN1 remains open.** On clean source
`630f871293e48588e0a1ceae7ceb64973d3ec31d`, the original maintenance cost
campaign (`samples=2`, `searches=4`, `attempt-budget=8`, `seed=1`) executed
64 cohorts / 256 searches: 160 setups, 992 prove calls including 816 target
misses, 176 winning searches, 80 exhausted searches and 352 post-search verifier
calls. Independent scalar reconstruction checked 62 distinct challenges and the
complete retained proof streams; the 256 searches contain only 16 distinct search
paths and must not be reported as independent hardware samples. In the four
fixed target/setup groups, maintenance-split-limb had the lowest observed complete
setup-plus-search wall median, 7.877421% to 23.296266% below generic. Reducing its
setups from eight to two saved only 0.091616% and 0.829763% of the corresponding
observed totals; search timing variation is not all amortization. This is one
machine and finite seeds, not per-prove CPU, energy, global cheapest work or a
hardware bound. Timed target-miss proof bytes were not retained by that original
cost collector, and its native PID is unrecorded; neither is reconstructed as
an original observation. Cost receipt SHA-256:
`e77e1fc242ed56c186b8df5f04bde381ed2c643bf78d818e46bb67108d13bd00`.

Five original native selectors on the same clean source also passed, with zero
selected failures or ignored tests. They exercise actual-parent maintenance
admission/reopen, authorized zero and one-zero task preparation, invalid signed
recipes, expiry and a heavier-branch registration rollback within their individual
profiles. They do not authorize arbitrary replacement of a funded task or qualify
every checkpoint/growth profile. Their original temporary databases were cleaned
by the tests, so source-bound assertions and stdout are retained evidence rather
than externally replayable per-proof/database exports. Independent receipt:
`dec8ca58256fb0be7b842d0e50c8736190bfa202512b8f0817116bca34ac19fa`.
The separate local two-actor v2 control is likewise finite: it does not close the
retained v1 failure, the 4,097-identity supplement or the original service campaign.
Full collection remains disabled pending complete transient SQLite I/O accounting
and reviewed execution/output path binding. Preserve the original generic service
workload, limits, confirmations and historical failures while implementing these
owners; a faster cost producer must not silently replace that workload.

The original hosted x64 and ARM64 cost jobs at this same source, run
`40190608316` / attempt1, now provide matched inputs for four suites and two
campaigns. Their original readers validate 432 paired case groups, including
24 unsupported groups retained in the denominator. Across the eight fixed
maintenance cases, split-limb has the lowest complete observed wall total on
both runners; ARM64/x64 totals for that same strategy range from 2.8534 to
2.9532. These are different hosted VMs and times: four logical processors do
not establish equal physical cores, clock, isolation, energy or price. The
observation does not qualify hardware fairness, least-cost work or identity
exhaustion. Independent paired-artifact receipt:
`db2c4de84bbf6e767bc37613209bbef1fcd320047e747b9ea39a588967752d6e`.

The uncommitted execution-binding increment has five finite native FD controls
and seventeen related reader controls, with the original permission failure
retained. The reader now consumes the actual nested `phase.samples` owner and
rejects the audited numeric identity/index aliases; all 231 retained assertions
remain. This is not a real Python-three-FD to Rust bridge or a complete campaign.
The original clean-source fence rejects the current overlay, and a clean commit
alone still cannot pass the disabled v2 preparation gate. Review an explicit
finite preparation contract before that bridge; do not construct a successful
prepared record, enable full collection or substitute archive inodes for the
original held objects. The SQLite I/O boundary and all full acceptance remain open.

**Next I02 implementation boundary, still within PN1; design only.** The local
v2 evidence descriptor's fixed `native.sqlite`, `-wal` and `-shm` roster is not
the production r13 signed CPU/work-identity contract. Actual SQLite 3.46.0
initialization also writes a transient rollback journal. Keep that journal's
real name and the failed/incomplete v2 result: neither final-file inventory nor
changing journal mode to MEMORY/OFF closes its transient I/O boundary.

Review a fresh local I/O receipt namespace before implementation. The proposed
representation permits at most three simultaneously retained growing inodes per
Node, each at most 16 MiB, across the same seven Node roots and 336 MiB total.
This changes object/lifetime semantics; it is not a claim that old v2 passed.
Keep the complete 8 GiB evidence ceiling, every other bucket, parent/actor
AS and FSIZE limits, original 4 CPU/16 GiB scope, 2-second call and three
30-second pressure rounds. No metadata or unassigned-margin borrowing is
allowed. Linked-but-closed files, deleted-but-open files and outstanding mappings
still occupy their original inode slot and byte reservation. A fourth object,
oversize growth or uncertain lifetime fails and retains evidence. One observed
initialization fits this candidate slot model; that is not a bound for all SQL,
temp, spill, recovery or complete campaign paths.

The M15 Node owner must consume a safe connection factory for every persistent
writer, schema probe, read-only reopen and cold public reader. Its inputs are
held original root identities, fixed limits and the actual owning process;
its outputs are a controlled connection and bounded actual lifetime/usage
receipts. Keep `trnm-pon-node`'s `forbid(unsafe_code)`. Raw SQLite VFS callbacks
require a separately reviewed safe boundary with correct inventory ownership,
Cargo graph and lockfile changes; do not hide them in an unrelated crate or
weaken an existing safety lint. The existing locked SQLite version must be
checked, and every unsupported backend must reject explicitly.

Reserve before all allocation paths, including journal/temp opens, writes,
truncates, size hints, chunk rounding, shared-memory growth and mapping; an
`xWrite` wrapper alone is insufficient. Preserve FULL synchronization and
original SQL behavior. Account for default-Unix internal SHM operations and
deferred closes, C callback/name lifetimes, URI/ATTACH/extension escape paths,
all connection owners and panic/error paths. The full supplement's Node stores
are currently opened by its controller process; actor TCP/evidence writers
remain separate owners under the same whole-campaign ledger. A process-local
counter is not a cross-process disk quota. Logical file-length reservations
also do not establish allocated-block, filesystem-metadata or global host
quota bounds. Nonpreemptive filesystem calls retain their original deadlines
and terminal owners; Unknown cannot refund a reservation.

Implementation order is safe-boundary/graph review, complete VFS plus ordinary
Node/reader wiring, real native initialization/reopen/crash and cap-refusal
controls, then the legitimate prepared-source/three-FD caller chain and the
unchanged full capacity/service cohorts. Keep every original W1, identity,
depletion, confirmation and timing assertion. The new local representation
needs independent review and actual source-bound results; it grants no
execution permission, guard opening, work qualification or new roadmap.

**Finite native implementation increment, 2026-10-25; PN1 still open.** The
new M15 `trnm-sqlite-io-boundary` safe factory now has actual Linux controls in
the fresh `pn1-owned-sqlite-real-inode-v1` domain. The
[retained receipts and limitations](../../evidence/pon-native-io-pn1-20261025/README.md)
include both original Node failures, the read-only close initialization repair,
ten VFS controls with 89 exact receipt rows, and the final ordinary Node
writer/public-read/same-domain AuthV1 cold-readback control with 20 metadata
files and 27 complete healthy root receipts. The ordinary Node control retained its original SQL,
4 KiB pages, WAL/FULL, 256 signed transfers, two-second call deadlines, resource
limits and old assertions. This is an uncommitted component result, not a fresh
commit/merge qualification, a new W1 search or the full capacity campaign.

Implement the next connection at the actual Python/Rust held-directory boundary:
consume the original held directory capability and create the seven fresh roots
relative to it. Do not canonicalize `/proc/self/fd` into a physical path or
weaken the no-symlink ancestor walk. Bind every controller writer, read-only
probe and cold reopen to its original lease; stream complete lifetime and
terminal receipts into reserved existing buckets. Review the legitimate
three-FD caller and independent reader before enabling any full selector. The
frozen v2 filename descriptor remains historical; its guard stays closed.

Separately dispose of bundled SQLite 3.46.0's known
[WAL-reset defect](https://www.sqlite.org/wal.html#walreset) before general
multiple-writer persistence acceptance. Its official fix requires a reviewed
dependency/lock/graph and ABI-witness update, followed by actual native controls.
The current per-callback mutex and successful finite readback do not establish
that repair. No previous failure is attributed to WAL corruption without evidence.

**Source/evidence update, 2026-10-26; the same PN1/I02 gate stays open.**
The [dated evidence addendum](../../evidence/pon-native-io-pn1-20261026-addon/README.md)
keeps the preceding observations as historical source-bound results. On the
SQLite 3.46 overlay, held-directory native002 passed four real children,
43 metadata files and 18 receipt locations; original001 remains an overall
MemoryError/missing-final-receipts FAIL. The 8,192-byte database bucket label
defect remains recorded, with all bytes charged under the stricter provenance
cap. Original VFS004 then passed ten children/89 locations (86 healthy plus
three original expected SQLite 13 cap refusals); only its cap case uses 64 KiB
pages. Node005 passed 20 metadata/27 locations, the original two-second
Head/History limits, actual single join and same-lease cold AuthV1 readback.
Its earlier 6b4 preparation failure remains separate from actual 6b9 execution.
None of these finite observations generated a new W1 search.

The six-file original harness now connects private held-output authority and
the exact seven role leases to miner, receiver, verifier and cold reopen. Its
outer JSON writer reserves the first-pass byte count before actual second-pass
writes and keeps the first error/poisoned reservation without refund. Normal
compilation, strict-Clippy002, 13 finite units (11 retained plus two stateful
serialization cases) and final formatting passed on that old graph. Keep
strict-Clippy001's exit 101 and all 13 ignored selectors; ignored is not PASS.
The native libtest child PID/starttick was not separately serialized, so no
collector PID or earlier component child grants original three-FD caller,
whole-writer or strict-reader qualification. Two copies of its diagnostic
178,353,576-byte ELF (opt-level 3/debug 2/assertions and overflow checks enabled)
exceed the unchanged 192 MiB binary bucket. This measurement applies only to
that diagnostic ELF; the original full selector's actual `--release` ELF size
has not been measured. The next existing caller preparation must use its
original release profile (opt-level 3/debug 0/assertions and overflow checks
disabled/test true), then check exact profile and source binding. Keep the
original diagnostic bytes and budget evidence; do not strip/delete them,
refund charged copies, borrow margin or raise a limit to qualify a run.

A separate source-only admission pins all seven SQLite consumers to exact
rusqlite 0.39.0, sys 0.37.0/SQLite 3.51.3 and the fresh
`sqlite-3.51.3-normal-native-linux-layout-v2` fence, with a reviewed 155-node
resolved graph. This does not inherit the 3.46 normal-C witness, ELF or PASS.
The first fresh normal build actually failed with exit 101 after 28.262877 s;
its generated C witness artifacts are retained, not whole-build or independent
ABI qualification. After a narrow equivalent MAIN_DB API adaptation, attempt002
also failed with exit 101 after 4.054297 s. Both original failures, logs and
source-before/after pins remain. After the equivalent VFS-name API adaptation,
normal003 actually compiled with exit 0 after 6.614984 s. Its sealed normal-C
receipt binds the actual cfg/v2 fence, four defined witness globals, all 19
read-only layout values and a 19,130,200-byte VFS ELF (opt-level 0/debug 2).
An independent read-only C-object review confirms that compile gate. This is
normal compilation and static C readback, without native execution or runtime
ABI/control qualification. It does not close WAL-reset persistence acceptance,
runtime/release closure or the full graph's security review.

Continue the original PN1 order: actual new normal-C ABI/witness and unchanged
held-directory, ten-case VFS and ordinary Node controls; then complete outer
writer accounting, legitimate original three-FD execution and independent
strict-reader qualification; only then the frozen 4,097 complete identities
crossing the 4,096-entry paid boundary, fresh 24-actor pressure and original
public-service profiles. Keep every original proof, CPU, identity, depletion,
confirmation, two-second call, three 30-second pressure rounds and whole
8 GiB/resource assertion. Full guards stay false until those source-bound gates
actually pass. No work-hardness, Windows, ordinary three-round model,
release/loader/custody/repair or independent-WAN gate closes.
The original LAN setup3 is a retained FAIL after 6.586268785 hours; its seven
successful samples/14 cold hops and unknown remote terminal/1 GiB charge cannot
be relabelled as a completed or continuing 72-hour WAN run.

**Later controlled 3.51.3 increment, 2026-10-26; still PN1/I02.**
The [source-bound three-family result](../../evidence/pon-native-io-pn1-20261026-addon/sqlite3513-compat-three-finite.json)
retains the first real new-engine VFS FAIL: ten terminal children, three
WAL/SHM failures and 80/89 required receipts. Exact upstream 3.51.3 passes
`writeLock=2` as the SHM extension argument; its Unix backend treats that
nonzero value as extension. The controlled wrapper now admits only 0/1/2
and reserves the complete rounded length before either nonzero call, keeping
unknown-value rejection, the three-inode limit and every 16 MiB ceiling.
No optional parameter-trace native was executed. With that minimal source fix,
all original finite families actually passed and were independently read back:
VFS ten children/89 receipts, ordinary Node 20 metadata/27 receipts and held
four children/43 metadata/18 receipts. Original Node two-second calls, 256
transfers, retained proof, single join and same-lease cold readback remain.
Locked workspace/all-targets compilation and seven-consumer strict Clippy also
passed. These are local overlays, without new W1 search, original three-FD/full
writer/reader acceptance, full 4,097 identities, Windows, model efficacy,
complete release/custody/repair or independent WAN qualification. The held
collector's 8,192-byte database bucket-label defect remains explicit; all bytes
were charged under the stricter provenance bound. No old failure or limit is
removed, and the original release-profile binary/caller gate stays open.

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

**Scoped PQ/DAA component increment, 2026-10-27.** On the separately frozen
`5e797326b9c7635e43b93f97c65a309e51eafb46` integration base, extend the existing
native TPQ1 owner with exact schema/TEMP refusal, pinned-owner/tip checks and
same-transaction statement/sequence readback. QTX1 connects the existing actual
ML-DSA-65 verifier to shared M06 nonce/fee/transfer arithmetic as an explicit
fresh-network component preview; it adds no installed dispatch or durable account
migration. The source-bound quantum DAA experiment checks actual M02 integer
rules while making its assumed search-cost model and unproved fresh-work
alternative explicit. The [component contract](../security/PQ_NATIVE_TRANSFER_AND_QUANTUM_DAA_V1.md)
records boundaries and commands. Ordinary Node PQ admission, transport, governance,
final-use, physical rollback resistance, quantum work hardness and joint PN1/PN2
qualification remain open. No activation or former FAIL verdict changes.

The [scoped execution archive](../../evidence/pon-pq-native-daa-20261027/README.md)
records native code `99be553ea80bee137b0bcc3b67d8786348547256`, retaining upstream
`21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59` as a real merge parent. The original
local owner produced three RED regressions before hardening; the final unique
copied binaries passed M01 PQ 5 (210 pinned Wycheproof cases), M00 39 with two
original ignored tests, M06 78 with six original ignored tests, and local PQ
owner 12 with 723 other Node tests filtered. DAA/native parity passed seven
tests and 1,079 vectors; CI contract 95, negative source-integrity 34 and project
boundary 16 checks passed. Strict Clippy first refused two inherited constant
assertions; test-only commit `215fc89386a6375e8a2663774085c3a11b24e24e` preserves
both bounds as compile-time assertions. Workspace/all-target/all-feature strict
Clippy, formatting and that exact one-test copied-binary selector then passed,
without claiming a full suite at 215f. Clippy's 1,675 tracked non-evidence blobs
matched before/after; its original physical SQLite I/O UNQUALIFIED warning
remains. The atomic native wrapper still refused its post-source guard because
old self-generated hex files reappeared as untracked; sparse historical evidence
also prevents a full local repository guard claim. These failures are retained,
and the clean published-source gates remain required. No ignored/filtered test
is counted as executed. The complete W1 oracle ledger is static accounting only:
the conditional `r=0.25` DAA model is not an implemented reversible W1 circuit,
and quantum physical costs, fresh-work hardness and joint qualification stay open.

The [original native CI readback](../../evidence/pon-native-campaign-ci-20261027/README.md)
retains every predeclared campaign at exact heads `63ae5018` and `e9c4bb0d`:
FAIL/PASS/FAIL and FAIL/FAIL/FAIL. The five failing from-zero phases observed real
CPU-credit depletion after their last business round; all original predicates
remain unchanged and no passing run replaces a failure. These legacy regressions
explicitly used an eight-bit protected transport ticket, so they do not qualify
the separate zero-grinding pure-PoN profile. Full original reports, metadata and
logs remain hashed; directed integration success does not erase this gate failure.

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

The fixed initial V1 remains the original canonical positive-zero parent. Both
LoRA factors are zero, so copying it over PEFT initialization leaves both factor
gradients zero. The explicit [trainable working-copy preparation V2](../../scripts/llm_initial_trainable_setup_v2.py)
now captures the caller's seeded A, reads back the original parent through the
existing copy operation, then restores A while B stays positive zero. It rejects
negative-zero-only A, factor/base/buffer overlap, operator drift and compiled
module dispatch before mutation. Thirteen real small CPU Torch/PEFT controls
pass without skips; the original nine controls and all V1 assertions remain.
This is an unsigned preparation component only: the seed is caller-declared,
function preservation is algebraic B-zero reasoning, and its setup hash change
is neither learning nor useful gain. PN3's existing runtime owner must still
bind the explicit V2 source/recipe and actual predecessor readback into the
same training/evaluation budget and lineage, verify the full 135M model, and
complete ordinary installation and next-task readback. No CURRENT, selection,
FinalUse, reward or three-round gate is opened by these controls.

A later [single controlled V2 train](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/initial-v2-controlled-train-20261026.json)
on isolated Chain `a23b5f2d` loads the real 135M backbone and original canonical
parent, checks the distinct new-task contract, and completes ten optimizer steps
under the original 1,800-second / 16-GiB supervisor. Setup changes sixty A factors
with B still zero; subsequent training changes all 120 factors, separately from
setup. Original completion and exact wait4 succeed in 25.334008 seconds, with
the missing-RSS/terminal-reconciliation record preserved. The fourteen raw pins
include thirteen result-tree files and one separate launcher stream. This is
unsigned train-only evidence; V2 evaluation/readback, matched quality evidence,
selection, I10 installation and ordinary next-task/three-round closure remain
required. Setup changes and training loss do not count as useful gain.

A separate [candidate-only V2 observation](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/initial-v2-candidate-observation-20261026.json)
on isolated Chain `0dcf8001` then loads that actual `a23b5f2d` trained 135M
candidate, reads back the original parent and all 120 candidate factors, and
executes eight tasks / sixty-four real forwards. The actual derived contract
`c9b06f9a` stays distinct from parent `2bb480a2`; no parent or task registration
is silently rewritten. Its original 600-second / eight-GiB supervisor reports
success and exact wait4 in 8.854378 seconds, with all seven stages and the
original missing-RSS reconciliation retained. This unsigned observer is a
separate explicit route: the parent-step V2 evaluate/readback dispatcher stays
closed. Outputs are engineering observations, not quality gain, FinalUse,
selection, I10 installation, CURRENT, ordinary next-task or three-round success.
The fixed V1 zero-parent profile and prior strict same-plan refusals remain.

A separate [new-engine I09 run002](../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/i09-eleven-material-sqlite3513-controlled-20261026.json)
on Chain `4c8c2ee7` / Hepta `8d25c5d7` uses fresh SQLite 3.51.3 databases, fetches
all eleven objects in 4.257683 seconds within the original 35 seconds, and passes
the original signed native case in 10.357 seconds. Three authorizer bindings
yield two durable nonce claims. The controller still fails exit1 at unavailable
I10 selected installation. Run001 retains its original `915f933c` / `da4a920`
sources; neither observation grants CURRENT, ordinary, WAN or three-round
acceptance, and this finite run does not qualify full PN1 or the SDK.

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

The original release-profile no-run build now actually passes (2026-10-26T03:18Z): exit 0 in 268.031 seconds, exact opt-level 3/debug 0/assertions false/overflow checks false/test true, and an actual 10,134,904-byte ELF. Its two-copy arithmetic is 20,269,808 bytes, within the unchanged 192 MiB bucket. The root independently rechecked the ELF, both original streams, the actual durable terminal and all 22 before/after source pins; no monitor violation or owner error occurred. The separately documented 178,353,576-byte diagnostic ELF and every failed build remain historical evidence. This new result removes only the release-build/profile/size preparation blocker: no lawful prepared bundle or execution copy was created, and the original three-FD caller, whole writer, strict reader and full 4,097-identity acceptance remain unqualified. No full guard, deadline, assertion or budget changed. See the [original release-build compact receipt](../../evidence/pon-native-io-pn1-20261026-addon/sqlite3513-original-release-build.json).


### PN1 / I02: public finite three-FD preparation and readback candidate

The existing PN1/I02 sequence gains a separately named finite component entry.
It does not enable or change the original V1/V2 full route, Plan, assertions,
deadlines, Windows groups, pair steps or resource and evidence limits. The new
profile and prepared/inventory/claim/dispatch/execution/readback domains use
`pn1-native-io-three-fd-component-v1` and the corresponding
`pon-native-io-three-fd-component-...-v1` names.

| Interface | Contract and next owner |
| --- | --- |
| [Public collector](../../scripts/run_pon_native_io_component.py) `prepare` | On the ROG-integrated clean committed source, require exact head/tree, original Nice 10 / four CPU / 16 GiB, a fresh disjoint held build target and output. Actually run the locked offline original release no-run build, capture the compiled executable through the same held target FD, and seal original streams, source/resources, origin identity and inventory. No supplied success flag or old ELF can substitute. |
| Same collector `execute` | Consume that real preparation once. Bind its original parent/root/leaf identity and stable claim key, retain both physical binary copies under the original 192 MiB aggregate, and pass exactly executable/output/source-cwd FDs. Run the new exact ignored selector through the existing native-I/O `Plan::control()` path; record actual parent PID/birth/wait and original descendant FD/terminal evidence. |
| [Independent component reader](../../scripts/ci/check_pon_native_io_component.py) | Require pinned preparation and execution inventories plus the retained original claim; reject unknown/missing/partial/cap/error outcomes. Reconstruct all retained complete W1 attempts, actual calls/CPU balances, two actors and their FD bindings, three actually used healthy closed roots and private-copy SQLite cold history. It does not open producer databases for repair. |
| [Counterexamples](../../scripts/ci/test_pon_native_io_component.py) | Retain real rename/copy/replacement, unreadable-tree, inherited-input, actual birth/wait, failed-start pipe cleanup, terminal-write and held-artifact controls. Synthetic byte fixtures only exercise capture; they are never executed or used as public preparation. |

Implementation order remains PN1/I02: ROG reviews and commits the complete
collector/selector/reader/tests delta on the existing branch, then a caller
actually invokes public `prepare`, pins its returned documents, invokes
`execute` once, and runs the independent reader. Only those actual results can
close this finite mechanism prerequisite. An isolated compilation, a passed
mechanism unit test or an internally consistent fabricated bundle cannot do so.
The trusted local operator, chosen toolchain and pinned input receipts remain
explicit assumptions; hashes and local process records are not host attestation.

Acceptance keeps the original control Plan: two actors, one prefix plus two
pressure calls each, prefix 30 seconds, pressure two seconds, call two seconds,
readiness 180 seconds and cleanup five seconds. The outer finite collector is
fixed at 180 seconds and its build child at 1,200 seconds. The original AS/FSIZE,
three physical-domain eight-GiB ledger, all bucket limits, synchronization and
first-error accounting remain. The separate six-GiB build target with 512 MiB
reserve is conservatively monitored, not a physical block quota or instantaneous
peak proof. Directory replacement or unknown scans fail; limits are not raised
and charged partials are not refunded.

The finite reader must prove two prefix and six final unique paid work identities,
not a 4,096-entry exhaustion result. It actually uses roles 0/5/6: miner, fresh
receiver and independent client. Seven registrations are not seven exercised
Nodes. All full-writer/full-caller/full-reader/full-4,097, model, Windows, WAN and
merge qualifications remain false. The next original acceptance still requires
the complete whole writer, original caller and strict reader, followed by the
unchanged 4,096 plus fresh sustained 24-actor workload.

At this source admission, twelve finite mechanism counterexamples pass locally
under a repository-portable loader. The Rust selector format check passes.
Public prepare/execute/readback, compilation of the added selector on a clean
committed source and exact-head required CI are **not yet run or qualified**.
The original warning-bearing attempt and all earlier failures remain retained.
Nice-19 mechanism controls do not qualify the Nice-10 public resource contract.


2026-10-26 PN1/I02 review follow-up (V15 → V17; original acceptance unchanged):
ROG review found that the new component owner's stream loops overwrote the step label;
a real child/writer counterexample recorded the erroneous member name
`build.stderr.log.step.json` in the retained RED log and failed the required
`build.step.json` lookup. Its temporary fixture files were not preserved. Keep the step label separate from
stream member names for both build and component execution. An independent review
also found that the component reader called the original full-reader limit validator,
although the actual native installer honestly writes `full_ledger_implemented=false`.
Use a separate finite-component validator that requires that exact false value and
preserves every original schema, role, typed PID, cgroup, address-space and file-size
assertion. Do not mutate receipts, set a full flag true, weaken the full reader, or
claim the false full-ledger field as full qualification. The unchanged twelve mechanism
cases plus two new counterexamples passed after correction; the original RED and all
prior receipts remain retained. These Nice19/AS1GiB mechanism observations are not
public Nice10 preparation/execution/readback, full-writer/strict-reader, 4096+fresh,
Windows, model-upgrade, WAN, or merge acceptance. A clean committed corrected source
and its actual public preparation → execution → independent readback are still required.


2026-10-26 PN1/I02 complete-review follow-up (V18; original acceptance unchanged):
The revised ROG V15 ACK identifies four findings. V17 addressed R01 (step label)
and R04 (finite/full resource discriminator); its local resource-fix label must
not be confused with the ACK's R02. V18 addresses that R02 by retaining bounded
failure context when real stream or step publication fails after a child has
terminated: original child error, actual return code, PID/birth/parent/wait record,
observed stream lengths/hashes and the publication error remain distinct. Error
prefixes are bounded by their ASCII JSON representation, with explicit truncation.
The original terminal reservation, first writer failure and partial charges remain;
no physical ENOSPC guarantee is added. Claim termination uses an actual step or the
same component/profile failure context only after the original owner validator
accepts the recorded terminal; missing, aliased or unknown ownership stays unknown,
and native success and full qualification are never promoted by a publication error.
Actual read-only reserved descriptors produced kernel EBADF in the real ComponentIO
write path after a nonzero child and a timed-out/reaped child. Both original RED
observations and corrected finite passes remain retained; these are controlled
storage faults, not a real disk-full or public claim execution qualification.

ACK R03 restores the original finite actor schema/worker/source/tree/binary,
setup_calls=1/prepared-generic producer and typed metadata checks, and the original
completion-work domain/capacity/epoch/counter validation before finite 0/2/6 checks.
A separate test module serializes and rehashes the same 61 synthetic fixtures;
its original 60 negative assertions failed before correction and are rejected after
correction. Its positive fixture reaches only the unrelated FD replay sentinel:
these are predicate controls, not native, complete-bundle or signed authenticity proof.
The combined four-module check passed nineteen mechanism/predicate tests with all
fourteen preceding test bodies unchanged. Nice19/AS1GiB diagnostics, rehashed
fixtures and retained failure context do not qualify public Nice10 preparation,
execution and readback, whole writer/strict reader, seven actual roots, the original
4096+fresh workload, Windows, three model rounds, independent WAN, or merge readiness.
A clean committed corrected source and all original required executions remain due.


2026-10-26 PN1/I02 first real public preparation failure and bounded monitor correction (V19):
The first actual clean-source public prepare on ec0acdff5717b8f584b26f30f1162bd9bf1cc888
(tree 49de9450a7738b15f3dc63b808f957ce49804df2) failed. The real Cargo child
PID 1404396 / birth 8179665 / parent 1379349 was reaped with wait -9 after
62.971600613 seconds; the complete owner used 88.91997036199609 seconds.
The original 1200-second build bound did not expire. Actual source and Nice10,
400% CPU, 16GiB and four-CPU observations were retained. No prepared document,
execution or independent readback was produced. Original stdout/stderr, step and
terminal records remain failures. The sender and cause of SIGKILL are UNKNOWN:
normal compiler-progress logs and the limited journal/kernel lookup do not prove
or exclude OOM, an external stop, or a monitor stop.

An independent controlled reproduction against immutable ec0 source found that
real unlink and rmdir between enumeration and stat/descent abort the original
monitor with ENOENT; the same watch fault kills a real owned child. Those three
original RED observations establish a defect, not the cause of the earlier build.
The correction restarts the entire held-tree scan only for internal ENOENT, under
the same single five-second deadline and cumulative 200,000-entry bound, retaining
partial observed logical peaks. It does not skip a disappeared entry and accept
an incomplete scan. Missing or replaced top roots, permission errors, symlinks,
FIFOs, other unknown objects, persistent churn and cap overruns remain refusals.
The original 6GiB target / 512MiB reserve and watch interval are unchanged.

The monitor retains its first bounded typed error, observed retries, actual owned
child wait and kill attempts alongside the original first writer error. A later
NONZERO or terminal-publication refusal cannot promote success or erase these
observations. The mandatory prepared monitor record uses fresh stored schema
`pon-native-io-three-fd-component-prepared-v2`; build-specific failure diagnostics
use `pon-native-io-component-owned-build-step-failure-v2`. The profile, claim domain,
original execution failure schema, selector, native/full acceptance and all caps
remain unchanged. Logical sampling is not a physical or instantaneous quota.
New tests exercise actual filesystem changes and owned child termination; they
cannot qualify Cargo preparation, one-shot execution, complete-bundle readback,
full-writer/strict-reader, seven roots, 4096+fresh, Windows or model/WAN acceptance.
A new clean committed source and the actual public prepare → execute → independent
readback remain required. Any new-source attempt must retain the first failed
owner's spent budget; no unchanged-head retry, fake prepared record, old binary,
fresh budget reset or discarded failed target is allowed. Full guards and merge
readiness remain false, and the existing PN0–PN6 acceptance stays in force.

On the fixed V19 source, all seven added controls passed in 6.050 seconds.
The final combined five-module run passed all twenty-six tests in 6.578 seconds
(owner 7.094219090 seconds); the two original test files and all original nineteen
test bodies remained byte-for-byte unchanged. All five actual ec0 helper sources
and every current candidate Python pin were checked before and after. These are
bounded Nice19/AS1GiB controls, not a successful public build or any full acceptance.


### PN3 / I09–I10 cold release contract clarification — 2026-10-26 (OPEN)

This refines the existing PN3/I09–I10 and PN5 implementation order. It creates no
new roadmap, budget, authority or passing gate. The pinned cold-release audit
below supersedes any inference that unlike capacity measurements, by themselves,
prove a universal runtime contradiction. All historical failed runs remain failed.

| Original observation or cap | Exact scope retained | Required accounting |
| --- | --- | --- |
| 922,881,591 B installed-runtime observation | Sum of existing RECORD pathname lengths in the old 29-distribution venv; not a complete interpreter root, wheel archive size, physical peak or new admission | Complete the missing dependency closure and meter the actual retained representation; do not grant fit from this sum |
| 432,269,632 B `libtorch_cpu.so` | Already included in that runtime sum | Do not add it a second time or treat it as an admitted I09 base role |
| 512 MiB Cell cache | Original logical chunk/manifest accounting and separate main-DB image bound, both enforced; WAL/SHM are not free | Each cache must satisfy both constraints; simultaneously retained caches and destinations also enter the host total |
| 300 MiB fixed I09 base role | Per-file bound for the unchanged eight base roles; adapter files remain 2MiB each and sidecar 64KiB | Reject an extra or oversized role under that old version; do not redefine it as a general runtime/VM limit or silently enlarge it |
| 2 GiB per original LAN data-host root | Original cooperative controlled-root forecast/accounting, including both slots, cache DB/WAL/SHM, binaries, output and metadata | Count every overlapping staging/install/archive/old-version/held object; metadata64MiB remains inside the total. This is not a filesystem hardquota |
| Pocket4 provider-0133 UNKNOWN 1GiB | Original NETWORK response reservation | Keep the charge and original failed outcome. Do not subtract it as measured disk use, refund it from SSH255/path absence, restart it or probe a replacement |

The original frozen LAN forecast is 1,964,390,944B; its 183,092,704B margin cannot
admit another 269,060,552B weight file. That historical additional-weight NO_GO is
preserved. It is neither a current free-space measurement nor proof that the old
run exceeded its limit. A new cold root cannot borrow or reset that frozen plan.
Single-cache capacity also does not establish impossibility of bounded chunk
consumption into an independently admitted destination within the same host root.
Every overlapping representation still counts; an area called “outside cache” is
not an accounting exemption. No new root or complete cold run has been admitted.

Implement these interfaces through the existing owners, in this dependency order:

1. **PN3/I09 release declaration → runtime identity.** Add a reviewed, explicitly
   versioned `runtime_root` contract alongside the existing release/profile owner.
   The interface must bind platform/ABI and marker/extras selection, interpreter
   and stdlib/base-image identity, actual original wheel bytes/lengths/provenance,
   installed-file hashes/modes, native/system-loader dependency closure and the
   import/`.pth`/pyc/generated-file policy. Match the exact source and inference
   arithmetic profile. A requirements file or six project-source hashes alone
   cannot satisfy this contract. New stored/signed contracts need fresh namespaces;
   the old eleven-role version and its digests continue to reject extra roles.
2. **M09 fetch/materialize → admitted private namespace.** Consume that manifest
   and existing model/adapter materials through bounded verified chunks. Return
   only an owner-constructed runtime/material capability tied to the actual held
   namespace and release identity, rather than a caller-supplied ready flag or
   unchecked path. Connect it to the same owner's cache/destination/DB/WAL/SHM,
   extraction scratch, archive, old/new version, metadata and UNKNOWN ledger.
   Reserve the complete peak before effects, then charge actual overlap. Retirement
   requires proven release of readers/held handles and custody responsibility;
   a hash, unlink or expired connection alone cannot refund retained/unknown work.
3. **Existing Hepta loader → original execution authority.** Bind the admitted root
   to `SmolLmNeuralReadConfigV1`, execution-profile identity and the namespace used
   by the actual interpreter, imports and HF material opens. Preserve existing
   offline/local-files-only/trust-remote-code refusal and reject unknown ambient
   site/user/`.pth`/library-path or online fallback. Continue original ResourceGrant,
   CURRENT/selector window, FinalUse, parameter, Ready and forward checks. Verified
   Cell bytes do not grant installation, CURRENT, a new key or execution authority.
   A completed forward is separate from shutdown and actual OS-child terminal.
4. **PN3/I10 selection/artifact/TaskFlow → ordinary next-task readback.** Use the
   original resource/effect owners and installation path; join actual evaluated
   parent identity, cross-node download, authorization, local selected generation
   and the next ordinary task's actual loaded bytes. Keep revocation, reorg, denial,
   late cancellation and terminal/funding reconciliation. Report mechanical closure
   and measured benefit separately; a no-benefit candidate remains rejected.
   Three denials cannot replace the required three successful installation/readback
   rounds, and three successful transfers cannot replace them either.
5. **PN5 custody/repair → original WAN acceptance.** After the complete loader and
   release close, retain the existing three independent complete replicas,
   renewal/repair and version-retention requirements. The union of node files is
   useful only while all referenced versions have the required custody and a
   recoverable manifest. Discovery or a signed advertisement does not prove bytes,
   persistence or repair. Keep the preregistered at-least-72-hour experiment across
   three independent administrators/failure domains, every original fault/load
   cohort, confirmed goodput, cold loading, repair and recovery objectives.
   Same-administrator LAN and loopback observations cannot satisfy this WAN gate.

Acceptance remains fail-closed and evidence-based. A fresh destination must have no
preinstalled model/runtime cache; offline acquisition, installation and first actual
forward must use only the declared release. Capture exact source/runtime/parent and
manifest identities, actual bytes/time/overlapping peak, custody and actual child
terminal. Missing wheel/library, incomplete dependency, replaced ancestor, cache
retirement while still needed, full disk, permission failure, crash and unknown
termination must refuse without a new dispatch, hidden allowance or early refund.
Keep all applicable original fetch/call/owner/cleanup/resource bounds. The old
35-second eleven-material cohort retains its original scope; complete cold success
cannot exclude runtime acquisition or inherit the preinstalled-environment PASS.
If the complete work has no admitted budget under the original envelope, keep
NO_GO rather than inventing a timer, resetting phases or omitting dependencies.

Current proof remains partial: original SQLite3.51.3 I09 run002 fetched eleven
materials (272,190,131payload B /269chunks) in4.257682651s and its original signed
native load/query/terminal-unload case passed in10.357s using the existing runtime.
The controller still failed (exit1,180.167288273s) at I10 selected installation
UNAVAILABLE. Its native receipt stays UNVERIFIED; full cold release, ordinary
installation/next task, three model rounds/benefit, Windows and WAN remain OPEN.
The 71a selected-initial API is not registered into an ordinary initial Agentd route
in the reviewed source, and its three real-model tests remain ignored/NOT_RUN.
The separate two-field fixture source patch is not compiler or model qualification.

Pinned audit: [cold-release evidence](../../evidence/pon-upgrade-implementation-20261018/native-rounds/cold-release-contract-20261026/REPORT.md). Audit receipt SHA256
`4e6cdcf05bdd58b897c529de67af03ae1dc8453f11953956ab3dcfe7c378022b`;
report SHA256 `8ca0b29590fa53c0a3e9ae94ea30915fdd9e0b409c7b7a305c28bf47d221bcd6`.
This contract and its interfaces are pending implementation/native verification.
`task_complete=false`, `merge_ready=false`; PN0–PN6 and every original acceptance
criterion, limit and failure observation remain in force.

Retained V19 [original failed preparation and integrated bounded controls](../../evidence/pon-native-io-pn1-20261026-v19/README.md)
include the additional source-check diagnostic timeouts; none closes public or full qualification.

### PN1 / I02 real-Header fixed-dispatcher 64-reuse candidate (OPEN)

The opt-in component-v2 source adds signed controlled development registration,
ordinary Node parent/template acquisition, one pre-Header fixed dispatcher setup,
and 64 disjoint nonce-window sibling searches under that same parent. Every miss
and winner carries a complete work proof; ordinary admission and cold packet/state
readback are followed by independent Python attempt reconstruction. This is not
64 successive parents, a public paid-identity campaign, an all-13-kernel minimum,
or a hardware-fairness or throughput result. PNH1/PNW1 and existing profiles stay
unchanged. The original two-second parent RPC and120-second owner/oracle/seal
bounds remain; incomplete EOF or remaining descendants remain UNKNOWN.

Original real RED, revision002's remaining finally error path and Clippy101 are
retained. Revision003 preserves first_error across event-file flush/fsync/close
refusal and removes two redundant Result wrappers. Strict release Clippy passed
for the exact Rust slice, while the final Python finally correction has only its
injected partial control; no whole-source/native64 execution is claimed.
The original600-second W1 build envelope is retained; conservative maxima for the
two diagnostics are300+20=320 seconds, with no reset of historical failures.
[Source, partial controls and diagnostic history](../../evidence/pon-w1-real-header-64reuse-source-20261026/README.md)
remain below the existing PN1 acceptance. Source-to-binary/held caller/whole writer
and reader, minimum cost, hardware and original4096+fresh work remain OPEN.

### PN1 / I02 actual held-target ABI refusal and v3 admission (OPEN)

Original be785 Cargo0 captured a release ELF but emitted no SQLite C witness cfg
or links and an explicit UNQUALIFIED_REASON. The corrected absolute-Nice10
launcher then reached the original native selector and failed PRIVATE_ABI_UNSUPPORTED.
Its claim is consumed; the earlier capture-only admission inference is corrected,
and all original failure/partial/terminal bytes remain. No old prepared/claim
replay, numeric limit change, generic symlink admission or full-guard promotion
is permitted. The Linux v3 path source retains an exact private inherited target
FD and each ancestor; original/dup/canonical identity, compiler/toolchain and
three-required-plus-one-optional loader allowlists stay mandatory.

Prepared-v3 requires and replays the actual unique correct-package Cargo event,
normal witness cfg, exact v3 fence/amalgamation SHA, static witness link and
same held-target OUT_DIR. Cargo success alone is insufficient. Final32 Python
controls (old26 unchanged) and13 real tmpfs path controls passed; actual new
normal-C/nm/public prepare/execute/independent reader remain due. Conservative
400 prior owner +60 diagnostics +730 next owner stays1190 under the original
1200 build limit; failure history and original180-second execution contract stay.
[Original failures, correction and bounded controls](../../evidence/pon-native-io-pn1-20261026-v20/README.md)
are mechanism/source evidence only; full W1/Windows/model/WAN/merge gates remain OPEN.

### PN1/I02 — original399 native SQLite13 and checkpoint-policy candidate (2026-10-26)

The [retained original run and forensic evidence](../../evidence/pon-native-io-pn1-20261026-v21/README.md) records real normal-C v3 support followed by a nativeFAIL101: the fourth unchanged256-transfer seed exhausted the original1024-event ledger. Original source, assertion, failure, single consumed claim and all limits remain. A native-IO writer-only `wal_autocheckpoint=64` policy is a candidate for real WAL-offset reuse, with strict readback; it changes no schema, page geometry, fixture, caller, lifetime or evidence capacity. PASSIVE is not a hard WAL bound. The conditional default-hook checkpoint-error/lease-health propagation risk remains open. Acceptance requires the original fresh-claim native terminal and unchanged reader to succeed within all original budgets; no global W1 cost, full4097, Windows, three-round model, release or WAN result follows from source review or pragma configuration.

### PN1/I02 — explicit W1 lifecycle correction after retained v2 RED (2026-10-26)

The [original real v2 run and source](../../evidence/pon-w1-real-header-64reuse-v2-original-20261026/README.md) remainFAIL:64 same-parent admissions/126trials completed, but ordinarycoldrecover correctly chose heavier durable work and violated the auditfixture frozen-parent expectation. ProductionSTATE_RECOVERY and its original tests remain authoritative. The explicitv3 component keeps the originalhotparent/gen1 and fullcoldtuple equality assertions, adds ordinaryhotrecover with independently computedwork/height/id selection, then checks all64 coldpackets/states. Only receipt domains advance; no originalRPC2s/whole120/bytes/AS/FS policy changes. Exact-source v3 build/native/oracle are NOT_RUN; it cannot turn oldv2 red into PASS or qualify currentpair/full4097/hardware/globalminimum.


### PN1 shared authenticated snapshot source successor (2026-10-26, NOT QUALIFIED)

The existing I02/PN1 capacity item now has a reviewed source successor in `store/shared_snapshot.rs`: a fresh held-native-IO physical schema stores the complete working partition with an actual persistent account-root record. Public readers materialize every account and retain full State/root/history/continuity checks. The original independent receipt-reader and harness scripts, 4 KiB/FULL/WAL policy, 64-row public limit, original tests and all resource/time caps remain fixed. The private 65-row allowance is only the same-transaction insert-before-prune verification. Ordinary JSON and deployed/old formats are not migrated.

[Retained source revisions and independent findings](../../evidence/pon-native-io-pn1-20261026-v22-shared-layout-source/README.md) distinguish original failures, source admission and execution. Revision004 fixes the prior unknown/genesis-key and ATTACH-control findings; source checks pass, but compilation, strict Clippy and original native/reader performance remain NOT_RUN. Known-but-pruned key relocation, unselected-payload binding, arbitrary COMMIT/BEGIN continuity and post-COMMIT health semantics remain security OPEN. A component PASS cannot close these gates.

Conservative preparation charge is 1,035.743 of the original 1,200 seconds, leaving 164.257, based on actual durable terminal rather than the earlier pre-publication snapshot. The existing preparation requires a fresh target and fixes its child timeout at 1,200; wrapping that collector in a shorter external cutoff is not a valid deadline chain. No expired-window reset, reused/prewarmed target, new profile, larger allowance or substituted fixture is authorized by this source change. Keep original native preparation NOT_RUN until the ownership/deadline path is valid; full4097 and all PN0-PN6 acceptance remain open, `merge_ready=false`.


### PN0 bounded Worker procfs cleanup race (2026-10-26, LOCAL VERIFIED)

[Retained original CI and local repair](../../evidence/pon-worker-process-cleanup-esrch-20261026/README.md) bind runtime job 121574328486 to source53fb/actualpreviewbd609. The original concurrent-groups test failed with ESRCH (370 passed, 1 failed, zero skipped). A real live-open proc descriptor returns std::io ESRCH after its owned child is actually reaped; the new regression first failed before the production change. The narrow fix restarts a complete scan for that typed procfs race within the same deadline, while raw Rustix wait/pidfd, permissions and identity errors remain refusals. ESRCH never proves terminality or ownership.

All original 371 tests, 8 MiB output, 1-second cleanup and 3-second call assertions remain; 373 local tests now pass with zero skips, and strict Clippy passes. Original logs, official ZIPs and the initial new-control compilation failure are retained. This is local Worker verification only: exact historical syscall causality and new published-head/actual-merge CI are unproven; earlier qualification timeout, native storage, Windows, model and WAN gates remain open. Keep merge_ready=false and the existing PN0-PN6 acceptance criteria.


### PN1 retained snapshot binding successor (2026-10-26, SOURCE ONLY)

The existing shared-layout capacity/security item now streams every retained canonical record through SQL-key, embedded-block, context/native-record and complete working-partition root/count binding. The known-but-pruned-key relocation counterexample is rejected on the optional-None path after progress, as well as the final public cache/empty-read-set/no-anchor windows. The actual selected State still requires all original account materialization, COW, root, continuity and history checks. Snapshot format/signed domains, public64/private pending65 bounds and all original tests/assertions remain unchanged.

[Retained revision005 and exact independent review](../../evidence/pon-native-io-pn1-20261026-v23-retained-binding-source/README.md) distinguish this codec-binding improvement from authentication of all unread states: coordinated resealed unread records, arbitrary transaction continuity, post-COMMIT health, independent decoder/migration and original latency/resource/native execution remain OPEN. Preflight/format/diff and26-member/155-node locked graph pass; no new compiler/test/native qualification is claimed. The original preparation debt and limits remain, with no new budget or restarted attempt. Keep fullguard/full4097/merge_ready=false and the existing PN0-PN6 acceptance unchanged.


#### PN1 R6 executed transaction scope and W1 cost audit — 2026-10-26 (SOURCE ONLY / OPEN)

[Executed transaction-scope source and retained review](../../evidence/pon-native-io-pn1-20261026-v24-transaction-scope-source/README.md) refines the existing R5 storage boundary without a new roadmap or changed stored/signed namespace. `TransactionScope::capture(&Connection)` produces an opaque connection-borrowed observer; `unchanged()` requires the same private SQLite clientdata owner, live executed tracer and unchanged explicit-control epoch. Actual STMT execution covers cached/read-only COMMIT/BEGIN/END/ROLLBACK/SAVEPOINT/RELEASE. Held factories install the observer; borrowed/owned snapshot and Some/None/final-read paths carry the scope. No caller Boolean, epoch reset or cross-connection substitution is accepted. COMMIT effects are not undone; implicit engine rollback and unread resealing remain OPEN.

All 477 original boundary pins, 467 original Rust test files, the 79,958-byte inline store test tail, existing R5 assertions, Snapshot format, settings and limits remain preserved. Fourteen new controls are uncompiled/unexecuted. Preflight, format/parser, locked 26-member/155-node metadata and diff checks pass only at source level. Original fresh prepare/native/caller/three-FD/whole-writer/strict-reader/full4097 gates remain required; the original 1,200 s build budget has only 164.257 s left, without a safe admitted hierarchy. No deadline reset, target reuse, fake prepared result or production activation is permitted.

[W1 minimum-known-cost source audit](../../evidence/pon-w1-minimum-cost-source-audit-20261026/README.md) adds winning-only proof assembly, fixed 318-byte header-prefix reuse, and unregistered-zero-task completed-W1 scheduling promotion before task refusal to the existing PN1 adversarial measurement set. Mandatory transcript work remains; local promotion is not block admission or a proved capacity attack. The historical399 one-setup/126-attempt/64-admission registered-zero sample and its cold failure stay intact. These are unmeasured source findings, not lowest-cost or hardware-fairness certificates. Preserve the original 4096 paid identities plus fresh4097 sustained24-actor/three30-second/original2-second confirmation acceptance. `task_complete=false`, `merge_ready=false`, **NO_GO**.


PN1 R6 first actual development typecheck retained an E0282 failure for the SQLite observer's raw pointer. [Original failure and narrow correction](../../evidence/pon-native-io-pn1-20261026-v25-pointer-typecheck-red/README.md) explicitly bind that pointer to the already required private `Observer` type. No original assertion, schema, authority or limit changes. The14 new controls were not fully compiled or executed in that failed attempt. Any corrected development check stays inside its original inherited560/620s window without refund; this is separate from public preparation, the unchanged1200s/164.257s balance and all native/release/3FD/whole-writer/strict-reader/full4097 gates. **NO_GO**.


#### PN1 retained hosted 3-hour runtime qualification failure — 2026-10-26 (OPEN)

[Original source-bound failure and complete evidence](../../evidence/pon-runtime-head-3h-timeout-20261026/README.md)
retain the first actual head-runtime 3-hour qualification observation in run
`40310512277`, attempt1, job`121574328675`, on source
`53fb654b532ed8e737e0dea635a31dce3b73b3cc` / tree
`d82ba0c7bbaea04200f11d38f6e9c4dccac81f78`. It did not qualify:
the official conclusion is `cancelled`, with the explicit maximum-execution
annotation `3h0m0s`. The release 65,537-account growth test ran
4,293.980079 seconds before cancellation; its last observed state was
61,444 accounts / height240. Completion, cold reopen and subsequent growth-v2
and account-verification-cost execution remain unproved.

The complete original log, annotation, exact source/attempt, two official ZIPs
and partial-transfer history are preserved with member hashes. This is not the
earlier 0.5-second timeout or procfs ESRCH finding, and establishes no performance
cause, minimum-cost or hardware claim. No rerun or increased limit was used.
The original 3-hour maximum, assertions and resources remain fixed; R4/R5/R6
and all original PN1 native/release/three-FD/whole-writer/strict-reader/full4097
gates remain unqualified. `task_complete=false`, `merge_ready=false`, **NO_GO**.

#### PN1/I02 original-writer public IO handoff — 2026-10-27 (SOURCE ONLY / OPEN)

The existing [outer writer](../../scripts/pon_identity_outer_owner.py) now contains
the mechanically moved original `require`, `held_directory`, `publish_new`,
`json_chunks` and `V2Writer` implementations. The existing collectors import and
re-export that implementation. `CollectorIO(output, 'v2', writer=owner)` and
`ComponentIO(output, writer=owner)` retain the exact live owner, held directory,
version, used bytes and reservations. The public identity
`prepare(args, output, io=io)` accepts that same IO; its ordinary CLI remains
unchanged. Component `prepare(args, io)` and the original claim, execution,
inventory and error paths are preserved.

The required startup order remains: independently pin the bootstrap owner;
construct the original writer; reserve capsule and record costs; retain the
approved capsule in the original preparation; verify and load P/T; attach the
same live writer to the collector; then use the existing public prepare and
readback paths. A capsule loader must preserve the same verified owner module
and class identity across this handoff. The trusted P0/T loader, actual capsule,
record emission and all eleven admission cutpoints are still unimplemented.
This source refactor grants no prepared, claim, installation or native authority.

[Preserved raw results and correction](../../evidence/pon-original-writer-handoff-20261027/receipt.json)
record the finite validation as **FAIL_INCOMPLETE**. The original-source phase
failed during import because its exported baseline lacked
`config/pon/ledger-v1.json`: zero tests ran, so its three intended counterexamples
remain NOT_RUN. Two old mock receivers genuinely failed after implementation
movement; only their receivers were migrated to the actual publisher. The
candidate then passed nineteen finite controls, comprising nine new and ten
original cases. All eighty-nine original test names and assertion ASTs remain.
The original controller's zero exit and incomplete success accounting are
retained alongside the explicit correction. The single 90-second ceiling,
original 164.257-second remaining preparation balance and native gates are not
reset or reclassified.

The original source-inventory generator was actually run on the integrated
source, followed by its unchanged `--check` and pinned Rust formatter check.
Its observed 1,061 entries include ten previously missing Rust paths; this count
is an observation, not a new limit or native result. New script bytes require
new committed-source observations. Existing stale blob guards still require
reviewed source bindings and the original eight-lane execution.

The preceding published Chain source `bd81849bb47b10e912cfea84f7532ccc1175e4ee`
and its actual PR preview `985dd37f4dc6f1859b57ffcaed8f0cd75da3a032` separately
passed the original release 65,537-account/cold-reopen test, in jobs
`121824408173` and `121824408381`, within the unchanged 10,800-second job limit.
That complete-State reference result leaves the historical `53fb` failure
intact. It does not qualify the later local root-reuse optimization, bounded
witnesses, paid 4,096/fresh-4,097 W1 campaign or full native IO boundary.
The existing PN0–PN6 exits remain **NO_GO**.

The two stale workflow blob guards were subsequently reviewed against their
actual old and current Git objects and synchronised only to those exact source
identities. The [material review and preserved diffs](../../evidence/pon-source-binding-material-review-20261027/receipt.json)
record the existing full-graph account materialisation and versioned shared
snapshot, read-scope, final-read and lease-health changes. The 64-page WAL
checkpoint policy applies to every opening with native IO, including openings
outside the shared layout; it does not guarantee physical WAL size. All twenty
guards, eight original lanes, assertions and resource limits remain. Source
identity agreement grants no SQL, C ABI, layout, two-second service or native
qualification; the original lane executions and fullT/Layout003 remain open.


### 2026-10-27: pinned public model inputs for local P1 execution

The pure-PoN continuation uses exact source `5e797326b9c7635e43b93f97c65a309e51eafb46`
as its base for a separate public-input transport change. The existing
`pon-cloud-build-inputs` workflow gains one bounded job that obtains the seven
original model files declared by `llm_runtime_pilot.py` and the existing
`model-runtime-cpu-requirements.txt` hash-locked CPU wheels. It retains the source
commit/tree, original material hashes, wheel hashes and a complete input inventory.
No credentials, ambient caches or unpinned model revisions enter the bundle.
The original Rust input job and the original model training/install owners remain
unchanged. This input preparation is not an execution or installation receipt.

Local transport controls covered exact bytes, short and excess input, hash
mismatch, HTTPS downgrade refusal and preservation of a pre-existing destination.
The first control harness used an incorrect exception class and failed; correcting
only that harness to catch the implementation's ValueError produced six passing
controls. Python AST, workflow YAML parsing and source preflight passed. Actual
network retrieval and offline model execution require their own later observations.
The helper removes only a partial file it created itself and rejects an oversized
input block before writing it. It bounds the complete input bundle to 768 MiB.

This change addresses a concrete missing-input blocker for the requested P1 real
Hepta task. It does not complete ordinary I10 installation, runtime execution
closure, parent-to-successor neural improvement, cross-node custody, next-task
readback, work hardness or full-chain post-quantum qualification. All production,
public reward and installation qualification flags remain false.


### PN3 runtime material declaration and real neural observations — 2026-10-27 (PARTIAL / OPEN)

The existing Cell release owner gains a fresh `hepta-runtime-material-release-v1`
read-only declaration/readback interface. It checks canonical original-wheel
extraction and static ELF dependencies, with13 material controls, the original8
Cell release controls, and the existing strict CI roster checks. It creates no
execution namespace capability, installation selector or new resource owner.
The actual31-wheel pip environment remains incompatible: all31 top-level RECORDs
were rewritten; generated/vendored metadata and `.pth` need reviewed handling.
The tiny cold-interpreter control is not complete cold SmolLM execution.

[Retained real component observations and failures](../../evidence/pon-neural-material-controls-20261027/README.md)
bind Chain c96022 and Hepta e1537. Original V2 training completed10 CPU steps,
526 tokens/40 supervised tokens, and changed230400 FP32 adapter values. Original
candidate observation completed8 requests/64 forwards; every output was `yes`,
scoring2/4 on calibration and2/4 on evaluation. The actual four-control follow-up
aborted on full-tune SIGKILL(-9) with no successful full-tune receipt; its
`INCOMPLETE_NO_ADOPTION` result remains. Post-failure OOM counters cannot establish
the exact kill cause without a before counter. No unknown host service is stopped.

The three Cell cohorts preserve sandbox bind denial, dev deadline failure and
release connection reset. None verified all11 materials; no ordinary installation
or next request was reached. Do not interpret initialized UNAVAILABLE fields as
an executed installation denial. Model improvement, cold runtime, independent
operators, complete useful-work accounting, I10, three beneficial rounds and WAN
acceptance remain OPEN under their original gates.

The dedicated fresh five-participant CI diagnostic reuses the existing fixed
public inputs and original pilot owner at10 steps/two threads. It keeps a15-minute
job ceiling and10-minute outer model step; original per-role caps are unchanged.
It has a new source/run/candidate, and does not replace the local V2 receipt or
ordinary closure. Timeout/missing evidence remains failure; early setup failure
or hard job termination may prevent uploads. The diagnostic is NOT_RUN at this
source freeze. Existing model matrices gain only13 small material checks, not
extra pretrained-model runs. `task_complete=false`, `merge_ready=false`.

### PN3 initial CI preparation failures and bounded repair — 2026-10-27

The first published source `abe552b6d2a408adbf82e27c817b4f914a7322a2`
produced two genuine CI failures, preserved in the
[preparation failure evidence](../../evidence/pon-model-diagnostic-env-failure-20261027/README.md).
Independent diagnostic run `40485837206` passed exact-source verification, then
failed because its same-step Python probe could not read a value written only
to `GITHUB_ENV`. No model execution occurred. Exporting that exact directory
in the current shell passes a real old/new shell reproduction and a fresh
subsequent-step control; input pins and the 15/10-minute limits are unchanged.

Parent-evidence run `40485837111` failed its new runtime suite before any of its
thirteen tests executed, on all four architecture/source matrix jobs. The
fixture confused a library's mapped real filename with its SONAME alias. The
fix resolves only unique aliases to files already mapped into the current test
process. It does not execute a loader, alter the production runtime validator,
skip any test or relax the strict roster. Actual system-Python red-to-green
fixture execution, all thirteen primary-Python material controls, eight original
Cell controls and four registration controls pass locally. A new exact-source
CI run must establish the full system-Python and ARM results.

The original failed runs, local full-tune SIGKILL, all-yes candidate results,
Cell failures and uncompleted ordinary I10/runtime/benefit gates remain intact.
This repair carries no neural improvement, installation or release authority.

### PN3 new Cell004 and actual downloaded-model readback — 2026-10-27

The [new source-bound Cell004 observation](../../evidence/pon-cell004-model-readback-20261027/README.md)
uses the reviewed provider source `57fbdfeead5cfa1436eeef0d1691ee9933246d4d`.
The empty consumer genuinely downloaded all eleven materials/269 chunks and
272,189,870 payload bytes; aggregate fetch, cache-only materialization and final
hash readback took25.906427551s within the unchanged35s limit. The provider
retained45s/two workers and exited0 with280 completed/zero overloaded connections.
The final original controller still exited1 at native-consumer/owner-receipt
UNAVAILABLE. Batch003 remains failed, unchanged and causally undetermined.

The original backend then loaded the downloaded candidate bytes and executed the
predeclared next request. Actual loaded parent/artifact match `d3b3e79e`; eight
generated tokens decode to `yes`. Original supervisor wall29.929171552s,
CPU33.798063s and wait4 peak1,147,097,088B are retained under their actual scopes.
This is direct controlled backend readback, not ordinary Agentd task execution.

Hepta's separate `hepta-neural-agentd` qualified bootstrap already exists; the
remaining integration must consume its real SystemLongitudinal eligibility,
selection/CURRENT, resources and FinalUse, and propagate actual load/forward
provenance into the ordinary Context/AppServer route. Initial-only selected
material cannot become an evaluated child or an ordinary installation. The
all-yes candidate and incomplete matched controls remain unqualified; this
component result closes neither ordinary I10 nor full cold runtime, model benefit,
three installed rounds, independent operators or WAN gates.

### PN3 actual fresh five-control CI result: zero benefit — 2026-10-27

The [fresh CI diagnostic evidence](../../evidence/pon-model-five-controls-ci-20261027/README.md)
at source `678c9e00b97885b1af9fa2dcf3572f65a5ac3b45`, run40487735989,
job122133657558, completes all twelve original phases, including real full-tune
training and all five evaluations. Candidate, fresh LoRA and full tune each score
1/2 under the original source-group evaluation metric; candidate gain over the
strongest control is0/1 and `positive_vs_all_controls=false`. All authentication,
independent/prospective acceptance, public reward and public-network flags remain
false. The fresh candidate `eff04d14` does not replace local V2 `d3b3e79e`, the
original incomplete SIGKILL cohort or Cell004. No candidate is adopted.

The three trained arms retain10 steps/526 tokens/40 supervised tokens. All twelve
phase walls sum to226.827036961s and child CPU to310.018861s; full-tune wait4 peak
is6,141,497,344B, a single-process high-water under the recorded scope. Original
per-role600s/8GiB, outer-step10m and job15m limits remain unchanged. All81 retrieved
non-checkpoint files match their inventory. The540,891,786B checkpoint artifact
exceeds the536,870,912B download limit and is not locally verified.

Parent-evidence run40487735846 also completes the four ARM/x86 source/merge
material jobs: each original13-test runtime roster passes once with zero skips.
This validates the canonical extraction material controls, not the real pip
installation's rewritten31 RECORDs or held runtime closure.

Newer Hepta4071 at `3b308ce2ca0c5117280c2820ca034ca5e5e0287f` does implement a
distinct public-initial V2 ordinary route. Its actual run40488014123 passes519
scoped tests (24 skipped), then fails the required ordinary model test before
readiness because the original fixture omitted the Codex executable path;
proposal rounds and descendants are skipped. Preserve that source/run outcome
and the separate original qualified-child gates. Any later provenance/fixture
repair needs its own actual CI; this evidence closes no ordinary I10, model
benefit, held runtime, beneficial installation or three-upgrade gate.

### PN3 prespecified answer/EOS research V3 — 2026-10-27

This separate diagnostic retains the exact old pilot, its public4+4 evaluation,
all four controls and an actual CURRENT-incumbent sixth arm. Those public tasks
are already inspected fixtures, not an independent or unseen holdout. Original
zero-gain campaigns, the ordinary hold-only loop and all qualification gates
remain unchanged. Equal observed scores did not imply equal learned weights;
later descendant predictions also differed while their scores remained tied.

The only new candidate recipe is `answer-eos-balanced-loss-v1`: fixed AdamW
learning rate0.001, matching the established fresh-LoRA control's prior rate;
one answer token receives half the per-example loss, and the three existing EOS
tokens each receive one sixth. All40 target tokens have positive weights. The
same10 steps,526 physical tokens, initializer seed7, rank4, alpha8, zero dropout,
frozen parent, row order, forward shapes and original per-role caps remain. No
single-EOS shortcut, fabricated token count, holdout-driven parameter search or
equal-cost claim is permitted. Native wall/CPU/RSS and supported FLOPs must be
measured again. This tests a plausible objective imbalance; the old failures
have not established that imbalance as their cause.

The old pilot plan remains byte-identical as the material/forward and original
control contract. It still contains its original candidate learning-rate stanza;
the new research plan explicitly marks that stanza unused for this new candidate.
The V3 plan separately freezes the recipe, exact source hashes, original plan,
parent descriptor, task identities and six-arm roster before execution. The
original parent-step supervisor/load/setup/export owner dispatches only the
explicit V3 profile; input, attempt, actual, candidate and result domains are
versioned. V1/V2 reject the new request fields. The unchanged initial setup receipt
still makes only its original algebraic B-zero claim.

The new byte controls and small actual CPU-gradient controls check source/recipe
drift, old-namespace relabelling, missing pre-execution plans, false qualification,
original failed-reap semantics, all four live causal target losses, masked prompt
positions and measured tiny-model token counts. They do not qualify a135M model.
The planned single new six-arm run is NOT_RUN at this source freeze. A positive
public diagnostic would still lack independent evaluation custody, original
SystemLongitudinal/EligibleForIndependentSelection authorization, qualified
selection/CURRENT installation and actual child FinalUse. Ordinary useful-model
evolution, held runtime closure and the three-upgrade gate remain OPEN.

### PN3 existing-parent task research V4 — 2026-10-27

The explicit V4 parent-step namespace composes the unchanged V3 answer/EOS
objective with the original V2 exact task-admission link. A preexisting actual
parent may have a different registered task admission from this experiment;
its immutable target contract, parameter bytes, model, tokenizer and numeric
contract remain unchanged. Preflight and the actual loaded-model check both
require that target admission is the sole difference. V3 remains strict and
does not accept the new profile, fields or receipt domains.

The original parent-step owner retains setup, training, child supervision,
terminal wait, resource caps, byte export and completion. A separate V4
candidate-observation namespace reuses the original observer while binding the
complete V4 input, terminal result and candidate record. A zero exit without
the original owned reap cannot qualify training or evaluation.

`scripts/run_llm_task_research_v4.py` freezes one public six-arm diagnostic:
the parent-derived candidate, all four unchanged controls and a reload of the
actual source parent. The source parent is explicitly not represented as an
admitted CURRENT. Every arm uses at most two CPU threads and retains the
original per-child caps; full-tune checkpoint size and local disk headroom
have explicit limits. The fixed V3 recipe remains ten steps, 526 input tokens
and forty positive-weight targets. Actual CPU, wall, RSS and failed attempts
must be retained rather than inferred from those counts.

This continuation is based on the original runtime bytes shared by the parent
and V3 source. V5 exit observation changes both runtime-bound tokenizer and
numeric contract identifiers; the V4 admission-only link correctly refuses
that migration. No V5 compatibility, independent future-task quality, useful
release, ordinary upgraded-child installation, CURRENT mutation or FinalUse
follows from this research path. Exact local execution evidence, including any
nonpositive result, is retained separately from this source declaration.

### PN3 actual V4 public comparison and controlled transfer — 2026-10-27

At source `c86cabce381ff24f0e002693eb46d9b7a49e1690`, one frozen real135M six-arm
run completed all18 required child stages with original owned reaps. The
candidate, fresh LoRA and full tune each scored1/2 on the four public evaluation
examples; the actual source parent, untrained backbone and randomized LoRA
scored0. Relative gain against the strongest control is exactly0, so the fixed
decision is `nonpositive-gain-no-installation`. The controlled source parent was
never represented as admitted CURRENT. All three trained arms measured ten
steps,526 input tokens and forty supervised tokens, with actual unequal costs.

A separate bounded loopback producer and empty consumer fetched three exact
candidate objects (1,011,315 payload bytes), then the original inherited-runtime
owner performed a real next-prompt forward from the fetched candidate bytes.
This single-host path reused the existing verified backbone and grants no
ordinary installation, independent-node or installed-child FinalUse claim.
Exact-source validation passed71 distinct Python boundary/gradient/registration
tests with zero skips. Earlier failures, the prior failed Hepta owner gates,
raw terminal and transfer receipts, source pins and explicit excluded model-byte
inventory are retained in
`evidence/hepta-task-bound-v4-20261027/README.md`. Full useful-model evolution,
independent qualification and ordinary upgraded-child installation remain OPEN.

### PN3 explicit original-model observation execution V1 — 2026-10-28

The original public V2 model plan and target contract remain exact bytes. A
separate `llm-runtime-parent-observation-plan-v1` explicitly selects the existing
`linux-owned-exit-worker-pidfd-v4` supervisor observer, retaining its 100 ms drain,
the original 1800 s / 16 GiB training and 600 s / 8 GiB inference caps, and exact
owned-child wait/reap requirements. This is a new execution policy and identity,
not a claim that the historical strict-v1 run used this observer.

The original V2 parent-step owner dispatches the opt-in observed-input-v1
request, runs the original full model/parent preflight, starts the same child,
and verifies its actual factor bytes and completion under new input, attempt,
actual, candidate and result namespaces. The runtime source and model plan are
unchanged. Legacy V1/V2 requests refuse the new observation fields and arguments.
No executor, resource owner, training objective or product authority is replaced.

Local verification passed 54 controls, including eight new byte/namespace/owner
controls and a real small-process owned-wait probe. Full preflight also passed on
the historical c9b06f9a public target and exact parent bytes, returning exactly the
same tuple as original V2 preflight. These are compatibility and execution-source
checks; no new pretrained-model run, training, qualification, ordinary install,
CURRENT update or future observation window was performed. Historical third-round
strict failure, zero gains and zero installed children remain unchanged. Evidence
and reproduction boundaries are in
`evidence/hepta-observed-execution-v1-20261028/README.md`.

### PN3 separate binary-answer observed training V2 candidate — 2026-10-28

The original Hepta neural study at `067bc8a16c7b7cac5124dd7bc4c6ae894c4a2286`
completed ten real training steps and 2,048 real future forwards. Parent and child
chose the same answer on every row; the original ProductEvaluationRunner rejected
the candidate with NoGain. No ordinary child installation followed. This failed
observation remains authoritative for that experiment.

The new `canonical-positive-zero-binary-batch-observed-v2` profile is a separately
frozen training hypothesis, not a rerun of the old workload. It retains the exact
original model plan, pilot, target contract, parent bytes, rank-four factors and
seeded initial working copy. Ten optimizer updates each accumulate the mean of
ten original source-row gradients. This is 100 actual forward/backward exposures
of ten independent examples, not 100 independent examples. The original two
single-token yes/no answer logits at the last prompt position define its binary
cross entropy. Labels are absent from the visible prompt; this new objective has
one supervised answer and no EOS supervision per exposure. AdamW uses the fixed
learning rate 0.002 and zero weight decay, with no holdout-based parameter search.

A new input, execution plan, actual receipt, candidate, attempt and result domain
binds the recipe and original material context. A bounded runtime trace records
all 100 completed microsteps and ten optimizer updates, actual token IDs, source
row identities, answer logits, losses, gradient norms and event clocks. Completion
recounts this trace and refuses legacy 526/40 totals, reordered or missing rows,
nonfinite values and changed source/recipe/observer identities. This trace remains
unsigned execution evidence; it grants no model qualification or installation.

The original owner retains the 1800 s / 16 GiB training cap, actual wait/reap and
the existing 100 ms terminal observer. Live model release runs within this same
budget; primary training errors remain primary even when finalization or receipt
I/O also fails. V1, V2, V3, V4 and observed V1 keep their original exact workload
and receipt rules. Seventy-one local finite namespace, material, trace and owner
controls passed, including ten new controls. These fixtures are explicitly not
pretrained-model or gradient-execution evidence.

The complete source checkout and finite compatibility controls are available.
Actual development execution retained the original ordinary parent artifact
`1c5af7b5a7144a619dfac83b14bd83ae77f1e2227b18a6a9c5dcb214889a0cba` and the
original public model snapshot. This local directory rebase does not constitute a
new ordinary installation or independent qualification of that parent.

The first development attempt wrote all 100 microsteps and ten optimizer updates
but the child exited on SIGKILL before its final actual receipt. Its original
owner also rejected terminal cleanup beyond 100 ms. A shared 8 GiB cgroup had an
OOM-kill event, but no before-counter was retained for that attempt, so a unique
causal diagnosis is not claimed. This attempt remains failed. The profiler was
then bounded to one context per ten-microstep optimizer update, with all 100
forward/backward operations still measured and supported-operator FLOPs summed.
Independent AST comparison found the gradient and optimizer statements unchanged.
The observation overhead changed and remains charged to the original owner.

The second attempt froze the identical mathematical recipe before execution with
trainer source `6e588493c7c956b5fb55f6b5875dab3fb951b964783c1dc8366caa9178e827fc`.
It completed under the unchanged owner: wall 490.563795345 s, child CPU
766.764043 s, observer CPU 9.337635507 s, and wait4 single-process high-water
2,828,050,432 bytes. Measured terminal cleanup was 9,590,857 ns. Before/after OOM
counters were unchanged. Native compilation ran concurrently, so these costs do
not establish an exclusive-machine performance comparison. The actual trace has
4,860 input tokens, 100 supervised answer positions, zero EOS positions and
2,667,553,722,120 profiler-supported operator FLOPs; the FLOP count is not total
work. Independent readback reproduced every source-row token, microstep ordering,
binary cross entropy, optimizer completion, full execution-plan context and
original resource-owner binding.

Eight pre-existing public calibration/evaluation prompts were frozen before the
development queries. The real parent answered yes on all eight and was correct
on four; the actual trained child answered yes once and no seven times and was
correct on five. This excludes the earlier all-yes behavior on this small public
development set only. It is not a prospective quality result and grants no
selection, two-node transfer, installation or next-task FinalUse. Neither this
attempt nor its source uses these eight prompts as a new future window.

The explicit Hepta binary study has separate input and evidence namespaces,
retains the original forward implementation and qualification thresholds, and
independently reads the complete 100-microstep trace. Its future cohort generator
excludes all 1,024 previously consumed prompt identities, freezes a fresh seed
and all tasks before model queries, and retains two 512-row balanced cohorts in
the original task families. Native cohort verification and finite reader,
transport and training-binding controls are source-level evidence only. The full
prospective ProductRunner decision, retention, withdrawal, two-node Cell,
ordinary generation-two installation and next-task byte readback remain pending.
A further NoGain result must again block installation.

### Legacy evidence reader and held-layout selection — 2026-10-28

The actual head and prospective-merge external-evidence-contract jobs for the
binary trainer candidate `f1fdee165623c376005270ba84a65b0b6f9cf15b` failed at the
legacy schema reader. The native opener already selects the shared-snapshot
layout before binding its DDL and schema ID; the reader still required the old
unwrapped pair. This is an evidence-reader mismatch, not a successful runtime or
model qualification observation.

The reader now recognizes only that exact module, enum, layout implementation,
source-file binding and direct three-statement selection. It verifies that
CanonicalJson preserves the original legacy DDL and schema, while shared storage
requires AuthenticatedV1 and held native IO with its separate namespace. Unknown
mapping bodies, literals, substituted arguments, old-pair decoys, rebinding,
shadowed modules and missing or symlinked layout sources remain refused. Shared
snapshot tables remain outside the legacy evidence scope, including resealed
metadata and source attempts to append them to legacy DDL. The independent
4775-byte legacy DDL and pre-backend hash remain unchanged.

This repair changes the reader and its negative controls only. All native runtime,
transaction/signature/nonce code and all trainer/model source bytes remain exact.
Full CI and the prospective ProductRunner decision retain their original gates;
this parser repair confers neither model efficacy nor an ordinary installation.

### PN3 same-call worker count transition — 2026-10-29 (candidate / OPEN)

A retained real original-model validation stopped during exit observation after
an earlier full worker binding. The compound `exit-task-identity` refusal did not
retain the exact mismatching field. A deterministic control separately reproduces
the narrower race in which the complete task roster contains two original tasks
and a bound worker retires before the next leader status read reports one thread.
This reconstruction does not reclassify the historical failed observation.

The V4 observer now distinguishes only a positive count decrease after complete
initial classification and binding. All successful identity, namespace, memory,
state and stat reads must still pass before that transition can request proof.
A strictly smaller complete roster, a nonincreasing observed count and a new
terminal event from the same retained original worker pidfd are all required.
The incomplete frontier is discarded; the existing finite recapture requires
two complete remaining frontiers, the original owner and the original deadline.
A changed-count status followed by missing stat remains a refusal. Worker
retirement does not establish released RSS or group completion. Only the exact
owned-child wait4 receipt can close the observation within the unchanged 100 ms.

All 96 original and added observer/resource controls passed with zero skips,
including actual own-child kernel pidfd probes. Wrong identities, task additions,
count increases, missing terminal events, incomplete reads, pre-binding changes
and expired deadlines remain refusals. Model, training, task, retention,
qualification, resource and timing rules are unchanged. Source-bound observation
policies acquire the actual new worker-source hash; the old observer policy is
rejected on the changed source. This source repair grants no model efficacy,
qualified child installation or next-task child-byte read.

This binary candidate applies the identical observer and regression tests to
the 090d source tree, which already contains the strict shared-layout evidence
reader repair. All four binary trainer and trainer-test files remain byte-for-byte
identical to their preceding published binary source. The separate original
model route keeps its 003-based training code; these source roles are not swapped.

### PN3 separate diverse60 scalar training V3 — 2026-10-29 (candidate / OPEN)

The explicit `canonical-positive-zero-binary-diverse60-observed-v3` candidate is
a new training execution contract. It keeps the exact original ten-step material
plan and parent target contract, while a separate recipe records thirty optimizer
updates over sixty fixed public source rows. Six committed ten-row groups repeat
five times: 300 actual scalar forward/backward calls, 300 supervised original
yes/no answer positions, no EOS positions, and exactly 15,600 input tokens. Each
optimizer update keeps one original CPU profiler context. This is thirty profiler
contexts, not three hundred. AdamW, learning rate 0.002, zero weight decay, rank
four, alpha eight, seed seven, dropout zero and mean ten-row gradients are fixed.
There is no tensor batch, OpenMP pause, intermediate model selection or future
task in this Chain execution contract.

The explicit input is
[`config/pon/binary-diverse60-training-v3.json`](../../config/pon/binary-diverse60-training-v3.json),
47,712 bytes with SHA256
`d457f4b01cc6aaa445403e81b1fa9511e24f23e4254a6ef9ff9ec29abab693cf`.
Its sixty row records, original tokenizer arrays and 30-by-10 schedule match the
precommitted development input identified by plan
`920553660721745af24963bb4d360f76e0d0bc0f6bb1a65c1c03e1cb369605b7`.
It contains no temporary paths, future windows, future predictions or claimed
qualification. Distinct prompt rows are not a claim of independent semantic
operations. The declared 120 source-ledger records describe the later required
one-decision/one-target provenance width, not an authenticated ledger created by
this trainer.

The new
[`llm_binary_diverse60_observed_v3.py`](../../scripts/llm_binary_diverse60_observed_v3.py)
provides strict plan, input, data, trace and completion readers. Callers must
provide both `--diverse-plan` / `--diverse-plan-sha256` and
`--diverse-training-data` / `--diverse-training-data-sha256` with the new profile.
Other profiles reject these arguments. The input's `initial_setup` binds the
original setup recipe and parent material, plus the separately pinned plan and
training-data roles. Data is offered explicitly; the bundled file is not a
silent fallback. The fixed data digest and actual new module digest are included
in the source closure, and preflight rereads the supplied data before and after
training. The original material/setup validator still checks the actual parent
and all factors. A setup-only unchanged candidate cannot complete this new
training profile.

The `binary-diverse60-observed-v3` input/actual/candidate/result suffix and
`binary_diverse60_observed_execution` context are separate from Binary V2.
The bounded `binary-diverse60-training-trace-v3.jsonl` contains exactly 332
records: start, 300 scalar microsteps, thirty optimizer completions and complete.
Each microstep binds the global source-row index, within-update position, exact
token IDs, target, both answer logits, CE, actual backward completion and clocks.
Readback verifies the committed schedule, five uses of every source row, complete
work and token totals, finite gradient norms and unchanged source/plan context.
The actual tokenizer must reproduce the frozen token arrays before training.
Full parent-to-seeded-setup-to-child byte checks remain in the original runner.

The current V4 owned observer is pinned to
`aae68f92393e5e88c5aaa02095b5990200c121834bec05d8b3a11cd3f09ffc50`.
The original 1800 s / 16 GiB training limit, 600 s / 8 GiB inference limit,
100 ms terminal rule, original wait4 ownership and live release behavior remain
unchanged. The new completion checks also recheck full owner policy, nonnegative
CPU/wall/RSS counters, both RSS measurements and any present cleanup timestamps.
Absent cleanup observation is not a zero-duration measurement. A development
result from an older AEF observer is not an execution result under this new AAE
source. Model failures, owner failures and receipt failures remain failures.

The original V2 trainer and its 10/100 readers remain byte-for-byte unchanged.
Fourteen new finite controls cover source/data/namespace confusion, exact scalar
trace and token accounting, schedule/row omission, changed parent bytes, source
and budget relabelling, failed owner receipts and actual child discriminant
failure before model import. Their successful model materials, logits and owner
receipts are explicitly fabricated fixtures; they do not certify model execution.
The original seventy-one compatibility controls remain required on the changed
dispatchers. No pretrained model, gradient run, Cargo rebuild, hosted CI,
qualification, installation or protocol activation is performed by this stage.

The sixty public training inputs were frozen before a later prior-study raw
exposure audit became available. The complete ten-study audit reports three
exact prompt overlaps with these inputs. Its 9,382-prompt union has SHA256
`b691fd97f2e2f7ef73806d858ea3ece4c67c0ad9ed7e2aab966196b080831d1d`.
The fixed training input is not renamed an unseen or fresh holdout, and it is not
retrospectively changed. Hepta's separately frozen, hash-only exclusion fixture
has 10,382 unique prompt identities and SHA256
`946d33b8f3cd95949f8eaf3623948639cf68c58214ad8b8f191ae0c2088606e4`:
all ten formal studies, the old 067 study, original public tasks and the sixty
fixed training rows. The old eight and 128 development inputs are covered too.
A subsequent formal study must exclude that complete known set before creating
its new future cohort.
It cannot reuse an a593 window as qualification for a new child. Hepta's original
two 512-task windows, IPS/confidence and family-retention checks, 2700 s whole
study cap, ordinary batch-one/four-thread forward, two-node Cell acquisition,
normal installation and next-task child-byte read remain separate unmet gates
for this new source/profile until actually executed and independently read back.

### 2026-10-29: diverse60 native source inventory follow-up

The first published diverse60 source, `0bd7019a06e34c69fcbc84f23dda8510689b9a8d`,
failed the original repository-truth inventory check in both head and prospective
merge jobs `123296601045` and `123296600859`. The preceding audit, boundary and
repository checks passed, but the fixed training JSON had not been added to the
embedded native source inventory. The original inventory generator now includes
that existing 47,712-byte file. This is one seven-line include entry; the training
data, all Python execution and reader code, observer, budgets and qualification
conditions remain unchanged. The two original failures remain failed observations.
This registration change does not establish a model result or a passing native
campaign. Its new source identity must be selected explicitly by any later Hepta
candidate before hosted execution.
### P0 work cost — executed native v2 x64 evidence (2026-10-27)

The [complete original v2 observation](../../evidence/pon-w1-native-v2-e9c4bb0-20261027/README.md)
now replaces the earlier “compiled only” status for these two low-rank research
producers. Exact source `e9c4bb0d3a324b1d79b7b99326512bfb707d0025`, focused run
`40490909605`, actually completed all 4,032 offered cohorts and 702,232 attempts
in 494.775912 captured seconds. All misses, exhausted searches, unsupported
cases and setup costs are preserved in the original 28,291,500-byte log; the
source-aware checker and full-grid reader pass. This evidence-only update does
not change the default miner, native work primitive, task eligibility or limits.

Each new low-rank arm completed 48,604 attempts and 6,452 primitive-valid winning
calls, but zero native admission calls. Across all supported aggregate groups,
scalar/paired low-rank beat Prepared CPU in 15/4 groups respectively; neither
was the least-cost measured supported algorithm in any group. The long-horizon
representative comparisons alone must not be generalized into “always slower.”
Registered genesis-maintenance produced 10,464 original Node admission calls,
with only 509 distinct winning header contexts after shared-stream deduplication.
Repeated admissions are not additional rewards or finalized blocks.

This is one shared x64 host and two rounds, not a minimum-cost or fairness proof.
Native verification/admission and report costs remain outside the measured
producer denominator. The original artifact records the executable's stable
before/after hash but does not contain that executable. Current-v2 ARM64, genuine
GPU and energy measurements remain **OPEN**; older architecture results cannot
close them. Correct-product/false-trace native replay, full transparent W1 proof,
permissionless public-service security and all PN0–PN6 production exits remain
**OPEN / NO_GO**. The additional complete readback performs no new benchmark run.

### P0 work cost — current-v2 native ARM64 execution lane (2026-10-27)

The separate `pon-pure-cost-arm64-v2.yml` research lane schedules the unchanged
fourteen-arm producer on an actual `ubuntu-24.04-arm` runner and refuses a
non-`aarch64` process architecture. It binds the complete tested commit/tree,
Rust 1.95.0, locked Cargo graph, original test-profile package overrides, source
inventory, before/after executable hashes, complete raw cost log, source-aware
reader and all 4,032 cohorts. The original grid, seed, two rounds, eight attempts
and 256-search horizon are unchanged. The explicit native wall ceiling is 1,800
seconds, with a 1,860-second outer capture, instead of the earlier x64 run's
900/960 ceilings. It does not turn a timed-out or partial grid into success.

This lane retains the actual executable as well as public `lscpu`, affinity,
cgroup and process-architecture observations. These are shared hosted-machine
observations, not hardware authentication, a reserved CPU frequency, energy
measurement or a GPU result. Native verification/admission remains outside the
producer timing denominator. Existing x64 evidence and all failed trials remain
intact; no native miner, W1 semantics, task eligibility or consensus target is
changed. At source freeze this new ARM64 execution is **NOT_RUN**. Its actual
terminal artifact must be read before any architecture comparison is claimed.


**2026-10-27 complete current W1 v2 ARM64 readback:** Exact source 2b070fafcdd253c142da90fd7306d211057d3418 completed run 40507587240: all 4,032 cohorts, 702,232 attempts and every failed search retained, actual 741.246320278-second capture and actual ARM ELF archived. Independent source-aware readback found every fixed input, complete proof stream, ticket and non-timing cohort field equal to the original x64 e9c4bb0 experiment. The same 509 distinct native maintenance headers underlie 10,464 repeated admission calls per host. Maintenance-split-limb is least observed producer CPU in all eight eligible native groups on each host; horizon-256 retained-preparation ARM cost is 1.260630 ms/win vs Prepared 1.305780, excluding verification/admission/IO. Neither new low-rank arm is cheapest, and neither has native eligibility. See [complete original ARM archive and comparison](../../evidence/pon-w1-native-arm64-v2-20261027/README.md). Different shared hosts, two rounds, unauthenticated hardware and no GPU/energy evidence do not establish hardness, stable speedup, chain TPS or production qualification; no miner or consensus rule is changed.

### P0 legal solver — first admission and ordinary cold recovery cost (2026-10-27)

The [fixed positive-ticket experiment](../protocol/pon-nakamoto-v1/details/LEGAL_TICKET_FIRST_ADMISSION_COST_V3.md)
adds eight fresh native stores and distinct first admissions to the existing
producer/hardware evidence. The original general and eligible split-limb arms
share exact paired header/proof streams, 64 disjoint nonce-window searches,
eight attempts per search, two rounds and cold versus retained preparation.
All misses, setup, template acquisition, encoding, native validation/SQLite,
ordinary cold recovery and byte readback have separate measured cost scopes.
The original verifier already runs inside admission and is not counted twice.
Ordinary cold selection keeps original work/height/id semantics; repeated
fixtures across stores are reported separately from distinct packet IDs.

[Source controls](../../evidence/pon-legal-ticket-cost-v3-20261027/README.md)
include eight actual synthetic reader passes. New native build, strict Clippy,
x86_64/ARM campaigns and end-to-end advantages remain NOT_RUN at source freeze.
The exact-head workflow retains executable/raw failures and original profiles.
This finite experiment does not establish GPU/hardware batching, energy,
physical power loss, live-chain rewards, public throughput or a global minimum.


## 2026-10-28: positive legal CPU batches and retained first-admission payloads

The [V4 experiment](../protocol/pon-nakamoto-v1/details/LEGAL_CPU_BATCH_COST_V4.md) adds actual 1/2/4-thread batches to the original legal maintenance work and native admission owners. One aggregate batch process clock includes all workers; overlapping trial clocks are diagnostic only. Twelve fresh-store cohorts retain all misses, preparation, ordinary cold recovery, first-admission payload bytes and separate archive costs. V3 remains unchanged. New source/reader controls do not imply native execution; the exact-source x86_64/aarch64 workflow must supply actual compilation, strict Clippy and campaign terminals. GPU/ASIC/energy/global-optimum claims remain false.

### 2026-10-28 — legal CPU batch V4 report construction repair

The first exact-source x86-64 hosted build at c4d055d81a6f707fb28c9726821da4163b0057cb failed before native execution on the large serde_json macro recursion expansion. The unchanged phase object is now constructed separately after the outer observation and inserted into the same report. No compiler recursion attribute, runtime budget, complete W1 work, predicate, packet output, accounting scope or acceptance control changes. The original job log and hash are retained in evidence/pon-legal-cpu-batch-v4-20261028; both original native architecture lanes still need real terminal results.

### PN1/I01-I02 — complete producer and attacker cost continuation (2026-10-28)

This continuation starts from `0f04de8ee26b1871ef95653dda51df220660bd4a` inside
the existing M01/M02/M03/M04/M15/M17 owners. Required-work accumulation, target
arithmetic, equal-work nonreplacement, DAA, maintenance eligibility, zero useful
maintenance credit and probabilistic finality remain unchanged. Statement
correctness, computational-cost qualification and honest public service retain
three separate verdicts. Model evaluation or a finite experiment grants none of
the other authorities.

The original prepared generic and maintenance-limb producers now additionally
offer an opaque borrowed `ProducerCandidate`. It retains the exact task prefix,
challenge and fully computed transcript. Every candidate still evaluates all
noise and 512 transcript tiles. The candidate can expose its ticket before a
49,188-byte proof is materialized. Winning assembly has its own real
`BeforeProof` cancellation boundary; it creates bytes only, never `VerifiedWork`.
The existing `prove` callbacks, error order, arithmetic, wire bytes and default
verifier are retained. The independent 898-observation / 56-cancellation legacy
control passed against the original implementation before this refactor.

The new [six-arm native driver](../../trillionnium/crates/trnm-pon-node/examples/pon_ticket_first_cost_v1.rs)
separates legacy assembly, candidate assembly on every attempt, and assembly only
for target hits for each of the two kernels. Two paired rounds, four actual
horizons (1/8/64/256), fresh/retained setup and six arms produce 96 fresh stores.
The seed-two nonce windows are disjoint from the old V5 fixture. Complete missed
attempts, actual setup, first native admission and ordinary cold packet readback
remain in the recorded cost scopes. A missed candidate's canonical proof hash
is streamed from the fixed prefix and real trace without allocating its full
proof; it is not mislabeled as a serialized or independently verified miss.
The [independent reader](../../scripts/ci/check_ticket_first_cost_v1.py) checks
paired raw records and distinguishes allocation changes from avoided miss
serialization. The new 600/610-second observation is separate from the unchanged
V3/V4/V5 campaigns. Source controls alone do not establish a performance gain.
Bounded, flushed write-ahead records retain completed trial observations when a
cohort fails; successful readback reconciles their exact sequence and clocks
against the complete stdout records. Missing or inconsistent records cannot
qualify a surviving subset. Exclusive phase costs, the enclosing cohort and the
whole native process remain distinct; final cleanup, serialization and producer
destruction are included only in the whole-process capture. The explicit new
release capture identity cannot relabel an old test-profile observation.

The original V5 reader now rejects inconsistent per-trial challenge/proof/ticket
or cold packet records even if the producer repeats the same claimed stream
digest. Actual old x86_64 artifact 12834526404 and aarch64 artifact 12834666223
were reread with their original source/capture bindings: all 144 cohorts per host
pass, and the original summaries remain byte-value equivalent as JSON. Four
in-memory substitutions accepted by the old reader are rejected by the new
reader. These are historical-byte rechecks, not current-source native runs.
Optional [paired diagnostics](../../scripts/ci/legal_ticket_cost_diagnostics_v1.py)
retain both rounds, all failed-search cost and unknown CPU. They reuse the
existing conditional work-share sensitivity and do not calibrate the DAA model,
infer independent hosts, or assert a global minimum from two shared-host rounds.

The original pressure harness additionally writes a separately named
`pon-pure-attacker-cost-v1` sidecar per actor. It includes preparations that cross
the original phase deadline or never enter the original client call. An enclosing
thread-CPU interval covers the actor entry through loop exit; nested stage
measurements are never added again. Unknown CPU remains unknown. Process launch,
other threads and final evidence publication are explicitly outside that scope.
The [cost reader](../../scripts/ci/check_pure_pon_attacker_cost_v1.py) requires
complete records and exact links to the old calls without changing the old v3
service verdict. Original 30-second phases, two-second calls, actor/request
bounds, resource policy and historical failures remain authoritative. Missing
sidecars cannot be backfilled as a historical cost pass.
A create-only parent manifest binds each original actor report and cost sidecar
by exact byte length, SHA256, terminal and counts after the old joins, service
stop and report construction. Fixed-path no-follow regular-file reads and a
separate bounded observation deadline preserve the original attack windows.
The reader rejects even same-length coordinated deletion of an unissued final
preparation with rewritten summaries. CPU-versus-monotonic checks are consistency
diagnostics only. Initial template search counts remain explicitly unobserved;
neither the local clocks nor jointly forged host files acquire physical
authentication from these bindings.

The optional transparent-proof admission host also rejects impossible
header/task/target contexts before decoding and cryptographically verifying the
receipt. The frozen guest, proof grammar and native work authority are unchanged;
this is a research API rejection-cost improvement, not live proof intake or
evidence that forged work was previously accepted.

At this source freeze, exact-committed-source native qualification, strict
Clippy, complete pressure costs and the six-arm measurements are **NOT_RUN**.
Working-tree controls do not substitute for those verdicts; exact-source results
must be read from their raw records. Public stranger/Sybil fairness, whole receiver-owner
costs, optimal CPU/GPU/FPGA/ASIC and energy bounds, quantum effective work,
independent WAN service, beneficial model releases and production activation
remain **OPEN / NO_GO**. Original finite passes and failures retain their own
source/profile identities; no fallback consensus or new development roadmap is
introduced.


### PN1/I01-I02 — exact A readback and blocker continuation (2026-10-29)

The preceding source-freeze NOT_RUN labels are superseded only for exact source
`8018eb875aaf2cc1f74b33232b5c9197e94bfea4` by its completed local observations and
[original x86_64/aarch64 cost run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40815302333)
and [original pressure run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40815302237).
Each complete six-arm capture retained 96 cohorts, 16,404 attempted observations,
7,860 repeated first-admission calls, 36 exhausted searches and 655 distinct
winning packet contexts. Repetition across paired arms is not new work, rewards
or independent confirmations. The representative retained-preparation,
horizon-256 pair reduced proof materializations from 1,089 to 509, while keeping
all 1,089 complete W1 attempts; the three shared-host observations did not show a
stable total CPU advantage. The default miner remains unchanged.

The original three 30-second pressure phases with 24 actors in each attack phase
completed on both hosted architectures, with three honest rounds per phase.
They remain finite loopback observations. The x86_64 correct-product/false-trace
phase retained 2,271 preparations and 2,270 client calls; the final unissued
preparation is part of cost evidence. The original CodeQL export failed during
transport after empty analysis observations. That is an incomplete security
export, not a clean scan or a proved GitHub permission diagnosis. None of these
A-source artifacts is reassigned to later source, binaries or resource owners.

#### Complete independent W1 arithmetic

The separate [offline replay](../../scripts/ci/replay_ticket_first_w1_v1.py)
uses the unchanged scalar `work_oracle.evaluate` for all recorded unique inputs.
It replays noise, all 512 transcript tiles, trace and product for wins, target
misses and exhausted searches. Calling the existing target-checking `verify`
would incorrectly skip missed work, so that entry is deliberately not used.
The dictionary key contains the task, challenge and full canonical prefix bytes.
The frozen complete capture contains 1,367 unique inputs: 655 winners, 688 misses
before a winner and 24 exhausted-search misses, each observed in all twelve
arm/setup pairings. Multiple captures can share arithmetic only when their
complete input sets agree; shared replay is not independent host execution.

An explicitly synthetic mutation of one actual A-source miss changed all twelve
paired traces and consistently rebuilt the ticket/proof/stream/journal hashes.
The original structural cost reader accepted it; the unchanged scalar oracle
and new complete replay rejected it. Original raw artifacts remain untouched.
A developmental replay over the local, x86_64 and aarch64 A captures completed
all 1,367 evaluations and covered 49,212 raw observations in 120.858697 seconds.
Its exact helper snapshot predates the final output-cap addition and is retained
separately. Those timings measure offline verification, never native mining.
The final helper has an independent cooperative 300-second limit, bounded input
roster, 16-KiB journal lines, an 8-MiB journal and a 16-MiB receipt. It reserves
failure-terminal space and retains incomplete observations. Blocking file I/O
and an in-progress scalar evaluation are not claimed to be preempted.

The original [cost workflow](../../.github/workflows/pon-ticket-first-cost-v1.yml)
adds this independent readback after its original successful reader, with a
separate seven-minute step. Original native 600/610-second limits, six-arm
semantics, summaries and qualification flags remain unchanged. Statement
correctness does not certify the recorded machine, cheapest legal strategy,
energy cost, quantum resistance or public service.

#### Actual executable retention and complete process observations

The [create-only binary archive](../../scripts/ci/pure_pon_binary_archive_v1.py)
retains the actual six original pressure executables, after the native stages,
with complete build/source associations and independent copied-byte readback.
Fixed no-follow directory traversal, regular-file checks, before/after identity,
a 64-MiB per-file bound, a 192-MiB total bound and a separate 30-second cooperative
copy budget constrain this evidence step. Missing binaries, changed source bytes,
partial copies and failed campaigns remain failures. An archived executable does
not authenticate a physical host or prove that it was executed.

The pressure harness uses one parent-owned `wait4` reaper per original actor.
It retains startup-through-exit user/system CPU, peak RSS, exit status and
monotonic spawn/reap brackets. The existing two-millisecond polling and absolute
five-second cleanup deadline remain. A known reaped or ECHILD child is not killed
again through a possibly reused PID. The separate process sidecar binds final
report, thread-cost, log and process-family bytes; its
[independent reader](../../scripts/ci/check_pure_pon_process_cost_v1.py) compares
nested CPU scopes with explicit clock precision tolerance, without adding them
together. Missing CPU or process-family observations remain unknown.

Process-family evidence records bounded per-thread Linux child lists and actual
RUSAGE_SELF/RUSAGE_CHILDREN. A stable empty list is an observed quiescent state,
not hostile-host authentication; terminated descendants count only when actually
waited for. Waited-child CPU is nested inside Linux wait4 usage. Peak RSS is not
a summed or simultaneous process-tree memory peak. Original service verdicts,
request limits, attack windows, deadlines and fixed-parent qualification remain
separate from these cost observations.

The separately named [receiver-owner supplement](../../trillionnium/crates/trnm-pon-node/tests/support/pure_receiver_owner_v1.rs)
places the real Node, two protected reactors and their worker threads in one
fresh child process. The honest client, sampler and 24 attacker siblings stay
in the parent or separate processes. Its own three 30-second phases, two-second
calls and fixed cleanup deadline preserve the declared experiment. Private
bounded observation IPC, startup, final publication and teardown are included
in receiver wait4 cost. Only this temporary child sets its local subreaper
attribute; no deployed receiver or parent setting changes. Joined reactors,
dropped Node ownership and final per-thread child observations must agree with
the actual reaped terminal. An existing fixed public parent is inspected
read-only, if available; no stand-in is provisioned. Its aggregate counters
include other members and are not exclusive receiver CPU. A new-namespace
reader retains the original campaign's separate verdict and never reclassifies
this supplemental campaign as an original-run or public-fairness qualification.

The local development environment did not expose per-thread procfs `children`
files. Their ENOENT records remain unknown, not empty child lists. A separate
`pon-child-ownership-probe-v1` records one non-reaping Linux waitid with P_ALL,
WEXITED, WNOHANG, WNOWAIT and __WALL, together with unchanged SIG_DFL and absent
SA_NOCLDWAIT before/after observations. Only the actual -1/ECHILD result can
observe no eligible children at that probe; zero-event success, an observed
zombie, other errors and signal-policy uncertainty cannot. Live-child,
repeated-zombie and post-reap controls exercise these distinctions using real
processes. The reader identifies the evidence method and retains the original
procfs status. The probe does not consume the child's wait4 record, count CPU
again, replace worker joins, cover CLONE_PARENT causal siblings or authenticate
a kernel or complete historical cost. See the
[Linux wait interface](https://man7.org/linux/man-pages/man2/waitpid.2.html).

Independent review found that per-call socket timeouts did not bound a whole
prefix/payload exchange by the fixed cleanup deadline. The supplemental IPC now
recomputes the same absolute remaining budget around each actual read/write,
retains partial frames, and refuses late completion. The reader binds arm's
epoch to that request's clock bracket and rejects stop completion or receiver
reap after phase-plus-five-second cleanup. The earlier accepted synthetic
clock counterexamples and actual startup/procfs control failures are retained.
No original campaign budget or failed observation is rewritten.

#### Unsupported authority and numerical-model controls

The [complete-proof observation checker](../../trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/check_observations.py)
now compares the entire artifact backend manifest with its source-owned manifest
using typed canonical JSON, and refuses duplicate keys, nonfinite values and
unsupported PQ/activation/Groth16/fake/remote-proving flags. Historical actual
build-only bytes supply the positive control; ten manifest mutations accepted
by the exact A checker are rejected after this change. This is source/build
identity evidence and does not claim a newly generated or verified proof.
These controls run before native work in the existing proof workflow. The
public-readiness checker keeps the same unsupported-authority boundary.

The complete public-readiness regression also exposed an existing source
contract mismatch: the A-source opener already delegates through
`shared_snapshot::Layout`, while its evidence reader still required the older
direct bindings. Both the exact A reader and the initial candidate failed this
positive case. The reader now recognizes only the exact held-I/O None bridge,
module binding and identity mapper. Path/attribute substitutions, nested or
string/comment decoys, unknown mapper bodies, rebinding and shared-table
pollution remain rejected. No Rust storage owner changes. The ordinary legacy
DDL remains 4,775 bytes with raw SHA256
`ce0de86674de23181ef1f6fb59f357f94971feeaee0c5503f065dbf45bb5c964`;
its separately domain-derived schema ID remains
`8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0`
under `native-branch-schema-v2`. This finite source contract is not a general
Rust semantic proof or native storage qualification.

The conditional Grover model previously rounded a nearly full 64-bit marked
set to probability one before amplifying the phase. For 2^64-1 marked points and
one billion iterations it reported about 0.9999999999998794 instead of the
independent 100-digit decimal value 0.7983866285855264. The complement expression
preserves the small unmarked set, and the half-domain case is exactly one half.
An independent Chebyshev-doubling oracle supplies boundary controls; original
input ceilings stay fixed. This remains a floating-point conditional model,
not a measured quantum oracle, general numerical-error theorem or security bound.

#### CodeQL evidence failures remain distinct from security findings

The [read-only exporter](../../scripts/export_codeql_analysis.py) adds separately
named, bounded-category request-failure observations. HTTP status, DNS/TLS/
connection/timeout/protocol categories and deadline observations are retained
without exception text, response bodies or signed URLs. A malformed-response
counterexample showed that the original HTTPException path could leak an
unrelated signed-URL sentinel through generic error text; this path is now
converted to the same safe failure handling. The original request timeout,
overall deadline, no-retry policy, exact source/PR bindings and security verdict
are unchanged. Diagnostic controls cannot supply a missing CodeQL analysis.

#### Remaining qualification boundaries

These changes close specific reader, retention and measurement defects only
after their own committed-source controls and native observations complete.
They do not close cheapest-legal-algorithm/hardware/energy research, arbitrary
Sybil arrival fairness, the fixed public kernel parent, independent operators
and preregistered WAN service, beneficial model releases, whole-chain PQ128 or
production governance. Related PQ4/PQ5 and transparent-proof candidates retain
their own branches and evidence until explicitly reviewed and integrated. The
existing PN0–PN6 production exits remain **OPEN / NO_GO**.

### PN1/I02 — fixed-parent custody and actual static analysis (2026-10-29)

This continuation retains source
`504ccfe6bc4aa504f4a67f73c16040fca5b8e10e` (B), its original failures and all
earlier qualification boundaries. New fixture and reader controls must be
verified on their own committed source. A local control, a complete scan and a
passing host-fixture observation have different scopes; none enables PN0–PN6.

#### Partial process observations retain positive evidence

The [process reader](../../scripts/ci/check_pure_pon_process_cost_v1.py) previously
returned early when a per-thread census was incomplete. A counterexample based
on an actual B partial census retained one successful row containing a child PID
and another row with ENOENT, but supplied an incorrect empty aggregate. The old
local predicates ignored the positive row and accepted the separate ECHILD
quiescence claim. This was a reader-semantic defect, not a demonstration that
modified bytes bypassed an unchanged parent SHA-256 binding.

The reader now checks the saved before-thread row coverage and the union of all
successful child reads before that early return, and checks the same association
at the independent probe entry point. A changing or unavailable after-thread set
remains a partial observation. Unknown usage is not zero, and the independent
ECHILD basis cannot override an actually observed child. The directory negative
control also reseals its synthetic parent bindings and still rejects the
contradictory census. Precommit process/receiver/attacker controls passed 24/23/24;
six original B local/x64/ARM process and receiver outputs remained byte-identical.
The x64 receiver's original qualification exit remained 1.

#### The original x64 failure is not erased

The [B pressure run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40825729556)
retains the failed x64 from-zero receiver supplement. Its 597 samples include
36 with the original freshness upper bound below the 100 ms reservation, but
those samples have cumulative paid debit at most 706,710,672 ns. The 409 samples
with paid debit above 1.9 seconds have a minimum freshness upper bound of
198,714,857 ns. No sample satisfies the unchanged conjunction. All three honest
confirmation rounds and their measured hostile overlap passed. These point
samples neither prove a continuous-time absence of depletion nor establish an
invalid-block acceptance attack. An upper bound is not a lower bound on actual
credit. The B fixed-parent observation was unavailable, so these B measurements
must not be described as running inside the fixed 0.25-CPU kernel parent.

The new fixed-parent experiment keeps the 128/s challenge profile, 0.25-CPU/s
paid refill, 24 hostile actors, 30-second phases and two-second calls. It reports
three distinct outcomes: fixture custody/resource observations, honest service,
and the original paid-depletion predicate. A kernel ceiling over all receiver
work also covers reactors, parsing and observation IPC; therefore a 0.25-CPU
whole-receiver ceiling does not promise that paid W1 debit will continuously
exceed a 0.25-CPU/s refill. Finite-window CFS accounting, initial/carry credit and
discarded refill require their own bounds. No quota reduction or predicate change
is used to manufacture the missing depletion witness.

#### A separate, owned fixed-parent experiment

The separate [fixture owner](../../scripts/ci/run_pure_pon_fixed_parent_v1.py) is
restricted to a disposable GitHub-hosted systemd/cgroup-v2 runner. It refuses an
existing fixed parent or unit. The runtime-only transient slice keeps the exact
original ceilings: `cpu.max=25000 100000`, zero CPU burst, 2 GiB memory, zero swap
and 256 tasks. The unit's nonce/InvocationID, root-owned parent/leaf identities,
boot ID, resource files, memberships and cumulative counters are retained.

One root-opened `cgroup.procs` descriptor intentionally grants migration into
the owned leaf. No root/common-ancestor write permission or capability is given
to the running service. The trusted pre-exec hook writes only zero to migrate
itself; the kernel descriptor capability is broader than a write-zero-only rule.
The descriptor is close-on-exec, and the controller drops its copy before
starting honest clients, sampler and hostile actors. The receiver stays its
controller's direct child for the original wait4 accounting. Three independent
phase controllers reuse the same parent and immutable prepared inputs; this
has a fresh schema and is not the old 90-second campaign. Fork/pre-migration CPU
remains in wait4 and is explicitly outside the cgroup interval.

Only owned, identity-matching, empty assets may be removed. Controller nonzero
exit, reap errors, truncated capture and failed ownership cleanup refuse
qualification. The parent is sampled before process-group cleanup so that a
later signal cannot conceal receiver residue. Root unit identities and held
directory identities are rechecked during partial-creation cleanup as well.
These are finite custody observations, not independent-operator or physical-host
authentication. A positive kernel-parent result requires the real new CI run;
local ordinary-file refusal and IPC controls cannot supply it.
The [new disposable-host workflow](../../.github/workflows/pon-fixed-parent-receiver-v1.yml)
is separate from both original campaigns. It retains the exact compiler's Cargo
artifact record, two real short controls, binary bytes, original controller IPC,
root-held file bindings and independent reader output. Its success condition is
the new host fixture only; the original finite paid-depletion predicate is
reported separately and the previous failed x64 sample remains failed.

The receiver startup handshake now shares one absolute deadline across partial
prefix and body reads, reusing the established control-channel deadline owner.
The original 180-second readiness budget is unchanged. Two new actual native
controls passed before commit: ordinary files cannot serve as migration
descriptors, and delayed/partial readiness frames cannot restart their deadline.
Release/all-features interface compilation and strict Clippy also passed. These
precommit observations remain distinct from committed-source qualification.
The new sidecar brackets the actual deadline-arm operation with monotonic
observations, rather than incorrectly using process-spawn completion as its
exact start. The 180-second value and original read deadline remain unchanged.

#### Actual CodeQL execution is separate from the existing security gate

The [pinned analysis workflow](../../.github/workflows/pon-pinned-codeql-analysis-v1.yml)
executes the unmodified official CodeQL 2.27.3 code-scanning suites and retains
SARIF, every selected query's BQRS, query bytes, source checks, extraction
diagnostics and failures. It uses `contents: read`, no persistent checkout
credentials and no `security-events` writes. The original exporter/default
setup and its failed or missing security verdict are unchanged. Findings remain
findings even when query execution completes.

The official Linux64 bundle is pinned to 558,869,612 bytes and SHA-256
`5e7607e1b721728955e31f5402d460ad227cbd2ffed0d4cc610116755796150e`.
Original query packs are Actions 0.6.38, Python 1.8.13, Rust 0.1.45 and C++ 1.9.2.
The [analysis owner/reader](../../scripts/ci/run_pinned_codeql_analysis_v1.py)
uses the retained bounded process owner, fixed outer phase deadlines, a fresh
database and source checks on both success and failure. Its thread/RAM options
are CLI hints, not a claimed process-family hard resource ceiling.

Independent local B execution completed 18 Actions queries over all 19 tracked
workflows and 45 Python queries over all 384 tracked Python files, with no
reported findings or warning/error diagnostics in those two runs. First Rust
extraction returned exit zero but could not load any of its four discovered
workspaces; all 1,038 Rust inputs lacked semantic analysis. Its 37 queries and
186 hard-coded-cryptographic-value findings are retained as partial results,
with original severity and traces. First C/C++ execution completed 61 queries
with zero findings but successfully extracted only two of three tracked C
translation units. Neither partial result qualifies complete security analysis.

The exact official extractor
[toolchain selector](https://github.com/github/codeql/blob/a1575b98a8cc19bcfa7bb6cb41be688cb3dae65c/rust/extractor/src/toolchain.rs)
selects Rust 1.99.0 for non-nightly projects; its configuration explicitly enables
that toolchain's automatic installation. Diagnostic forwarding retained actual
child commands trying to install 1.99.0 when it was unavailable, while direct
project 1.95.0 Cargo metadata succeeded. Adding only 1.95.0 `rust-src` did not
repair that failure. The independent workflow therefore installs the official
extractor dependency separately. The project/default runtime compiler remains
1.95.0; an analyzer's newer compiler must not be described as native-runtime
validation of another toolchain. Old partial databases and failed observations
remain retained until a new, unchanged-source extraction proves its own coverage.

Installing the official 1.99.0 analysis dependency recovered real main-workspace
semantic loading, but did not establish full archived-source or macro coverage.
That extraction retained 33 warning/error lines and 299 semantic-failure marker
lines, including incomplete historical workspaces and guest macro expansion.
Its subsequent original-query run exited 100 inside CodeQL's relation-cache
reader: a recorded 3,562-byte relation produced a 5,787-byte read. Eleven of 37
diagnostic/metric BQRS files completed; 26 query results and the new SARIF were
absent. No new security-query result or zero-finding result is inferred. The
original failed database, cache sample and logs remain retained. Resource
observations showed neither OOM nor sampled disk exhaustion; the underlying
cache failure cause is not established by the generic exception wording.

The [C analysis compiler](../../scripts/ci/build_pinned_codeql_cpp_v1.py) explicitly
reconstructs the original two-fragment native translation unit as the unchanged
spawn bytes, one LF, then unchanged retirement bytes. Byte ranges, line offsets,
source hashes and generated-file bytes are checked independently. Named-file
input replaces stdin only for analysis; path/line-sensitive predefined macros
are refused. The SQLite analysis uses the exact original 0.37.0 registry
amalgamation/build-source pins, witness input, include macro, 20 explicit defines
and optimization setting. Both original recipe owners are hash-bound; changed
owners require review. These analysis compilations do not execute a native
library or publish the production SQLite build fence, whose loader-override
refusals are unchanged.

The C context is not itself extraction coverage. A composed input counts only
when the original SARIF diagnostics actually name the exact, byte-verified
generated unit; the witness still requires its own direct successful extraction.
The independent context reader checks all four actual command phases, their
logs, completion statuses and compiler output bindings. No missing fragment,
query result or diagnostic is waived to make the analysis green.
The first manual compilation and all 61 original queries completed, but its
generated unit was outside the declared analysis root: the official successful
file diagnostics named only the witness, and independent readback correctly
retained 1/3 tracked-source coverage. That zero-finding partial result remains.
The new runner instead uses one narrow analysis directory containing only an
exact tracked-source copy and the generated build directory. All copied files
are compared byte-for-byte by independent hashes before and after extraction;
symlinks, special files, omissions and extra files are refused. Database/tools
stay outside that root. Diagnostic URI bases and the project/generated prefixes
remain explicit, separately checked mappings, not a blanket coverage waiver.

Reader negative controls retain two additional counterexamples: a configuration
error cannot be hidden behind successful execution, and a foreign SARIF URI base
cannot relabel another source tree as current-source coverage. Missing tools
retain a false terminal and both available source observations. Zero findings,
exit zero or a selected-query count alone cannot substitute for actual coverage.

#### Additional exact-B cost readback

The [complete legal-cost run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40825729541)
and [ARM v2 run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40825729599)
were downloaded with their original GitHub sizes/digests. Independent readback
checked seven actual ELF files, unchanged original summaries, 128 paired
full-outer-cost ratios and the v2 compiled source bindings. Each x64/ARM V5 run
retains 144 cohorts, nine supported legal producers, four horizons, 11,772 first
admissions and 654 distinct paired fixture packets. The ARM v2 run retains all
4,032 cohorts, 702,232 attempts and 58,916 exhausted searches.

The V4 CLI's original absolute packet destination correctly refused a relocated
local archive. That refusal remains; the subsequent explicitly mapped offline
readback used the original semantic and packet-byte readers without modifying
capture metadata. Full outer cost includes admission and storage work and must
not be called a universal marginal mining cost. No new native cost run or full
failed-transcript replay is inferred from this structural readback. Global
cheapest-work bounds, accelerator/energy qualification, arbitrary public Sybil
fairness, independent WAN operation, beneficial Hepta releases, whole-chain
PQ128 and production governance remain **OPEN / NO_GO**.

### PN0/PN1/PN5 — retained CI failures and narrow follow-up (2026-10-29)

Exact source `39e865f453926a2b86565bf69e197a621e74b93c`, tree
`c6101eb1832d76cd2e09f947b6593fbaed8bf98f`, completed 391 local Python
controls and 332 actual native tests. The local 26-step native record includes
both locked Cargo graphs, release formatting, strict workspace/all-target/
all-feature Clippy, the original pressure and separate receiver-owner runs,
retained actual executables and the complete independent W1 arithmetic replay.
Before/after source observations agree on all 6,179 tracked entries and
819,750,990 bytes. These are local observations under the recorded inherited
resource envelope; they do not authenticate hardware or qualify public service.
The same source's [public PoN CI](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40836515063)
completed successfully on both hosted architectures. The earlier exact-B x64
paid-depletion failure remains an original failed sample; new successes never
rewrite it or establish a universal work-cost or fairness bound.

#### Fixed-parent setup: typed absence and temporal evidence

Both architectures of the [first owned-parent run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40836515148)
stopped at the second manager command, before unit creation or a pressure phase.
`systemctl list-unit-files` returned status 1 with empty stdout/stderr for no
matching files. This is a query-contract error in the fixture, not an observed
resource-parent permission failure or a completed failed depletion experiment.
The original artifact ZIPs, both actual ELF files, Cargo build identities,
manager outputs and false qualification records are retained and independently
hash-checked. No historical command output is rewritten.

The follow-up uses systemd's read-only `ListUnitFilesByPatterns` D-Bus method
with an empty state filter and the one exact owned unit name. Absence requires
integer exit status zero, no command error, the exact typed `a(ss) 0` reply and
empty stderr. A missing method, timeout, malformed reply, populated result or
nonzero status remains a failure; there is no compatibility fallback. The
loaded-unit query, filesystem checks, `StartTransientUnit(mode="fail")`, exact
identity/resource checks, single owned lifecycle and safe cleanup remain.
The offline reader requires unique absence commands before creation and
consistent nonnegative integer monotonic intervals in actual execution order.
A retained counterexample moved the absence query's recorded time after creation
and recomputed the outer binding. List order alone had accepted it; the new
reader rejects that contradiction. This is an evidence-reader defect, not a
claim that the original runner executed commands concurrently or out of order.

Python controls cannot demonstrate a real parent creation, migration descriptor,
phase process, accounting interval or cleanup. The new committed source needs
its own two-architecture hosted execution with the original service predicates.
The challenge rate, paid CPU refill, actor count, phase duration, call deadlines
and all public/production qualification boundaries remain unchanged.

#### Separately accessible CodeQL diagnostics

The [first pinned CodeQL run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40836515003)
completed Actions, Python and C/C++ successfully; Rust failed. Its original Rust
artifact is 843,326,935 bytes, above the connected artifact downloader's
536,870,912-byte limit. The downloader refused it and returned no download URL.
The job log alone does not identify Rust's internal failure. The preceding
local exact-B relation-cache error must not be assigned to this different
hosted run without its original execution record.

Independent readback of the three accessible original artifacts verified all
124 original query/BQRS bindings: Actions 18 queries over 21 workflow inputs,
Python 45 over 391 inputs, and C/C++ 61 over three original inputs. The C scope
retains one directly extracted witness plus two original fragments covered by
the byte-verified composed translation unit. Source-copy bytes/modes, actual
compilation records, original diagnostics and official query identities were
checked; these three SARIFs contain zero findings and no warning/error
diagnostics. This limited successful analysis is not a Rust result or a
whole-repository security clearance.

A separate bounded metadata artifact now retains a fixed diagnostic inventory:
original source/result/phase JSON and explicitly partial log tails. It records
missing, oversized, unsafe, changing and unreadable files; each retained tail
has its observed original file size, byte interval and sample hash. JSON files
are limited individually and in aggregate; log tails have their own bounds,
and the entire artifact is below 32 MiB. Reads refuse symlinks, non-regular
files and multiple hard links, use a cooperative deadline and have a separate
outer workflow timeout. The inventory does not infer analysis success,
coverage, findings or security clearance. A successful diagnostic collection
cannot turn a failed scan into a passing scan.

The original large artifact, complete available SARIF/BQRS/diagnostic files,
original official suites, analyzer version, phase budgets and source checks are
retained. No security-events write, finding suppression, query removal, default
branch policy change or substitute required gate is introduced. The new small
artifact makes future failures reviewable through the existing authorized
connector; it does not recover unread bytes of the previous Rust artifact.

#### Cell TCP fixture initializes before publishing an address

Exact B's required prospective-merge runtime failed
`tcp_two_bootstraps_newer_owner_sequence_never_dials_superseded_endpoint` with
`WouldBlock`, `phase=response-header`, after the fixed 200 ms request allowance.
The original failure is retained. Its log alone does not prove the historical
cause or show that a superseded endpoint was dialed.

The test fixture previously opened the real Cell store in its worker after
returning a listener address. The follow-up validates the existing limits,
finishes the store open and sets nonblocking mode before spawning the worker
and publishing its address. Store initialization retains its existing bounded
writer setup. A real SQLite file with an incorrect cache namespace now fails
synchronously; the former fixture returned a peer before that failure. The
negative control uses no sleep, retry or scheduling assumption. The fixed
200 ms request limit, ten-second overall allowance and all real stale/current
connection assertions remain. All 136 data-availability library tests passed
on the precommit Rust snapshot. This fixes premature publication, not arbitrary
host scheduling delays; exact-source hosted runtime acceptance remains separate.

#### Newly observed upstream dependency and proof gates remain open

Both exact-B required-quality lanes rejected four original dependency graph
entries: `bincode 1.3.3` (`RUSTSEC-2025-0141`), `derivative 2.2.0`
(`RUSTSEC-2024-0388`), `paste 1.0.15` (`RUSTSEC-2024-0436`) and
`tracing-subscriber 0.2.25` (`RUSTSEC-2025-0055`). The first three advisories
report unmaintained packages; the fourth concerns ANSI injection in logging.
The current tracing dependency has default features disabled and no enabled
formatter path in the observed graph. This narrows the demonstrated exposure
but does not waive the unchanged dependency gate. The fuzz graph passed. These
main-workspace manifests and lockfile were unchanged by exact B and C.

The current published RISC Zero 3.0.6 and inspected newer upstream source still
introduce parts of this graph. A narrow maintenance route would require real
parent-crate changes: ark-relations' tracing API/dependency, a complete derivative
to educe backport, and seven parent manifests using the maintained pastey package.
It must preserve algorithms, features, provenance, licenses and exact graphs.
Renaming old package source, removing proof features or adding advisory ignores
would not establish maintenance or close the security requirement.

The bounded proof receipt codec requires separate compatibility evidence. The
main succinct receipt and standalone composite host use different accepted
structures and limits. Switching the serialization beneath the same wire magic
without real receipt compatibility tests would introduce a new verifier risk.
Removing a direct main-workspace dependency would also not eliminate bincode
inside the standalone SDK client. No such change is silently counted as done.

The [exact-B complete-proof experiment](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40825729537)
retains native/guest agreement for 13,364,385 user cycles and 62 segments, followed
by the actual 5,400-second prove timeout and no receipt. Its observed waited-child
CPU is not complete descendant CPU accounting, and its resource qualification
is false. It proves neither successful cryptographic W1 verification nor a
lower bound on proving cost. Global cheapest-work and accelerator/energy bounds,
arbitrary Sybil service, complete proof qualification, independent WAN custody,
beneficial Hepta releases, whole-chain PQ128 and governed activation remain
**OPEN / NO_GO** until their distinct original acceptance evidence exists.

### PN0/PN1 — exact-D failures carried into the next candidate (2026-10-29)

Exact D `bd7a9511eb69d77bf448f72232ab9ed66d6cc176`, tree
`fc7879cc21b8f748338880edd246dbd457ff235a`, completed 432 Python controls
and all 24 declared control/check steps. Its separate eight-step native record
completed all 136 data-availability library tests, locked main/fuzz graphs,
release formatting and strict workspace/all-target/all-feature Clippy. Both
records independently verified unchanged source before/after on all 6,181
tracked entries and 819,800,777 bytes. This does not represent every workspace
test or a successful hosted qualification.

#### Owned-parent membership formatting: actual migration succeeded

The [exact-D fixed-parent run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40840801235)
passed the typed absence query and actually created the owned parent on both
architectures. Original receiver observations show the process and all its
threads in `0::/trnmponpublic.slice/owned-….group`, with the migration descriptor
absent and the fixed-parent guard observing the intended group. The Rust
expectation incorrectly omitted the slash after `0::` because
`Path::strip_prefix("/sys/fs/cgroup")` returns a relative path. Strict role
verification therefore rejected the receiver after approximately two
milliseconds. The parent retained its original 180-second readiness deadline;
no phase was armed and no 30-second stress observation took place. Owned cleanup
completed. These samples do not support a permission/migration failure theory.

A shared Rust formatter now restores the absolute hierarchy slash for both
receiver entry and parent-side role checks. The existing native descriptor
control retains its original ordinary-file refusal and adds the two original
D path vectors, an actual `/proc/self/cgroup` round trip, and adjacent-prefix
refusal. A rebound Python counterexample continues to reject an expected or
observed membership string with the slash removed. No membership, descriptor,
privilege, service, budget or cleanup requirement is relaxed.

The original two ZIPs, build/ELF identities, native short controls, all 57 present
binding rows and all 43 missing rows are retained. Independent invocation of the
exact-D reader still exits 1 and reproduces each original summary byte-for-byte.
The initial HTTP 503 download failure is separately retained; the later transport
retry did not rerun a hosted experiment. New actual host execution is required
on the next committed source to test this formatting correction.

#### Small diagnostics exposed the actual Rust allocation failure

All four small diagnostic artifacts from the [exact-D CodeQL run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40840801599)
were accessible and independently checked against their public artifact sizes
and digests, fixed member inventory, source records, phase JSON and retained log
byte intervals. Actions, Python and C/C++ producer records report completed
analysis; this small-artifact readback does not pretend to reopen their full
SARIF/BQRS inputs. Those artifacts remain separately available.

The 25,960-byte Rust diagnostic archive retains the complete 18,219-byte analyzer
stderr with the same SHA as the original phase. Creation completed in about
196.455 seconds with status 0; analysis exited 99 after about 347.951 seconds,
before the original 1,200-second deadline. The actual errors identify Java heap
and off-heap allocation exhaustion, including a Java heap maximum of 1,080 MiB.
This is query-engine allocation failure, not evidence of an OS OOM kill or the
same failure as B's local relation-cache error. C's inaccessible large Rust
artifact still has an unknown internal cause.

Only Rust's explicit analysis RAM hint changes from 4,096 to 8,192 MiB. One
language-specific configuration feeds the create/analyze argv, `CODEQL_RAM`
environment, phase records and result. Other languages remain at 4,096 MiB;
two threads, official suites, no-download analysis, source scope, before/after
bindings and both 1,200-second phase deadlines remain. The declared public
`ubuntu-24.04` runner has a documented 16 GB memory class, but CLI hints are not
hard process-family limits. A bounded `/proc/meminfo` snapshot records actual
readable values without certifying cgroup capacity or future availability.

The failed D extraction also retains 299 semantic-unavailable markers. Logs
report only twelve diagnostic/summary queries completed and no completed
security query. More evaluator memory may repair execution; it does not waive
semantic coverage, supply a missing SARIF, dismiss a finding or authenticate the
original official security gate. The new source must produce its own original
analysis artifacts and undergo independent readback.

#### Complete W1 proof: bounded progress and actual process observations

The old 5,400-second proof timeout has genuinely empty stdout/stderr and no
receipt. The pinned SDK's `--port` interface returns after the entire prove call;
the host previously printed only after strict verification, serialization and
file synchronization. The new optional observer therefore records a separate
bounded host phase journal at entry/return of the SDK call, strict verifier,
codec and receipt write. Its event vocabulary contains fixed labels only, not
proof contents or exception payloads. Partial journals remain partial. Host
`Instant` values have their own epoch and are not subtracted from the owner's
monotonic timestamps. A journal write failure cannot hide an earlier SDK or
verification error or promote a printed success to a successful process exit.

An explicit `--observe-proof` path retains the original full W1, Composite/
Poseidon2 profile, segment power 18, fixed input/image, no-development/no-remote
requirements and 5,400-second work deadline. A narrow held-ELF exec shim
preserves the SDK's `--version` stdout protocol; only `--port` redirects backend
progress into separate capped pipes. The real backend replaces the shim in the
same PID. The host's machine-readable stdout remains separate. Executable
before/after identities, actual sampled executable images and file descriptors
are observations; they are not compiler or physical-hardware attestations.

The process owner retains an unreaped leader, uses non-reaping exit observation,
signals its owned process group before reaping, and records one actual direct
`wait4` result plus separately adopted child rows. Current incomplete cleanup
is a failure. Historical process-family completeness remains unknown even after
successful finite cleanup. Sampled process CPU ticks are not added to nested
wait4 totals. Unreadable, missing, racing or bounded-out process/cgroup evidence
remains explicit; no inferred whole-family CPU or memory peak is reported.
Logging, hashing and sampling overhead stays inside the measured outer work
scope and its original deadline. Cleanup keeps its existing separate finite
allowance; cooperative checks are not hard real-time kernel-I/O guarantees.

Because direct wait4 and the old observer-parent `RUSAGE_CHILDREN` difference
have different meanings, the new process record uses
`pon-w1-observed-process-v2`. Historical process-v1 records and failed artifacts
are not rewritten. The new workflow explicitly requires the proof observer;
legacy compatibility must not allow a changed schema label to bypass required
sidecar/source/phase checks. None of these observations substitutes for an actual
receipt, independent verification, all original negative proof controls or a
quantitative security argument. Complete proof, whole-chain PQ128 and public
service qualification remain separate open requirements.

The original native pressure schedule has also been independently checked:
its shared monotonic epoch is consistent, actors start within milliseconds, and
honest rounds are deliberately scheduled at 1/5/9 seconds while pressure lasts
30 seconds. C's first depletion at 14.56-14.87 seconds follows its third completed
round. No time-origin defect was found. A separately named, predeclared late-round
supplement could test this coverage gap; no such experiment is counted as run,
and moving honest CPU work cannot assume the old depletion trajectory persists.
The original schedules, samples and failed overlap predicates remain intact.

Before publication, the next candidate's real standalone host/client dependency
graph, strict all-target Clippy and eight actual host tests passed with unchanged
selected backend source and a retained test ELF. Two real node controls checked
the cgroup formatter and the original absolute readiness deadline. These are
explicit precommit observations, not exact-commit qualification. The 59 parent
reader, 25 CodeQL, 17 process-owner and 13 proof-reader controls also passed in
their retained author runs; independent reviews retained the original rejected
counterexamples. None of these short tests executes the full W1 prover.
## 2026-10-27: scoped History internal cancellation and durable child settlement

The original #498 continuation now carries the existing CPU/Host/permit checkpoints inside History activation and continuous admission context. Actual two-worker settlement (including a joined failed child) survives cold journal reopen; a cancelled three-block History completion can retry and activate with its original owner. Nine distinct selected native regressions and strict all-target Clippy for M01/Node passed on source/binary-bound Rust 1.95 output. Baseline API/constructor, inventory, formatter and CI-order failures and their repairs are retained in [the complete increment evidence](../../evidence/pon-history-continuity-20261027/README.md).

The P0 continuous History acceptance remains **OPEN**: generic import still lacks an authorized durable per-operation scope. Keeping that path closed prevents unjournaled work but cannot count as completion. Successful durable decode/W1/M06/activation, internal cancellation, actual crash restart and every child settlement must be demonstrated together without resetting debt or disabling import. This increment grants no public-network, whole-workspace, performance or production qualification.

## 2026-10-27: authorized single-successor History and known-prefix process recovery

The follow-up on PR503 parent `081c04e893850a42b539d98d6ccfa659496e99ee`
adds an explicitly authorized, journal-backed single-successor operation. Original
independent validation/activation claims cover paid Page decode, full W1, two
actual M06 children, original admission and internally cancellable activation.
An opaque recovery handle resumes an already admitted exact successor only after
matching the original known settlement and fresh signed claims; ordinary V5
advance/pending/unknown refusals remain intact. The concrete-source fixed Host
permit remains mandatory at the public entry, including loopback.

Actual native evidence now includes seven new passing tests and nine retained
passing regressions on one source-bound unique executable, plus strict all-target,
all-feature Clippy for M01/Node, 34 source-integrity tests and 91 CI-contract tests.
The mandatory process test performs real SIGKILL/wait4 after known validation and
cancelled-activation settlements, then starts a second native process with zero
initial CPU credit, spends fresh selected claims, activates the target, cleanly
closes and reads the journal back. Old receipts remain unchanged and repeated
residual settlement is refused. A separate actual causal negative reproduced the
original protected receiver accepting packet nonce 8 under delegation nonce 9;
the shared original nonce fence now refuses it before Work or children.

The original 25-package graph and Cargo.lock are unchanged. PR503's real CI blob
pin failure occurred before native execution; this follow-up retains all sixteen
checks and explicitly rebinds the three reviewed byte changes. Three earlier
fixture-start failures, the first adapter's nonce failure, the original receiver's
independent nonce failure, and the `/proc` observer failure are preserved in the
[complete increment evidence](../../evidence/pon-history-journal-operation-20261027/README.md).
The [operation/recovery protocol](../protocol/pon-nakamoto-v1/details/CONTINUOUS_HISTORY_OPERATION_V1.md)
defines the exact enabled API and closed-process observation boundary. Synthetic
model bytes and disclosed local test authority keys do not qualify a real model
forward, external Registry2 admission, public Host campaign, independent security
or production operation.

The standard whole-repository Markdown gate was executed and remains locally
blocked by intentionally unmaterialized historical evidence in the genuine sparse
checkout. The failure is retained. All local targets in the new documents exist;
all 53 missing historical link references resolve to preserved Git index paths.
That supplemental check is not a full-checkout gate PASS or a new remote CI result.

**Whole History P0 remains OPEN.** Validation-in-progress, admission-commit-before-
settlement, activation-commit-before-settlement and arbitrary multistep fork/reorg
crashes are not qualified by the known-settled process test. The next independent
V6 research namespace must separate an externally signed owner frontier from
each execution parent, bind effect intent to atomic native SQLite markers,
preserve irreversible local spent anchors and retain unknown CPU splits while
requiring independent conservative closed-process cost evidence. It must actually
recover the validation and activation-commit windows; retaining V5 HOLD alone
does not satisfy that work. V5 signed domains, stored events and production gates
are not to be reinterpreted or relaxed.

## 2026-10-27: History V6 prepaid effect recovery implementation in progress

The independent `restricted-history-effect-v6` research namespace starts from
published V5 `1116ae390e4ed408ab0899e13aec5d1f90f2192c`. It separates signed owner
frontier from execution parent, persists the complete original allowance before
Native work, inserts exact effect markers inside the original SQLite transaction,
and preserves unknown owner/worker CPU splits. Recovery requires independently
signed latest-anchor and actual closed-process evidence whose conservative
reported CPU bound fits that specific original operation's allowance. It creates
no Node effect or CPU credit; later startup and operations need fresh signatures.
The original 25-package graph, Cargo.lock, V5 namespace and production gates stay
intact. The [V6 protocol](../protocol/pon-nakamoto-v1/details/HISTORY_EFFECT_RECOVERY_V6.md)
defines its finite local scope and remaining unqualified cut points.

The first actual build failed with five compiler errors and executed zero tests.
After those repairs, attempt02 compiled on source-bound Rust 1.95 and ran two
passing native controls, two failing process controls and one ignored child
helper. Actual two-worker cancellation/retry/paid close/cold reopen and signed
authority/Host/worker/nonce fences passed. Both guardians actually SIGKILLed and
wait4-reaped their child: reported whole-process upper bounds were 1,061,382,000 ns
for live-worker validation and 351,766,000 ns for activation-COMMIT-before-
settlement, within their original 4,000,000,000 ns allowance. Both subsequent new
native processes refused SQLite mode 0644 under the required 0600 recovery gate.
Neither process recovery is accepted by that result. The unique attempt02 binary
SHA256 is `f20c976eeb9ff94cb758bc6eeafe1ee1c12480b05c8d57e5a1d0c0f6c14adcb9`;
its exact source and failed process logs remain immutable.

The subsequent source repair creates only fresh V6 databases at 0600 and keeps strict
recovery checks. It also preserves actual Native/CPU results across a late
journal-lock failure, adds exact-operation cancellation, and requires matching
journal/SQL validation facts for every stored non-genesis block, cached reuse and
activation. New actual negative controls target a bad product with retained trace
in a deliberately corrupted cache and a late journal mutex fault after actual
COMMIT. Those are final-source negative controls, not a claim that an additional
old-version causal RED was executed.

Attempt03 compiled with source and binary bytes stable and ran **four passing
controls, two failing process controls and one ignored child helper**. The cache
and late-lock negative controls passed, alongside actual two-worker cancellation
and the authority fences. The activation-COMMIT crash was actually killed and
reaped with a 574,086,000 ns reported process upper bound. Its fresh process
reconciled the old unknown operation, cold-started at zero credit, performed the
next real validation/activation and paid close, but final cold journal readback
failed with EAGAIN: two fixture callback clones still retained the original
journal flock. The worker-active observer encountered a disappearing enumerated
`/proc` row and correctly refused closure; cleanup still killed and waited for
its owned child. Neither control is accepted. The immutable attempt03 binary
SHA256 is `e9955faadaa29cdaa13fad6877974a481fe438ffb66ded50d1fe0a6704acf137`.

The next minimal fixture change scopes the callback clones to their live calls.
The observer now actually SIGSTOPs its pidfd-pinned direct-owned thread-group
leader, verifies the stopped state and requires two equal complete parent graphs
within four total observations before the original SIGKILL/wait4. Two small
observer-component runs each executed three passing Python owned-process controls;
the second recorded identical source before/after. Missing rows and denied reads
remain UNKNOWN. Those component results are not native History acceptance. The
raw closure and its parser now explicitly restrict descendant accounting to the
source-bound, non-subprocess native fixture; current parent graphs do not prove
arbitrary historical orphan/adoption closure. The next six native controls remain
pending. Strict M01/Node all-target, all-feature Clippy subsequently passed on
stable source with warnings denied, the original locked 25-package graph and
single-job metadata compilation. Its two earlier failed passes (three library
lints, then two fixture lints) are retained; no lint suppression or gate reduction
was used. Raw attempts, fixtures, source snapshots and byte-verified archives are
retained in [the increment evidence](../../evidence/pon-history-effect-v6-20261027/README.md).
**Whole History P0 remains OPEN**, including separately authorized bounded reorg
continuation and unqualified journal-publication and crash cut points.


## 2026-10-27: explicit journal publication repair candidate

A separate [publication repair signature domain](../protocol/pon-nakamoto-v1/details/HISTORY_JOURNAL_PUBLICATION_REPAIR_V1.md)
selects exactly one complete existing V6 frame and externally pins its prefix and
published anchors. It replays original signatures, nonces and prepaid budgets,
repairs only the same physical file's temporary/final publication names, and
leaves unknown CPU and native effects to the original independently authorized
V6 recovery. Ordinary V6 open, stored events and production gates are unchanged.
The source defines five actual publication SIGKILL cuts, idempotent repair and
fresh-process continuation, plus original-event and physical-tail refusals.
Execution status, exact source/binary identities and all failed observations must
be read from the [increment evidence](../../evidence/pon-history-publication-repair-20261027/README.md).
This design entry is not an execution verdict or closure of startup, partial
frames, signed multi-step reorg, arbitrary process adoption or whole History P0.


### Settled-epoch recovery V1 continuation (2026-10-28 UTC)

The [explicit settled-epoch recovery](../protocol/pon-nakamoto-v1/details/SETTLED_EPOCH_RECOVERY_V1.md)
adds a fresh signature/record namespace for a dead epoch whose final operation
was already durably settled. Both outside signatures, independent source/binary
pins, the exact death receipt and native frontier are required. The full dead
process upper bound is charged conservatively again within the existing lifetime
ceiling, with no refund or invented residual split. An expired budget can authorize
no new work: fresh closure is followed by a separately signed Budget renewal before
a new zero-credit epoch. Generic publication cannot bypass these pins; the new
pinned repair wrapper shares native readback and verifies old event authority at
its original frame time plus current publication authority.

The source-bound native controls cover actual settled-activation SIGKILL/restart,
all five reconciliation publication cuts, repair-process interruption and an actual
expired budget. [Executed observations and retained failures](../../evidence/pon-history-publication-native-20261028/README.md)
record the exact tested source/binary and verdicts. Pending Startup/Close scopes,
signed multistep ReorgContinuation, arbitrary subprocess adoption and physical-host
qualification remain open; this increment does not close whole History P0.

### Startup resource propagation audit (2026-10-28 UTC)

The separate [Startup CPU/cancellation and material reuse audit](../protocol/pon-nakamoto-v1/details/HISTORY_STARTUP_CHECKPOINT_REUSE_AUDIT.md)
examines the frozen runtime's 2.087314423-second Startup CPU refusal. It identifies
two material derivations, unpropagated internal progress checks and two retained
active-State reads. The subsequent implementation passes the original owner checkpoint through
bounded material stages and consuming a private same-Startup material proof while
still rechecking actual file identities, complete hashes, current authority and
native generation. The [frozen runtime's independent hosted result](../../evidence/pon-history-hosted-afc8d6d-20261028/README.md)
is a complete 15/0/1 release run under the original limits. The
[separate implementation candidate](../../evidence/pon-history-startup-native-20261028/README.md)
has nine current-source material tests passed, but its Node compile and complete
19/0/1 group remain pending independent hosted execution. All original 15 methods,
600-second outer bound, 2-second burst, 4-second allowance and four-snapshot limit
remain mandatory; actual new release binaries must be retained and reconstructed.
There is no new signed domain, budget increase, performance qualification or whole
History P0 closure in this candidate.

### Startup wait and retained frontier follow-up (2026-10-28 UTC)

The isolated [wait/frontier follow-up](../../evidence/pon-history-wait-frontier-20261028/README.md)
adds cooperative cancellation and signed-expiry checks inside the original cold
credit wait. A refusal before CPU begin appends the original NotStarted record,
retains the full reservation and consumed nonce/epoch, and creates no CPU receipt.
Settled-epoch recovery now derives its actual frontier from the current epoch's
retained effect markers instead of a later refused request's proposed frontier.
The existing recovery domain, extra whole-process debit and lifetime ceiling are
unchanged. Two additional mandatory methods retain all original 19 methods and the
600-second/2-second/4-second/four-snapshot bounds. New Node compilation and actual
21/0/1 native execution remain NOT_RUN locally and require same-source hosted
qualification. Pending Startup/Close crash scopes and partial initialization remain
open; live pre-begin refusal is not evidence of an unobserved process's nonexecution.

### Explicit first-Startup empty-container closure (2026-10-28 UTC)

The independent [first-Startup closure capability](../protocol/pon-nakamoto-v1/details/HISTORY_FIRST_STARTUP_EMPTY_NAMESPACE_V1.md)
adds a fresh signature/record namespace for one already known failed first
Startup. It requires an exclusively created, privately locked container observed
unchanged from before the original signature through actual SIGKILL/wait4, exact
original intent/journal and independent source/binary/preparation pins. It retains
the original known CPU receipt and predebit and adds a finite whole-process charge
under the original lifetime ceiling. It neither resets Native nor fabricates
NotStarted. Complete interrupted closure records require the dedicated pinned
publication wrapper, original-frame-time validation and current repair authority.

All original 21 methods and the original ignored child helper remain; a new actual
process method requires 22/0/1 with the unchanged 600-second suite, 2-second burst,
4-second operation allowance and four-snapshot limit. Local source/component
checks do not establish Node compile, Clippy or native success. The new same-source
hosted gate must execute the complete group and retain the actual executable.
The document specifies separate persistent stages needed for partial
initialization; the old generic initializing marker is not upgraded into History
or material authority. Whole History P0, pending Startup/Close, partial/torn
records, SQLite cuts and signed multi-step reorg remain open.


### Paid multistep reorg continuation and lifecycle closure candidate (2026-10-28 UTC)

The new `TRNM-HISTORY-REORG-CONTINUATION-V1` domain authorizes a fresh paid
attempt against one sealed partial Native reorganization. It binds the original
intent, prior attempt, old frontier, target, cursor, step and staging digests,
source, executable, actual closed process and outside journal anchor. Preparation
consumes a fresh nonce and management allowance before further work. Each permit
admits only its specified fresh epoch and Startup/Validation/Activation operation
IDs; known cancellation, unknown death and no-progress retries require distinct
signed attempts. Cursor progress does not refund old reservations or permit reuse.
A fresh validation marker remains required, and the final activation retains the
original reorganization intent. Streaming staging inspection preserves the
original 65,536-key and 4,096-byte-value limits without introducing a smaller
aggregate-state refusal.

The separate `TRNM-HISTORY-LIFECYCLE-RECOVERY-V1` domain closes a dead pending
Startup/Close or a known failed Startup after reading the actual retained Native
prefix. It preserves absent, empty, committed-genesis and ready database states;
ordinary paid Startup completes initialization. A missing owner marker is accepted
only through the separately signed proof of an exclusively created empty birth
namespace, original Startup envelope/time, actual death, complete unchanged
namespace identities and an independently pinned held lease. Directory absence
alone supplies no nonexecution authority. Existing first-Startup closure limits
remain unchanged. Neither management event fabricates a successful operation,
rewrites a receipt, resets a database nor grants work authority.

Both domains preserve all prior spent balances and original operation allowances.
Unknown operation debt requires the conservative whole-process upper bound to fit
the original allowance. Known operation debt retains its exact original CPU
receipt; the fresh management allowance additionally covers the whole dead process.
An expired budget can authorize administrative closure but cannot start work. If
pending debt exhausts the current lifetime ceiling, an explicit original-domain,
doubly signed replacement Budget can be bound inside the new management envelope.
Its identity, anchor, sequence, nonce range, unused ID and nondecreasing ceilings
are verified before one atomic journal append. It cannot absorb an old operation
overrun. Specialized publication repair revalidates the exact original event at
its original frame time and holds the same Native or birth-namespace fences;
current publication authority remains independently required.

The unchanged original native lane still requires exactly 22 passed methods and
one ignored process helper under 600 seconds. Two additional mandatory lanes use
that exact retained binary and same-source original terminal: seven reorg methods
and twelve lifecycle methods, each under a separate 900-second limit with no
ignored cases. They cover real committed cursor cuts, cancellation and fresh
attempts, Startup/Validation deaths, final-marker recovery, all five publication
cuts, repair interruption, expired/exhausted budgets, partial initialization,
pending Close and repeated empty-birth recovery. Their reader controls reject
missing, duplicate, substituted or ignored methods. The recent-batch four-lane
acceptance remains separate; its live Store source pin follows the independently
reviewed initialization checkpoint hooks.

This entry describes the implemented candidate and its mandatory execution gates.
Typechecks, formatter checks and observer controls are not native execution
receipts. The original frozen baseline's passing results do not qualify this new
source. Whole History P0 remains OPEN until this same-source original-plus-new
execution and independent adjacent gates pass with actual journals, process
receipts, binaries and cold readback retained. Public deployment, arbitrary
process adoption and physical-host cost qualification remain outside this scope.

### Fresh reorg validation and separate fixed-parent verifier recovery checkpoint (2026-10-28 UTC)

The exact published History head `003d2ad660464ccc3784c9b2a35afcdba868ae50`
(tree `c72d9f188c20b12c8cf6f0dfea85c92f342f67e2`) has separate observed
verdicts. Its [original-plus-new History run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40662127288)
passed the original 22 methods under 600 seconds and all 12 lifecycle methods
under their independent 900-second limit. The reorg lane passed one method and
failed six at fresh Validation with `REORG_IN_PROGRESS`. Those failures remain
failures. The [original native campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40662127440)
failed all three declared runs at the actual public kernel-parent boundary;
the outer four-CPU service was not the verifier's original fixed quarter-CPU
parent. Its [four recent-batch lanes](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40662127467)
are distinct adjacent observations and do not replace either failed gate.

The fresh Validation branch now requires the already reserved current operation,
exact Page and packet digest, current task binding and original frontier before
examining a continuation. An existing permit must match that exact operation and
the complete current cursor/steps/staging snapshot. The original pending replay
then rechecks the actual SQL target, current namespace, network, time and exact
stored packet bytes. Reuse still requires the original validation fact in both
the journal and SQLite. Only the new paid operation can write its new epoch's
validation marker. Without a continuation, ordinary pending-reorg refusal remains.
The original seven-method reorg lane includes five actual cut-and-reopen negative
subcases: changed stored proof, removed SQL fact, cursor drift, internal cancellation
and resource withdrawal. Old nonce, old epoch and another target must leave the
journal unchanged; known native failures must retain the full new allowance and
produce neither a marker nor additional cursor progress. The original 22-method
missing-journal-fact control remains mandatory.

The original campaign now places its actual public History importer in a separate
unprivileged process under the unchanged administrator-provisioned
`trnmponpublic.slice`: `cpu.max=25000 100000`, 2 GiB maximum memory, zero swap
and 256 tasks. Producer, attackers, receiver and observer retain the original
outer four-CPU/16-GiB service, original 30-second windows, three rounds, 24 attackers,
seed inputs and three predeclared complete 600-second runs. The actual release ELF,
request bytes, response bytes, calling-thread/process identity, original strict
kernel checker, final Node close and empty fixed parent are retained. Whole verifier
process CPU and whole fixed-parent CPU have separate scopes; nested intervals are
not summed or relabeled as outer-process CPU. No production importer, consensus
predicate, admission budget or wrong-parent refusal is weakened.

The strict reader binds every actual import target/cursor and confirmation
transaction/block/result to the original phase, and binds the final snapshot to
the original client tip. The recovered reader bytes are SHA256
`9f503d0770e206114733bfd6e585f531f4c224a8a2b70b43ba6c3456aa11a327`.
A new three-method synthetic fixture re-executed 24 boundary mutations and
19 coherent semantic substitutions: the old reader accepted all 19 semantic
substitutions, while the recovered reader rejected all 43 mutations. Rehashing
all changed IPC digests does not make an altered target or result acceptable.
These are reader controls, not execution evidence or independent host attestation.

This checkpoint is reconstructed from the exact published head after loss of the
unpublished local candidate; it does not claim to restore that candidate's tree
or transfer its checks. New Rust formatting and reader controls do not establish
typechecking, native reorg completion, recent-batch acceptance or campaign success.
The original 22/600, new 7/900, new 12/900 and all four adjacent lanes must execute
this new source and actual binary. Controller SIGKILL currently retains only the
finite systemd runtime/stop backup; capability-bound controller-death propagation
through Node setup, import and the final report remains a separate open obligation.
Whole History P0 and public-service qualification remain OPEN.


### Private controller lifetime through native verifier exit (2026-10-28 UTC)

A separate increment now binds the isolated public History verifier to its actual
controller lifetime. Before launching `sudo -n systemd-run --pipe`, the controller
creates an anonymous Unix socketpair, opens only its own kernel pidfd and queues
that descriptor through `SCM_RIGHTS`. The service receives the original socket
endpoint as stdin. Numeric peer credentials are consistency observations, not an
API for selecting another process or authority granted by a same-user listener.
Named/abstract sockets, wrong or missing descriptors, extra rights, truncated
ancillary data and changed protocol bytes are refused. The actual pidfd type is
checked with `waitid(P_PIDFD, WNOWAIT)` without requiring an inner `/proc` mount.
Unsupported platforms return an explicit error before Native work.

The verifier arms a real polling thread and completes a readiness handshake before
opening Node. That thread holds the pidfd and socket until the entire helper's OS
exit. Returning from the Node runner, unwinding a native failure or entering the
outer report serialization/fsync tail cannot disarm it. Kernel-visible controller
death, private-channel EOF, unexpected data or observation errors cause the helper
to exit itself with status 137; no arbitrary PID or process group is signalled.
This is asynchronous termination, not an atomic guarantee of zero additional
instructions after controller death. It does not manufacture a clean Node close,
a successful settlement or a completion report. The original systemd control-group
kill mode, 240-second service ceiling and five-second stop backup remain in place.

The pinned libc-only module was actually compiled by Rust 1.95 with `-D warnings`
and executed as six parent controls, with one explicitly invoked process helper.
The final standalone ELF SHA256 was
`65130b3710e21a3dd2e7b59726e26cf25e65e971a14aecd4240011babcb421ec`.
The controls cover actual controller SIGKILL even while a separate process retains
the socket peer, EOF while the controller still lives, an already-dead controller,
normal exec/return, incorrect capabilities and later protocol data. The failed
restricted-environment run and the failed overlong pathname fixture are retained;
they were not rewritten as successes. These small controls do not qualify the
actual systemd launcher, Node or original campaign.

A new mandatory, separate 600-second lane reuses the exact retained release ELF
from the original campaign build. It verifies the full source before/after, original
compiler artifact profile and every retained executable byte, executes the six
small methods, and executes three distinct systemd/Node controls under individual
180-second limits. They kill only the still-owned controller Child after actual
Node open and before seeding, after a successful original strict public import and
before its IPC response, or after real Node close and runner return but before the
outer report. These labels describe actual call boundaries; they do not claim an
instruction-level kill within W1 arithmetic. Each case requires actual main-process
`CLD_EXITED`/status 137 and an empty unchanged fixed parent within five seconds,
observed before any administrative stop. Failed units are retained for this
observation and only then reset. Cleanup cannot supply a passing result.

The death controls use their own empty-seed/one-legal-packet fixtures and cannot
replace the original 1024-transfer campaign. The outer four-CPU/16-GiB/Nice-10
limits and the verifier's original fixed quarter-CPU/2-GiB/zero-swap/256-task parent
remain distinct. The original campaign keeps its three 600-second runs, 30-second
windows, three rounds and 24 attackers. Its ordinary reader rejects death-control
jobs, requires the same private owner observations at Node open and close, and
retains all original target, cursor, confirmation and cost-scope checks. Its three
synthetic methods now cover 57 refusal vectors; a separate seven-method reader
suite covers the new death-boundary evidence, build/source binding, exact method
rosters and finite deadlines. Neither synthetic suite substitutes for native runs.

The public fixture's only additional shared-entry change is a three-line tail hook.
Its independently reviewed recent-batch source pin is
`1e02fb6659984e49830737b7665ff26d26ffbc39`; the other fifteen pins remain unchanged.
This increment's full crate typechecking, actual three systemd/Node kill controls,
original campaigns, original 22/600, reorg 7/900, lifecycle 12/900 and four adjacent
lanes still require same-source hosted execution. No earlier source's success is
transferred, and whole History P0 remains OPEN until the applicable evidence closes.


### 2026-10-28 — History fixed-parent provisioning and serialized confirmation follow-up

The exact `9360088c5e48c1a0ed4209744bd41cbe544d0489` campaign stopped before
native build because its fixture required `LoadState=not-found`. The failure
artifact is retained. The failing host's complete unit properties were not
recorded; implicit loaded slices are a source-supported candidate explanation,
not a claimed observation of that host. The new fixture retains the actual
manager state and unit search paths before making any change. It accepts only
an inactive, dead, fragment-free, drop-in-free, non-transient unit with no job,
no alias, no kernel parent and no unit/dependency configuration on disk.

The original source-pinned 25% CPU, 2 GiB memory, zero swap and 256 task slice is
created exclusively. A root-only `/run` lease binds the workflow run and attempt,
unit identity, file device/inode and hash. Writable output receipts are evidence
copies and cannot authorize cleanup. Configured, active, replaced or foreign
parents are refused. A separate real systemd probe checks fresh creation,
duplicate refusal, forged-copy refusal and owned cleanup inside the original
four CPU, 16 GiB and nice 10 ceiling. Its 90 second helper lifetime and 120 second
administrative service ceiling do not change the three original native 600
second campaigns or the 600 second lifeline lane.

The same exact source's strict all-target build exposed an E0609 error in the
multiprocess campaign: the isolated verifier returns serialized JSON, while the
confirmation check still used Rust struct fields. The follow-up reads the same
four fields with strict JSON boolean/integer comparisons, preserving confirmed,
not finalized, no execution authority, and depth exactly six. Missing or mistyped
fields fail closed. The recent gate's exact public test blob pin is updated to
these bytes; all other pins and native budgets remain unchanged.

The new predicate controls and source checks alone do not certify Node, systemd,
History settlement or a successful campaign. New exact-source cloud gates must
run, and the original failed provisioning and compiler observations remain part
of the evidence history. No production protocol, persistent schema or activation
path is disabled by this fixture repair.


### 2026-10-28 - Preserve the owner-lifeline descriptor check under pinned Clippy

On exact candidate d832759a21fab745d6e454f08a78e9309cae1b06, the real
fixed-parent creation/duplicate/forged-copy/cleanup probe and subsequent fixed
History parent provisioning steps completed successfully. Full raw artifact
readback and the original native campaigns remain separate required evidence.
The recent x64 head lane completed its business controls but strict Rust 1.95
Clippy rejected one manual remainder check in the existing SCM_RIGHTS parser.

Replace that expression with usize::is_multiple_of while retaining the exact
descriptor-payload divisibility predicate, rejection path and all fixed bounds.
No lint allow, new domain, test removal, timeout increase or skipped owner-death
path is introduced. The existing pathname-only official distributed inventory
is regenerated and checked; its 1052 entries remain byte-identical, and
include_bytes! binds the updated helper at compilation. Source and formatting
checks alone do not qualify the complete native History/activation path.
All original cloud gates must execute on the new exact tree; the d832 Clippy
failure is retained rather than relabeled as success.


### 2026-10-28 - Fresh current-path kernel reads preserve every History progress fence

Exact d832759a21fab745d6e454f08a78e9309cae1b06 completed the real fixed-parent
probe, provisioning and cleanup and all six lifeline methods plus three actual
Node/controller-death boundaries. Its original three native campaigns all failed
under the retained 30-second phase and fixed 25-percent verifier CPU ceiling.
The baseline first round reached its first confirmation after 45.48 seconds;
its 92 additional account-graph checks consumed 9.722 seconds of nested CPU.
The original 22 History controls and nine material controls passed, while strict
Clippy stopped the full gate; reorg/lifecycle followups were not credited. The
8909154 followup repaired that lint and its four recent lanes passed, but its
separate original native campaign still failed. All failed raw artifacts remain
failed evidence, never a replacement for same-source successful native gates.

Use a fresh-open, stack-buffered text reader for current kernel observations.
Every original progress callback still reads the current boot identity, parent
identity/mode, actual calling-thread membership and all five resource limits.
File opening still checks the current path and current credentials on EVERY
call. There is no descriptor, contents, permission, authority or quota cache.
Short reads continue to real EOF, Interrupted retries, and late errors or invalid
UTF-8 cannot qualify a successful prefix. The existing 128-byte quota recheck
uses a 129-byte refusal sentinel; initial limit parsing, boot identity and
thread membership retain their original accepted-length behavior. All original
CPU, cancellation, revocation, resource and native validity checks remain.

Five reader boundary controls cover exact/oversize input, short/interrupted
reads, late I/O and UTF-8 errors, current replacement/removal/permission behavior,
and a real distinct calling-thread procfs read. The four recent lanes require
all eleven original kernel-boundary tests plus those five controls, retaining
the original job budget. A separate Rust 1.95 local real procfs/sysfs diagnostic
observed 669.88ms versus 329.47ms for 20,000 seven-file iterations; this isolated
I/O result does not predict or qualify the original campaign. No 30-second
window, 25-percent kernel ceiling, worker count, W1 semantics, signed domain,
stored namespace, test requirement or native campaign budget is changed.


## Ordinary History graph resource fence v1 — recovery candidate, 2026-10-28

The previously published `4086f6c2de16f0726893d202b4af9020cd65618d` retained all original 22 History, 7 reorg, 12 lifecycle and four recent-lane functional gates. Its three independent original fixed-budget propagation runs still failed receiver/client state equality. Those failures remain failures. This candidate introduces the explicitly selected `history-account-graph-resource-fence-v1`; it is a new resource observation policy, not an equivalent timing optimization of the strict profile. No production activation is claimed.

Only the ordinary History API may select this policy. Signed V6, continuous and mining owners keep their original strict entry points. A private typed account-graph cursor emits entry, every node ordinal, final relation and exit. Original CPU/cancel checks, actual SQL reads and the complete graph relation remain on every original node. Fresh complete kernel checks occur before entry, node 0 and every eight node bodies, final relation, exit, ordinary boundaries, real admission/activation commit and settlement. The kernel checker itself retains no descriptor, value, permission or successful verdict cache. A persistent resource change is detected within eight bounded node bodies; this is not a wall-clock revocation guarantee or a claim to detect changes reverted between observations.

The new policy key and random epoch nonce are atomically coupled to the original durable public CPU marker. Full fences freshly read both markers from one bounded SQL snapshot; actual commits also recheck the original connection's uncommitted view. No profile switch can clear an active epoch, grant CPU credit or discard unknown debt. Known same-process settlement refusal holds a private live capability for a real retry after the original parent is restored; it neither serializes that capability nor permits cold debt recovery. Original strict next work and explicit v1 next work must run after successful known settlement. Existing V6 recovery and journal/nonce behavior remain independently required.

The original 22/7/12 workflow jobs and their native budgets are unchanged. The propagation workflow has separate strict and v1 lanes, each with all original three complete runs, three 30-second phases, original signed work, original 25-percent verifier CPU, 2-GiB memory, zero swap, 256-task cap and original confirmation criteria. Each result and artifact names its selected profile; a strict failure cannot be overwritten by a v1 pass.

A separate 1800-second physical lane reuses the same actual executable retained by the original 22-test gate. It declares 23 finite cases: offsets 0 through 7; original strict next-node refusal; entry/final/exit/admission/activation/settlement refusal; burst, memory, swap, tasks and permission mutation; actual whole-process migration with a nonleader verifier thread; same-executable strict/v1 complete import and cold byte equality; and public-entry failure followed by same-live-domain settlement, ordinary strict import, another v1 import and cold readback. Each case retains its original 60-second limit. The privileged guardian verifies its root-owned exclusive parent lease and actual systemd MainPID, pins a pidfd and checks the actual executable and nonleader membership. All privileged case-file reads and writes use a directory descriptor opened component by component with `O_NOFOLLOW`; replacing the unprivileged case pathname cannot redirect privileged writes. Final receipts use no-replace publication. Records are observations, not administrative authority or independently authenticated remote proofs.

Recovery provenance: the earlier unpublished 32-file stage4 candidate and old raw logs disappeared with the workspace. The retained native executable was SHA-256 `0cb89255895fb15c0bb0840508fc0a5d9d4a30cfc29e1f959b8cf52ed7d8771d`; its embedded source recovered all 19 changed native files byte-for-byte. A new actual invocation of that unchanged executable passed 16 controls and left only the explicit physical helper ignored. The non-native reader/workflow/document changes are newly reconstructed and reviewed; this candidate must receive its own source tree and raw validation. Neither the old stage4 tree nor vanished logs are claimed recovered. Physical controls and complete v1 propagation are NOT_RUN until their actual source-bound hosted results are read back.

### 2026-10-29 - Retain both owned cleanup actions and prepare a paired observation

The original campaign's cleanup and final-retention shell steps inherit Bash
`-e`. Their `set -uo pipefail` did not clear that setting: a failed probe cleanup
could prevent the fixed History parent cleanup, and a failed final source check
could prevent retention of partial artifact hashes. Explicitly disable errexit
in those two safety steps, retain both original commands, capture both statuses,
and still fail unless both required actions succeed. The root-only exclusive
lease remains cleanup authority; an output receipt does not grant it.

The additive same-runner diagnostic executes both original profiles in one
predeclared order, pins all twelve shell step bodies, and compares the retained
ELF bytes, complete source records, host boot/CPU/affinity and original inputs.
Every arm retains its 80-minute ceiling, each campaign its original 600 seconds,
each phase 30 seconds, and the original fixed parent and paid-depletion rules.
The independent lifeline retains its original twelve-minute step ceiling.
Strict failure cannot become success because the N8 arm passes.

Controller interruption sets a cancellation flag across subprocess creation;
timeout/cancellation signals only a freshly created, unreaped process group.
The final group kill precedes reaping, including a TERM-exiting leader with a
TERM-ignoring child. A separate workflow `always` step invokes only the pinned
root-lease cleanup after controller failure or death. Its safety time is separate
from the native work budget and cannot certify late useful work. Failures and
cleanup attempts are retained separately. Actual process controls and fake sudo
dispatch negatives test these orchestration boundaries; they do not prove actual
systemd cleanup, cgroup quiescence, paired measurements or History P0 completion.
Those hosted observations remain required on the exact newly published source.

Each arm also records the complete original step roster and requires every step
to execute and finish with zero status, without timeout or interruption. Existing
successful source/ELF/native records cannot hide a failed final source check or
artifact inventory step. A signal received during the final safety cleanup is
retained as controller cancellation and prevents normal success while cleanup
continues. Synthetic successful-record controls retain both these negative
cases and the positive all-steps-complete path; none is a native qualification.

### 2026-10-29 - Additional pure/raw-W1 ordinary History integration

Add the explicit research namespace `public-pure-pon-history-raw-development-v1`
on the `96f5e502d677fa37d53e0241208ce228a913d907` History implementation. Its signed
policy binds zero ticket bits, canonical acknowledgement nonce zero and a zero
search budget. The historical protected constructor, signed IDs, actor jobs,
tests and workflows retain their existing behavior. Pure configuration refuses
arithmetic, rejection-cache and native-growth overlays; the original complete
raw W1 checks and ordinary journal/activation/History paths remain enabled.

The separate strict/N8 selectors preserve every original workload, CPU/memory
limit, deadline, paid-depletion, overlap, full-state equality and confirmation
predicate. Their independent reader refuses protected or nonzero-search
receipts and requires the original real verifier IPC, fixed-parent and lifeline
evidence. Its synthetic controls and actual TCP/CLI component controls cannot
replace a source-bound hosted fixed-cgroup execution. The additive workflow has
its own concurrency group and artifact names and preserves failed/partial runs.

See `PURE_HISTORY_RAW_JOINT_V1.md` for the exact signed vector, CLI, selectors and
evidence boundary. This integration does not claim that the original failed
protected campaigns passed. Hosted pure campaigns remain unqualified until
their actual frozen-source results are read. Existing clean-close and owner-death
receipts do not by themselves close mid-journal/activation crash recovery or
all durable child settlement; that additional fault/restart work remains open.

## 2026-10-29: explicit pure/raw History convergence candidate, not qualification

The isolated convergence candidate combines fixed pure-PoN/model source
`0c762c561644f28f7f80e06babdc16f5225b5c70` with fixed History source
`98873ccfbb4a416218c49df39082f0b3a842b5c8`. An explicit serialized admission
variant separates raw History from the already existing zero-bit pure-v1/v2
profiles. Old policy JSON and signed identifiers remain unchanged; the raw
profile keeps its separate published identifier and refuses arithmetic facts,
product prefilters, rejection caches, growth and implicit v2 conversion.

The storage adapter carries typed native progress through held-I/O snapshot
reads and writes while preserving final actual State/namespace/transaction
checks. Account materialization still performs every original per-node strict
checkpoint. The pure-PoN completion hook remains after current registered
task/material and the second parent SQL epoch check, before full M06 execution;
it grants no block authority and creates no new CPU credit.

The actual pure History run `40865924107` at `f8b79050282fe0561b9cae1a8253e735d7fb0f6c`
failed both three-run arms. Its owner-death lane separately stopped because
the build reader did not recognize the new pure campaign schema. A reader
regression reproduces that error before the fix; the corrected reader accepts
only the exact pure source/profile/selector/zero-search binding, retains all
source and ELF checks, and leaves the failed campaign verdict unchanged.
Its eight reader methods pass; this is not a native owner-death execution.

The full Rust convergence source still requires exact-source compilation,
cross-profile native controls, strict Clippy and the original protected
resource campaigns. No old eight-bit result, reader control, syntax check or
textual merge closes pure History service or durable recovery qualification.

#### P1 native PQ transfer slice — 2026-10-27 (RESEARCH / OPEN)

The [fresh NPQ1/PQP1 native transfer composition](../protocol/pon-nakamoto-v1/details/NATIVE_PQ_TRANSFER_V1.md)
continues M00/M01/M05/M06/M15 in one explicit fresh namespace based on PR 504
`829c5d28ec9a0fc13de2bd098b477cbacacdb4b7`. The opaque `PqNodeV1` delegates to
the original Node. Full ML-DSA signature and SPKI bytes enter original M05/M06,
with exact header-time expiry, current three-leaf authority State/root, pure PoN
work, original SQLite/deltas/ancestry and branch activation. Full 6,129-byte
transactions retain the 524,288-byte budget (85 at maximum size). No dummy
Ed25519 envelope, implicit old-store/profile fallback or transport installation
is allowed. Chain nonces may reorg; local pool ordinals/removal history may not.

Source-bound M00/M06 subset results and Node metadata checks are recorded
separately from the actual native integration attempt. Retain every original
failure and exact compiler/source identity; a metadata check is not runtime
acceptance. The new controls cover cold reopen, real heavier forks/requeue,
randomized-signature duplicates, exact expiry/MTP/overflow, whole-byte caps and
interrupted original reorganization. Their actual terminal records govern any
pass claim. The original workspace/native/security gates remain required.

This first slice only accepts genesis-registered, generation-one PQ accounts.
Registration, key rotation/migration, other tags, transport/governance and Hepta
final-use remain open. Fresh public test balances are not a deployed asset
migration. Shor-compromised old Ed authorization cannot be repaired into a
unique original identity merely by adding a second signature. Neither this
transfer path nor the existing PQ component closes quantum W1/proof security,
physical rollback, physical I/O or production activation. **P1 / NO_GO**.

#### P1 native PQ accounts v2 — implementation in progress, 2026-10-27

The approved successor is a fresh `pon-native-pq-accounts-v2` / NPQ2 / PQP2
namespace. The original NPQ1 and PNX1 profiles stay distinct. M00's actual
four-case syntax run passed on a recorded 1,156-input working increment;
this was unverified framing/signing-core validation, not native authentication.
Exact NPQ2 sizes are 3,751–4,263 for ordinary transfers, 9,272 for dual-key
rotation and 9,432 for a separately anchored two-PQ-proof migration claim.
The unchanged 524,288-byte budget therefore has serialization ceilings of
122 full-memo transfers, 56 rotations or 55 claims, not measured throughput.

The implementation now connects actual current State key resolution to the
original M06 prepared carrier and reuses the original tags 2–5 task owner.
Positive transfers or mature PoN rewards can fund pending nonzero accounts;
registration consumes a real proof and a fee, without a runtime key whitelist.
Stable account identity survives generation changes; current and retired key
leaves remain actual State/root inputs. All signature roles bind the complete
new-domain statement. An authority-changing sender is exclusive within one
block in either ordering. Ordinary signatures omit repeated SPKI; registration
and new-key possession carry it. Chain nonces and branch key State can reorg;
independent local operation/removal history must not rewind.

This is under construction. Original Node constructors currently refuse this
new profile until its separate opaque wrapper and selected packet/store/pool
path are complete. Fresh genesis supplies no migration anchor; role 5 refuses
instead of granting claim authority. The protected trusted-PQ-checkpoint
constructor, complete conserved account/task/reward import, conditional claim,
real pool/full-W1/SQLite/cold/reorg tests and the remaining inner signatures
are required later work in this same slice. Its migration assumption must be
explicitly independent of the old repository; a copied checkpoint or successful
Boolean does not supply trust, and Shor-forgeable Ed signatures cannot repair
original ownership. Registration base fee 200 and rotation/claim 400 plus full
byte fees are research parameters, not a proven CPU/storage price. Other
permissions, transport, W1 security and production remain **P1 / NO_GO**.

The first M06 v2 composition gate then actually passed two real-ML-DSA tests
(90 existing cases filtered, no ignored new cases): funding/registration/current
State transfer/zero credits and dual-key rotation with original task permissions
and both-order authority-change exclusion. Its 1,159 input files were unchanged
before and after. The prior compile failure in a retained Config test initializer
is preserved; only explicit absence of the new profile was added there. These
are M06 tests, not full PoN Node admission, cold/reorg, migration or CI acceptance.

The migration implementation now pins an independently selected prior PQ registry
and a source checkpoint through a protected, non-wire constructor. The source
account/task/reward projection is complete and conserved; positive unsupported
liabilities, missing/extra registry entries, ID collisions and untranslatable
windows refuse. Actual M06 attempt 04 compiled and ran: two existing cases
passed, two new migration cases failed at the original continuity reward-queue
check. That failure and its exact 1,160-input source remain retained. The new
profile now accounts for byte-identical anchored pre-genesis reward rows within
the original 20-block maturity window, using the original mandatory reward
payment and original root. Old profiles still require the original exact queue.
No test result after that correction is claimed here; native source-checkpoint,
PQP2/store/pool/cold/reorg composition and all production qualification remain open.

M06 attempt 05 then actually passed all four selected PQ2 cases (90 existing
cases filtered, no ignored new cases), including two genuine-proof migration
cases and the original funding/rotation cases. The imported reward is paid at
its translated height by the unchanged mandatory owner, with conservation and
queue reservations checked before and after. The source Header in these unit
cases is expressly synthetic and unverified: this result does not qualify
native source-chain work, Node admission, cold replay or reorganization.

The separate PQP2 packet projection, opaque `PqNodeV2`, selected authenticated
SQLite schema and original M05 pool adapters now pass an actual locked/offline
`cargo check -p trnm-pon-node --lib` (1,163 stable inputs). This is compilation,
not native execution. The raw NPQ2 digest and semantic statement use distinct
SQL tables; original PNX1/PQP1 constructors and schema IDs remain explicit.
Real Node cases for open mining/registration, two-key rotation, permissions and
conditional source migration are next; no successful block or reorg is inferred
from this metadata check.

The first nine-case native integration metadata gate then failed before execution
because the fixture accessed private `Settings` fields. Its complete source and
compiler diagnostics are retained. The corrected source keeps those fields
private, exposes only read-only signing inputs and adds an original-Node source
checkpoint exporter that rechecks actual full W1, State/root and the pinned active
tuple while refusing controlled owner/service paths. The new test target includes
real reward-funded registration, dual-key task permissions and actual source-chain
checkpoint/claim/cold/heavier-fork composition. It has not yet executed. Shared-host
phase timing records are observations, not worst-case CPU or throughput bounds.
The implementation boundary, exact frame sizes, independent migration trust and
remaining gates are recorded in
[Native PQ accounts v2 research](../protocol/pon-nakamoto-v1/details/NATIVE_PQ_ACCOUNTS_V2_RESEARCH.md).
All prior failed observations and the original acceptance gates remain required.

An independent [authority-command capacity continuation](../../evidence/pon-pq2-authority-capacity-20261027/README.md)
now executes the distinct 56/57 dual-key-rotation and 55/56 anchored-claim byte
boundaries through the actual public M06 entry with genuine ML-DSA proofs.
The final formatted integration source passed both cases, with 112/110 actual
signature verifications on the accepted cohorts, exact account/nonce/claim
checks and no imported-supply reissuance. It was compiled as an isolated native
probe linked to the original frozen compiled PQ2 libraries; this is not a full
Cargo workspace or Node run. The migration checkpoint in these two component
controls remains an explicit synthetic trust fixture. The dedicated runner now
requires both exact integration names, and retains the original compilation,
sparse-dependency and inventory failures. No protocol, monetary or activation
rule changed; the original native/reorg/physical/migration-trust exits remain.

That continuation also independently reproduced a native capacity-test failure:
the fixture compared the original pool's cumulative pending-prefix count to the
latest group size. The correction now checks both cumulative admission and ready
metadata counts, retaining the original 122/123 byte-limit and complete Node path.
The patched full nine-case target then actually passed with zero filtered or
ignored cases in 64.03s, with 196 valid phase observations and stable test/source
and 102-library hashes. This includes actual registration, rotation/task
permissions, source-Node checkpoint migration, cold reopen and heavier-fork
recovery. It reuses the immutable original compiled libraries and is distinct
from the incomplete prior Cargo command, whose terminal remains unavailable.
The two changed Rust targets pass direct warnings-denied Clippy; full workspace,
physical I/O, other permission paths and independent migration trust remain open.

#### P1 explicit NPQ3 quota continuation — 2026-10-27 (implementation / OPEN)

The [fresh NPQ3 quota profile](../protocol/pon-nakamoto-v1/details/NATIVE_PQ_QUOTA_V3_RESEARCH.md)
addresses the original quota consumer's inner Ed25519 authorization separately
from the provider envelope. Both actual ML-DSA proofs now resolve current keys
from the selected parent State; the consumer comes from the actual quota row.
The original M06 quota reserve/fee/settlement owner is shared, while original
NPQ2 codecs, settings and stores retain their exact explicit selection. Fresh
NPQ3/PQP3 signing, network and SQL namespaces never negotiate a fallback.
Both participants are included in authority-change exclusion in either block
order. The provider nonce remains the replay owner; original chain reorganization
may restore nonce/generation, with actual pool reauthorization required.
The full dual-proof frame is 7,314 bytes; eight M06 controls and five native Node
controls require the actual 71/72 byte boundary, dual cryptography, rotation,
replay/fees, complete W1, SQL, detach-cut cold recovery and heavier-fork recheck.
A separate explicit NPQ3 trusted-migration constructor composes the original
anchor projection with a same-profile real-source checkpoint/claim/quota-consumer
case; independent prior trust and source retirement remain external premises.
Source wiring is not runtime acceptance; the [retained observations](../../evidence/pon-pq-quota-v3-20261027/README.md)
and exact-head workflow must record actual execution, including failures.
Remaining tags 6–9/12–24, independent migration/retirement, custody, transport,
History and Hepta Final-use authority remain open. P1/whole-chain PQ and production
activation remain false.


#### P1 NPQ3 source-native closure continuation — 2026-10-28 (component / OPEN)

The [actual continuation](../../evidence/pon-pq-quota-closure-20261028/README.md)
retains a three-pass/one-fail native run: a valid NPQ3 imported-account claim
reached the migration apply owner and failed its hardcoded NPQ2 decoder. The fix
selects the already pinned profile without negotiation. The final native quota
cohort includes full 71-command dual-ML-DSA pool/complete-W1/SQL/cold-read capacity,
72-command rejection, actual trusted checkpoint claim, consumer rotation,
detach-cut recovery and branch reauthorization. Provider rotation, consumer
registration and parent-only quota resolution also have actual M06 controls.
All existing NPQ2 and NPQ1 native cases remain required; no function is permanently
disabled to complete these controls.

The current source is tested through an explicitly recorded native linking graph,
with immutable external artifacts; full Cargo build/all-targets/all-features
qualification is not inferred. The exact locked/offline graph separately resolves
173 packages/26 workspace members with an unchanged lock. This continuation uses
the prior owner's trusted-migration commit `0fc50c0701e0bfc94faa8c48df5957956cc6b8a3`
as its parent, preserves prior failures and records final source/command/binary
identities. Independent migration trust/source retirement, the remaining authority
owners, physical I/O, whole-chain PQ and P1 completion remain open.

#### P1 PQ legacy-reader and hosted Cargo follow-up — 2026-10-28 (component / OPEN)

The [strict reader continuation](../../evidence/pon-pq-legacy-reader-20261028/README.md)
recognizes the exact NPQ1/2/3 `selected_ddl` and packet-profile joins, the explicit
constructor guards and the original legacy header projection. It still returns
only the unchanged 4,775-byte legacy V2 schema. PQ, authenticated, shared-account
and growth schemas or packets cannot borrow that legacy evidence scope. All 53
prior methods remain; the complete expanded reader run executes 74 methods,
including real SQLite/packet negatives and joint-token/literal-prefix controls.
The prior strict-reader refusal, two original-parser false accepts and the first
67-method continuation's five failing subcases remain as observations. Source
binding and lexical recognition do not certify compilation or public readiness.

The [independent hosted Cargo replay](../../evidence/pon-pq-hosted-a1e407-20261028/README.md)
on published `a1e40747746772d1326bb3e656aec4ba10440147` executes all 164 selected
tests, including all 30 integration cases, with real locked Cargo builds and
strict M00/M06/node `--all-targets --all-features` Clippy. It closes the earlier
manual-link-only limitation for those targets, while preserving the eight
original library ignores. Both complete original artifact archives and their
independent source/binary/member readbacks are retained. A separate early
recent-batch failure is preserved; only four reviewed stale source-blob guards
are synchronized, with all sixteen guards and execution limits retained. That
workflow has not acquired acceptance from the pin update and must execute again.
This follow-up changes no Rust runtime or protocol namespace. Complete workspace
qualification, remaining authority owners, independent migration trust/source
retirement, physical I/O, whole-chain PQ, P1 completion and activation remain open.

#### P1 NPQ4 task-authority continuation — 2026-10-28 (candidate / native gate OPEN)

The [fresh NPQ4 task owner](../protocol/pon-nakamoto-v1/details/NATIVE_PQ_TASKS_V4_RESEARCH.md)
implements the selected 18/open → 21/dual registration → 20/revoke path with
actual State requester and source accounts, independent ML-DSA proofs, current
generation resolution and apply-time reauthorization. Its complete 7,894-byte
registration is retained as four bounded witness leaves under the unchanged
4,096-byte State-value grammar; 32 registrations account for 64 real proofs and
252,608 command bytes. Ordinary Node material/W1/output/publication/cold and
heavier-fork paths use explicit NPQ4 packet, network, SQL and signed namespaces.

Local revocations are published with actual activation events and retained after
detach. Cold audit also rebinds every detached event packet's actual transaction
bytes to the header; a retained original block ID/W1 cannot excuse replacement
of the transaction list. The source-identified counterexample and required real
SQLite negative control remain distinct from an executed native RED/PASS claim.
Branch-relative remote validity remains separate from monotonic local mining
permission. The finite local history cap and full-history audit cost remain
explicit; no outside database rollback anchor or unbounded-history qualification
is inferred.

The [new observations and remaining gates](../../evidence/pon-pq-tasks-v4-20261028/README.md)
keep metadata-only compilation, direct Clippy, strict reader controls and native
execution separate. New actual native execution is NOT_RUN locally because the
shared disk reached its stop line. The mandatory hosted gate retains the original
2,400-second command budget and requires the complete old 164-test cohort plus
16 new cases, with all original ignores and every integration name pinned.
The earlier hosted 164 PASS is historical evidence on its own exact source.
Remaining concrete model/evaluation tags 6–9/12–17/23–24, renewal 19/22,
independent migration/retirement, custody, transport, History and Hepta authority
owners are listed explicitly. P1 completion, whole-chain PQ and activation remain
false while the new native gate and those owners remain open.

#### P1 NPQ5 task-renewal continuation — 2026-10-28 (candidate / native gate OPEN)

The [fresh NPQ5/PQP5 continuation](../../evidence/pon-pq-task-renewal-v5-20261028/README.md)
adds atomic requester/source command 22 and explicit requester command 19 →
`awaiting-source` → current-source command 21. Actual State owners, current keys,
nonce, old revision and prior statement are resolved again before the fee patch.
Current, initial and last dual-authorized leases remain separate, so an earlier
source proof cannot authorize an extended window. Five bounded witness leaves
retain the complete 8,274-byte atomic proof without changing the original
4,096-byte value, 524,288-byte transaction-sum or 1 MiB packet limits. All size
and 32-slot capacity claims remain executable expectations pending native runs.

Ordinary Node pool/material/W1/output/activation/cold paths share the fresh
namespace. Local withdrawal uses a State-derived stable lineage across renewal
revisions and heavier forks; cold replay binds actual first-activation packets,
transaction roots, revisions and SQL history. Parent-authorized output in a
renewal block is preserved without granting future work to a pending revision.
V5 has no trusted migration constructor, and old profiles refuse its encodings.

Actual local observations include metadata-only Rust/Clippy and a complete
76-test strict legacy-reader run; they do not claim native acceptance. The
mandatory hosted gate requires all original 180 cases/eight ignores plus
24 new passing cases, all 37 V5 and 26 retained V4 full-W1 phases, and fresh
locked Cargo/strict Clippy under unchanged budgets. New native execution is
NOT_RUN locally at the shared-resource stop line. The earlier NPQ4 hosted
success belongs to its own source. Remaining model/retired-key authority,
independent migration/retirement, full V5 independent runtime review,
whole-chain PQ, P1 completion and activation remain open.

#### P1 NPQ5 anchored migration recovery — 2026-10-28 (new candidate / native NOT_RUN)

This continuation adds an explicit
`Settings::native_pq_tasks_v5_with_anchored_migration_v1` entry point for a new
`pon-native-pq-tasks-v5-anchored-migration-v1` network. Its immutable protected
configuration binds the independently supplied prior PQ registry and an actually
admitted, selected source checkpoint. Separate descriptor, network and parameter
domains prevent an existing fresh NPQ5 namespace from silently acquiring import
authority. All existing fresh constructors retain their previous branches.
Imported accounts remain locked until the ordinary complete prior-key/new-key
ML-DSA CLAIM succeeds with the actual current nonce and fees. This is a new
network construction; it does not upgrade an old database, prove registry
historicity, finalize or retire the source chain.

Three required native cases exercise source W1 admission and checkpoint pinning;
ordinary pool → CLAIM → requester consent → dual task registration → registered
material W1 → admission → activation → heavier fork → nonce/claim/task rollback
→ fresh signed task work → cold byte/state readback; the original 55 full
9,432-byte CLAIM acceptance / 56 refusal boundary; and incorrect checkpoint,
anchor, signing context, prior key, old NPQ2 and old Ed25519 refusals. The
9,432-byte signatures are counted in full. The original 524,288 transaction-byte,
1 MiB packet, 4,096 State-value, 32 task-slot, five witness-chunk and local history
limits remain unchanged. The same ordinary source/fee/account/task mechanisms
must execute; hand-built trusted State or successful stubs do not qualify.

The new lane has its own 900-second total budget and requires the unchanged
2,400-second retained native gate on the very same committed head/tree first.
Its reader reopens all original 18 command observations and artifact hashes,
requires the exact 205 passing cases / 68 integration cases / eight original
ignores, checks all original input pins and the actual retained binary, and
reparses the complete original phase records. It then requires all three new
case names, 19 actual full-W1 phases, selected parent chains, complete transaction
bytes and matching cold readback records. Parser fixtures never count as native
execution. The original report's historical qualification flags are not rewritten.

The earlier local unified candidate `9b049f1fa25ab8a8597e4483c97a2cdc59f96d1b`
and tree `7752537241f034e862244bfd8a5d072f3461c238` were not recoverable in full
after workspace reset. This source is an explicitly new reconstruction from the
exact published `d66b0daa1fb4a4c398a3d53fb50366ad5ff2d913` tree
`7a61863cf4dc87893da501e0547f1727ed5e2956`; it does not borrow the lost
candidate's three native results or fresh-namespace golden measurements.
The sparse local recovery reconstructs the full Git tree but does not claim a
full tracked-worktree source guard. New actual observations so far are the
nine synthetic reader controls, twelve retained reader controls and selected
Rust 1.95 syntax/format checks. Cargo type checking, strict Clippy, the complete
retained native gate, all three new native cases, and the four recent-batch
lanes remain NOT_RUN on this recovered candidate until exact-source hosted
execution and raw artifact readback. User-scoped P1 shared-profile acceptance
remains open until those gates pass. No production activation or whole-chain PQ
claim is made.

## 2026-10-29: isolated PoN, PQ, model and History source convergence

This candidate combines the actual source lines from PoN
`974932be6dcfe830ce1ce92d58cb10e89cb8358d`, PQ
`6cd321a6e5f36dabec60e5e234294c4167330476`, model and Cell
`c5728d02a7b64909302252f4986e33b56b91faa2`, and pure History
`98873ccfbb4a416218c49df39082f0b3a842b5c8`. The separately reviewed Hepta
lineage change is `47884ac6047f2341869ae566e4f599e57e864d45` (PR #4246).
These identities specify source inputs; they do not combine the earlier
branches' independent passes into a product or cross-repository qualification.

The ordinary public Submit path now grants complete-work scheduling priority
only after the actual native owner rechecks current parent, task and material
eligibility and the second SQLite epoch fence. The original full W1 proof,
M06 execution, output roots, durable commit and budget checks remain. A real
old-code regression showed an unregistered complete-W1 request rejected as TASK
after consuming one completion identity. The corrected component passed the
eleven completion controls and two original ingress controls before integration.

PQ retained State now requires the nonce to cover all retained rotations:
fresh generation g needs nonce at least g-1; an imported claimed account needs
at least source_nonce+g with checked overflow. Actual ML-DSA CLAIM/dual-rotation
negative controls failed against the old implementation and passed after the
guard. This is a minimum reachable-state invariant, not an external rollback
anchor or a claim that all same-generation nonce rollback is detected.

The two zero-search admission meanings now have explicit profile identities.
Existing legacy, pure-v1 and pure-v2 policy bytes retain their original meaning;
raw History requires its own admission variant and cannot acquire the product,
facts, rejection-cache, growth or v2 extensions. Typed History checkpoints,
sealed startup material, shared snapshot final revalidation and explicit PQ
constructors remain mandatory. The pure History lifeline reader also recognizes
only the exact new raw campaign schema/profile/policy combination while retaining
source, binary and failed-campaign checks. Native owner-death and whole original
History service qualification still require their actual combined runs.

Cell acquisition retains bounded failed-attempt ordering hints for one fixed
provider list and one original reservation. It never removes fallback providers
or refreshes the deadline, connection or received-byte budget. The seven-request
real-provider counterexample and the complete 137-test data-availability library
passed on the changed Cell source. See the detailed scope in
[Cell P2P](../protocol/pon-nakamoto-v1/details/CELL_P2P_V1.md).

Final combined-source native gates, strict Clippy, source/readiness controls,
and the source/profile/binary/log tuple must be retained independently of these
component results. Current public PQ wrappers remain closed; model contribution,
evaluation, publication and Hepta FinalUse still need versioned PQ owner
protocols. A Cell content pin and its availability do not authorize installation.
The existing three-round Hepta hold experiment and one-child study have their
own exact Chain tuple until a new paired run is actually completed. Independent
72-hour WAN operation, complete release retention/repair, strong-baseline model
benefit and end-to-end net throughput comparisons remain open. All existing
release and public-readiness denial flags remain in force.

### Native convergence observations and retained failures

The first complete local Node library preflight used the converged source tree
`f5ad3536ae52897a5ea55cae11fa05a57445fdfc`, now retained as the historical source
[commit](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/6a5eb9de422cc3ae4392ee7ace8ef12f3a7395e6).
All 1,297 paths captured by that run's source observer match this tree. This is
preservation of the failed observation's source, not retroactive certification
of inputs outside that observer's scope or of a missing compiler environment.
The real run completed with **816 passed, 21 failed and 22 original ignored
helpers**. Its retained executable SHA-256 is
`51022b9662c256e823291396dccc2e51260a4423768c2201314818684582002d`;
raw log SHA-256 is
`db29555130bdb605cb2361859a9c65f8ea11c5761890aa991dad3dbe28a6582f`.
The original two 65,536-key capacity controls and all eight pure/raw History
controls executed successfully; neither their datasets nor the failure inventory
were reduced.

Nineteen failures stopped at the absent compile-time
`TRNM_HISTORY_STARTUP_NO_NATIVE_SOURCE_COMMIT`: twelve lifecycle, six reorg and
one first-startup case. The repository's original CI already exports this source
pin; the local preflight invocation omitted it. Supplying an environment variable
to the old executable cannot qualify that build. The final committed source must
be rebuilt with its actual commit at compile time and runtime. The normal Rustup
entry point also remains necessary to execute the pinned SQLite build-script
layout witness; no synthetic qualifying cfg, fence or allowlist is supplied.

Two other failures require independent treatment. The settled-epoch publication
case could not establish the original two consecutive complete process-graph
observations while unrelated processes appeared and disappeared. The exact same
executable passed the original case and all five publication cuts in a subsequent
quiet serial run. This preserves a real observation/liveness limitation; it does
not turn the original failure into a pass or establish busy-host availability.
The inactive-parent History case independently failed with a known negative
CPU balance, not missing CPU accounting: an instrumented exact-case run observed
137,113,446 ns credited against 138,756,603 ns charged, leaving -1,643,157 ns with
no in-flight workers. Its existing crash fence therefore retained an unclean
owner. Clamping debt, treating the close as clean, increasing the reserve, or
changing the original test to ignore the refusal would not repair this problem.

The candidate instead removes the duplicated complete parent-State traversal
inside one History admission. A private checked parent is produced by the
original complete pre-W1 eligibility checks, kept inside the same mutable Node
call for the same packet, and reused only after current header/owner checks and
an unchanged stable SQLite epoch. The original second parent-binding checkpoint
and epoch check remain. A real external SQLite change requires fresh full
validation. Ordinary admission still supplies no reusable History parent, and
no cache, caller-held capability, work shortcut or budget change is introduced.
Three new controls exercise real W1/M06, invalid output, task/time preconditions,
external SQL mutation at both fences and cancellation. The original seven-page
cold fixture retains every success-path call and assertion; its diagnostic
reads occur only after refusal or after the original loop. Type checking on the
combined source succeeded, while actual budget/service acceptance remains a
separate native result.

The combined source/readiness follow-up retains the original strict PQ checks
and explicitly recognizes the fourth, separately sealed History backend. Its
closed source contract checks startup ownership, mutual exclusion, seal
consumption and ordinary-opener refusal. On the combined worktree, all 34 source
integrity controls, 96 CI contract controls, 97 startup-driver controls and 91
readiness controls passed with source bytes unchanged. The ten host-launcher
controls are included in the driver inventory and were also run separately;
they are not ten additional independent product qualifications.

Only the existing fixed-budget signed-business startup case now uses the native
fixed-parent host launcher. The original 90-second window includes setup and
attach. Its real ELF stays open in the unprivileged child; the narrow privileged
helper checks the run lease, PID births, executable inode and digest, original
fixed parent and deadline before releasing that same PID through `fexecve`.
The four other startup cases retain their original owners. No sudo policy,
general root command, alternative resource limit or successful fallback is
introduced. These local source/driver controls do not establish an actual
privileged host qualification, and cleanup remains part of the terminal result.

The Hepta lineage source in
[PR #4246](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4246)
has real hosted observations on its historical multi-Chain tuple. Its three-round
model experiment completed one legal no-update round, then failed while observing
the second round's exiting evaluation process. Its positive-child experiment
completed ten real parent training steps, then failed while observing the first
parent forward process; it never reached child qualification or installation.
Both failures are `rss-observation-unavailable` at an owned process's exit
transition. A later exit status of zero does not establish the missing original
bounded observation. Any observer repair must preserve identity, live RSS
refusals, actual `wait4` accounting, the original 100 ms drain and whole-stage
deadline, and must be selected through a new closed execution-source profile.
The two Linux x64 lanes, Linux ARM source-head lane and both Windows ledger lanes
passed; the ARM prospective-merge lane was cancelled before its final three
native steps. The blocking Hepta job was also cancelled. Neither cancellation
is recorded as a pass, and the cancellation actor/reason is not established by
the available logs.

The independent 90-minute complete-W1 Composite proof-cost experiment also
retains its actual timeout: full guest execution completed, but no complete proof
or independent verification completed inside its original 5,400-second owner
window. Backend observation shows continued segment proving on its original two
workers. This is a research cost result, not a current raw-PoN admission verdict
or a replacement for the distinct earlier Succinct experiment. The separately
started four-hour cost profile must receive its own terminal receipt; extrapolated
completion time cannot substitute for that observation.

Whole public-service, end-to-end PQ and automatic-model-evolution acceptance stay
open. A FinalUse PQ slice must pass through the real issuer, courier, nonce claim
and turn-start owner while preserving revocation and external frontier history.
It cannot certify the still-classical contribution/evaluation/publication/install
owners or retire a migration source. The complete-release fault experiment,
independent 72-hour WAN operation, strongest-solver work/service matrix and fair
PoN-NG/DAG/Prism comparison remain separate required observations.

### PN3 initial terminal receipt acquisition — 2026-10-29 (candidate / OPEN)

Two original Hepta `47884ac6047f2341869ae566e4f599e57e864d45` executions
remain failed. Run `40870778799` completed the first real round with
`hold-no-positive-gain`, then its second-round backbone evaluation refused
`exit-task-set` during the first observer capture. Run `40870778787` completed
ten actual training steps, but the first parent forward refused an initial
`ENOENT`. Both later exact owned waits reported exit zero and valid high-water
receipts; neither recorded a terminal wait timestamp inside the original
100 ms gap. Post-gap zombie-leader/running-PF_EXITING/no-mm diagnostics do not
retroactively qualify those missing samples, model results or installations.
The retained constructor errors do not identify the exact internal read or
whether worker binding had already started. The deterministic regressions below
isolate the incomplete-baseline branch; a fresh full-source model execution must
still establish whether it resolves either real failure.

The V4 worker owner now distinguishes a private initial terminal-receipt state
from a complete initial exit-only classification. It may retain the existing
reservation across a bounded nonleader disappearance or monotonically shrinking
task roster/count, while continuing to validate every successful identity,
namespace, state, PF_EXITING, memory and starttime read. Every successful count
sets a nonincreasing ceiling; new or reappearing tasks, any observed live memory
or invalid identity, and permission, I/O or malformed reads remain sticky
refusals. Initial incomplete capture never binds worker pidfds or becomes the
old full-baseline proof. Already fully bound V4 worker retirement keeps its
original terminal-event and complete-frontier requirements.

Only the original supervisor's exclusive same-child wait4, valid CPU and positive
peak-RSS receipt, original RSS cap and exit status may close this pending state.
Its deadline remains the lesser of the original missing sample plus 100 ms and
the original whole-child deadline. No missing RSS value becomes zero, physical
release, refunded capacity or an unlimited exit allowance. Failed constructors
retain only a closed, failed typed result in the exact existing owner context,
including the direct `__main__` entry, so a later exit zero cannot erase a prior
refusal. All acquired FDs close; the borrowed supervisor pidfd stays with its owner.

The frozen model-bound pilot and V2/V3 observer bytes remain unchanged. The V4
worker source hash changes the complete observation-policy identity; old V4
plans and receipts refuse on the new source. The paired Hepta experiment must
explicitly freeze the new closed execution profile and exact Chain source, while
retaining the original model plan, target and workload. Its execution profile is
`hepta-integrated-chain-execution-v1`, with a fixed commit and complete reviewed
source manifest; historical execution pins remain strict on the default path.
Deterministic capture
controls, an actual tiny owned wait4 with an explicitly synthetic initial roster
gap, and retained resource-owner tests exercise only this component. They do not
replay either historical model run or establish three installed generations,
future quality, cross-node independence, or a qualified model update.

### PN3 original cold activation and bounded recency — 2026-10-29 (OPEN)

The integrated source `147bae52e9abbc6f91f89f85e42c5dff4ae53d23`
passed all seven admission-parent controls with real compile-time source pins,
but its unchanged seven-page cold History fixture still failed on page index 6.
Its 21 cumulative `state_at` calls did not identify the failing phase. That
failure and executable remain retained; a later diagnostic does not relabel it.

The diagnostic-only child `4998469386f22115fd196f2a36e44b353f67bcb4`
compiled successfully, then the same original fixture failed again. New reads
occurred only after the original receive call had returned `Err`; no success-path
snapshot, retained settlement, hook, wait or extra refill interval was added.
Its actual Activation counter advanced from zero to one, with 135,518,495 ns of
known current-thread CPU and no failed stage observation. The target block at
height 8 was stored; the reorg row remained generation 2, cursor 6, done 0,
while the active seed remained generation 1. This establishes an activation
attempt and six committed steps, not the exact final checkpoint; a later step
or transaction may have begun and rolled back. Nested stage intervals are not
additive. Known paid CPU was 481,787,574 ns against 481,739,116 ns of credited
refill. The resulting 48,458 ns debt, zero in-flight work and available accounting
correctly left the ordinary epoch unclean. No debt is clamped or converted into
an unknown clock, and no restart grants a clean replacement epoch.

The next candidate changes only recency of the existing three complete-input
arithmetic entries. Every hit still serializes and compares the entire current
State and its network/parameters/genesis context. An exact complete-commitment
or root-only hit moves the existing entry to the end of the same bounded deque;
no new retained entry or larger byte limit is introduced. A conflicting shared
borrow merely prevents optional promotion and preserves the original exact hit.
The old active slot can therefore remain hot while new staging slots arrive.
The single opaque root material, independent initial root and historical-cache
invalidation lifetime remain unchanged. All current SQL reads, both state-slot
checks, account graphs, progress callbacks and CPU/settlement limits remain.
Three new controls cover complete hits, root-only hits and shared-borrow behavior.
They were not executed on the old source; the actual `4998469` cold failure is
the retained full-path baseline. This source change still requires new native
execution and does not itself establish cold-start or recovery acceptance.

[Integration PR #557](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/557)
preserves the exact four-parent historical source combination. Its first recent
batch CI run verified all 7,108 tracked entries and 924,278,644 bytes on the full
checkout, then correctly refused stale literal pins for the reviewed store and
cold-test changes. The follow-up updates those two pins and the newly reviewed
arithmetic-cache pin to their actual new blobs. The other literal pins, source
identity checks, native selectors, resource limits and recovery requirements
remain mandatory. Source identity success alone does not qualify any native test.
The later #545 F and #556 sources remain separate until explicitly reviewed and
integrated; their observations cannot be attributed to this frozen combination.

The independent full-W1 four-hour cost experiment has now reached a real terminal
result on source `007b80cc99ba52fe7afcd6d0e0dea52628f5a026`:
[run 40861413707](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40861413707)
completed a fresh 62-segment Composite proof in 14,320.133611461 seconds under
its separate 14,400-second limit. The 15,862,780-byte receipt passed independent
verification and all 16 retained attack controls rejected. The official artifact
ZIP SHA-256 is `3f22a3bfe047fa365bb52e3fe25ab299206e094f0e23be9967c60dd67cde8eba`;
all 67 members passed CRC and file-hash readback. Direct host `wait4` reports
28,643.838479 CPU seconds, potentially including descendants it waited; complete
family accounting remains unavailable and sampled/adopted CPU is not added to
that number. The original 5,400-second experiment remains a timeout. This new
cost result does not pass that original budget, public ingress, PQ-128 security,
same-source integrated qualification, work-hardness or production activation.

### PN3 exact legacy final-root reuse follow-up — 2026-10-29 (OPEN)

The bounded-recency candidate was frozen as
`ab545e25ed49269245f5f1a7242f8aed5840ea8b`, tree
`020a896647d18c03746a988717b039fb110e2ef3`. Its newly compiled test executable
SHA-256 is `4feef52a15deb32d345592dc63393cab556b2b3ff8f81a243016827970c8fef2`.
All eight arithmetic-cache controls passed (857 other tests filtered), and
workspace/all-targets strict Clippy passed with the exact source unchanged.
The original cold History fixture still failed: zero passed, one failed,
864 filtered. Its native runtime was 3.00 seconds; the complete recording
command took 11.993679351 seconds. The original failure log SHA-256 is
`c86dffcef9b45138eef28a5df64c230991172c2340bf5c2f26f966a1862cb158`.

The failure-only observation now showed generation 2, cursor 7, done 0,
while the active seed remained generation 1. Known paid CPU was 523,612,861 ns
and credited refill was 523,429,324 ns: the 183,537 ns debt was retained,
with no in-flight owner and no unavailable accounting. Final publication was
not completed. Complete-root computations fell from 36 to 26 compared with the
earlier `4998469` observation, but this run reached one additional committed
step on a shared host; aggregate elapsed/CPU differences are not an isolated
performance estimate. Cursor 7 does not identify the exact remaining checkpoint.

The next change reuses arithmetic only at the original final staged-state root
check, after the current SQL slot has been read again. Its exact predicate is
`AuthenticatedV1` plus the legacy packet profile. All PQ profiles retain the
original `Settings::state_root` call and validation/error order. The broader
draft was withdrawn before integration because the existing arithmetic helper
and original root function have different PQ2/PQ3 validation paths. Both growth
profiles are already excluded from this backend by the original constructor
checks. No current SQL read, continuity check, target-record read, checkpoint,
fault cut, account-graph validation or atomic publication step is removed.
The cache capacity, CPU debt, original time/resource limits and durable epoch
rules remain unchanged. New controls inject changed canonical input and signed
zero through an external SQL connection after the last attached step, and delete
actual PQ2/PQ3 authorization state at that same point. Their native execution
and the original cold fixture on this new source remain required; no pass is
inferred from static review or the earlier eight controls.

The separate exact-`4998469` hosted History recovery run
[40897810787](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40897810787)
has completed all four original lanes: the 600-second gate passed 22 tests with
one original ignored test in 517.957807999 seconds; graph checks passed 23 physical
cases; lifecycle passed 12 tests in 301.014390253 seconds under its own 900-second
limit; reorg continuation passed seven tests in 704.080576124 seconds under its
own 900-second limit. These results do not override the separate cold failures,
establish whole-History P0 closure or prove complete descendant quiescence.

### PN3 PQ root parity and explicit fixed Host client — 2026-10-29 (OPEN)

The exact `7eb5257368016b4880c55c54f74412209ab697ba` candidate passed both
final-root tamper controls, 37 growth-profile controls (two original ignored),
and workspace/all-targets strict Clippy. Its unchanged original cold History
fixture still failed on page index 4 before any Activation observation. The
target was unknown, no reorg row existed and the old active seed remained.
Known paid CPU was 412,022,247 ns against 403,972,426 ns credited refill;
the 8,049,821 ns debt was retained with zero in-flight work and available
accounting. This execution never reached the new final-root branch and cannot
establish that branch's throughput or cold-start benefit. Shared-host elapsed
times are not an isolated performance comparison.

The test-only child `37c4301153c911d6095636e0b9732359be713034` reproduced a
separate validation-parity defect in the arithmetic helper. Deleting the actual
PQ2 authority while retaining the real account/key history made original
`Settings::state_root` refuse, but the cold arithmetic path returned an `Ok`
root. The retained second invocation failed its target assertion: zero passed,
one failed, 867 filtered, 0.01 native seconds. Its log SHA-256 is
`10e6ca45547845a2e0aedbb9716a7022462a7a8ebc3bae4fb7966cf0b254e0f2` and
ELF SHA-256 is
`e528b043fa6c2e623c56fd18cd08daba827a9458b177e202d155acaa67a59d2a`.
The first invocation returned 101 but its saved output lacked the native
terminal; that incomplete observation is not counted as another target RED.
The first failing PQ2 cold assertion stopped the test, so its later PQ2 warm
and PQ3 cases were not executed on the old implementation. The candidate now
runs both original validators unconditionally, in their original order, before
any cache lookup. Disabled validators retain their original no-op behavior.
This is state-root parity hardening, not proof of a remote unsigned transaction
exploit, a final-publication bypass or end-to-end PQ authorization. The exact
new source must pass the whole cache module and original cold fixture; neither
acceptance is inferred from the local reproduction.

The pure-admission experiment now selects a separate
`pure-pon-fixed-host-client-v1` execution profile and source-bound sidecar.
The real History client/verifier runs inside the existing fixed public Host
parent, while compiler, receiver and attack actors retain the original outer
experimental parent. Original phase, actor, network, CPU, memory and cleanup
limits remain unchanged. Old native selectors remain available. The common
wait4 owner waits only its direct launcher; native actor CPU and enclosing
kernel CPU remain separate, nested observations and are never added together.
The strict reader requires actual IPC, matching source and profile, bound
initial/final chain positions and an empty fixed parent before and after.
Position agreement in the new pressure adapter is not full state equality;
the original receiver/client state and service-cost readers remain mandatory.
Python negative controls and source review do not replace native typechecking
or a real fixed-parent execution on the frozen candidate.

The separate full-release Cell experiment on `7eb5257` completed its explicitly
reserved eleven-member V3 local fault scenario: 272,189,870 input bytes,
269 cold chunks, zero cache hits and two live suppliers after author and
retired-provider exit. Cold completion took 41.699117094 seconds under its
120-second reservation. After all four provider processes were reaped, all
eleven receiver-only materializations matched their original sizes/hashes with
zero network counters. Its report SHA-256 is
`80856526073eb6f1ebdf62f602aafe082cba1a2070c8202d5594fe6d22a91cf1`.
This is a local complete-release availability observation with a development
adapter, not the older three-member/35-second scenario, an installed new model,
continuous disk-absence proof, independent operators or a 72-hour WAN result.

[Hepta PR #4294](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4294)
pins the reviewed `147bae5` execution profile; its receipts cannot be relabeled
as `7eb5257` or this follow-up. Its four Linux native-pair lanes refused the
original confirmation target. The inspected x64 head phase confirmed in
4.064181696 seconds, outside its unchanged four-second business window,
although native state equality and accounting controls passed. The separate
[FinalUse PQ PR #4297](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4297)
now includes the real Bazel-generated lock on `d734ba4`; its first run stopped
at the original lock check before native host tests. A new exact-source run
must qualify that lock and actual core/host paths. Three real model loops,
strong baselines, the single integrated product source combination, full PQ
authority closure, original cold recovery, independent WAN operation and a
fair successor-protocol comparison all remain explicit acceptance obligations.

### V4 binding acquisition reservation boundary (2026-10-29)

The `147bae5` / Hepta `8c19667` three-round product run failed in round one's
budget-matched full tune with a same-sample constructor `FileNotFoundError`.
The original artifact does not identify its constructor substage. The later
zombie snapshot and successful process exit do not repair that missing RSS
observation. Its failure remains an acceptance result, not a legal no-update.

The next source-bound V4 observer admits one narrower pending state: an
original nonleader has already passed both complete prebinding frontiers;
reading its held task-directory `status` or `stat` then returns `ENOENT`; the
same owned roster actually loses that task; and the remaining frontier still
passes its identity, birth, exit and memory predicates. This retains the
reservation and partial FDs. It is neither completed worker-pidfd acquisition
nor a worker terminal-event or zero-RSS proof. The unchanged original
100-millisecond and whole-operation deadlines, exclusive owned `wait4`, CPU,
RSS, exit-status and family-owner checks still decide completion. Missing
leader/group/fdinfo reads, `pidfd_open` errors and already-read bad fields do
not enter this state. Constructor diagnostics record bounded fixed-source
frames from the failing call, without granting authority.

The original pilot, V2 and V3 production files remain byte-identical. An old
V4 source receipt must reject the changed observer, and a separately frozen
execution profile is required for any new model run. One former blanket
disappearance subcase now explicitly asserts incomplete binding and no release;
the other original refusal cases remain. Controls include actual original
supervisor/owned-wait4 finalization of small children, with synthetic proc/task
acquisition fixtures, plus late, conflicting, missing and over-budget receipts.
These controls do not locate or replay the historical model race.

In the separate positive run on the original `147bae5` tuple, actual training
changed the weights and all four future forward phases completed. Parent and
candidate each answered 512 of 1,024 observed tasks correctly and made the same
1,024 choices. The original product runner returned `Ineligible`; the outer
expected-positive test failed and no child was installed. The equal IPS bounds
are utility estimates, not those direct correctness counts. A separate six-arm
descendant diagnostic completed three rounds and 33 supervised phases, including
nine nonzero-step training receipts and six zero-step controls. All three rounds
failed to beat the strongest control, installed zero children and left CURRENT
at generation one; the later candidate ordinals were not admitted generations.

### Retained recent-batch source-pin refusal (2026-10-29)

Run `40928680264` on exact head `91e4a5e9ad10d7ef00bf2922c7b7c69d48be27ad`
failed all four recent-batch lanes before native work. The inspected x64 head
job `123640974634` first verified the complete 7,114-entry committed source,
then rejected the old literal Git blob for `public_v3_multiprocess.rs`.
The earlier `f9df86d` single-module declaration fix changed that file from
`0449aafb3b3c3b4f85c80059f4f88f00fe7a93ab` to
`4e098e7a078dc269780c213eab7c84cab7f08482`. An exhaustive comparison of the
current workflow literal `git hash-object` pins found only this mismatch.
The follow-up updates that one expected blob, retaining all other pins,
original selectors, budgets and source checks. This does not turn the failed
run into an executed native result. Its later log-glob cleanup refusal is
also retained; subsequent acceptance requires a new exact-source run.

### PN1/I01-I02 — pure PoN security continuation rebuilt on current integration (2026-10-29)

The continuation is rebuilt on `540d72356a921da31dde1113537382e5c0f0c4fd` after
the previous unpublished local workspace became unavailable. Its missing
measurements are not recreated or counted. New source, tests, real proof
verification and independently checked historical readbacks are retained in
[the rebuilt evidence](../../evidence/pon-pure-security-20261030-rebuild/README.md).
The evidence namespace uses 2026-10-30 UTC; this heading uses America/New_York.
Current integration changes, including the worker binding race and recent-batch
source-pin correction, remain present.

Pure PoN Nakamoto fork choice, full work validation, 512-bit required chainwork,
strictly heavier reorganization and the original W1 relation remain. No stake,
quality/evaluator weight, independent Hashcash gate, automatic committee/hash
fallback or production activation is introduced. Three new native controls
retain exact scalar-error precedence, correct-product/false-trace replay for
fresh challenges, and the replay required after 65th-challenge cache eviction.
These expose residual rejection cost rather than claiming forged-block acceptance
or a new verifier speedup.

The explicit fresh-caller supplement derives a key for each phase/actor/sequence
inside original measured actor work. Observer v4 records a caller only after
the real request signature succeeds; the original observer stays v3. The
independent reader reconstructs the key, request and body, requires 65 actually
authenticated hostile identities per attack phase, and conjuncts the unchanged
original pressure criteria. It does not certify unrestricted Sybil fairness.
Both hosted architectures use the pinned interpreter and original fixed-Host
limits. The driver retains 15 original native gates and adds four native gates
plus four reader/environment gates. Ordinary old campaign/reader failures remain
failures without skipping the supplemental campaigns. Missing/malformed receiver
terminal output now preserves actual partial observations, including already
collected actor results and single-reap wait4 costs, then still fails.

The V5 cost reader now binds the original fixed profile, nonzero target, full
seed-header digest, every nonce challenge including misses, and exact 49,508-byte
winning packets. All existing pairing, roster, budget, timing, exhaustion and
cold-recovery predicates remain. Seven coordinated metadata mutations accepted
by the old reader are refused. The recovered historical 144-cohort capture keeps
all 25 original summary fields unchanged. This is stronger evidence binding,
not independent full genesis replay, current native campaign execution, or a
proof that an observed solver is globally cheapest.

The complete-W1 host checks claimed task/target and zero target before receipt
I/O. Its guest, image, complete relation, original strict verifier and bounds
are unchanged. The eight fixed audit-one cases all require an actual positive
verification prerequisite. A rebuilt host verified the original 15,862,780-byte
Composite receipt and refused all seven mutations. Single warm-verifier receiver
observations were 1332.826232 ms for valid and 1187.393954 ms for a late-seal
mutation. The timer includes bounded decode, strict verification and destruction;
whole-process costs and exclusions are separately retained. These are not the
older Succinct experiment, cold-start costs, a new proof generation, an admission
speedup or a practical-security verdict. The durable exact fixture and read-only
CI remove reliance on expiring artifact downloads; the Python metadata reader
does not independently verify the STARK or authenticate timings.

The actual strict History baseline at this integration source is independently
retained as a failure with no attackers: first depth-six confirmation at
45.067188843 seconds exceeds 30 seconds. Seven imports use 10.341637184 CPU
seconds under a quarter-CPU quota. From ready through the final snapshot,
including the separate confirmation and snapshot calls, nested account-graph
counters show 85 full traversals and 9.240268480 CPU seconds despite
127,426/127,571 decode-cache hits. This interval differs from the seven imports.
The raw SQLite and IPC records support repeated graph verification as a concrete
bottleneck. Nested timing is not added to process CPU, and no unverified
same-root cache or weakened persistence/resource check is introduced.

The separate existing N8 pure-raw History profile has bounded positive evidence:
three historical runs complete all 27 confirmations within 30 seconds, with
full receiver/client State equality and actual typed node/resource counters.
All six hostile phases nevertheless fail the required sampled paid-credit-
depletion and business-overlap predicates; the three whole campaigns remain
failed. Different campaign/resource profiles do not transfer qualification or
establish a causal speedup factor.

Fresh local checks include 130 M01 tests, six consensus tests, 183 public-ingress
tests, 19 pressure/receiver controls, 30 V5 reader controls, 66 admission-reader
controls, 17 standalone proof-host tests, all-target/all-feature crypto/node
strict Clippy, source-integrity negatives, the exact locked workspace graph,
formatting and source inventory. The two-caller rerun is already part of the
183; 16 long/subprocess pressure entries were intentionally ignored in the local
control invocation. This shared host has no systemd, so exact-head hosted
fixed-Host execution is still a separate gate.

Open-network honest service under the original pressure envelope, global
effective-work cost assumptions, practical complete-proof economics, quantitative
quantum security, independent acceptance and activation all remain OPEN.

### System-safety continuation of the integrated candidate (2026-10-29, New York)

This continuation starts from integrated candidate
`1d11f875493f8125e36b9adceacb342df108e5e5` (PR #557), preserving its concurrent
fresh-caller, proof and retained-failure changes on top of the originally audited
`540d72356a921da31dde1113537382e5c0f0c4fd`. It preserves canonical
bytes and domain separation, complete verification before atomic block/delta
publication, verified heavier-chain recovery, generation/fence rechecks,
reserve-before-execute accounting, original failures and Unknown observations,
and non-rewindable local revocation and external-effect history. No production
activation, consensus replacement, budget increase or security-gate waiver is
part of this change. Whole-system acceptance remains **OPEN / NO_GO** until
fresh exact-source native and security observations satisfy their original gates.

#### History CPU continuation and the original absolute phase deadline

The previous raw History failures remain failures, including
[the integrated raw joint run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471986)
and [the paired diagnostic run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40932471462).
The new code retains the same Node-owned CPU domain, original start reserve,
refill, burst and worker limits throughout each import operation. When a real,
known observation exhausts current credit, the same reserved operation may wait
for the original elapsed-time refill while checking its existing caller/resource
boundary and absolute deadline. Unknown accounting never enters this path.
Pre-settlement waiting remains inside that measured operation; final CPU is
still sampled and debited exactly, and any remaining negative or unknown tail
retains the original crash fence. No negative balance is clamped or refunded.

Explicit `receive_public_page_from_until` and graph-resource equivalents carry
the caller's absolute deadline across decode, W1, M06, activation and settlement.
The first full resource observation is inside the original paid operation;
cancellation still reaches actual settlement. CPU-only W1/graph checkpoints keep
the original full-resource cadence. A checkpoint that waits for credit must
recheck the full resource boundary before resuming native work.

The public CLI captures its original 30-second transport bound before requesting
a page and passes the same Instant through network I/O and import. Legacy
native/authenticated transports previously had five-second I/O phases and no
whole-page bound: they now have an explicitly new 30-second compatibility page
ceiling, with every original phase clipped to the same remaining time. This is
not described as a pre-existing legacy contract. No-deadline import wrappers use
the same finite compatibility ceiling; they cannot themselves prove an earlier
caller's network-plus-import deadline. The original two-second start-reserve
wait remains unchanged and cannot extend any enclosing bound. Partial I/O,
late complete responses and retries cannot renew an explicit caller deadline.
The distributed example passes its existing role timeout through its original
retry count and both import sites. A verified authenticated terminal still
settles its original nonce/outbox facts even when the final caller check fails.

The original finite campaign and pure History client pass their already-existing
30-second phase deadline and 35-second cleanup deadline into the isolated actor
and its IPC waits. The recent-batch literal source pin changes only for this
one-line phase binding; the native selectors, payloads, thresholds and resource
policy remain unchanged. The original cold/inactive fixture is not relaxed.

Last-close verification and ordinary History marker removal now share the
original CPU mutex. A concurrent cloned domain cannot start work between the
quiescence observation and marker removal. This does not add durable recovery
authority to an ordinary volatile domain or permit cold reconstruction of an
unknown epoch. Tests retain the original cold/inactive-parent fixture and add
known-refill, cancellation, absolute-deadline, Unknown, cloned-reservation and
delayed-IPC controls. Shared-owner throughput/fairness still requires the original
full native campaign; holding a Node owner during a bounded wait is not a new
parallel-admission architecture.

#### Active recovery modules and auditable CodeQL output

The six `trnm-peer-lease` recovery fragments previously joined with `include!`
are private Rust modules with explicit same-name public re-exports. Existing
types, owner, WAL, ACK and projection behavior remain in the same authority.
Independent token review found unchanged function bodies and all 35 constant /
static initializers; only required sibling visibility, module placement and
formatting changed. This removes a documented semantic-extraction obstacle in
actual compiled recovery code. It does not establish that a later CodeQL run
has complete coverage or that the remaining SSA/type-inference errors vanished.

The pinned CodeQL workflow preserves its original version, query set, all-tracked
source scope, findings and failure gates. It additionally uploads a bounded,
separately downloadable original SARIF artifact, retaining the original complete
database/BQRS artifact as well. The collector rejects changed files, links and
oversized inputs rather than truncating them. A creation-log semantic index is
saved before analysis, preserving INFO-level unavailable-module observations even
if a later query fails. Artifact export remains distinct from security clearance.

[The source-bound API triage](../../evidence/system-security-20261030/codeql-api-triage-540.json)
retains all 780 results available through the official export at the original
source: 757 hard-coded-value and 23 logging findings, across 73 hash-verified
files. The record classifies contexts, not exploitability or automatic dismissal.
The official API subset has the same counts as the original pinned scan, but
identity with every result in the unavailable original 4.87 MB SARIF is **not
proven**. That limitation is explicit in the record. One active CLI stdout path
remains unresolved; deterministic tests, historical fixtures, overwritten output
buffers, wire-length constants and container/panic model approximations are not
silently suppressed. The
[original semantic index](../../evidence/system-security-20261030/codeql-semantic-extraction-540.json)
retains 311 unavailable-file observations and the workspace-load failure. Two SSA
diagnostics and one type-inference error still lack a proven source location.

#### Validation state when this continuation is proposed

The unchanged-boundary preflight, 29 pinned-analysis reader controls, 26 metadata /
SARIF collector controls, 96 CI-contract controls and 34 source-integrity negative
controls passed locally. Rust 1.95.0 locked workspace/all-target compile checks
passed before the final caller-deadline continuation. The six-module recovery
refactor passed all 120 native `trnm-peer-lease` tests and all-target/all-feature
strict Clippy, with no ignored peer-lease tests.

Local original full-debug node builds retained their compiler/resource failures.
A subsequent functional build disabled only local test debug symbols, retaining
optimization, debug assertions, overflow checks and runtime resource budgets.
Its broad `history_` selection recorded 109 passes, 19 failures and six ignored
entries. The failures include specialized lifecycle/reorg/startup controls that
require their exact-source runner pins; the local compiler loader guard also
reported an unqualified duplicate path, which was corrected without changing the
guard. This is not a whole-History pass or fixed-Host qualification. All nine new
History CPU/close controls and the original activation cancellation/retry test
passed in that run. The final caller-deadline socket controls still require their
own fresh execution. Full sparse-checkout repository link verification correctly
refused absent historical evidence; no missing evidence was fabricated.

Fresh hosted jobs must run the original History V6, raw joint/pair, baseline,
strict Clippy/formatting and CodeQL gates on the proposed immutable source. The
independent [Hepta continuation](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4332)
starts with the contract/durable-journal operation-binding repair and is a
separate source candidate. It is not implicitly included in this Chain commit or
treated as an arbitrary external HTTP exactly-once guarantee.

### System-safety follow-up after exact fb7 observations (2026-10-30 UTC)

This follows the immutable PR #558 source
`fb7e12bd2a02ee0805dff6a053edc904ad2198c6`, tree
`eb0b11a8e827acd251cf8577715eb1a501ee0743`. It remains a draft continuation of
PR #557, not a merge or activation. Original failures and independent gates
remain authoritative; whole-system acceptance remains **OPEN / NO_GO**.

#### Actual recovery and ordinary-business observations

At fb7, all four original
[History V6 lanes](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40995210625)
completed successfully: native recovery, physical graph-resource mutations,
lifecycle, and reorg continuation. The
[focused native integration](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40995210573)
also passed. The
[raw History joint campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40995210492)
and the original ordinary campaign nevertheless failed. Those are different
claims and remain different outcomes.

The retained raw artifacts have identical source, executable, inputs and original
limits. In the fence baseline, each of three runs completed 19 of 20 attempted
imports and two of three required confirmations before the original deadline.
Every strict phase completed six of seven attempted imports and zero required
confirmations; the seventh import reached activation and then retained its actual
deadline failure. All strict verifier children exited normally, and receiver
live owners, unsettled CPU and reservations were zero. Those terminal facts do
not make the failed business result successful.

For the first six identical decoded pages, all of which completed in both
profiles, strict import CPU was 3.18--3.30 times the fence observation. Whole-run
totals contain different completed work and are not used as that comparison.
Nested graph/admission/activation timings are not summed. Strict does not run the
N8 graph observer, so its zero N8 counters do not mean resource checks were absent.
The exact source, artifact, executable and raw-file digests are retained in
[the first readback](../../evidence/system-security-20261030/raw-history-fb7-readback-summary.json)
and [the paired comparison](../../evidence/system-security-20261030/raw-history-fb7-strict-vs-fence-summary.json).
Readback is not a new execution or a speedup qualification.

#### Same-transaction verification reuse and original cleanup deadlines

The follow-up reuses at most the child and genesis graph results inside one
original `BEGIN IMMEDIATE` CanonicalJson admission transaction. It captures the
real SQLite connection/transaction owner before callbacks and writes. The
existing observer now also counts actually executed non-readonly statements,
including no-op, failed and reversed writes. This does not turn the ordinary
read-scope identity API into a generic immutability certificate.

Only the ordinary writer can retain `post_write_schema`, derived from executing
source DDL in a fresh in-memory database. The read-only migration archive keeps
`None`; its test-only observation of the actual catalog never becomes a production
baseline. SharedAccounts continues through full verification. A missing source
baseline also preserves the original full-verification path.

After the last native write, trusted `writable_schema=RESET` is executed through
completion before the first full graph. Source grammar, main/temp catalog,
rootpages, attached databases and relevant connection configuration are checked.
This closes the demonstrated parsed-schema/rootpage/cached-VM split. Each reuse
still rereads complete State and Record and performs the complete commitment
comparison; an account-root-only match is insufficient. A mutation disables future
reuse, and mutation after a consumed result is a sticky refusal. The final outer
callback and resource boundary are checked before the receipt is discarded; the
original owner remains checked after the known effect-marker write and before
commit, on success and failure. No receipt is persisted or reused across a new
transaction, connection, reorg or reopen.

The three original campaign/receiver cleanup bindings now compute the remaining
time until the original phase end plus five seconds. Expiry cannot mint a fresh
five-second allowance. Original CPU reserves/refill/debt, Host limits, worker
counts, transport windows, Strict/N8 cadence and business success criteria remain.
The new graph reuse has no throughput qualification until the same original
strict campaign runs on its immutable source.

#### Exact outer-service collection facts

The fb7 fixed-parent slice cleanup and outer service collection are separate
facts. Raw logs show an already collected service followed by an unconditional
name-only `systemctl stop`, returning exit 5. A successful lifeline could hide that
failure; a failed create could also cause the trap to stop a foreign same-name
service. These failures are retained in
[the original cleanup review](../../evidence/system-security-20261030/unit-cleanup-reviewed-triage.json).

Six such traps in the raw, qualification, admission/DAA and epoch workflows now
observe collection without acquiring stop/kill/unlink authority. Their nine
original `systemd-run` commands, names, resource limits, RuntimeMaxSec,
TimeoutStopSec, KillMode and `--wait --collect` remain unchanged. The observer
requires successful fresh local-system manager queries, a real cgroup-v2 path
absence, no-follow runtime-path absence, a typed empty unit-file result and a
second manager observation. Nonzero commands, diagnostics, permission errors,
invalid bytes, timeouts, output overflow and residual objects remain unresolved.
Known presence permits only bounded re-observation. Query limits are three
seconds per command and fifteen seconds overall; they grant no additional native
work budget and are not a hard-real-time kernel guarantee.

Both original and cleanup exit statuses remain in artifacts. Original failures
stay failures; successful work with unresolved collection also fails the step.
Cancellation that leaves a service is reported as unresolved and remains governed
by the original systemd service owner's limits. This is a sequential local absence
observation, not InvocationID ownership or hostile-host authentication. The
different fixed-parent receiver protocol is not rewritten by this change.

#### Exact SARIF, active modules and remaining security gates

The new pinned fb7 scan retained its complete original SARIF separately. It still
reported 780 findings: 757 hard-coded-value and 23 logging results. Six active
peer-lease fragments now have explicit successful extraction notifications and
no corresponding original include failure. Overall coverage is still incomplete:
305 affected files / 306 diagnostic lines remain, including the unlocated workspace
failure. The retained classification distinguishes 282 files outside the current
Linux module graph, five active cross-crate test fixtures, two other-platform
branches, the active source inventory, fourteen historical evidence sources and
one standalone formal fragment. This is not an exclusion or a waiver.

All four emitted flows and seventeen source locations for the active CLI stdout
alert were reviewed. That exact alert does not establish credential disclosure:
the observed paths carry public metadata or control flow, and the private identity
does not serialize its secret. This disposition does not clear every logging site
or the other findings. Raw results remain unchanged in
[the reviewed triage](../../evidence/system-security-20261030/codeql-fb7-reviewed-triage.json)
and the retained original SARIF/metadata archives.

This follow-up removes nine active inventory `include!` wrappers, using one shared
private test module in the lib target and private modules in the other targets.
It requests the pinned Rust extractor's actual `CARGO_ALL_TARGETS` environment
option, strips inherited extractor overrides, and records a separately bounded
extractor-resolution diagnostic. The original CodeQL version, 37-query suite,
analysis limits, tracked-source scope, findings and coverage refusal remain.
Requested all-target extraction is not a claim of complete new coverage.

An independent original cargo-deny gate also failed: bincode, derivative and paste
are marked unmaintained, and tracing-subscriber 0.2.25 has the ANSI log-injection
advisory. The retained all-feature dependency paths belong to the existing optional
complete-proof research graph. Removing the feature, relaxing the advisory policy
or silently changing proof/receipt encodings is not a repair. These remain open;
they are not four more entries in the 780 SARIF results.

#### Candidate verification and handoff

The recent workflow's stale snapshot count is corrected from 20 to the actual 22.
Its full native-authenticated module has 74 tests at this source, including the
four previously uncounted existing controls and fourteen new adversarial controls.
The original release-only cost observation still has its original explicit
create-new artifact path. The SQLite owner suite is independently connected to
all four recent lanes so an earlier cargo-deny failure cannot prevent its thirteen
transaction/trace controls from executing. Twenty literal source pins, the new
path triggers, and the original source/merge verification remain enforced.

The final ordinary-writer production field passed all fourteen new native
adversarial controls; the unchanged SQLite owner files passed all thirteen native
transaction controls. The final locked workspace/all-target/all-feature strict
Clippy and Rust formatting passed. Outer-unit controls passed 21 tests, CI
contracts passed 96, source-integrity negatives passed 34, and the unchanged
CodeQL diagnostic/metadata controls passed 29 and 26 respectively. Local Rust
functional builds disabled only debug symbols; they do not qualify release costs.
The broader local native-module run remains 73 passed / one failed because that
invocation lacked the original explicit release-cost artifact path. It is not
reported as a full 74-test pass.

All local executions, including compiler failures, failed assertions, missing
benchmark configuration, source-changing format/fix invocations and zero-test
filters, are retained with source hashes in
[the execution index](../../evidence/system-security-20261030/local-executions.json).
Successful local functional controls do not substitute for fresh hosted release,
fixed-Host, cross-architecture, CodeQL or full ordinary-business gates.

The paired Hepta PR #4332 separately retains immutable provider-operation binding,
original Unknown observations, original key/wire recovery, actual owner fences,
same-attempt late-ACK reconciliation and fresh chain-membership checks. Its final
pair must name this continuation's actual immutable source and ordered merge
parents; the earlier fallback pair at Chain 147bae is not this candidate.

### 2026-10-30 exact-source b23 follow-up: original escrow observations

This continuation records the actual hosted results of
`b23c0ef85f058507185b2ccb404a5d648e447c06`, tree
`cbb7f34ef9a84df3653f4d3adbe57725b7740a37`, and its actual ordered merge
`3c72efa27dab7f4f435dd3728293790dff7bbe13`. It keeps the original failed
campaigns and official-scan uncertainty. Whole-system acceptance remains
**OPEN / NO_GO**.

#### Actual hosted progress and remaining ordinary-business failures

[Recent acceptance run 41007754007](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41007754007)
passed in all four x86_64/ARM64 and head/prospective-merge lanes. The actual
release native-authenticated suite passed all 74 controls, including the fourteen
new transaction/schema adversarial controls; the separate original SQLite owner
suite passed all thirteen. The previous local 73/1 debug invocation remains an
original failure, not a rewritten pass.

[Raw History run 41007753791](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41007753791)
still failed both profiles. The strict profile completed six imports and failed
the seventh complete page at the original 30-second deadline in all nine phases,
with zero in-window confirmations. The graph-fence profile completed 21/21
imports and all three confirmations in eight of nine phases. Run 1 late-product
completed 20/21 imports and two confirmations; its last page began at
27.945743 seconds and returned the original deadline failure at 30.015471 seconds.
The successful late-product runs completed their third confirmation at 29.923329
and 29.519161 seconds, so these observations do not establish comfortable margin.

The actual outer cleanup result is now `original_exit=1, cleanup_exit=0` for
both failed campaigns; each separate controller-death lifeline records 0/0.
All eighteen verifier phases retain clean node close without parent-forced kill.
Successful cleanup never overrides failed ordinary business.

The [same-page cost readback](../../evidence/system-security-20261030/escrow-reader-followup/raw-history-b23-cost-readback-summary.json)
binds the original binary, pages, source and raw artifact hashes. In the matched
first six pages, b23 strict CPU is 13.20–15.17% lower than the corresponding fb7
observation and fence CPU is 37.86–43.54% lower. These are observed cross-run
comparisons, not a claim that every CPU difference is caused by the patch.
Actual fence graph entries fall from 48 to 36, node bodies from 74,064 to 61,692,
and full graph resource checks from 9,408 to 7,824; maximum node window remains
eight and before-commit checks remain six. The unchanged strict checks still
consume enough work to prevent the first confirmation. Nested CPU scopes are not
added, and an unused strict N8 observer is not described as absent kernel checks.

The separate [four-second protocol evidence](../../evidence/system-security-20261030/escrow-reader-followup/protocol-b23-readback-summary.json)
also remains failed: the head pressure case reaches real full-state confirmation
at 4.171532 seconds, 171.532 ms late; the merge pressure case imports only three
of seven pages and retains the genesis active tip. Their named test processes
exit zero and Hosts close cleanly, but those facts do not satisfy
`CONFIRMATION_TARGET`. The four-second fixture and thirty-second isolated
campaign remain distinct observations.

#### Preserve signed stored credit; reject actual deficit and forged escrow

The raw reader had an additional contract error. The unchanged original owner
and [public-pool contract](../protocol/pon-nakamoto-v1/details/PUBLIC_POOL_INTAKE_V3.md)
define the following simultaneous `actual_flow` observations:

```text
paid = live_debited + settlement_residual
     = settled_full + unsettled_known_live
remaining_paid = initial + credited_refill - paid - settlement_discard
booked = live_owners * original_100ms_start_reserve
stored = remaining_paid - booked
```

A full original reservation remains booked until its one final settlement, while
actual live CPU is debited immediately. Therefore stored credit can legitimately
be negative while actual remaining paid credit is nonnegative. This behavior is
already explicitly tested by the Rust owner. Changing the runtime to clamp the
stored value or return its reservation early would change that original contract.

All 5,336 samples in the original b23 fence artifact satisfy the existing
same-flow identities and original owner limits. There are 473 negative stored
observations; the lowest corresponding actual remaining credit is 52,303,708 ns.
The previous reader rejected these signed fields before evaluating their original
escrow relationship. The correction preserves every original numeric value,
permits only an exact bounded signed i128 stored value, and strengthens validation
of the existing invariants: actual remaining paid credit stays in [0, 2 s],
owners cannot exceed two, booked reservations must be exactly the original
100 ms per owner, both paid-CPU decompositions must agree, original unsigned
counters must fit u64, and a closed owner cannot retain unsettled live CPU.
A real paid deficit remains rejected even with a perfectly balanced escrow
equation.

The outer `meter` and `actual_flow` observations are separately locked; the
reader deliberately does not invent cross-snapshot equality. The original ZIP
contains a real meter-owner 0 to flow-owner 1 interleaving. Only the complete
owner/escrow tuple inside the same `actual_flow` is required to be simultaneous.
Neither a consistent third-party JSON object nor this diagnostic shadow creates
runtime authority. Original source, binary, IPC and artifact binding remain
mandatory, and the unchanged runtime retains actual debt and Unknown telemetry.
Samples also do not prove that an uninterruptible interval never temporarily
overshoots between cooperative checkpoints.

The original reader fails four of the five new adversarial test methods. The
corrected complete reader passes **14/14**, including all original nine controls.
A root-checkout repeat also passes **14/14**, CI contracts **96/96**, and source
integrity negatives **34/34**, all source-stable. The original workflow's exact
reader count changes from nine to fourteen; profiles, native selectors, CPU
limits, reservation/refill constants and both original business windows do not
change.

[Original-artifact comparison](../../evidence/system-security-20261030/escrow-reader-followup/candidate-original-artifact-readback.json)
retains the full raw ZIP hash and 532 report/IPC member hashes. With the corrected
reader, the original b23 runs 2 and 3 complete the full readback and retain their
native finite criteria; run 1 still fails the identical full-state-equality check.
This is new interpretation of preserved b23 bytes, **not a new native run**, and
does not change the original workflow's failed conclusion or establish production
qualification.

#### Security observations are still not closed

The [new Rust CodeQL readback](../../evidence/system-security-20261030/escrow-reader-followup/codeql-result-review.json)
binds [run 41007753676](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41007753676).
Create and all 37 selected queries execute successfully with the requested
all-targets option, but the result is still failed: 780 findings (757
hard-coded-value and 23 logging), 304 affected tracked files and 305 diagnostics
including one unlocated workspace failure, plus retained type/SSA consistency
errors. Only one previous include-related affected path disappears. A recorded
all-targets request does not establish complete semantic extraction, and 780 is
not a count of demonstrated exploits.

[Exact-source export run 41007753865](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41007753865)
ends at its original bounded deadline without a stable authenticated official
analysis. Its retained result has `target_pr_gate_authenticated=false`,
`complete=false` and `verdict=null`; it is neither official gate success nor a
demonstrated vulnerability verdict.

The independent all-features dependency policy still reports bincode 1.3.3,
derivative 2.2.0 and paste 1.0.15 as unmaintained, and tracing-subscriber 0.2.25
for its published logging advisory. These four are not the CodeQL finding count.
A possible smallest maintenance change is at the original ark-relations logging
dependency; codec and macro replacements additionally need original-byte,
generic-bound and proof compatibility controls. No dependency exclusion, blind
SDK migration or receipt/profile change is included here.

The raw records, genuine red/green reader controls, unchanged-byte comparisons
and new hosted observations are retained under
[the follow-up evidence directory](../../evidence/system-security-20261030/escrow-reader-followup).
The paired Hepta continuation has separately completed its original contracts/
evidence provider suite (74), full automation suite (128), four real late-ACK
controls and four full Agentd HTTP controls. Those local component results do
not qualify a new cross-repository head/merge tuple; the pair still requires
explicit immutable source/base/ordered-merge binding and its original hosted
gates.

### PN owner recovery continuation — 2026-10-30 UTC

This continues the existing PN0–PN6 sequence and M00–M17 ownership. It does not
replace the original acceptance gates or qualify the whole system. The frozen
starting sources were Chain b23c0ef85f058507185b2ccb404a5d648e447c06 and Hepta
6850ae0ca6191b0afa436b00403c059d58ca2893. Concurrent Chain publication
24b265834daea34947adbb5903d887e3f6043838 was fetched and adopted by fast-forward;
its stronger original-credit reader and retained evidence were preserved.

[The owner-recovery evidence index](../../evidence/pn-owner-recovery-20261030/README.md)
contains byte-hashed original RED/GREEN logs and independent historical readback.
The actual source pair is bound by the subsequently published Hepta execution
profile and its runtime candidate-tuple receipts; these starting hashes do not
stand in for that later pair or its applicable source/merge executions.

| Stage | Concrete continuation | Remaining original exit |
| --- | --- | --- |
| PN0 | Preserve concurrent 24b source; carry the two verified PQ files forward; version the ordinary Hepta source selection rather than reuse the old branch-name fallback. | Actual published source/base/merge tuples, complete source/config/binary receipts and applicable full gates. The binary/diverse research workflows retain their own frozen historical experiments and are not silently certified by the ordinary V3 pair. |
| PN1 | TPQ1 rejects actual SQLite ephemeral main backing before authorization consumption. Real ML-DSA RED: 13 pass/one failure; GREEN: all 14 selected owner tests pass. | W1 statement correctness, effective work cost, honest service under the original attack envelope, all authorization surfaces and independent cryptographic review remain distinct obligations. |
| PN2 | Adopt the parallel signed stored-credit reader without changing native accounting, deadlines or full-state predicates. Add balanced one/two-owner terminal controls inside its existing fourteen-test roster. | Strict History still needs the original complete business campaign; long-history/incremental-state, cold-sync, deep-reorg, disk-fault and independent-readback acceptance remain open. |
| PN3 | The ordinary model workflows use a separately versioned closed source selection; historical profile/source identities remain immutable. | Three real installed-parent/evaluation/download/install/next-task cycles, with beneficial release and valid no-update reported separately. Source selection tests do not establish efficacy. |
| PN4 | Hepta's existing AutomationStore verifies original step/fence and exact intent/payload in the same SQLite transaction as recovery observation append. The first native package selection passed all 103 tests. | Complete typed provider-operation persistence, legacy unresolved reconciliation, actual Agentd integration and loss/reorg/economic gates must have their own current-source evidence. No late Unknown becomes an invented absence or retry. |
| PN5 | Keep the original independent-operator, custody, fault-cohort and at-least-72-hour prerequisites. | Three real independent administrators/failure domains, joint PN1–PN4 acceptance and the frozen full WAN campaign are still required; this local session provides none of those independence/duration claims. |
| PN6 | Keep the existing versioned migration and release owners and false activation flags. | Full PQ identity/source-exit migration, retained liabilities/revocation/history, all prior qualifications and an actual release decision for the selected binaries. |

#### Bounded fixes and explicit limits

SQLite FULL synchronization does not persist an in-memory authorization owner.
The new backing check queries the actual opened main database, covering temporary
files, `:memory:`, memory URI modes and memdb VFS without rejecting an ordinary
disk basename. It uses the existing error, schema, signature domain and sequence
transaction. It is not a defense against restoring an entire old database copy
or proof that the remaining classical paths have become post-quantum.

Independent review of the original b23 graph-fence artifact verified all 1,575
member hashes and all 5,336 CPU samples, including 473 legitimate negative stored
balances backed by original reservations. Runs two and three pass the adopted
reader; run one still fails full receiver/verifier state equality. These are
historical readback results, not a fresh native campaign or an erased CI failure.
The additional terminal controls prove that balanced live credit still cannot
satisfy completed settlement. The production reader bytes remain those of 24b.

The original native PQ selection filtered 887 unrelated library cases. Scoped
strict Clippy and rustfmt passed; the retained SQLite I/O build-script warning
and cached canonical-compiler follow-up remain explicitly unqualified for I/O.
A functional owner test, lint pass or evidence index does not replace the
original fresh-build I/O, full-workspace, cross-architecture or public gates.

### PN transaction-local readback and durable effect recovery — 2026-10-30 UTC

This is the next bounded continuation on Chain
`a38d770966c65ad34c9d5e55f3c2917c2e3bda0f` and Hepta
`f874d948a38c119e57b1368adab79437956acd78`. These are the adopted parents, not
substitutes for the actual subsequently published heads, ordered merges or
execution receipts. The existing M00–M17 ownership and all PN0–PN6 exit
conditions remain authoritative. No activation or qualification flag changes.

#### PN2: reuse only original verified graphs in the same write transaction

The original admission readback can now retain four bounded roles: child,
genesis, the fully verified child's parent and the active tip read by the
original Node owner. Parent nomination occurs only after the original complete
child verification; active nomination uses the already-read tip. Neither
nomination performs discovery SQL, creates a verification receipt, replaces a
previously nominated role or renews an invalidated scope. A fifth unrelated root
is not retained.

Each hit still reads current State/Record/delta data, computes the original full
State commitment and performs the original block/parent/Record comparisons.
The original SQLite connection, transaction, write-epoch and schema checks remain
binding. Writes invalidate the whole scope; a mutation after a consumed hit
refuses the owning operation. The active reader checks the consumed scope after
its final callback and tip/generation/slot comparison, before publishing its
active commitment view. The final admission keeps the corresponding consumed
check before its existing effect-marker write. Shared-storage and no-receipt
paths retain their original behavior.

The [parent/active readback evidence](../../evidence/pn-owner-recovery-20261030/parent-active-readback/README.md)
retains the exact source, original failures and commands. The qualified native
RED has one passing and two failing controls: duplicate parent graph traversal
is five rather than four, and a final active-reader callback can otherwise return
stale success after a controlled KV write. The new GREEN controls pass all three.
The complete original release `--include-ignored` selection passes **77/77**, with
zero failed or ignored tests, including the original create-new retained-delta
cost output. The retained cost control has no speed threshold and does not
measure the new parent/active reuse or whole-Node State/History throughput.
The earlier debug selection remains **76 passed / one ignored**; it is not
relabelled as the release cost gate. The original owner/snapshot
selection passes 22 and the combined-source PQ owner selection passes 14.

The fresh canonical debug and release builds retain the unchanged
`sqlite-3.51.3-normal-native-linux-layout-v3` build fence. Package-scoped Clippy
with the original all-targets/all-features flags and `-D warnings` passes.
The earlier unqualified
exploratory build, corrected cold-reopen test assumption, and interrupted native
compilation remain separate original records. This controlled build observation
does not establish power-loss recovery, arbitrary-host I/O qualification or
bit-for-bit reproduction across independent machines.

This change removes repeated graph work within one existing transaction. It
does not eliminate the full-State hot path or tip-to-genesis History work and
does not establish a throughput multiplier. The independent original `24b`
strict campaign readback still fails all nine phases. Its first-window
confirmation and nested cost observations are preserved without adding nested
CPU intervals. The subsequent actual `a38` strict and graph-fence hosted
campaigns also remain failed; old `b23` reader successes do not replace them.
Every new published source still needs its own original business and attack
campaign, long-history/growing-account cases, cold sync, deep reorg, disk faults
and independent readback.

#### PN4: preserve original effects through stale owners and old writers

The paired Hepta continuation validates the original immutable step/fence and
exact intent/payload inside the same `BEGIN IMMEDIATE` transaction before
persisting recovery observations. A stale owner cannot first append a terminal
fact and only then fail settlement.

Published migration 21 remains unchanged. New migration 22 explicitly labels
new compatible appends on the four effect tables. Real already-open older
connections that omit the new columns cannot append through the new guard.
Legacy unresolved attempts without complete operation binding remain Unknown;
they cannot acquire an invented replacement operation or fabricated absence.
Existing complete v21 bindings retain their original operation, and complete
older terminal evidence remains readable. Exact SQLite column metadata is also
checked on reopen, closing the demonstrated default-value catalog bypass while
preserving the original migration bytes and trigger checks.

The final AutomationStore package selection passes **134/134**. Earlier 129 and
133 results are overlapping stages, not additional independent passing cases.
The original native REDs, one earlier flaky fixture execution and its exact
transaction-scoping repair remain retained. The typed provider ACK stores what
the adapter observed; it has no provider signature. Preserving a v21 binding
does not retroactively prove that the older implementation never lost an ACK.

Agentd reconciliation may observe the original operation after lease expiry;
new dispatch still requires the live owner lease. Six actual HTTP controls pass,
including an exact POST-then-GET history after AutomationStore close/reopen and
zero dispatch under an expired lease with an otherwise live grant. The selected
restart is not a whole Agentd process restart. Repeated terminal observation
performs no additional GET. The separate final-use owner rejects FIFO config
before it can block its constructor; its six selected native V2 controls pass.
Neither result closes full reorg, payment, refund, custody, repair or economic
budget obligations.

#### PN0, PN1 and PN3–PN6: preserve the remaining actual exits

The ordinary Hepta execution source is a new closed V3 selection; the historical
V1/V2 source identities, model profile, plan and target remain immutable. The
published pair must bind its actual source/base/ordered merge, with all 33 source
inputs reverified. A separate four-lane effect-recovery job executes x64/ARM64
and actual head/merge controls even when the joint business job fails. Identical
trees never substitute for execution of the actual commit in that job. This
source selection grants no model compatibility or installation authority.

The immediate PR bases remain `fix/chain-native-convergence-20261029` and
`fix/hepta-final-use-mldsa65-v2-20261029`. Their actual prospective merges qualify
only those named base/source pairs. They are not current-main integration
receipts; the upstream Draft stacks and actual main merge parents must remain
explicitly tracked before a main or release decision.

PN1 still requires W1 statement correctness, effective computation cost and
honest service under the original complete attack envelope as separate proofs.
The local PQ-owner and FIFO fixes do not replace classical identity, transport,
finality or Cell authorization surfaces. Production authority clocks, durable
frontiers, complete PQ migration and independent cryptographic review remain
open.

The local environment does not satisfy the original frozen model-host/runtime
prerequisites. Source-selection tests and controlled Cell handoff do not prove
three real installed-parent, frozen-evaluation, complete-download, ordinary
installation and subsequent-task cycles. Beneficial release and valid no-update
must still be reported separately. Public model material is not treated as a
missing private credential.

PN5 still needs three real independent operators/failure domains and the frozen
at-least-72-hour experiment with each fault cohort meeting its original target.
Several hosted runners do not establish operator independence. PN6 remains
blocked on those prior qualifications, actual PQ identity prebinding/source
exit, retained liabilities/history and a release decision for concrete binaries.
The two Drafts remain development continuations; component passes do not close
these system exits.
