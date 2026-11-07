# PoN security and acceptance requirements

Status: required evidence; no independently accepted runtime or neural-work claim.
The sole phase sequence is in the development plan. This file defines domain acceptance.

## S1. Consensus properties

Independent implementations must agree on canonical bytes, proof relation, required
target, chainwork, valid branch state and reorg output. Model checking/property tests
cover forks, partitions, unequal work, delayed/duplicate messages, time manipulation,
invalid/unavailable bodies and upgrade contexts. Show work hardness, challenge binding,
output uniqueness and verification cost; observed success is not a proof of these claims.
No less-than-one-third BFT assumption or seven-validator quorum is transferred to PoN.

## S2. Counterexample matrix

| ID | Counterexample | Required outcome |
|---|---|---|
| PON-C01 | greater height, lower valid cumulative work | keep heavier valid branch |
| PON-C02 | peer claims inflated chainwork/target | recompute and reject mismatch |
| PON-C03 | extremely lucky digest at ordinary target | no extra credited work |
| PON-C04 | same expensive result, new payout/body/parent/nonce | reject unless fresh qualified work proves new statement |
| PON-C05 | multiple proof randomness values for one output | one logical block/lottery |
| PON-C06 | multiple identities replay one contribution | no repeated contribution budget |
| PON-C07 | more evaluator votes or better model score | no ledger work or fork preference |
| PON-C08 | target interval off-by-one, time regression, overflow | exact deterministic boundary behavior |
| PON-C09 | future-time header | bounded deferral/recheck, no permanent invalid cache |
| PON-C10 | missing model/body needed by work validity | no active-chain apply or mint |
| PON-C11 | no new model improves | continue only qualified existing maintenance work; no invented gain |
| PON-C12 | zero/low-rank/cached/easy work | reject/repair primitive; never count as full effort |
| PON-R01 | reorg after model adoption/reward maturity | branch state unwinds, local effects retained |
| PON-R02 | crash during detach/attach/publication | exact intent/readback recovery |
| PON-R03 | undo pruned below valid fork | verified resync, not artificial finality |
| PON-R04 | lease disappears after remote API succeeded | reconcile original effect, no blind retry |
| PON-R05 | old local revocation restored with chain snapshot | reject rollback; authorization remains fenced |
| PON-M01 | incompatible base/tokenizer/layer/rank | reject parameter admission |
| PON-M02 | good isolated expert harms full model | reject adoption/reward under locked rule |
| PON-M03 | two complementary experts fail single-add test | evaluate declared bundle within fixed budget |
| PON-M04 | benchmark leakage/backdoor/unsafe loader | quarantine/reject; preserve evidence |
| PON-M05 | author offline after release | parameter retrieval and reproducible use still work |
| PON-E01 | all scores zero, no credible whole-model gain | zero model payout, retain budget |
| PON-E02 | split/perturb/relabel same root contribution | no budget amplification |
| PON-E03 | free-tier self-traffic/Sybil requests | bounded quota/spend; no fake learning reward |
| PON-E04 | claimed budget exceeds funds/commitment | atomic rejection without partial reservation |
| PON-X01 | old QC relabelled work proof | reject before authority |
| PON-X02 | imported liabilities omitted | refuse new-instance activation |

## S3. Required real-product experiment

At least three independently evaluated domains/nodes contribute compatible trained
parameters, not deterministic mock models. Hold out tasks by source and time. Compare
frozen base, best expert, simple merge, routed experts, composition-trained and distilled
models with equal declared training/evaluation/serving budgets. A new independent
consumer obtains free bounded service and shows future-task benefit, then contributes
its next authorized improvement. Bind binary, source, parameter bytes, data/consent,
proof/profile, hardware, traces and failed observations. Zero new efficacy data is
reported as unmeasured, not assumed improvement.

## S4. Operational and economic qualification

Run multiple independent mining/validation operators across hosts. Exercise forks,
partition/heal, eclipse resistance, process/power loss, proof flood, stale work, deep
reorg and workload exhaustion. Measure accepted work rate, stale fraction, verification
CPU, proof bytes, difficulty dynamics and work concentration. Separately measure
verified useful model improvement, end-to-end serving latency, parameter availability,
free-tier acceptance, budget conservation and recovery. Seven processes under one key
custodian are not seven independent security actors. No fabricated p95/p99 or throughput.

## S5. Source, evidence and release separation

Documentation checker success means inventory/reference/semantic-policy consistency.
Reference-model tests mean the specified arithmetic/state examples pass. Neither
means cryptographic work qualification, Rust runtime correctness, public-model benefit,
independent economic acceptance or activation. Preserve all negative evidence. New
source changes require exact-head and applicable prospective-merge qualification.

No new work profile, parser, reference model or banner is allowed to set a production
flag. An unqualified primitive cannot be replaced automatically by PoCO or pure hashing.
Failed qualification directs further design/implementation; it is not a reason to
announce a scientifically established impossible task or to claim success prematurely.

## S6. Audit remediation acceptance matrix

These are pending domain obligations for the existing PN0–PN6 sequence, not
newly executed test selectors, registered procedures or acceptance receipts.
Implement each in its current owner, then add exact source/test bindings to
the existing registries. Preserve all earlier counterexamples and old-profile
regressions. A passing documentation gate closes none of these rows.

| Ref / phase / owners | Adversarial case | Required acceptance evidence |
| --- | --- | --- |
| A01 / PN0 / M15/M17 | Hepta receipt pins an older Chain; scan succeeds with unresolved alerts | Exact head/tree/base/merge/binary/profile pair; actual required checks and rule/path/data-flow triage. Old-pair receipts and aggregate alert counts do not certify the current pair. |
| A02 / PN1 / M01/M02/M17 | Structured or preprocessed producer gets cheaper effective work | Equal-target full-cost samples, all setup/failed attempts and task/hardware assumptions, plus independent security analysis. No invented cost lower bound or machine-count adversary fraction. |
| A03 / PN1 / M04/M15 | Ticket-passing false transcripts consume shared resources while honest paid traffic runs | Original-budget three-mode campaign meets 3/3 timely client-verified rounds per mode in three complete runs; full CPU ownership and all failed/Busy/unknown cohorts retained. Resource bounds and computational security have separate verdicts. |
| A04 / PN2 / M00/M06/M07 | Research archive exceeds 65,536 leaves but native profile still uses old cap/root | Actual signed native admission of at least 65,537 permanent accounts in a new context, bounded working/witness/packet limits and independent aggregate/root verification. Old-profile replay remains exact. |
| A05 / PN2 / M06/M07/M09 | Missing account is presented as absent; required refund/miner/range row omitted | Original-parent proof authentication and complete mandatory coverage reject the omission; present-zero existence/nonce and monetary conservation survive re-entry/reorg. Unavailable is distinct from invalid or absent. |
| A06 / PN2 / M07/M08/M13 | Disk-full, partial commit, provider loss or GC removes a needed fork/duty | Reserved writes/root retention, atomic rollback/recovery, verified deep-fork backfill and cold readback; source-preserving migration. Local effects/revocations never rewind. |
| A07 / PN3 / M10/M11 | Public fixed tasks, same-custodian keys or future-window leakage give ceiling scores | Independent source/time custody, exposure audit, frozen statistical rule and strong equal-budget controls. Unknown/no-gain remains unaccepted/zero payout; private evaluations use an explicit trust profile. |
| A08 / PN3 / M14/M15 + Hepta owners | Old packet/task/provider or orphaned acceptance is reused to install | Exact schema-3 owner/provider/output/task/packet and active ancestry/generation, explicit confirmation policy and current local selection/withdrawal/resource checks. No chain observation constructs FinalUse. |
| A09 / PN3 / Hepta existing owners | Download/selection receipt claims improvement but runtime uses old weights | Three actual lineage cycles with installed-parent inference readback; sustained-benefit claim separately needs three installed prospectively qualified beneficial releases. Historical decisions retain actual model identity. |
| A10 / PN3 / M09/M10 | Valid individual chunks form incompatible or incomplete model | Bounded release closure, pinned base/tokenizer/router/layout/runtime and required Cells; reject cycles, version/shape/quantization conflicts, missing dependencies and unsafe loader input before use. |
| A11 / PN4 / M09/M12 | Sybil contributions, repeat repair or reorg creates unbacked reward/resource obligations | Separate funded finite budgets, duplicate/lineage controls, byte-time/repair/service units, exact effect reconciliation and conservation through maturity/expiry/refund. |
| A12 / PN5 / M04/M09/M17 | Origin/provider disappears, discovery is eclipsed or slow peers drain retries | Three independent replicas, retrieval with one lost, budgeted repair, bounded discovery/confidentiality profile, and preregistered 72-hour WAN fault/load campaign; all requested release cohorts reported. |
| A13 / PN6 / M00/M13/M15 | Migration/rollback promotes old proof or restores revoked authority | Complete source/obligation reconciliation, fresh destination/profile/domain identity, abort/recovery rehearsal and explicit governed release decision. No flag promotion by source merge. |

Each acceptance package identifies the plan revision, scenario refs, owner,
executed source/tree/base/merge and binary, full profile/configuration, hardware
and custody/failure domains. Include preregistered thresholds and denominators,
raw signed/byte artifacts and logs with hashes, retained failures, missing data,
independent reproduction and exact first error/recovery outcome. Separate source
binding, local component pass, ordinary product execution, independent acceptance
and production authorization. Null is required for an unmeasured outcome.

Numerical objectives in the plan are development gates. They do not establish
unlimited-attack fairness, cheapest-adversary hardness, infinite storage, future
model benefit or permanent data availability. Any changed assumptions, deadlines,
budget or scoring policy create a separately named campaign/profile; the original
failed cohort remains failed.
