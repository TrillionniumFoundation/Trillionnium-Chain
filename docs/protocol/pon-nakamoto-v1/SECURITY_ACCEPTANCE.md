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
