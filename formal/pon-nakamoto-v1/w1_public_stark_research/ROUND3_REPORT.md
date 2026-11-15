# Complete W1 research: bounded decoding, carry backend and cost-model audit

## Decision

**HOLD_NO_GO remains in force for all five production gates.** This round supplies
working code, exact-source checks, full proofs and retained failures. It establishes
positive end-to-end improvements relative to the previous research STARK backend
on one retained input. It does not establish a benefit over the native verifier,
a complete noninteractive/PQ128 theorem, global production rejection bounds,
universal physical-work hardness or production Node qualification.

The publication baseline is `3bbd072e4983eceee4531d7576d329da5b0d0900`.
The first bounded-decoder increment was separately checked and pushed at
`cae1e3657b0913991d9465995e709a544218a27c`. Carry commits
`ac4927c52266e7bd1fae547f92a1d0753f4f96d6` and
`9fe8aba32558e4f59c39b26c07ea1331b058762e` were integrated by normal cherry-pick.
The original measurements retain those source identities; later integration
checks do not relabel their provenance.

## 1. Security: an actual primitive-model restriction, not a new security number

[The audit](security_model_audit/README.md) reconstructs the exact P3 0.8.0
Goldilocks Poseidon2 permutation and its inverse with integer arithmetic.
For the raw compression primitive C(u,v) = first4(Pi(u||v)), two distinct
chosen permutation outputs with the same first four coordinates give two
explicit inverse inputs with the same compression result. The official native
P3 forward APIs independently confirm both witnesses. This rules out treating
that raw, unrestricted compressor as an arbitrary-input collision-resistant
hash. It does not constitute a valid restricted-tree collision or W1 forgery.

The same audit proves H4(x) = C(x,0^4) and H2(a,b) = H4(a,b,0,0).
Those widths occur in the actual quotient and FRI leaf roles. A proof for
independent leaf and branch random functions therefore cannot simply be
substituted for this shared public invertible permutation. The required next
security statement must cover the actual restricted commitment/tree game,
adaptive shared forward/inverse queries, sampling, Fiat--Shamir compilation,
both components and the full lifecycle budget. A valid union bound itself
does not require independent events.

Ten Python tests, the native P3 probe, all eleven primary-source registry
file matches, six archive hashes against Cargo.lock, and the historical
proof-config Git-object match passed. The native receipt is separately
retained; the original Python audit's statement that native execution was then
pending is preserved as historical evidence.

The estimator still reports approximately 63.95384529640614 conditional RBR
bits. Its input 128 is explicitly marked as a conditional estimator assumption,
not a raw-compressor security claim. Concrete shared-permutation tree binding,
complete noninteractive, quantum and lifecycle security bits remain `null`.
Metadata schema names advance; proof transcript domains and parameters are
unchanged. See [the native integration note](security_model_audit/INTEGRATION.md).

## 2. Arithmetic: complete pipeline improvement survives bounded admission

The new AIR keeps all 81,920 original Dot8 relations. It represents each row
by 35 quotient bits and 19/20-bit carries, with three separately lifted limb
equations. Every side is below 2^36 even for arbitrary Boolean witnesses, so
equality in Goldilocks lifts to equality over the integers before weighted
elimination. Five independent rows are then packed into each physical row.
The full trace has 16,384 rows, 370 main columns, 180 preprocessed columns and
385 degree-two constraints. No real logical row is dropped.

The new namespaces are component 3 / `W1P3ACR2` and component 4 /
`W1P3APC3`. Original components 1/2 are preserved. Every verifier rebuilds its
public preprocessing from the statement and independent expected inputs.
[The independent review](independent_review/CARRY_INDEPENDENT_REVIEW.md)
checks the integer bounds, completeness, zero padding and lane mapping.

### Final bounded-admission implementation

One additional ABBA block generated four fresh complete W1 proofs after both
runners received their structural guards. Each sample includes prepare,
fresh SHA proof, fresh arithmetic proof, serialization/persistence and a new
verifier process with independent preprocessing. Both sides used eight common
CPU affinities, Rayon 8, observed cpu.max 800000/100000 and an 80 GiB cgroup
memory cap. This was a shared host and one independent input task.

| Median metric | Original research AIR A | Packed carry B | B/A |
|---|---:|---:|---:|
| Complete pipeline | 23.961509 s | 13.764899 s | 0.574459 |
| Proof process | 22.936896 s | 12.833666 s | 0.559521 |
| Independent verifier | 0.943004 s | 0.887252 s | 0.940878 |
| Proof peak RSS | 2,383,922 KiB | 2,037,316 KiB | 0.854607 |
| Statement plus both proof envelopes | 5,264,276 bytes | 5,187,252 bytes | 0.985369 |

Source and binary bindings were identical before and after this comparison.
All four executions passed complete verification. This small block confirms
the direction seen in the earlier eight-sample packed comparison; it is not
a population or worst-case performance estimate.

### Earlier observations are retained without selection

The first, unpacked 74-column carry candidate reduced total pipeline time
from 32.328418 to 15.541584 seconds, but its verifier regressed from 0.967995
to 1.251529 seconds. All eight observations, including slow baseline samples,
remain in [the original carry measurements](CARRY_MEASUREMENTS.md).

The next packed ABBAABBA comparison improved pipeline median from 23.555768
to 13.304787 seconds and verifier median from 0.930409 to 0.860259 seconds.
Those eight runs predate the new component-3/4 structural guards and are
explicitly labeled accordingly. The final guarded comparison above is separate.

An additional pre-guard packed full proof passed an actual 2 GiB memory cap:
cgroup peak 2,098,737,152 bytes, only 48,746,496 bytes (about 46.5 MiB) below
the cap, with no max/oom/oom_kill events. This is one successful resource-cap
sample at its recorded source, not a universal production memory guarantee.

Across the two eight-run comparisons, that one cap sample and the final
four-run block, there are 21 fresh complete W1 proving executions on one
retained input task. Each produces both actual proof components. Small proof
unit tests and replayed historical proofs are not added to this campaign count.

### The native-benefit gate remains open

The frozen native candidate is 49,506 bytes. The packed research payload is
104.780269 times that size. The current public statement alone is 377,290
bytes, or 7.621096 native candidates, so reducing proof bytes alone cannot
make this representation cheaper to transmit than the native candidate.
The historical native FullLimb warm median is 1.913279 ms; it was not rerun
as a contemporaneous comparator in this round. The sub-second research
verifier does not establish a win over that reference.

## 3. Structural admission and the production-resource experiment

[Wire admission](WIRE_ADMISSION.md) validates both immutable buffers before
either allocation-owning decode. It checks the complete fixed bincode shape,
canonical base-field words, options, FRI counts, matrix widths, degree and
conservative full-path Merkle frontier limits without allocation or hashing.
All correctly shaped proof values still require the original PCS verifier.

| Arithmetic profile paired with SHA | Arithmetic envelope cap | Pair plus exact statement cap |
|---|---:|---:|
| Original component 2 | 778,437 bytes | 5,705,940 bytes |
| Carry component 3 | 554,565 bytes | 5,482,068 bytes |
| Packed component 4 | 659,205 bytes | 5,586,708 bytes |

The SHA cap remains 4,550,213 bytes. These are encoded-input and source-level
scanner-operation bounds, not total heap, CPU, wall-time, queue or cleanup
bounds. Fifteen native wire tests cover the actual four profile fixtures,
including cross-profile rejection and zero observed allocations during scans.

The first structural benchmark retained three positives and 96 negative
processes. Eight shape-error medians fell to 8.25--10.92 ms from
144.65--978.08 ms with the pinned original binary. Its separate successor
replay retained one positive, eleven ordinary controls and four late FRI
controls at the original cryptographic frontiers. All of these replay the
original proof bytes and generate zero new proofs.

The two integrated carry profiles then passed 36 fresh verifier processes:
two complete positives, 22 ordinary negatives, four typed arithmetic late
controls and eight structural negatives. Twelve typed mutant envelopes were
created; zero new cryptographic proofs were generated by this replay.
Both late subtypes remained FinalPolyMismatch and
CommitPhaseMmcsError(CapMismatch); structural cases reported no completed
phase before refusal. Source, executable and original-input bindings matched
before and after. The full runner is [run_carry_controls.py](run_carry_controls.py).

Two further batches used observed kernel controls cpu.max 25000/100000,
memory.max 2,147,483,648, memory.swap.max 0 and pids.max 256, with sixteen
verifier processes sharing a four-second observation window. One used the
guarded original profile; the other used the final packed binary. Each batch
observed all sixteen execs, zero completed cryptographic rejections by the
deadline, sixteen incomplete SIGKILL exits, zero unobserved exits and confirmed
cleanup. Total observation including exit collection and cleanup was
4.360192811 / 4.368416075 seconds. A four-second kill request is not a claim
that all cleanup completed within four seconds.

[The resource experiment](resource_pressure/README.md) preserves every request,
50 ms kernel samples, real wait4 usage/exit status, actual limits and cleanup
records. Its two case mixes differ, so they are not a performance A/B test.
The external observer, pinning and launch management are outside the verifier
quota. This is a user transient unit, not the required fixed root-owned
production slice, and it exercises neither Node queues nor the seven benign
submissions in the original service contract. It refutes completion of these
particular full-verification batches inside that window, not every possible
rate-limiting or queueing Node design. Cancellations are never counted as
cryptographic rejections or as production qualification.

These observations do not establish a global malicious rejection bound.
A production owner still must account for receipt, queueing, authentication,
all parsing and verification, cancellation, replies and cleanup under one
aggregate budget, including unfinished attempts and useful service under load.

## 4. Physical cost: a cheaper legal implementation and a limited-class theorem

[The physical-strategy increment](../physical_strategy_frontier_research/README.md)
keeps the original nonzero selected-event input, target and witness relation.
It recognizes each exact affine 8x8 block by checking all its entries, then
computes a useful product with 5 field multiplications and 71 additions,
versus the dense implementation's 512 multiplications and 448 additions.
Recognition/compilation charges 448 multiplications, 8,512 additions or
subtractions and 8,192 equality checks. The result is an achieved upper bound
for this input family, not a claim that arbitrary dense inputs have that cost
or that five multiplications is optimal.

Seven strategies each generate all 512 candidates, including every failed
candidate. All 3,072 cross-strategy full-witness byte comparisons match, and
42 fresh complete selected-event verifier replays accept the six hits for
all seven strategies. These are selected-event reference checks, not Node or
new complete W1 STARK proof generation. All 24 new tests passed; the old
21 upstream tests are retained as provenance and not counted as new work.
All 37 upstream snapshot files were independently checked against actual
Git objects at the publication baseline.

On that 512-nonce sequence, dense direct costs 1,048,576 field multiplications;
dense full-capacity lazy costs 951,808; affine direct costs 789,440; affine
lazy costs 788,495, including preparation. Other operation and memory costs
remain separately accounted rather than converted to physical energy.

[The proofs](../physical_strategy_frontier_research/THEOREMS.md) establish
exact optimality over all adaptive/randomized policies in an explicit iid
selector/Bernoulli-ticket, skip/attempt/store, bounded-cache model. The finite
version proves E[C] >= V(n,lambda) - lambda(1-alpha) for any strategy in that
class meeting success probability alpha. It includes paid skipped draws,
losing attempts and finite draw limits.

In the declared illustrative tariff, dense no-cache new-task cost is 134,984;
the dense capacity-16 class optimum is 114,109.562426...; the actually checked
affine direct implementation costs 102,984. Thus even a tight bound inside
that dense strategy class is not a bound on all legal arithmetic algorithms.
The price model, independence assumptions, device costs, batching, cross-task
reuse and larger algorithm classes remain explicit unresolved boundaries.

## 5. Production Node status

[The fixed-source audit](independent_review/NODE_PROFILE_STATUS.md) finds the
Node work path still calls `pon_work::verify_with_progress`, selecting native
FullLimb with a 49,188-byte PNW1 grammar. The P3 crate is a separate research
workspace. The Node crate declares experimental native composition and false
production-activation/consensus-authority flags. No research verifier success
is relabeled as production ingress or qualification.

The final integration check also compares the complete tracked runtime,
configuration and qualification directories to the publication baseline.
The runtime, configuration and qualification directory comparison is empty;
no untracked file was introduced there. The positive PNW1 call-chain evidence
therefore remains applicable to this research integration. The stage receipt
and final source verification keep their distinct identities; this is still
not an observation of a deployed Node or of the latest main branch.

Actual qualification still needs a versioned Node profile and external-context
binding; full verification, admission, persistence, activation and reopen
replay; and error/reorg/cancel behavior with no stale credit or authority,
all under the production resource/service contract. The other four gates
must be satisfied independently.

## Evidence, checks and publication scope

The integrated locked/offline dependency graph remains on P3 0.8.0. Formatting,
strict all-target/all-feature Clippy, all-target build and all 45 native tests
passed (24 unit, 3 carry-proof, 3 original-proof and 15 wire tests). The native
hash probe and ten Python hash-audit tests passed. The physical increment's
24 tests, 3,072 witness comparisons and 42 acceptance replays are separately
retained and not conflated with the Rust proof tests.

The first published wire commit also passed repository structure/Markdown
checks, 50 repository negatives and 43 source-integrity negatives, with equal
before/after exact-head source receipts. Final publication repeats the focused
checks on the final commit and binds it in the PR delivery receipt; that
receipt is distinct from the earlier measurement-source records. No complete
repository-wide Node CI or production qualification is claimed.

Convenient summaries and the native probe receipt are in
[evidence/round3-integration](evidence/round3-integration/README.md). A lossless
archive contains the full integration observations and metadata; its index
identifies raw bytes and excluded, reproducible proof/binary inputs by digest.
The measured backend's original commits are retained in a Git bundle with
the published baseline as prerequisite.

The source contains the executable campaigns, per-sample observations,
source/binary/fixture pins, primary-source snapshots, independent reviews and
retained failed attempts. The integration evidence archive preserves raw logs
losslessly, including terminal newlines. The first wire delivery's whitespace
refusal and the old gh GraphQL body-update failure are retained; gzip encoding
and a successful REST body update resolved those delivery issues without
altering measurement logs or bypassing repository policy.

This remains research evidence on a draft PR. It does not grant merge,
consensus, production activation, PQ128 or any of the five missing production
qualifications.
