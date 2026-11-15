# Stateful legal W1 optimization catalog

## Implemented increment and scope

This component joins finite producer choices to a complete attempt and cache
record. It does not introduce a new matrix algorithm. The existing
[V5 native experiment](../../../../formal/pon-nakamoto-v1/W1_RANK_BATCH_V5.md)
already implements exact bounded-rank preparation, paid failed probes,
seventeen producer strategies and an actual four-worker batch. Its source,
native observations and qualification remain separate.

The new [catalog](../../../../formal/pon-nakamoto-v1/contracts/legal-optimization-catalog-v1.json)
freezes two actual header encodings, four synthetic material classes, three
Python producer paths, complete nonces 0 through 3, two-worker issued batches,
and a fifth attempt cancelled after its first transcript tile. It covers
low-rank preparation, challenge-independent AB caching, batch work, a bounded
candidate bank, misses, withheld hits, post-first-hit work and a partial failed
attempt in one replayable record. No favourable nonce or material is added
after observing success. A four-attempt cohort with no target hit remains in
the report. Each strategy uses exactly the same task, header and nonce stream.

The [implementation](../../../../formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py)
executes the original 64 by 64, rank-eight, prime-field PNW1 relation. It retains
the complete 49,156-byte proof prefix once per cohort and every completed
32-byte transcript. These reconstruct the exact complete 49,188-byte proofs;
each reconstructed proof must match the original producer's SHA-256 digest.
The complete prefix includes all original A, B and returned C bytes.

This catalog is a finite executable list, not coverage of all legal algorithms.
There is no native Node execution, task admission, STARK generation, network
publication, actual chainwork, quantum implementation or cost lower bound.
Its status remains **HOLD_NO_GO**. The synthetic materials are not evidence of
Hepta input provenance or independent customer demand.

## Original relation and exact preparation

The eager producer computes the complete challenge-dependent noisy product and
the original two denoising terms on every attempt. The dense prepared producer
computes AB once and retains its canonical proof prefix. The rank-bounded
producer validates every input word, tries an exact row basis for A, then B if
necessary, and otherwise computes the dense product after paying both failed
probes. A successful rank-r preparation uses A=UV and AB=U(VB), or B=UV and
AB=(AU)V. Rank zero has a zero product but still pays input validation and
serialization. No floating-point rank tolerance or unverified factor witness
is accepted.

The declared material classes are full-rank Vandermonde pairs, a rank-two left
matrix, a rank-four right matrix with a full-rank left partner, and zero pairs.
The right-low-rank case therefore retains the failed left probe. The dense
case retains two proved rank-at-least-nine probe exits. Neither is silently
removed from its preparation cost. Every completed attempt still expands the
original bounded SHA-256 rejection sampler and hashes all 512 transcript tiles
in the original order. The original work profile and production producer do
not change.

## Header freedoms, cache and bank identity

The original PNH1 bytes and the PGH2 wrapper remain distinct. A template fixes
all header bytes except the actual little-endian nonce field. The target is
part of the challenged header; old tickets cannot be rethresholded after
changing it. The template binds the task digest to all canonical A/B words.
The retained fixture header is used as a byte template, with a declared task
substitution. This is not a claim that a native parent state admitted that task.

Prepared AB bytes can be reused across fresh challenges for the same task.
The candidate bank is narrower: its domain commits the complete nonce-zeroed
header and the current source/profile identity. Changing the parent, timestamp,
target, PGH2 witness, task or source identity prevents retrieval under the old
domain. At most four candidates are retained. A local extraction removes one
entry and marks its nonce spent; reinsertion and second extraction refuse.
This bookkeeping prevents duplicate counting **inside this experiment**. It is
neither a persistent consensus spent set nor a proof of the adversary's actual
private initial state.

Bank contents carry no verification authority. A caller can cache incorrect
bytes, and a retrieved candidate still needs complete verification. Tests store
a canonical false product in the bank and require the real scalar verifier to
reject it. Cache hits do not create new work. The experiment extracts at most
the first original-target hit in declared nonce order; all other hits stay
withheld and all misses remain in the record. No local extraction is labelled
a network publication or a block reward.

## Full replay and cancelled work

The unchanged [scalar W1 verifier](../../../../formal/pon-nakamoto-v1/work_oracle.py)
recomputes every complete candidate from its actual challenge and task. Hits
are verified at the original target. A target miss necessarily fails the
original complete verifier at its cheap target filter, so the reader performs
two separate checks: full relation replay at an explicit all-ff diagnostic
target, and the expected TARGET refusal at the original target. These misses
are counted as original-target refusals, never as accepted successes.

The fifth nonce is predeclared and cancelled after one real transcript tile,
after the complete noise construction has executed. It emits no proof, final
transcript or ticket. The reader independently reconstructs that first scalar
tile and its partial hash state digest. This checks the deterministic partial
observation; it does not turn cancellation into a complete W1 proof. Partial
work retains its measured CPU and wall time. The campaign does not claim to
cover arbitrary operating-system kills, all failure modes, or missing remote
descendant costs.

The reader checks the exact grid and order, every nonce, all proof commitments,
target results, preparation paths, bank inventory, first-hit selection and
matched complete outputs across strategies. Removing a miss, cancellation or
cohort fails coverage. Rewriting a proof with internally consistent digests
still reaches full transcript/product verification. Source digests and bounded
claim fields prevent a recorded component result from being relabelled native
admission, a lower bound or complete physical billing.

## Measured costs and exclusions

One inclusive process-CPU and wall interval covers each producer constructor,
failed rank probes, both issued batches, worker creation and joins, all complete
and cancelled attempts, bank insertion/extraction, record construction and
local teardown. Each attempt also has its own calling-thread CPU interval.
Those intervals are nested diagnostics and must not be added to the inclusive
total. The two Python threads execute real work; the GIL and this small host
sample prevent any inference of a parallel speedup or hardware advantage.

Synthetic material construction is measured once separately. Each of the eight
profile/material header templates also has a separate construction timer. These
common costs are neither free nor added repeatedly to each matched strategy.
Each strategy additionally pays fresh validation of both matrices inside its
own constructor. Source inventory and record-file I/O are outside the producer
windows and are not claimed completely billed. The fresh full scalar reader
run is also separate. The CLI reports
the reader's separate inclusive process time. Setup, miss, withheld, cancelled
and bank work are never amortized over an invented number of winners. A
no-hit cohort has no finite per-success cost estimate. Repeated matched
strategies are not independent mining samples or extra credited work.

This process does not measure energy, hardware purchase cost, aggregate global
memory, GPU cost, native admission, network use, STARK generation or all
external help. Those fields remain null. CPU observations and literal operation
coverage do not establish a fastest legal strategy, a uniform-ticket law, a
classical/quantum envelope or a consensus resource share. Initial caches are
empty only for the objects constructed by this script; the host's complete
physical initial state is not certified.

## Reproduction

Run the ordinary project preflight first. Freeze the commit and listed source
bytes before the observation. The inventory records any listed file whose
bytes do not yet match that HEAD; a development run must not be described as
execution of a clean published commit. Each output path must be fresh; the command
retains a per-cohort partial JSONL file as it executes. It writes the complete
observation before running the reader, so a reader refusal does not erase the
actual producer record. A partial file is never accepted as a complete grid.

```sh
bash scripts/project-preflight.sh
python3 formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py \
  --output /absolute/new/legal-optimization-observation.json
python3 formal/pon-nakamoto-v1/legal_optimization_catalog_v1.py \
  --replay /absolute/new/legal-optimization-observation.json
python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p test_legal_optimization_catalog_v1.py -v
```

The default campaign contains 24 cohorts, 96 complete candidate attempts and
24 deliberate partial cancellations. Those are fixed invocation counts; actual
target-hit and no-hit counts are derived from the actual retained bytes. The
dedicated tests exercise the full fixed grid and adversarial record mutations.
Results on another source commit must be reported as new observations rather
than substituted for this campaign's identity.

The sole development plan remains
[the existing plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
