# Complete W1 AIR/STARK and selected-event composition — research result

Qualification: **HOLD_NO_GO**. This is evidence for a standalone research
component, based on C4 commit `8df4b21d893906570d48f5beafabb3b31e0aefbc`.
It does not change the production Node, consensus, task admission, release
criteria or the existing integration candidate's eight open gates.

## Final-source observations: retained-native-02

The final source generated both full-size proof components again, then
passed three independent fresh verifier processes, eleven original negative
controls and four typed late-FRI controls. Each negative must match its
specific rejection stage. These counts do not turn an intentional verifier
rejection into a successful acceptance. The final verifier binary SHA-256 is
`7700eff6ea4a3ff1f8f6551c323ac5b90b2bb5a96d1eaeca41e108bc54a7e3fc`; its SHA-wrapper source SHA-256 is
`a5e4d045eede07e01474225d5568326f2d6abdf0aae8246311bd9084a9b137fa`. Full source and fixture identities are in
[provenance.json](results/retained-native-02/provenance.json).

| Retained artifact | Bytes | SHA-256 |
|---|---:|---|
| `statement.bin` | 377,290 | `d8b06f64c5e3ff0242e1fe30110280be56fe9eca9cfb55086f7ed7ab5bdb3b6c` |
| `sha.proof.bin` | 4,356,101 | `ca4867c63de4f0d247930944d4c47d87342a4945a399abe9f8a57eba2502e33c` |
| `arith.proof.bin` | 530,885 | `cfce6e90bd1f171ab6d202e70f2e442f8a88e490a22c806275dde2af1d6cf204` |

The final proof pair is available in [retained-native-02](results/retained-native-02).
The three artifact hashes all match
the original run-01 hashes. This is an observed byte comparison; the final
run still has its own source identity, generation, resource and verification
receipts. Three verifier processes check one retained proof pair, rather
than three independently sampled tasks or proofs.

| Measured component | Final observation |
|---|---:|
| Public-witness prepare, outer process wall | 0.025448374 s |
| Complete two-proof generation, outer process wall | 21.196110213 s |
| Complete generation, internal process wall | 21.180277754 s |
| Prover peak resident set | 2,381,440 KiB (2.271118 GiB) |
| Fresh full verifier, outer median | 0.948203783 s |
| Fresh full verifier, internal median | 940.944317 ms |
| Both independent verification-key setups, median | 582.997263 ms |
| Both STARK proof checks alone, median | 299.892722 ms |
| Largest positive-verifier peak resident set | 132,996 KiB |
| Native retained FullLimb, warm median / observed p95 | 1.913279 / 2.630817 ms |
| Complete prefix reconstruction from raw, median of three | 2.448736 ms |
| Observed full verifier outer / native warm median | 495.590963x |
| Statement plus both proof envelopes | 5,264,276 bytes (106.336120874x original input) |

| Fresh verifier process | Internal wall, ms | Outer wall, ms |
|---|---:|---:|
| 1 | 941.346325 | 949.266404 |
| 2 | 930.113915 | 936.410328 |
| 3 | 940.944317 | 948.203783 |

This measurement requested eight Rayon threads, an 800-percent CPU quota
and an 80-GiB memory ceiling on the Intel Xeon E5-2673 v3 desktop. Those are
research job requests, not an exclusive-host claim or the production
service budget. The same-host native harness used CPU 0 and one thread.
The requested preference for Hepta Colab/Kaggle was checked: the connected
runtime exposed operator-host aliases but no directly callable cloud entry.
This does not establish that either cloud service itself was unavailable.

The sum of the observed prepare outer wall, prove outer wall and median
verifier outer wall is **22.169762370 s**. It is a synthetic sum of
measured components starting with raw input and a complete prefix, not a
paired task-to-winner end-to-end median. Original candidate and prefix
production, network and queue costs are outside that sum. The verifier is
already slower than the native receiver before those additional costs.

The native campaign's three retained-prefix reconstruction samples were
2.655389, 2.375195, 2.448736 ms. Adding their median
to the above synthetic component sum gives
22.172211106 s
starting with an existing raw candidate, still excluding original raw
candidate generation and nonce search. These existing samples were
extracted without rerunning the benchmark; their exact raw-file identities
and all five fixtures' preparation observations are in
[native-prefix-preparations.json](results/native-baseline/native-prefix-preparations.json).

| Typed late control | Required rejection | Outer wall, ms |
|---|---|---:|
| `sha-last-fold-query-value` | `FinalPolyMismatch` | 428.773269 |
| `sha-last-fold-auth-sibling` | `CommitPhaseMmcsError(CapMismatch)` | 598.215414 |
| `arith-last-fold-query-value` | `FinalPolyMismatch` | 994.634917 |
| `arith-last-fold-auth-sibling` | `CommitPhaseMmcsError(CapMismatch)` | 1043.657165 |

The largest observed ordinary negative is
2.238432757 s, and the largest
typed late control is 1.043657165 s.
Neither is a worst-case time bound. Exact phases, resource observations,
input hashes, mutation paths and original failed attempts remain in the
[verification campaign](results/retained-native-02/verification-campaign)
and [late campaign](results/retained-native-02/late-query-campaign).

The slowest ordinary sample is `arith-commitment-changed`. Its bounded
read/decode/shape phase took
965.892610 ms,
while its arithmetic STARK rejection phase took
2.606757 ms.
The larger wall time is retained without filtering; it does not identify a
deeper cryptographic rejection than the typed late controls. The clocks do
not by themselves attribute the increase to a specific system cause.

The final native pipeline also passed locked/offline Cargo metadata,
formatting, strict all-target/all-feature Clippy with `-D warnings`,
18 library tests and three actual small PCS/FRI integration tests. The
all-target build passed. The doc-test command passed with zero doc tests;
that is not an additional test count. These standalone component checks
do not execute the production Node or the complete repository CI lanes.

All derived values and source-receipt hashes are retained in
[MEASUREMENTS.json](MEASUREMENTS.json). The remaining sections explain why
successful proof execution does not close the economic and security gates.

## What the complete statement covers

The verifier receives one fixed 377,290-byte public statement. It contains
the original 49,506-byte W1 header/proof, the complete 131,072-byte prefix in
the original `bi,bj,bk,i,j` order, claimed hash outputs, and public arithmetic
intermediates. Independent expected-header and artifact-commitment files
remain separate verifier inputs. Proof-carried verification keys, arbitrary
SHA plans and arbitrary arithmetic row lists are not accepted.

The SHA component constrains all 519 messages: artifact A, qualified input
B, task, challenge, four sets of 128 original noise-counter messages, the
complete prefix trace, ticket and work ID. Its wrapper enforces the original
framing, SHA-256 padding, IV, consecutive compression chaining and final
digests around the upstream P3 SHA AIR. There are 4,114 real compression
operations, padded to 8,192 rows, with 7,728 main and 27 preprocessing
columns. The original rejection sampler chooses the first 512 accepted
32-bit values per label and retains its 128-digest exhaustion rule.

The arithmetic component constrains all factor products E/F, all Ahat/Bhat
additions, all eight complete noisy prefixes, and full `AB=C` over
`q=4294967291`. It has 81,920 real rows, padded to 131,072, with 516 main
and 18 preprocessing columns. Each eight-term dot product reduces each
individual product with `ab=qk+r` before summing. Bit constraints and the
bounded sum carry prevent a large integer product or sum from silently
wrapping in Goldilocks. Public arithmetic values are canonical modulo q.
The detailed integer-lift review is in [DOT8_516_REVIEW.md](review/DOT8_516_REVIEW.md).

Both proofs are real Plonky3 0.8.0 PCS/FRI proofs. The verifier rebuilds both
preprocessing commitments from the same public statement and independent
expectations, then verifies their conjunction. It does not recompute native
W1 matrix products or W1 hashes as an acceptance fallback. Diagnostic file
SHA fingerprints are timed but do not replace any relation proof.

The retained full-size fixture has 4,096 distinct nonzero words in each of
A, B and C. Its target is all `ff`, so it is a correctness and cost control,
not evidence about realistic nonce-search success. The extra public witness
also makes this construction non-zero-knowledge and non-succinct in the
public statement. The proof trials concern this complete fixture; they do
not constitute a campaign over every admissible task or target.

## Cost interpretation

The native comparator is a fresh measurement of the frozen FullLimb harness
from source commit `e70f13448aad715286fb8eb56fc802b09db643a3`. Both builds
used Rust 1.95.0 and `-C target-cpu=native` on the same desktop. Native calls
are single-threaded; the research proof setup and proving use eight Rayon
threads. Native timings are warm calls inside three fresh processes; the
STARK verifier timings include a new process, bounded file parsing and
independent reconstruction of both verification keys. Their ratio describes
these explicit boundaries, not a universal implementation-speed factor.
The frozen baseline logger still contains a hardcoded "default target CPU"
label; [its companion record](results/native-baseline/README.md) preserves
that discrepancy and identifies the actual native-flags build receipt.

Of 41 copied upstream source files, 39 match C4 exactly, one differs
(`legal_attempt.rs`), and one frozen `legal_attempt/low_rank.rs` is absent
from C4. The FullLimb entry `src/pon_work.rs` itself matches C4, as do the
other retained verification and protocol sources. The frozen whole crate
is nevertheless not relabelled a current-C4 build or a production-Node run.
The source comparison and raw observations are retained in
[results/native-baseline](results/native-baseline).

Let G be the cost of producing an already valid original raw W1 candidate,
P the additional full-prefix reconstruction from that candidate, W the
public-witness preparation, S the STARK proving cost, and Vn/Vs the native
and research receiver costs. For N receivers and this particular path,

`native = G + N*Vn`

`research = G + P + W + S + N*Vs`.

When the prefix is already retained, P is zero at this boundary. A merged
producer may share noise or prefix work, so the measured reconstruction
must not be added mechanically to another producer that already performed
the same work. The native harness records `parse + make_prefixes` separately:
this recomputes noise, factors and all noisy prefixes from existing raw data;
it does not create the raw candidate's original C/header/trace/ticket or
search for a winning nonce. Neither full task-to-winner production nor
network transfer, energy, receiver queues or WAN scheduling was measured.

On the measured path Vs exceeds Vn while P, W and S are nonnegative. Thus
the observed implementation has no replication count at which additional
receivers amortize the proving work into a net gain. The larger wire payload
does not improve that result. This conclusion needs no assumption about the
unmeasured common G. It is not a theorem excluding a different backend,
preprocessing policy, statement representation or implementation.

## What the rejection controls establish

The original eleven negatives cover bounded framing, truncation, trailing
proof bytes, changed commitments, last C/prefix/intermediate values, an
unused noise tail, and wrong independent expected inputs. Their exact error
stages are retained. Public-input or commitment changes alter the
Fiat–Shamir queries, and several of these negatives consequently fail in
pruned-multiproof shape validation. Reaching the arithmetic verifier is
not automatically evidence of its deepest rejection path.

Four additional typed controls keep the public statement, independent
expectations and every proof-carried transcript field unchanged. In each
component, one changes the final-fold extension value of query 63; another
changes one field element of the last external digest in the last nonempty
shared commit-phase multiproof. P3 verifies input multiproofs, all 64 query
fold chains and final-polynomial checks, and then shared authentication
rounds. The required rejection variants are respectively
`FinalPolyMismatch` and `CommitPhaseMmcsError(CapMismatch)`. A shared proof
frontier is not an independent last-query Merkle path. See
[LATE_REJECTION_REVIEW.md](review/LATE_REJECTION_REVIEW.md).

These are controlled corruptions of an available valid proof. The helper's
runtime is a feasible mutation cost, not the cheapest from-zero adversary
cost. Its last nonempty authentication round is one late path, not a global
maximum over all malformed input structures. Byte caps, fixed proof degrees
and panic containment do not by themselves establish an adversarial time or
memory bound.

The first late-control harness incorrectly expected the upstream name
`RootMismatch`; the actual verifier rejected with `CapMismatch` and the
harness stopped. That failure and the old script bytes remain archived.
The corrected harness requires the exact source-defined variant. Similarly,
the first strict-Clippy run found one `needless_range_loop` in the SHA
wrapper. The final source uses exact iteration over the same 16 words,
without allowing the lint or weakening any constraint. The old source is
archived so the original run-01 provenance remains reconstructible.

## Selected-event: actual composition and a priced work model

The separate selected-event result is in
[THEOREM.md](../selected_event_composition_research/THEOREM.md) and
[PRICING.md](../selected_event_composition_research/PRICING.md).
The reconstructed round-2 document, new hashes and newly executed checks
are distinguished from the recovered original round-1 sources and fixtures.
No lost round-2 execution log is represented as recovered evidence.

The theorem now follows the actual framed hash dependency graph:
Merkle leaves/nodes, task, context, seed, selector/noise, event and ticket.
In the classical full-message random-oracle model, let M cover all lifetime
candidate pairs, H all adversarial row-family touches, and R the per-pair
cap on early guesses, including discarded candidates and guesses whose
rows are completed later. Let q be the arithmetic modulus and p bound each
predictably fixed target's success probability. Then, with

`beta = 1 - (1-q^(-8))^4`, `K = min(M, floor(H/32))`,

`Pr[W >= t] <= Pr[Bin(K,p) >= t] + 32*M*R*beta + epsilon_hash`.

Here W counts distinct accepted canonical events. If Q counts all lifetime
full-message queries, including public setup, retained oracle-derived
advice, discarded candidates and verifier completion, and qm=qleaf+qnode,

`2^256 * epsilon_hash = choose(Q,2)`

`  + qm*(2*qnode + 2*qtask) + qtask*qcontext`

`  + qcontext*(qseed + qevent) + qseed*(qselector + qnoise)`

`  + qevent*qticket`.

The extra terms account for an attacker querying a downstream digest slot
before a later fresh producer hits that slot. Output-collision accounting
alone misses that ordering. The proof keeps the raw-oracle hazard argument
separate from its auxiliary whole-row revelations and uses unconditional
failure coupling. Honest verifier noise computations never retroactively
pay the miner's H. These budgets are model assumptions, not certified limits
on every miner's lifetime activity. Concrete SHA-256 and quantum access are
not proved by this full-message idealization.

The priced model records actual standard SHA compression work and exact
legal reuse strategies, rather than assuming one row access costs two new
compressions. Thirty-two noise digests need 64 ordinary compressions, or
33 with their common first block reused. All optimized outputs match the
original outputs. A bounded cache has at most five prefix states plus two
complete-digest slots, 981 bytes of logical payload, excluding allocator,
index and runtime overhead.

| SHA work | Ordinary evaluation | Full-digest memoization | Bounded prefix cache |
|---|---:|---:|---:|
| Tree preparation | 1,146 | 1,146 | 894 |
| First nonce | 96 | 88 | 57 |
| Later nonce | 96 | 80 | 47 |

The nonce rows in this table use J=32: each of the 32 row samplers accepts
enough words at counter zero. Rejection-sampling retries increase the
actual J; ordinary producer SHA work is `2J+32`. The general retry-aware
formulas and the 128-counter-per-row cap are retained in PRICING.md.

Direct selected arithmetic needs 2,048 field multiplications and 1,920
additions per nonce. Precomputing the 512 possible useful products U needs
262,144 multiplications, 229,376 additions and 131,072 payload bytes, then
reduces each nonce to 1,536 multiplications and 1,472 additions. With only
those arithmetic operation prices, both strategies tie at 512 trials and
the cache wins from trial 513; nonzero memory/time prices can remove that
advantage. The model also includes exact Strassen variants and nonnegative
price vectors. The minimum among the implemented strategies is an achieved
upper bound, not a minimum over every legal strategy.

For the documented illustrative p=1/64 budget, 44 paid trial slots give
0.499890250976003... hit probability and 45 give 0.507704465804503....
The stated small exception budget therefore requires H>=1,440 for half
success inside the model; H=1,408 is insufficient. This does not establish
1,440 physical hashes, a currency cost, an elapsed-time floor or useful
external demand. Wall-clock improvements for the new selected-event
prefix-cache strategy have not been benchmarked here.

## Remaining qualification gates

The fixed P3 profile uses Goldilocks, quadratic challenges `X^2-7`, default
Poseidon2 width 8, two separate application/component domains, 64 FRI
queries, log blowup 2 and zero grinding. All P3 crates are pinned to 0.8.0.
Actual-AIR metadata includes preprocessing widths and 15,487/536 batched
functions for SHA/arithmetic. The reported conditional round-by-round
estimate is about 63.953845 bits for each component; the separate
conjectured estimate of 98 bits is not substituted for it. Neither is a
complete instantiated noninteractive soundness bound or PQ128 claim.

The actual FRI call chain was traced to Goldilocks low-bit masking. Under
conditional independent uniform base-field samples, its exact 64-query
density correction is `(1+(2^b-1)/P)^64`, with b=15/19 and
`P=2^64-2^32+1`. The corresponding bit losses are about 1.64e-13 and
2.62e-12. This closes a concrete code-path and conditional distribution
calculation, not Poseidon2 independence, transcript retry budgets, PCS/hash
binding, out-of-domain sampling, cross-proof composition, a complete ROM
compilation or QROM security. See
[QUERY_SAMPLING_REVIEW.md](review/QUERY_SAMPLING_REVIEW.md) and
[P3_SECURITY_REVIEW.md](review/P3_SECURITY_REVIEW.md).

Complete concrete noninteractive security, a production-resource receiver
bound, the globally cheapest legal physical-work bound, and production
Node admission remain open. The existing four-second, 16-hostile,
seven-honest-submission, quarter-CPU, 2-GiB, no-swap and 256-PID service
contract is not replaced by this eight-thread research run. The original
request/history limits and independently administered WAN campaign also
remain unchanged. Successful research checks and Git delivery do not
promote qualification beyond **HOLD_NO_GO**.
