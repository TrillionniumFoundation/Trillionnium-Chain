# Complete W1 relation and specialized proof backends v1

Status: research specification and backend comparison, 2026-11-06 UTC.
Source baseline: `b173c1f52d927522af67df30dd08ecfb2e3a1bb0`.
This work refines PN1 / work package 2A in the
[sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
M01 owns relation correctness; M02 retains work identity and credit; M04/M15
retain service resources and admission; M17 retains evidence and qualification.

There are two separate routes. **A preserves the exact W1 relation and changes
its proof implementation. B defines an explicitly versioned Cell relation and
would require a protocol upgrade before use as chain work.** Neither route is
activated by this document. A complete witness generator or local constraint
checker is not a polynomial commitment scheme (PCS), succinct argument or
cryptographic proof. This continuation does not yet supply a new specialized
PCS/prover or a proof-only Node admission path.

## Existing relation, evidence and authority

The normative inputs are [NEURAL_WORK](../../../protocol/pon-nakamoto-v1/NEURAL_WORK.md),
[WORK_PROFILE](../../../protocol/pon-nakamoto-v1/details/WORK_PROFILE.md) and
[LEDGER_WIRE](../../../protocol/pon-nakamoto-v1/details/LEDGER_WIRE.md).
The native implementation is
[pon_work.rs](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs);
the separately coded scalar oracle is
[work_oracle.py](../../../../formal/pon-nakamoto-v1/work_oracle.py).

The new [specialized relation reference](../../../../formal/pon-nakamoto-v1/w1_specialized_relation.py)
materializes all arithmetic reduction rows and SHA compression states; its
[controls](../../../../formal/pon-nakamoto-v1/test_w1_specialized_relation.py)
compare the saved native fixture with the independent scalar oracle and mutate
relation witnesses. It remains a complete local recomputation experiment.
SHA rounds use integer operations, not polynomial SHA constraints, and there is
no committed-witness PCS or cryptographic verifier. The report keeps those
implementation flags false. Its internal CPU/wall clock surrounds `execute`;
JSON decoding/serialization, file I/O and process startup are outside that
sample and need separate whole-process accounting.

The [statement-v2 ABI](../../../../evidence/pon-w1-statement-v2-20261105/RELATION_ABI.md)
already exposes the exact header, trace, ticket, original work ID, raw A/B
artifact commitments and all product words. Expected header and artifact
commitments come from the caller's independently checked context, never from
the proof's own claims. V2 adds the previously missing public material binding;
historical v1 receipts do not prove those extra fields.

The [full-v2 observation](../../../../evidence/pon-w1-full-v2-20261105/README.md)
contains one actual complete generic zkVM proof, 43 segment proofs and its
recursive compression. Its declared fresh proof pipeline took
6,248.484106799 seconds; total campaign time was 6,253.711474144 seconds.
Build/setup and fixture construction were outside that budget. The repaired
saved-receipt campaign passed one positive and 57 negative controls. Those are
historical measurements of one proof and explicit repetitions, not a prover
latency distribution or measurements of a specialized backend.

In the saved [controls-result.json](../../../../evidence/pon-w1-full-v2-20261105/controls-result.json),
`seal_word_last` changes bytes at offset 222676 and is rejected with 0.026583
seconds of process CPU and 0.053213024002616294 seconds of wall time. Process
CPU here is the recorded `wait4` scope. One rejection is not a worst-case bound,
and the `crypto` rejection label does not assert traversal of every STARK check.
It demonstrates why valid-proof verification alone is an insufficient service
cost metric.

The [locked component-budget record](../../../../evidence/pon-w1-qrom-budget-20261105/README.md)
does not certify the separate research failure-probability budget of `2^-128`.
Its numerical component expressions are not attack costs or a complete QROM
theorem. A new backend needs its own exact parameters and composition argument;
it does not inherit qualification from a valid old receipt.

## A. Full relation coverage

The work profile remains `pon-matmul-transcript-64-v1`, with `n=64`, rank 8 and
`q=4294967291`. The complete native certificate remains exactly 49,188 bytes;
the canonical header is 318 bytes. A new proof envelope may have its own fresh
namespace without altering these work bytes or their lottery semantics.

| Obligation | Required relation | Incomplete substitute |
| --- | --- | --- |
| Canonical inputs | Every A, B and C element is a little-endian u32 strictly below q; exact length, magic and framing | Reducing arbitrary bytes modulo the proof field |
| Header and challenge | Exact canonical PNH1 bytes and original `H("challenge", header)` | A subset of header fields or a caller-supplied challenge without its preimage binding |
| Task and materials | Original TaskId over A/B plus original `artifact` and `qualified-task-input-v1` hashes of their raw bytes | A prover-chosen task or commitments sourced only from the public output |
| Noise | All four labels, counters from zero, SHA-256 words, rejection of words at least q, first 512 accepted words per label, 128-block cap | Unconstrained noise matrices or skipped rejected samples |
| Encoded matrices | `A' = A + EL ER` and `B' = B + FL FR`, exactly modulo q | The same formulas modulo a different prime |
| Prefix states | All 32,768 prescribed updates, including the correct previous value and eight products at each update | Only `A' B'`, final tile states or sampled tile openings |
| Trace bytes | Exact `bi,bj,bk,i,j` traversal and canonical LE32 of each updated accumulator | A multiset of equal words or a different traversal |
| SHA-256 trace | Original prefix, challenge, all trace bytes, SHA-256 compression chain, padding and length | A commitment hash with different semantics |
| Recovery | All intermediates of `C = C' - (A FL) FR - EL (ER B') mod q`, and all 4,096 output words | Only a final matrix-product assertion disconnected from the trace |
| Ticket | Original `H("ticket", c, t)` and comparison with the required target in the independently checked context | A proof-randomness nonce or a merely declared threshold |
| Work identity | Original `header.block_id(trace)` / `H("block", header, t)` | Receipt bytes, recursive wrapper, backend ID or proof randomness as new work tickets |
| Native authority | Existing fresh parent/task eligibility, manifest/withdrawal, execution, state root, clock, storage epoch and commit checks | Treating a mathematical receipt as permission to admit, pay or use a model |

The proof can authenticate a relation involving the header's target. The native
Node still has to establish that this is the branch-derived expected target and
that the task is currently eligible. This does not add those mutable authority
decisions to the historical v2 journal or claim they are already proved there.

The original `H` is SHA-256 with `TRNM-PON1\0`, the little-endian tag length,
tag, and a little-endian length before every part. Raw SHA-256, alternative tag
framing and an algebraic hash are not interchangeable with that relation.
Any hash used only inside a new PCS has a different purpose and must have its
own domain and security analysis.

### Deterministic structural counts

The exact trace contains

```text
8 * 8 * 8 * 8 * 8 = 32768 accumulator words
32768 * 4 = 131072 accumulator bytes
16-byte "TRNM-PON-TRACE1\0" + 32-byte challenge + 131072 bytes
    = 131120 bytes before SHA-256 padding
ceil((131120 + 1 + 8) / 64) = 2049 SHA-256 compression blocks
```

This last count concerns the trace hash alone. Task, artifact, input, challenge,
noise, ticket and work-ID hashing add work. Noise normally consumes 64 hash
outputs per label when every word is accepted, but the relation must handle
every permitted rejection and reject exhaustion; it cannot hard-code that
normal path as the whole relation.

The straightforward dense relation has 458,752 scalar field products:
65,536 for the two noise products, 262,144 for the trace and 131,072 for the
four recovery contractions. These are reference-operation counts, not a lower
bound on the cheapest lawful implementation, a circuit-gate count or a physical
energy measurement. Trace SHA block counts likewise do not determine proving
time without compiling and measuring the complete constraint system.

### Connecting arithmetic and SHA-256

One monolithic proof can constrain shared byte/word columns directly. A split
construction must prove that the arithmetic and SHA subarguments refer to the
same complete ordered sequence. It needs an explicit binding commitment,
opening/equality relation, index domain and length; two unrelated public
digests are not a connection proof.

Range constraints connect each canonical u32 to its four bytes, and each byte
to the bits used by SHA-256. The hash subrelation must constrain initialization,
message schedule, rotations, Boolean functions, wrapping u32 additions,
compression chaining, final padding and digest encoding. The last arithmetic
state must also be the C' used in recovery. SHA block transitions cannot be
checked in isolation while their inputs or output state remain unconstrained.

## B. Backend candidates for the unchanged W1

| Candidate | Useful property | W1-specific work still required |
| --- | --- | --- |
| Same-q multilinear sumcheck/GKR with a suitable encoding-based PCS | Preserves native arithmetic; multilinear sumcheck does not itself require a large radix-2 multiplicative subgroup | Complete byte/SHA relation, extension-field membership, PCS parameters, concrete FS security and measured costs |
| Same-q AIR with a deliberately chosen evaluation/commitment scheme | Represents repeated state transitions directly | A domain construction suitable for q; common FFT/FRI defaults cannot simply be reused |
| AIR or polynomial IOP over an existing fast proof field | Reuses mature field/hash machinery where available | Exact non-native q arithmetic with bounded limbs, carries, quotients and canonical encoding |
| Direct composition of arithmetic and SHA arguments | Exposes each component's cost and shared commitments | Full transcript binding, additive verification cost and composed soundness |
| Recursive composition | Can compress several already correct argument verifiers | Verifier circuits, recursion field transitions, supported programs, extra prover/memory cost and recursive security budget |

### Why W1's original field changes the AIR/FRI choice

For `q=2^32-5`, exact integer factorization gives

```text
v2(q - 1) = 1
v2(q + 1) = 2
```

Here `v2` is the exponent of two dividing an integer. For odd extension degree
`k`, `v2(q^k-1)=1`; for even `k`, the standard lifting identity gives

```text
v2(q^k - 1) = v2(q-1) + v2(q+1) + v2(k) - 1
             = 2 + v2(k).
```

Thus the base field has only a size-two binary multiplicative subgroup, and
degree-eight extension permits only a size-32 one. A radix-2 domain of size
`2^20` would require extension degree divisible by `2^18` under this approach.
Small extensions do not repair the usual large FFT-domain requirement.

This is an obstruction to blindly reusing a conventional multiplicative
radix-2 LDE/FRI configuration, not an impossibility theorem for AIR or for
proving over q. Multilinear protocols and suitable code-based commitments are
worth comparing because they need not make this particular subgroup choice.
If challenges live in an extension, the witness's base-field membership must
still be enforced. Extension size alone is not a total soundness estimate:
degree factors, round counts, union/composition losses and FS remain relevant.

### A concrete 8-bit non-native multiplication gadget

Let the proof field be BabyBear, `p=2013265921`, only for this example. W1
elements must remain canonical integers in `[0,q)`. Since q is greater than p,
embedding a whole u32 as one BabyBear scalar is not injective.

For a multiplication use the integer relation

```text
x * y = z + k * q
0 <= x,y,z,k < q
```

Canonical x, y and z make the quotient unique; a valid multiplication actually
has `k <= q-2`. Decompose all four integers into four base-256 digits. Every
digit is in `[0,255]`, and the combined four-digit values must also be less than
q. Checking bytes alone permits the five forbidden u32 values from q through
`2^32-1`. The constant q has little-endian digits `(251,255,255,255)`.

For `i=0..7`, with out-of-range digits zero, define

```text
b_i = sum(x_a*y_b : a+b=i) - sum(k_a*q_b : a+b=i) - z_i
b_i + c_i = 256 * c_(i+1)
c_0 = c_8 = 0
-1024 <= c_i <= 1024
```

Carry bounds can be encoded as `d_i=c_i+1024` with `0 <= d_i <= 2048`;
endpoints have `d_0=d_8=1024`. A 12-bit check without the upper bound 2048
would be a different range and requires a new bound calculation.

Each convolution coefficient has at most four products of bytes, hence
`-260355 <= b_i <= 260100`. The absolute local residual
`b_i+c_i-256*c_(i+1)` is at most 523,523, strictly less than p. Consequently
equality in the proof field implies this local integer equality. Multiplying
the eight equations by `256^i` and summing cancels the carries and establishes
the full integer multiplication relation, rather than an accidental equality
modulo p. Correct integer products generate carries inside the stated bound.

All digit, canonical-value, carry and endpoint checks are essential. A 16-bit
limb product can reach `65535^2`, which already exceeds BabyBear; using the same
argument with 16-bit limbs would be unsound without additional decomposition
or carry/range reasoning. Addition can use `x+y=z+kq` with Boolean k;
subtraction can use `x+kq=y+z`. Their own coefficient and carry bounds must be
derived, rather than borrowed from multiplication by assertion.

### Batched dot-product reduction rows

The reference checker retains a complete dot product as one integer reduction
row instead of reducing every scalar product through the gadget above. Its
straightforward W1 decomposition has 62,464 rows:

| Rows | Purpose |
| ---: | --- |
| 8,192 | EL ER and FL FR |
| 8,192 | A' and B' additions |
| 32,768 | All ordered C' prefix updates |
| 512 + 4,096 | A FL and its multiplication by FR |
| 512 + 4,096 | ER B' and its multiplication by EL |
| 4,096 | Complete C recovery |

This is an arithmetic-row inventory, not a count of cryptographic gates. Each
row checks every product operand and linear term, its q quotient and the
canonical remainder. A sum of up to 64 u32 products can need a five-byte
quotient; silently using a four-byte quotient truncates valid rows. With that
quotient, four-by-five byte convolution reaches index seven. Eight residual
columns suffice algebraically. The implementation additionally retains a ninth
all-zero high column and stores carries `c_1..c_9`, with implicit `c_0=0` and
checked `c_9=0`. Its report therefore counts **562,176 carry equations**.

The implementation bounds product operands below q, the nonnegative quotient
below `2^39`, each scalar below `2^34`, at most 64 products and at most six
signed scalar terms including the remainder. Recovery uses
`C' + 2q - c1 - c2` to keep the integer total nonnegative; adding 2q leaves the
canonical remainder unchanged. Thus a negative quotient representation is not
needed. Its signed carries are bounded by `2^17`. A conservative absolute
local-residual bound is

```text
64 * 4 * 255^2 + 6 * 255 + 4 * 255^2 + 257 * 2^17
    = 50593534 < 2013265921.
```

The terms bound product convolution, scalar digits, quotient-times-q
convolution and both carries. Nine columns include all possible nonzero
coefficients; the zero endpoint telescopes to exact integer equality. This
bound is different from the single-product gadget's 1,024 carry limit. Changes
to row arity, operand widths, quotient range, signs or the field require a new
derivation. A Python integer check validates this reference relation but does
not implement a field circuit, PCS, FS transcript or soundness reduction.

## C. Fiat-Shamir, Freivalds and composition

For fixed A, B, C and a uniformly independent random vector r in `Fq^n`, a
nonzero error matrix `AB-C` is missed by `A(Br)=Cr` with probability at most
`1/q`. Independent repetitions have the corresponding bound only with their
stated fixed-statement and randomness assumptions.

If r is known before C is chosen, let `u=A(Br)`. For nonzero r, choose a
coordinate j with `r_j != 0` and set `v_j=1/r_j`, all other coordinates zero.
Then `C'=u v^T` satisfies `C'r=u` while generally `C' != AB`. If r is zero,
every C passes. Parent-hash-derived vectors known before the output commitment
therefore do not provide the required challenge timing.

A formal FS construction must bind the fixed relation/circuit identity,
canonical public statement, all prior round commitments, domain separators
and exact transcript order. It must analyze adaptive statements, transcript
grinding, parallel composition and any claimed quantum-query model. Merely
hashing a commitment does not establish the interactive soundness bound for
an arbitrary concrete noninteractive construction.

[Khovratovich, Rothblum and Soukhanov, How to Prove False Statements](https://eprint.iacr.org/2025/118)
give practical adaptive attacks against particular GKR-based FS arguments;
functionally equivalent circuit representations can have different security
outcomes. This is a reason to review the precise compiled construction, not a
claim that all GKR or all FS protocols are broken. The ePrint metadata checked
for this review records a 2025-12-11 revision. No attack code was executed here.

Even a secure proof of `AB=C` does not prove W1's challenge-dependent prefixes
or SHA trace. These obligations cannot be supplied by consensus assumptions,
task registration, a model score or sampling a few matrix tiles.

The first measured specialized backend should prove the full direct relation.
Only then compare direct multi-proof verification with recursive wrapping on
the same statements and threat model. Recursion must authenticate the exact
inner verifier/program, public bytes and common commitments; accepting an
arbitrary verifier key or relation ID creates a different statement. Record
all inner and outer prover work, not only the final verifier time. Proof
randomness and the number of wrappers must create zero additional tickets.

## D. Primary research checked on 2026-11-06

### TensorZKP

[Lu et al., USENIX Security 2026](https://www.usenix.org/system/files/usenixsecurity26-lu-tao.pdf),
section 7.1 and Tables 1, 2 and 4, use H100 80 GB, CUDA 12.6,
HyperPlonk PIOP and Brakedown PCS. The measured field is BabyBear
`p=2^31-2^27+1`, extended to degree eight with `X^8-11`.

The `2^25` multiplication-gate benchmark reports 215.28 ms and 52.9 GB.
The separate SHA-256 benchmark reports batch 64, 301,634 gates per block and
233.0 ms. The work targets prover acceleration; verifier time and proof size
retain the underlying CPU protocol's behavior. CPU baselines are the paper's
single-threaded implementations. These are component measurements, not W1 or
Cell end-to-end timings. Neither W1's q arithmetic nor its complete trace and
external bindings have been ported or benchmarked here.

The [author's publication page](https://ji-peng.com/) links the official
[artifact DOI 10.5281/zenodo.20337923](https://doi.org/10.5281/zenodo.20337923).
The [USENIX artifact results](https://secartifacts.github.io/usenixsec2026/results)
list Artifacts Available; this review did not retrieve its source archive,
verify its digest, run its benchmarks or establish functional/reproduced badges.
Record that gap before claiming a code-level comparison. In particular, scaling
the SHA batch number to 2,049 trace blocks is not a measured proving forecast.

### WHIR

[Arnon, Chiesa, Fenzi and Yogev, WHIR](https://eprint.iacr.org/2024/1586)
describe a Reed-Solomon proximity protocol and derived polynomial commitment.
The abstract's degree-`2^22` example uses **100-bit security**, with 1.2 seconds
for commit/open, 63 KiB and 360 microseconds for verification. These numbers
do not include a complete W1 or Cell relation.

The [author-linked implementation README](https://github.com/worldfnd/whir/blob/83bc41744c994aa182c547d43c73ce3d1f76d04d/README.md)
was inspected at main commit `83bc41744c994aa182c547d43c73ce3d1f76d04d`.
Its README blob was `ef91b05da5b048b51399f1c2045813d974e85b26`.
It labels the implementation an academic prototype, not production-ready.
Documented defaults include security 100, `ConjectureList`, `Goldilocks2` and
Blake3. Other documented choices include `UniqueDecoding`, `ProvableList`,
`Goldilocks3`, `Field192`, `Field256` and SHA3. W1's q is not one of those
documented field choices. This review did not compile or audit the implementation.

A comparison must freeze the actual soundness regime, field, rate/folding,
queries, grinding, hash, parser limits and source version. The default benchmark
is not evidence of a `2^-128` composed error budget or an instantiated quantum
security theorem. WHIR remains a candidate commitment component.

## E. Separate Cell successor route

The [grouped operator v0](GROUPED_CELL_OPERATOR_V0.md) already specifies the
actual routed integer fixture, selected experts, stable grouping and complete
independent native recomputation. Its `3 x 257` shape is rectangular; 257 is a
feature dimension, not a field modulus. Its exact signed integer arithmetic,
bias and lowest-index ties must remain explicit. It currently supplies neither
a succinct proof nor a chain-work lottery. The separate
[useful-Cell relation](USEFUL_CELL_RELATION_V1.md) binds a broader consumer
context but also retains its declared research and disabled-STOP limits.

A successor should freeze its full model/operator manifest before selecting
proof dimensions. Required semantics include matrix layout and group partition;
integer accumulator widths; quantization scale, rounding and saturation;
nonlinear tables or exact approximations and range bounds; routing scores,
top-k and tie rules; state transitions; stop predicates and a maximum step
budget. Commitments connect model, input, state and every boundary tensor in
one relation. Binding a claimed route or stop bit is not proof that it was
computed correctly.

The original native implementation remains the correctness oracle. Operator
and proof identifiers, work profile, signed domains and stored schemas need
explicit versioning where their semantics change, followed by old/new vectors,
migration and activation review. This document grants no such activation.
Linear-layer measurements must remain operator measurements until the complete
Cell, input commitments, nonlinear/control logic and transport are measured.
Arithmetic correctness does not establish real demand, model quality, authority
or an unavoidable minimum mining cost.

## F. Concrete measurement and acceptance gates

These gates refine the existing work package; they are not a second roadmap.

| Gate | Required reviewable result |
| --- | --- |
| Complete relation reference | Independently generated native/oracle vectors and all prefixes, noise decisions, hash blocks, recovery intermediates and v2 public bindings; malformed and inconsistent witnesses rejected |
| Complete cryptographic backend | Actual committed witness, exact verifier/program identity, noninteractive proof and independent verifier covering every row of section A; no successful stub, sampled substitute or native fallback |
| Exact security selection | Source/lock/artifact hashes; all field and PCS parameters; proven versus conjectured assumptions; transcript and canonical decoding; composition error and explicit remaining QROM premises |
| Cost comparison | Same task/header/target/artifacts across native, generic v2 and specialized arms; separate setup, witness, proving, verification, proof bytes, memory and transport |
| Hostile verification | Valid and malformed proofs, late seal failures, changed statements, mixed batch failures and split/retry costs; original shared resource owner and budgets |
| Native integration | Original current-parent/task/revocation/application/state checks plus expected public statement; no new admission or payment authority from proof acceptance |
| Independent qualification | Reproduction on the exact complete source and accepted parameters; existing work-security, original service and WAN gates remain separate |

Report compiler, dependency versions, hardware, clocks, CPU thread limits,
GPU/driver, cold/warm state and sample population. Keep witness generation,
device transfer and circuit setup visible even if an upstream microbenchmark
excludes them. Report peak RSS and VRAM with their actual scope; a largest
single-process peak is not an aggregate process-tree peak. Mark unavailable
measurements null and retain failed, cancelled, stale and timed-out attempts.
Repeated verification of one receipt is not another independent proof sample.

Service evaluation must cap bytes and parsing before crypto, validate bounded
context, acquire the existing global CPU/worker owner and preserve `Busy`,
`Deadline` and consensus `Invalid` as distinct outcomes. New identities do not
create new CPU credit. An invalid proof must not trigger an automatic complete
native replay. Negative caches bind concrete invalid proof bytes and context;
one bad proof must not poison a valid proof for the same WorkID. Verification
batch splitting and retries consume the same budgets. Non-preemptible calls
need bounded workers and measured termination behavior; a timeout checked only
after return is not a hard execution bound.

For a declared finite arrival model, `lambda_h*c_h + lambda_a*c_a < B` is only
a necessary resource condition. Bursts, queue residence, network bytes, memory
and tail latency also require bounds. No finite machine guarantees completion
of every honest request under unlimited adversarial input. A low component
verification time therefore does not close the original confirmation-service
gate, and a correct new proof does not by itself close work-hardness or model
usefulness qualification.
