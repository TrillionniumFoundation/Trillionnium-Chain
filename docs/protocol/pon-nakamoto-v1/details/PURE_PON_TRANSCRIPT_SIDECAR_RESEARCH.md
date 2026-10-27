# Full-transcript sidecars: a cost and soundness screen

Research review, 2026-10-27. **The straightforward N64 sidecar/Freivalds
replacement is not supported as a throughput improvement or a PQ-qualified
acceptance rule.** This document derives arithmetic counts, not measured runtime
or a lower bound on all possible verifiers. It changes no code, work accounting,
consensus namespace, `VerifiedWork` constructor, admission budget or activation.
It adds no hashcash, stake or committee. No sidecar campaign was executed.

## The complete relation, not just the final product

The [frozen W1 source snapshot](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/5c8cd8bd59cd9d8197617239664e66dd8b086baa/trillionnium/crates/trnm-crypto-primitives/src/pon_work/full_relation.rs)
has N=64, inner block width b=8 and q=2^32-5. Its `replay` derives four
challenge-bound noise matrices, forms A'=A+EL*ER and B'=B+FL*FR, and hashes
**every cumulative** 8-by-8 tile in `(bi,bj,bk,i,j)` order. This published source
snapshot is not a claim that a later commit was the runtime HEAD.

Rearrange those values into eight 64-by-64 matrices S_k, with S_-1=0. A complete
sidecar check must establish, for every k=0..7,

```
S_k - S_(k-1) = A'[:,8k:8k+8] * B'[8k:8k+8,:]  (mod q).
```

It must also check canonical field words and exact lengths, reconstruct the
original ordered SHA-256 trace, bind the entire header/task/target/PNW1 context,
check the ticket, and establish the original corrected C. The latter is
S_7 - (A*FL)*FR - EL*(ER*B'). A correct cached C cannot prove the transitions.

There are 512 tiles, 32,768 words and **131,072 bytes** of intermediate values.
Appending them to the 49,188-byte PNW1 produces at least 180,260 bytes before
framing or additional proof data: 3.665 times the original witness size. Extra
serialization time alone is 1.049 ms at 1 Gbit/s or 0.105 ms at 10 Gbit/s,
excluding latency, contention and gossip copies. These are wire calculations,
not observed network performance. Reading/hash-checking the sidecar is mandatory.

**Counterexample:** replace an interior S_k by S_k+D and keep S_(k+1) and S_7
unchanged. Adjacent transition errors are +D and -D. Final-C verification or an
unweighted sum of all transitions accepts this cancellation, although the trace
contains a false intermediate result. Checking only some tiles also leaves an
uncovered-position attack; a trace digest binds supplied bytes, not their truth.

## Freivalds: exact scalar-operation model

For a fixed nonzero error matrix D and a fresh uniform v in F_q^64,
Pr[Dv=0] <= 1/q, since D has rank at least one. Independent repetitions t give
q^-t. Every transition must pass; for a fixed false sidecar it is enough to
bound one nonzero transition, so an additional factor 512 is not required for
this conjunction. The challenge must be chosen after the whole claim is fixed.
The method and its verifier/prover tradeoff are described in [1], section 2.2
and section 4.4, and the original matrix-product protocol in [2], section 7.

Count field scalar multiplications; additions, reductions, hashing, memory,
randomness expansion and network I/O are additional costs. Keep the existing
noise and final correction computations exact:

| Work | Multiplications |
| --- | ---: |
| E=EL*ER and F=FL*FR | 65,536 |
| Native complete transcript accumulation | 262,144 |
| Native four correction products | 131,072 |
| **Native complete relation** | **458,752** |
| 512 separate 8-by-8 Freivalds transitions, per repetition | 98,304 |
| Eight grouped 64-by-8 times 8-by-64 transitions, per repetition | 40,960 |

The grouped figure is 8*(4,096+512+512): reuse the projections S_k*v between
adjacent differences. All eight transitions share one v within a repetition;
different repetitions use independent vectors. For a fixed false sidecar at
least one D_k is nonzero, so requiring every transition to pass still has error
at most 1/q per repetition. It covers all 512 tiles; it is not merely an AB=C check.

| Repetitions t | Grouped full verifier | Relative to native | Separate-tile full verifier |
| ---: | ---: | ---: | ---: |
| 4 | 360,448 | 0.786 | 589,824 |
| 8 | 524,288 | 1.143 | 983,040 |
| 9 | 565,248 | 1.232 | 1,081,344 |

These are counts for the stated algorithm, not universal complexity bounds or
predicted milliseconds. In particular, the eight/nine-repeat version already
loses in multiplication count before its extra proof handling. An invalid claim
may be rejected in its first repetition, so rejection-only filtering can have a
different tradeoff from honest acceptance. It must still fall through to the
unchanged full verifier on a pass; it cannot mint `VerifiedWork`.

### Randomly folding the eight transitions does not remove the main cost

Let D_k denote transition errors. A common v and independent random weights
lambda_k can check sum(lambda_k*D_k*v)=0. But projecting the eight supplied S_k
still costs 8*N^2=32,768 multiplications per repetition. The RHS needs another
2*N^2=8,192, with weighting overhead. Explicitly constructing a weighted matrix
also costs 32,768 multiplications before its matrix-vector multiplication.
There is no free single-matrix check hiding the cost of forming that matrix.

The folded check has the weaker general bound <=2/q: v can annihilate every
D_k with probability <=1/q; otherwise random weights can annihilate their
nonzero projected tuple with probability <=1/q. Fixed/public weights chosen
before the sidecar permit the cancellation attack above with adjusted errors.

### When can larger matrices help this particular algorithm?

For N divisible by b, sidecar size is 4*N^3/b bytes. Native work is
N^3+6*N^2*b; the grouped verifier is 6*N^2*b+t*(N^3/b+2*N^2).
Arithmetic improvement requires

```
b > t  and  N > 2*t*b/(b-t).
```

Thus **increasing N alone cannot help when b=8 and t>=8**. Holding eight inner
blocks instead, b=N/8, gives the threshold N>10*t. For t=9, N=128/b=16 has
about 17% fewer multiplications, but a 512-KiB sidecar. With b=16 fixed, t=9
requires N>41.143; N64/b16 has only 6.25% fewer multiplications. Those are new
relations/noise dimensions requiring a separately specified namespace and cost
study; neither is an optimization already established for the current W1.

## Eight/nine repeats are a quantum-search screen, not a PQ proof

log2(q)=31.9999999983. Four repeats have error approximately 2^-128 for a fixed
claim and honest independent coins, not 128-bit security against adaptive
Fiat-Shamir search. Strictly q^-4 is slightly above 2^-128; five repeats meet
that exact classical inequality. Generic quantum search for a favorable
Fiat-Shamir transcript suggests work proportional to q^(t/2) [3]. Therefore
t=8 is approximately 128 search bits, and t=9 approximately 144; **neither
number certifies PQ128 for this proposed protocol**.

Specify an adversary oracle-query budget Q_A and permitted failure epsilon.
Even a one-challenge idealized screen must account for roughly
C*(Q_A+1)^2/q^t, not just q^-t. The required condition is
t*log2(q) >= log2(1/epsilon)+2*log2(Q_A+1)+log2(C).
Quantum Fiat-Shamir reductions require an appropriate underlying protocol and
assumptions [4]; [5] establishes that quadratic loss is real and gives
round-dependent losses for multi-round protocols. Constants, adaptive instance
selection and complete proof composition remain unanalyzed here.

Any candidate must bind the full sidecar, all native input/context bytes,
protocol version, dimensions, order and repetition labels before deriving
unbiased independent field challenges. Header-only challenges let an attacker
choose D in their nullspace. A short hash seed/XOF expansion is a computational
assumption, not unlimited information-theoretic challenge entropy. Hash binding,
quantum collision/second-preimage resistance, grinding across valid headers and
multi-receiver/restart use require their own analysis. Native SHA-256 trace
compatibility alone provides none of these missing proofs. No new hashcash
condition is implied or proposed.

## Sumcheck and useful-work limits

The specialized matrix sumcheck in [2] can avoid a general VM arithmetic
circuit, but final-product certification does not cover intermediate prefixes.
A new protocol must bind the entire transition tensor and check every relation.
Verifier evaluation of public input/sidecar polynomials still costs work; a
sublinear oracle claim requires a real commitment/encoding and its opening
proofs. Multi-round Fiat-Shamir needs its own QROM analysis [5].

There is also a concrete batching trap: multilinearly extending the k index in
both U_k and V_k and directly multiplying those extensions introduces cross
terms, so it need not equal the multilinear extension of U_k*V_k. A sound batch
needs the Boolean-index sum/equality polynomial and an explicit degree bound.
An extension field preserving characteristic q can increase challenge size,
but one F_(q^m) operation is not one 32-bit multiplication. Moving directly to
a large prime or binary field changes the native modular relation unless the
original reductions are explicitly constrained. No sumcheck runtime or PQ
parameterization has been demonstrated for this N64 sidecar.

Finally, correctness proves no minimum physical work. A'=A+EL*ER has rank at
most rank(A)+8, likewise B'. Zero/low-rank tasks, public reusable products,
task selection, cross-header preparation and specialized kernels remain relevant.
At N64 a particular low-rank algorithm may be slower; the existing structured
cost observations are not a universal shortcut or a hardness proof. A proof
system admits any algorithm producing correct outputs [2]; it cannot by itself
make generic matrix work non-amortizable or establish real LLM utility. Modular
word correctness also does not certify quantized/floating-point training semantics.

**Decision:** reject the direct N64 replacement as a demonstrated improvement.
Keep a bounded reject-only filter and a dedicated arithmetic/sumcheck protocol as
separate research candidates. Before acceptance, require exact relation and QROM
arguments, first/interior/final transition fraud controls, complete honest and
malicious-path costs including bytes, and unchanged pure-PoN work boundaries.

## Backend choice after the actual complete-W1 execution

The pinned general VM is a useful executable reference for the whole relation,
including its byte encodings and SHA-256 transcript. It is not yet an economical
consensus verifier design. The retained local attempt exhausted 1,800 seconds
without a receipt; a [separate original two-thread hosted attempt](../evidence/w1-risc0-hosted-run-40482711995/README.md)
exhausted 5,400 seconds and also retained no receipt. The 13,364,385 guest cycles
are execution measurements, not a proving-time estimate. A future successful receipt must be measured independently
before any native comparison. Increasing requested prover threads alone does not
establish either a CPU allocation or proportional speedup.

There is an additional field constraint. For the exact native prime
q=4,294,967,291, q-1=4,294,967,290 has 2-adicity 1 and q+1=4,294,967,292 has
2-adicity 2. Thus neither its multiplicative group nor its base-field circle
group provides the large power-of-two domain used by ordinary radix-two or
Mersenne31 Circle FFTs. The efficient Circle construction in [7] specifically
needs a large power of two dividing p+1. This does **not** prove that every STARK
over q is impossible: alternative domains, ECFFT or different encodings require
their own implementation and cost study. Replacing q with BabyBear, Mersenne31,
Goldilocks or a binary field without constraining the original reductions would
prove a different statement and requires a new work-profile namespace.

| Research path | What it can reuse | What remains necessary before a decision |
| --- | --- | --- |
| Keep the pinned general VM as the reference | Full relation, native differential fixtures, fixed ELF/image, strict parser and real-receipt audit | Actual receipt, full proving/verification resources and acceptable concrete security. Do not infer throughput from guest execution or upstream headlines. |
| Dedicated AIR or arithmetic circuit preserving W1 | The exact native relation, all prefix states, context codec and independent kernels | Constrain canonical q arithmetic, bounded integer reductions, all 512 ordered updates and every transcript hash. Measure the non-native arithmetic and SHA costs; preserve all mutation controls. |
| Specialized sumcheck/GKR plus a transparent PCS | Structured matrix tensor checks from [2], and field-agnostic commitment directions such as [6] | Bind the complete transition tensor and input/context; give degree, commitment/opening and multi-round QROM arguments. Small q needs a sound challenge-domain/composition design. Full source, verifier budget and actual receipts are still absent. |
| A newly specified proof-friendly neural work profile | Task/compiler interfaces and the existing reference implementation as a comparison | Reassess useful semantics, hardness, structured shortcuts, task selection, quantum search, fork choice accounting and all network/storage domains. This is a new consensus experiment, not an invisible W1 optimization. |

Brakedown [6] is a relevant field-agnostic, transparent research construction,
described by its authors as plausibly post-quantum. Its arbitrary-field statement
requires a sufficiently large field; it is not evidence that this q32 workload
already has cheap, PQ128-qualified proofs. Its polynomial commitment technique
also cannot be substituted for the current verifier without the rest of the
statement and composition argument.

### A bounded exact-arithmetic embedding candidate

A dedicated circuit can preserve the native q without using q as its proof
field. One concrete arithmetic observation uses the Goldilocks prime
P=2^64-2^32+1 [10]. For a modular multiply-accumulate, constrain

```text
a*b + s = q*k + r  in F_P, with a,b,s,k,r all integers in [0,q-1].
```

The integer left side is at most q*(q-1)=18,446,744,026,464,911,390 and the
right side at most q^2-1=18,446,744,030,759,878,680. Both are strictly below
P=18,446,744,069,414,584,321. Therefore equality in F_P implies equality over
the integers and, with r<q, the unique original-q remainder. This is a
degree-two arithmetic relation plus essential range constraints, not a complete
AIR or proof backend. The range constraints must be enforced by the proof,
not merely by host-language types or honest witness generation. A 32-bit label
alone permits the five noncanonical values q through 2^32-1.

Two exact counterexamples explain the constraints. If the quotient is unbounded,
a=b=s=0, r=1 and k=878416384462359601 satisfy the field equation despite the
wrong remainder. Also P mod q=21: for two products of (q-1)*(q-1), direct native
reduction gives 2, while first accumulating modulo P and then reducing modulo q
gives 4294967272. Thus a complete dot product cannot be accumulated in F_P
without the individual bounded reductions or an explicitly constrained wider
integer representation.

The [integer observations](../../../../evidence/pon-pure-integration-20261027/arithmetic-embedding/goldilocks-range.json)
retain these bounds, both counterexamples and eight corner examples. The
universal implication follows from the range argument above, not exhaustive
testing. All original noise derivation, ordered tiles, SHA-256 bytes, canonical
encodings, target and block-context bindings still require complete constraints.
Lookup/range overhead, actual proving and rejection costs, commitment parameters
and Fiat-Shamir/QROM security are unmeasured. No throughput or PQ claim follows.

Neural proof papers can inform arithmetic scheduling without supplying the PQ
trust boundary. For example, zkLLM [8] uses tensor sumchecks and GPU parallelism,
but its actual Hyrax/Pedersen commitment is instantiated over BLS12-381 and relies
on discrete logarithms. Importing that complete backend would introduce a
classical cryptographic dependency. A transparent replacement changes both
performance and security; the paper's benchmark must not be copied as an
estimate for this chain.

The upstream RISC Zero 3.0 security page [9] distinguishes the STARK provers
from the BN254/Groth16 wrapper and labels the latter not quantum safe. This
research host already refuses that wrapper. The page's conditional 96-bit
RISC-V headline is not a proof of PQ128 for the actual multi-segment profile;
the retained per-receipt parameter calculation and its stated limitations remain
the controlling observation.

For every path, chainwork continues to count the required fresh PoN relation.
No independent hashcash gate, stake weight or committee vote is introduced.
Any proof-system-internal challenge grinding must be accounted for in the full
classical/quantum analysis and prover cost; it cannot be left unanalysed or
quietly counted as additional consensus authority. An implementation must also
budget malformed-byte parsing, maximum seal work, verification queues and cold
restart state globally before its proofs become public Node admission inputs.

## Primary sources

1. Justin Thaler, [Proofs, Arguments, and Zero-Knowledge](https://people.cs.georgetown.edu/jthaler/ProofsArgsAndZK.pdf), author manuscript, July 18, 2023; sections 2.2, 4.1 and 4.4.
2. Justin Thaler, [Time-Optimal Interactive Proofs for Circuit Evaluation](https://arxiv.org/abs/1304.3812), version 4; section 7, specialized matrix multiplication.
3. Lov Grover, [A fast quantum mechanical algorithm for database search](https://arxiv.org/abs/quant-ph/9605043), version 3; quadratic search speedup.
4. Don, Fehr, Majenz and Schaffner, [Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model](https://arxiv.org/abs/1902.07556), version 4; conditions and quantum reductions.
5. Don, Fehr and Majenz, [The Measure-and-Reprogram Technique 2.0: Multi-Round Fiat-Shamir and More](https://arxiv.org/abs/2003.05207), version 3; Corollary 3 and the multi-round analysis. Oracle-query count in this paper is not the field modulus q used above.
6. Golovnev, Lee, Setty, Thaler and Wahby, [Brakedown: Linear-time and field-agnostic SNARKs for R1CS](https://eprint.iacr.org/2021/1043); transparent linear-time prover and sufficiently large arbitrary-field construction.
7. Habock, Levit and Papini, [Circle STARKs](https://eprint.iacr.org/2024/278), revision dated 2025-02-20; the large power-of-two divisor of p+1 is part of the efficient-domain condition.
8. Sun, Li and Zhang, [zkLLM: Zero Knowledge Proofs for Large Language Models](https://arxiv.org/html/2404.16109v1), sections 3.4 and 8; Hyrax/Pedersen, discrete-log assumption and BLS12-381 implementation.
9. RISC Zero, [Cryptographic Security Model](https://dev.risczero.com/api/security-model), version 3.0, accessed 2026-10-27; conditional STARK assumptions and the distinct non-PQ Groth16 wrapper.
10. Plonky3, [p3-goldilocks 0.8.0 Goldilocks field documentation](https://docs.rs/p3-goldilocks/0.8.0/p3_goldilocks/struct.Goldilocks.html); exact prime definition only. No new dependency or claim about that crate's proof security is introduced here.
