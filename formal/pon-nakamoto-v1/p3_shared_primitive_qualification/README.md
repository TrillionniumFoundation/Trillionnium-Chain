# P3 shared primitive qualification research

Status: **HOLD_NO_GO**. This package addresses the shared-primitive issue
separately from the W1 AIR relation, physical-work pricing and production
admission. It starts from the exact published PR #783 source
`cc836dfc13ef0006eb0878abd8cb5eca9a76bec0`.

The substantive results are a conditional classical ordinary-path argument
for the retained construction; an incompatible tagged SHA3-512 research
profile that generates and verifies complete W1 proofs; an exact-arithmetic,
explicitly conditional ideal-sponge query calculator; and a structural
two-opening collision reduction for the tagged profile's actual binary
cap-zero pruned multi-matrix verifier.
None grants concrete noninteractive, quantum, lifecycle or production
qualification. The old unrestricted raw-compressor collision remains a
valid finding and is not relabelled a Merkle or W1 forgery.

## Results and their exact scope

| Item | Result | Boundary |
|---|---|---|
| Old raw compressor | Existing inverse witnesses and native P3 audit retained | Arbitrary input pairs; not an accepted conflicting W1 opening |
| Retained ordinary tree | New classical ideal-permutation binding proposition, allowing arbitrary siblings and shared forward/inverse calls | Fixed ordinary shape/index; no concrete Poseidon2, quantum, pruned multiproof or PCS/FS theorem |
| Full-hash path extraction | Deterministic extraction from two already available conflicting ordinary openings | Toy executable framing; not the actual P3 multi-matrix adapter or a quantum extractor |
| Tagged pruned-MMCS binding reduction | Two accepted outputs conflicting at one shared matrix-row coordinate yield a full framed-hash collision through the actual P3 0.8.0 verifier | Fixed binary cap-zero power-of-two geometry and context; structural postprocessing also covers quantum-produced classical outputs, not quantum commitment extraction or concrete security |
| New commitment/transcript profile | Full SHA3-512, framed roles, typed statement context, raw 512-bit digests, separate wire magic | Same concrete primitive in all roles; no independent-oracle claim |
| New complete W1 execution | Two separate campaigns of eight fresh complete W1 executions, independently verified across old/new variants and two inputs | Research processes; no mining/search, recursive verifier, Node or production service measurement |
| Independent byte reference | 31 fixed Python `hashlib` vectors exercised by native role APIs | Finite interoperability evidence |
| Ideal-sponge arithmetic | Exact rational evaluation of the cited 2026 theorem, with advice/query restrictions | Caller assumptions remain assumptions; `qualified=false` in every output |
| Model-assisted source review | Locked upstream source identities, encoding, sampling and inherited state aliases documented | Internal source review; not an independent external security audit |

The [security contract](SECURITY_CONTRACT.md) defines the different games and
the remaining obligations. The [profile specification](PROFILE.md) gives the
exact bytes and parameter choices. Existing old-profile audit evidence is
unchanged in the [original integration record](../w1_public_stark_research/security_model_audit/INTEGRATION.md).
The [initial source review](independent_review/REVIEW.md) and
[final delta review](independent_review/FINAL_DELTA_REVIEW.md) identify their
own staging snapshots and explicitly separate internal review from native
execution and exact-commit validation.

## Retained-construction result

Let a uniformly random permutation act on two halves of size `N = p^4`.
Fix a positive leaf width `w`, an ordinary path height `h`, and the queried
position. Set `b = ceil(w/4)` and `T = Q + 2(b+h)`. All classical forward and
inverse queries, including leaf, branch, transcript and preprocessing uses,
share the single bound `Q`. Initial advice must be independent of the sampled
permutation, or its generation must be included in the same query history.
For `T <= N^2`, the proposed bound for two conflicting accepted rows is

\[
\Pr[\text{conflicting ordinary openings}]
\le \min\!\left(1,\frac{2NT^2}{N^2-T+1}\right).
\]

The proof marks entries by their first forward/inverse exposure. An
inverse-created unrestricted raw collision is permitted. A conflicting
fixed-position ordinary path needs an additional bad table event, which is
bounded explicitly. The proposition does not assume siblings have honest
subtree preimages. Its scope and complete argument are in
[RETAINED_CONSTRUCTION.md](restricted_tree/RETAINED_CONSTRUCTION.md).

The finite structural control exhausts all 24 permutations for a two-element
half space, 29,624 conflicting opening pairs, 108 distinct table/call-set cases
and 12,768 first-exposure direction/order combinations. It also preserves
negative controls for inverse-created raw collisions and cross-shape aliases.
This enumeration checks the proof's mechanism; it is not a substitute for
the mathematical argument, quantum analysis or a proof assistant.

The separate [full-hash extraction argument](restricted_tree/COLLISION_EXTRACTION.md)
uses at most `2(h+1)` full-hash evaluations, plus two if the extracted collision
is rechecked. It postprocesses two classically available openings and cannot
be promoted to a quantum knowledge extractor. Its executable uses toy local
tags, so it does not claim implementation equivalence with the new profile.

## Tagged pruned/mixed-height opening reduction

The [new argument](pruned_mmcs/BINDING_REDUCTION.md) handles the actual P3
0.8.0 binary cap-zero verifier with fixed ordered power-of-two matrix heights
and widths, one context, exact shared frontiers, unequal global query lists
and shorter-row injections. It tracks shared `(matrix, reduced row)`
coordinates and allows arbitrary sibling digests. The native executable
uses the unchanged R1 leaf/branch APIs, verifies pruned proofs, restores
full paths, and independently verifies each restored path. Actual
`ExtensionMmcs` and explicitly flattened base-field rows agree.

For two already available accepted conflicting outputs, verification finds
an explicit collision in the complete framed hash. With `q0,q1` query
counts, maximum height `2^h` and `k` distinct matrix heights, at most
`(q0+q1)*(h+2*k-1)+2` additional whole-hash calls suffice, including the
collision-witness recheck. This postprocessing also applies after a quantum
producer outputs classical openings, in the same oracle/advice experiment.
It provides no numeric collision bound and is not a quantum PCS or
Fiat-Shamir extractor. The native controls force collisions only in
explicitly artificial leaf/branch oracles; no real SHA3 collision or W1
forgery is claimed.

## Initial complete W1 comparison

Both arms use the same existing SHA AIR and packed carry AIR. The old arm is
the retained `packed_carry_backend`; the new arm is `tagged_sha3_backend`.
Each run starts from raw/prefix inputs, prepares the public statement,
generates both real STARK proofs, serializes them, and launches a fresh
verifier that rebuilds both public preprocessing keys from independent
expected inputs. Small test proofs are excluded from the count below.

Two fixtures each run in ABBA order, for two executions per variant per
fixture. The host is shared, CPU affinity has eight logical CPUs and
`RAYON_NUM_THREADS=8`. Source, binary and input hashes agree before and after
the frozen campaign. The dense fixture consists of read-only input bytes
copied from the unmerged R4 worktree with exact provenance; no R4 source or
cached performance result is incorporated. All eight full proofs here are
freshly generated with this package's baseline and profile.

| Fixture and measurement | Old Poseidon2 | New tagged SHA3-512 |
|---|---:|---:|
| Retained: full prepare/prove/verify median | 20.414321 s | 9.708290 s |
| Retained: fresh verifier median | 1.221478 s | 0.747086 s |
| Retained: transmitted statement + proofs | 5,187,252 B | 5,435,252 B |
| Retained: median peak process RSS | 2,037,994 KiB | 2,039,534 KiB |
| Dense: full prepare/prove/verify median | 20.511479 s | 9.742452 s |
| Dense: fresh verifier median | 1.120189 s | 1.004059 s |
| Dense: transmitted statement + proofs | 5,186,804 B | 5,444,148 B |
| Dense: median peak process RSS | 2,037,060 KiB | 2,042,930 KiB |

All eight initial executions succeeded. These are small-sample observed medians,
not confidence intervals or a claim about all inputs or isolated hosts.
The second new dense verifier in this initial campaign took 1.240611 seconds and is included, not
discarded as an outlier. Median phase sums need not equal median pipeline
time. The pipeline scope excludes nonce search, native candidate generation,
production queues, WAN transfer, energy and recursion. The larger payloads
remain over 100 times the 49,506-byte native candidate. No native-backend or
production benefit follows from a comparison between these two STARK arms.

## Integration with the advanced research branch

Before publication, PR #783 advanced to
`09fbc0f45151a68a1bf205641171840fbf309882`. The candidate preserves those ten
parallel commits and both append-only plan/module changes. Its tagged profile
keeps the same exact frame, components 1/4, AIRs and wire representation.
The [base integration report](BASE_INTEGRATION.md) records the source review,
original exact-commit gate archive and a new eight-execution ABBA campaign on
the resolved integrated code.

The integrated campaign passed all eight fresh complete W1 executions, 68
Rust tests, strict release Clippy, 71 structural controls and 11 receiver
controls. Its observed pipeline medians are 19.158297 -> 8.386623 seconds for
the retained input and 19.481059 -> 9.607534 seconds for the dense input.
The two campaigns remain separate observations, with 16 full W1 executions
in total. Historical receipts retain their actual source/binary identities;
post-commit checks bind the final integrated candidate independently.

## Quantum and preprocessing model

The [budget calculator](budget/README.md) evaluates Theorem 5.5 of
[Carolan and Majenz's 2026 preprint](https://arxiv.org/html/2609.28469v1)
using exact integers and fractions. For `T=q+2L`, it records the stated
preimage or collision sum, its theorem domain and every charged role,
direction and preprocessing phase. Standard XOR queries are converted to
the theorem's swap-query convention. Fixed-target unions use the full
shared budget for every event. It never resets the budget per role.

It rejects unknown/free construction-dependent advice, uncharged correlated
initial states, unsupported concrete-permutation claims, honest-call counters
presented as adversarial upper bounds, and attempts to certify Merkle,
Fiat-Shamir or W1 security. The 40 tests include exact boundaries and invalid
inputs. The hypothetical example is not a claimed real adversarial budget.

The [2025 quantum sponge theorem](https://arxiv.org/html/2504.16887v2) is a
full-sponge ideal-permutation theorem with explicit losses, not a proof for
the fixed Poseidon2 or Keccak permutation. The
[2024 precomputation paper](https://arxiv.org/html/2410.16595v1) explains why
ordinary primitive replacement is insufficient for general auxiliary-state
models. The [duplex Fiat-Shamir work](https://eprint.iacr.org/2025/536) has
its own transformation and hypotheses; this P3 hash challenger has not
been proved to satisfy them. See the security contract for the precise
distinctions and source references.

## Validation and reproduction

The [initial native evidence store](evidence/native-v1/README.md) retains every raw
observation, proof and mutated control byte through a content-indexed gzip
store. Its materializer recovered all 239 indexed files, totaling 74,307,487
original bytes, with exact size/hash checks. The retained
[ABBA manifest](evidence/native-v1/abba-v1/manifest.json),
[receiver-control summary](evidence/native-v1/receive-controls-v1/summary.json),
[fixture provenance](evidence/native-v1/fixture-provenance.json) and
[final native identities](evidence/native-v1/final-source-identities.json)
state their original source/run scopes. The full observations are about
40.98 MB after binary deduplication and compression; compiled binaries are
represented by hashes and build metadata, not committed executables.

The two newly added cached dependency archives (`sha3 0.10.9` and
`keccak 0.1.6`) match their locked checksums, and all 31 and 12 archived files,
respectively, match the actual registry source bytes. The
[offline source check](verify_new_dependency_sources.py) reproduces that
identity check; it is not an algorithm audit.

The [exact-commit check runner](run_qualification_checks.py) requires a clean
checkout and a 40-character expected commit. It performs preflight, source
identity checks before and after, repository/Markdown checks, retained
negative suites, the historical hash audit, Python model/extraction checks,
finite enumeration, independent-vector regeneration, the locked offline
Cargo graph, formatting, strict Clippy, all-target Rust tests, doc-test and
build commands, and the original native hash probe. It also checks that
runtime, configuration and qualification paths do not change from the
baseline. Outputs and build targets must be outside the checkout.

```sh
python3 -B formal/pon-nakamoto-v1/p3_shared_primitive_qualification/run_qualification_checks.py \
  --expected-head COMMIT_SHA \
  --output /absolute/new-observation-directory \
  --target-dir /absolute/research-build-target \
  --cargo /absolute/path/to/cargo
```

The environment must already provide Rust 1.95.0 and the locked dependencies;
the runner neither installs packages nor accesses the network. Preserve the
reported build flags and host metadata when comparing the retained benchmark.
A successful focused runner is not the complete repository CI lane. Raw
observations, failed development attempts and source/binary identities must
remain distinguishable from the final exact-commit verification receipt.

The initial native implementation campaign passed 56 Rust tests: 24 library,
three carry-proof, three original proof-smoke, 11 new-profile and 15 retained
wire-admission tests. One new-profile test exercises all 31 independent
reference vectors. The full-proof structural harness passed 71 controls,
including intentional structural admission of raw all-`ff` digest bytes;
it is not 71 cryptographic rejection claims. Eleven separate receiver
process controls matched their expected outcomes. Their replay generated
no additional proofs. The byte scanner observed zero allocations on its
own thread, without asserting a bound for the rest of the process.

## Remaining acceptance conditions

Concrete joint leaf/branch/transcript security, commitment extraction beyond
the bounded pruned-opening structural reduction, PCS extraction and
Fiat-Shamir knowledge soundness remain open. So do
quantum queries, construction-dependent advice, lifetime budget justification,
recursive-verifier AIR cost and global malicious receiver cost. The new
profile intentionally leaves the corresponding security-bit fields null.

The original production service contract, native dispatch and system gates
are not changed. This package makes two research routes reviewable and adds
measured implementation evidence; it authorizes no Node admission, consensus
weight, release, activation or main-branch merge.

