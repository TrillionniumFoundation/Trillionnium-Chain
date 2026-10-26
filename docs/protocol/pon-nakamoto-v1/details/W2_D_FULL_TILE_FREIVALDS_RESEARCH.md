# W2-D: complete 512-tile Fiat-Shamir/Freivalds research

**Status: P5 RESEARCH ONLY, not a W1 consensus replacement.** Development
source was branched from Chain #335 at
'db0dad68f0909460e8b1cf0c248d8bab4b59c129'. The original 49,188-byte
PNW1 proof, challenge, ticket, required-work, native admission, chainwork,
genesis, source/task/finality authority and signed V3 Cookie are unchanged.
This experiment creates NO VerifiedWork, no Chainwork and no W2 activation.

## Different from the unsound W2-A sampling prototype

The original 'w2a_merkle_sampling.py' verifies only a selected number of
tile openings; a wrong *unopened* tile demonstrably passes. W2-D instead
transmits **all 512 intermediate tiles**, in W1's exact
'(bi,bj,bk,i,j)' update order: 512 × 64 field words × 4 bytes =
**131,072 additional bytes**. It first checks that the SHA256 of this
complete byte stream matches the exact original W1 final transcript digest.

It checks ALL updates without recomputing their complete 8-product dot
products directly. Define each 8×8 tile's required cumulative transition:

    DeltaTile[bi,bj,bk] = A'[bi,bk] * B'[bk,bj] (mod q)

For each pair (bj,bk) and each of **two independent rounds**, derive
a uniform Fq^8 challenge vector from the SHA256-domain-separated hash of
the full statement and all committed sidecar bytes, using rejection
sampling of 32-bit words less than q=4294967291. For each tile assert

    DeltaTile * r == A'_tile * (B'_tile * r) (mod q).

The right-hand matrix/vector factor is shared across all eight output row
tiles for a fixed (bj,bk,round). Both initial zero prefix, all intermediate
512 states and update ordering are checked. The sidecar's W1 trace digest
is checked *exactly*. The final claimed C from PNW1 is separately checked
through TWO 64-dimensional Freivalds equations A*(B*r) == C*r,
avoiding complete direct AB recomputation in this reference verifier.

Both challenge vector families derive from

    H("w2d-statement-commit", profile-domain,
      challenge, expected-task, target, entire-PNW1, entire-sidecar)

and use separate 'tile' vs 'product' labels. This is a NEW research
Fiat-Shamir domain, not the existing W1 ticket or signed work identity.
The externally derived header challenge/task/target must be authenticated
by the true network/consensus caller; the pure Python verifier does not
prove that the caller is authorized or holding the current parent.

## Security interpretation: conditional, NOT proven for public miners

For a fixed nonzero 8×8 incorrect relation E, an independently uniform
r in Fq^8 satisfies Er=0 with probability at most 1/q. Two independent
rounds yield a fixed-input upper bound 1/q^2, approximately 2^-64.
The final wrong product has the analogous property. This is **NOT** a
universal adversarial forging bound once attackers adaptively grind full
sidecars and hash commitments: any security claim needs a precise
random-oracle/query-budget model, chosen-parent/target grinding, special
material shortcuts, SHA256 assumptions, transcript uniqueness and
independent cryptanalysis. A determined attacker may try to exploit the
difference between *fixed* relation soundness and adaptive proof search.
A sampled Merkle proof with only 8 openings remains explicitly UNSOUND;
W2-D is not a reclassification of that negative result.

The profile needs a true noninteractive argument of computation security
analysis (or a stronger cryptographic proof) before becoming consensus.
There is no trusted evaluator, source admission, final-use or model
improvement claim. Full sidecar verification is probabilistic and cannot
reconstruct an unconditionally exact C result.

## Actual independent-reference CPU observation (not source-attested native)

Run:

    python3 formal/pon-nakamoto-v1/test_w2d_full_tile_freivalds.py -v

The new test module has eight explicit negative/control selectors: dense,
zero, four forged trace claims, one wrong intermediate tile with a
recomputed forged digest, wrong product, changed task/challenge/target,
noncanonical/malformed witness, and explicit no-authority outputs.
On 2026-10-26 the local Python 3.13.5 isolated test environment executed
these eight tests and all passed; the verified GitHub blob SHA for each
source file exactly matched the bytes re-executed locally. It used an
inlined exact SHA256 field-hash oracle and the repo's independently coded
W1 scalar work oracle, but not a full local Chain checkout. Therefore
this does NOT qualify original AGENTS preflight or the native Rust build.

One bounded exploratory cohort under Linux 6.18.55 with one fixed
challenge '000102...1f', target all 'ff' (**research-only loose target**),
no GPU, no simultaneous network load:

| Material | W1 complete proof CPU | W2-D extra witness CPU | W1 full verify CPU | W2-D probabilistic verify CPU |
| --- | ---: | ---: | ---: | ---: |
| Dense | 103.47 ms | 97.24 ms | 105.13 ms | 64.57 ms |
| Zero | 103.22 ms | 92.88 ms | 94.15 ms | 63.92 ms |
| Sparse | 108.49 ms | 95.42 ms | 101.55 ms | 59.80 ms |

These are single CPU observations, not statistical confidence or fastest
adversary/accelerator costs. The extra witness almost **doubles honest
producer computation** in this separate unoptimized reference constructor.
The sidecar grows on-wire bytes by ~2.67× relative to the existing PNW1
certificate alone and may worsen WAN throughput, propagation, miner
concentration and whole-network energy economics. Lower isolated Python
verifier CPU is not enough to conclude a useful-work or security gain.

## Strict P5/P6 acceptance gates (OPEN)

1. Independent mathematical/protocol review of Fiat-Shamir soundness
   against adaptive sidecar/parent/target grinding, challenge reuse,
   hardware advantage and arbitrary chosen canonical A/B.
2. Independent Rust/Go implementation, exact cross-language byte vectors,
   corrupted intermediate positions including first/middle/last, nonce,
   task, changed challenge, low-rank/cached and malicious small-q controls.
3. Real signed native source/task window, W1/W2 uniqueness and target
   arithmetic. New versioned proof wire, consensus parameters, fork-choice,
   migration, reorg and no downgrade; independent reviewer must approve
   any new authority. No implicit W1-to-W2 auto fallback.
4. Same-target true full producer CPU/GPU/ASIC attempts, failed attempts,
   proof generation, network/DA, state execution and honest receiver p95/p99
   under original public V3 budget; full A03 P4 remains separately required.
5. Comparative total **network** resources (every validator's verification
   times, 131 KiB replication, retention, sidecar repair) plus real Hepta
   useful-work adoption. Optional smaller proof systems may be necessary.
6. External independent cryptanalysis/third-party reproductions.
   Internal test success is NOT P6 acceptance.

SHADOW_ONLY / HOLD_NO_GO / production_consensus_activation=false.


### Security-margin versus verifier CPU: explicit negative cost control

A separate **in-memory exploratory run**, not a versioned protocol or executed
committed default, varied only the W2-D number of rounds using the same
dense source, same target, challenge and 131,072-byte witness. For each
round count two calling-process-CPU samples were retained:

| Freivalds rounds | Fixed-commitment false-relation random-vector error | Actual Python verifier CPU, two samples |
| ---: | --- | --- |
| 2 (committed research default) | <= q^-2 (about 64 bits) | 71.17 / 60.06 ms |
| 4 (temporary exploratory override) | <= q^-4 (about 128 bits) | 101.94 / 111.30 ms |
| 6 (temporary exploratory override) | <= q^-6 (about 192 bits) | 152.65 / 220.84 ms |

**Critical tradeoff:** in this tiny Python cohort, a four-round research
variant reaches or exceeds the original full W1 verifier's roughly
94–105 ms CPU. The apparent 2-round speed advantage may vanish at a
security margin appropriate for a long-lived permissionless chain.
These values are not protocol configurations or SHA256-computed security
proofs: the candidate code intentionally hard-codes ROUNDS=2, and the
alternate variants need **different versioned statement domains** before
any wire compatibility claim. An adaptive adversary's total commitments,
grinding and GPU advantage still reduce security margins. This NEGATIVE
result blocks treating the 2-round performance gain as P5 closure.
