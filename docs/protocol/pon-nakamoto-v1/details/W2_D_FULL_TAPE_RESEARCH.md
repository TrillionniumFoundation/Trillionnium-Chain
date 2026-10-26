# W2-D full transcript + Fiat-Shamir batch projection research

Status: RESEARCH / HOLD_NO_GO. This is a separate experimental Python
verifier, not succinct proof, independent soundness review, new consensus
profile, verified work, model training evidence or authorized chainwork.
Original W1 PNW1 bytes and consensus activation remain untouched.

## Construction and mathematical security scope

The previous W2-A Merkle sample check admits a known wrong *unsampled*
tile. This W2-D prototype includes ALL 512 tiles of the original 64x64
matrix-prefix transcript in W1's (bi,bj,bk,i,j) byte order. Research
sidecar is 4-byte PFD1 magic plus 131072 field bytes (131076 total);
together with original 49188-byte W1, this is 180264 bytes. Propagation
cost is more than 3.6x W1 before outer packet framing.

Original cheap TaskId and target filters run first. The verifier checks
SHA256 of the complete tile tape against the exact claimed original W1
trace, then derives deterministic Fiat-Shamir field-valued random
vectors with domains binding challenge, task, target, full PNW1 bytes,
complete tape hash, and independently labeled rounds for prefix and
product checks. It verifies ALL eight prefix equations:

    (C'_k - C'_(k-1)) r =
        A'[:, kR:(k+1)R] (B'[kR:(k+1)R, :] r) (mod q)

and independently C*r == A*(B*r). All W1 challenge noise, A'/B',
field q=4294967291, lettered transcript, product and task semantics
are preserved. The native Node does not call this prototype.

For a fixed invalid matrix and uniformly independent field vector,
one Freivalds check has a false-accept probability at most 1/q.
Under three independent rounds and a union bound over eight prefix
equations plus one product equation, a nominal 9/q^3 applies ONLY
under those idealized assumptions. Here randomness is derived through
Fiat-Shamir and SHA256. An adversary may grind candidate witnesses,
exploit correlated equations or use specialized arithmetic shortcuts.
No cryptographic soundness theorem, GPU lower bound, unique-proof
lottery property or third-party security acceptance is claimed.

## Executable negative regressions

    python3 formal/pon-nakamoto-v1/test_w2d_transcript_freivalds.py -v

Eight local Python tests passed:
- Valid zero and dense source proofs are byte-for-byte equal to the
  existing independently coded scalar W1 oracle.
- One altered intermediate tile with freshly recomputed claimed trace
  is still rejected as PREFIX, not accepted by an unchecked sample.
- A fully fabricated all-zero tape whose trace is its honest SHA256
  digest still fails PREFIX.
- Correct trace plus forged final C fails PRODUCT.
- False trace alone fails TRACE_BIND; wrong task, field, magic,
  sidecar size, proof rounds and hash domains retain explicit negatives.
- No test result constructs VerifiedWork or Chainwork; research success
  returns only a non-authoritative status.

These are attack regressions, not a proof against adaptive forgery.

## Actual local CPU cost, bounded and source pinned

The reproducible 'formal/pon-nakamoto-v1/w2d_cost.py' script checks
the exact Git blob SHA of the original 'work_oracle.py':
9cbfccd2d50af48fc43522b967ffdfb1f45ec098.

A local run with --seed 1 --samples 2 used a deliberately all-FF
RESEARCH target (not active chain difficulty), producing raw JSON
SHA256 eb2b9c24cd7b31f2a28f873186f0616548f8434cba8993a6006f2787292a6c64.

| Material | Original W1 valid verify | W2-D valid verify | Fake internally consistent tape reject | Fake trace reject |
| --- | ---: | ---: | ---: | ---: |
| All zero | 88.14 ms | 44.05 ms | 22.07 ms | 3.46 ms |
| Dense | 86.10 ms | 40.55 ms | 23.43 ms | 3.97 ms |

This single-process Python measurement neither supplies Rust compiler
results nor accounts for large message bandwidth, GPU/ASIC costs,
disk/state replay, WAN cgroups, actual signed client service or
independent miners. Invalid self-consistent tapes remain much cheaper
to produce than their 22-23ms rejection cost. W2-D is a faster
research relation checker, NOT a fully solved receiver DoS defense.

## Required before reconsidering P5/P6

A new W2 wire/profile must receive formal soundness and Fiat-Shamir
grinding analysis, independent cryptographic review, unique lottery,
canonical counterexamples, cross-language validators, target/chainwork
and versioned migration/reorg tests, plus complete matched resource
costs on real CPU/GPU/ASIC hardware. P1-P4 resource fairness and
A03 physical attack cohorts remain separate. No production
activation or automatic hash-only/BFT fallback is authorized.
