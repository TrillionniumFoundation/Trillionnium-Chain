# W2-D: Fiat–Shamir Freivalds product projection (research-only)

**Status:** mathematically motivated CPU-cost experiment, explicitly **NOT** a qualified PoN consensus proof. Frozen parent of the incremental experiment:
'db0dad68f0909460e8b1cf0c248d8bab4b59c129' (Chain PR #335).
No existing W1, PNW1, block format, retarget, genesis, cumulative chainwork,
transport V3 policy, rewards, mining activity or production flag was changed.

## New research-only relation

The exact source is 'formal/pon-nakamoto-v1/w2d_product_projection.py';
the differential tests are 'test_w2d_product_projection.py'. They
explicitly reuse the **original fixed** q=4,294,967,291, n=64, r=8
and the four W1 challenge-derived noise factors.

The noncanonical **new** experimental proof format has 65,540 bytes:
'PND0' + original A + original B + claimed C=AB + claimed
C'=(A+EL ER)(B+FL FR), with four canonical 64x64 field matrices.
Its separate SHA-256 ticket binds the challenge and the complete proof.

For the base product and challenge-masked product independently, the
verifier applies **six** SHA-derived Freivalds vectors each, seeded by a
domain-separated commitment of the complete immutable proof, task and
challenge. It compares A(Br) against Cr and A'(B'r) against C'r,
without executing the original 512-tile W1 transcript replay. Each
counterexample changes one claimed product and must be rejected before
any work/chain authority is granted.

Under an **ideal random-oracle assumption** for each committed malformed
statement and independent uniform vector, the probability that a fixed
false matrix equality survives six rounds is at most (1/q)^6. This
conditional calculation is **not** a validated adaptive Fiat–Shamir
soundness theorem, worst-case attacker work floor, or an assurance that
miners can never grind proof/header choices or exploit model-input structure.
The actual signed work program, task qualification and adversarial
noninteractive proof security need independent cryptographic review.

The successful reference result is intentionally named
'PROJECTION_CHECKED_RESEARCH_ONLY' and explicitly returns
'verified_work=false', 'chainwork=0' and 'consensus_activation=false'.
No Rust VerifiedWork, packet admission or model evaluation can be
constructed from it.

## Essential producer-cost counterexample

The same mathematical statement admits two **byte-identical** proof
producers for each challenge, after an already computed reusable
C=AB product:

1. Direct producer: compute fresh A', B' and perform a complete 64x64
   masked product C'=A'B' per challenge.
2. Algebraic producer: compute

       C' = AB + (A FL) FR + EL (ER B) + EL (ER FL) FR   (mod q)

   using the four challenge-dependent *rank-eight* factors. This
   avoids recomputing the full dense product for each new nonce.

The independent test checks exact proof byte parity on a dense matrix
and a zero matrix; a separate zero-input control shows even stronger
structured simplifications are eligible.

**Therefore faster verification does not imply PoN economic hardness.**
The frozen AB can be reused across challenge/nonce searches, some
zero/low-rank tasks are cheaper, and different hardware/accelerators
can advantage one algorithm over the other. None of the theoretical
Freivalds rejection bounds is a lower bound on legitimate mining cost.

## Bounded Python CPU observations on October 26, 2026

The local 7-test run passed with a scratch Python H/matrix oracle using the
same fixed arithmetic and domain rules. Both committed research source
files were subsequently confirmed by exact Git blob SHA equality with
the tested local files. This does **not** replace running the exact repo's
locked source, native Rust, WAN network or an external reviewer.

Four frozen sample rows (two zero and two dense), all with **target=all ff**
so this is a per-candidate cost study, **not** a difficulty-winning search.
The same base C=AB is prepared once per material class, and is reported
separately in the JSON and excluded from the per-nonce CPU columns.

| Sample | Full masked C' producer CPU | Reused low-rank producer CPU | Two-relation projection verifier CPU | Wrong claimed C' rejection CPU |
| --- | ---: | ---: | ---: | ---: |
| Zero / nonce 0 | 54.03 ms | 33.17 ms | 29.43 ms | 22.64 ms |
| Zero / nonce 1 | 49.39 ms | 35.28 ms | 28.68 ms | 20.20 ms |
| Dense / nonce 0 | 50.26 ms | 37.85 ms | 28.91 ms | 21.28 ms |
| Dense / nonce 1 | 49.04 ms | 37.35 ms | 28.72 ms | 20.90 ms |

Full raw CPU JSON SHA-256:
'8f42bd3f124f84c2871b14fee842c9cb473f74f854fea0cfd082ae6dc086458a'.
The raw local file is not a signed public hardware receipt and is not
claimed to originate from the selected production operator or a GPU.
All nested setup, hardware, concurrency, energy, data distribution, and
honest-service overhead require separate exact-source measurement.

## P5 / P6 explicit failure and future design requirements

- W2-D remains **probabilistic** under heuristic FS/R.O. analysis, not a
  completed proof of required work. The changed matrix relation removes
  W1's challenge-ordered partial-transcript hash, which was intended to
  disincentivize prefix/mask shortcuts. Never silently accept W2-D under
  W1's existing block IDs, ticket domain, difficulty or cumulative work.
- A from-zero bad C'=0 can still pass the cheap ticket and require
  bounded Freivalds CPU on the receiver. This may reduce but does not
  eliminate cheap-fake/expensive-reject asymmetry. Physical Host CPU and
  actual client admission pricing remain required.
- The six round count, hash-based vector generation, prover-chosen proof
  commitment, conditional q^-6 bound, multi-round grind advantage and
  versioned upgrade/fork behavior require outside cryptanalysis. No
  internal Python/Go/Rust code is an independent third-party review.
- If a future new proof relation is adopted at all, it needs a separately
  governed signed network/Genesis namespace, explicit transition/fork
  handling, security lower bounds on the **cheapest valid producer over
  all selectable tasks**, measured honest workload benefit, and complete
  native adversarial/host/WAN acceptance.
- W2-A sampling unsoundness, W2-B missing succinct proof, W2-C local
  ticket amplification, P1 shared Host CPU, P2 real GPU/ASIC pricing,
  P3 mixed attacks, original A03 P4 3 modes × 3 runs × 3 confirmations,
  and P6 external cryptanalysis remain OPEN.

Run the model-only differential locally with:

    python3 formal/pon-nakamoto-v1/test_w2d_product_projection.py -v
    python3 formal/pon-nakamoto-v1/w2d_product_projection.py

Status remains DRAFT / SHADOW_ONLY / HOLD_NO_GO.
