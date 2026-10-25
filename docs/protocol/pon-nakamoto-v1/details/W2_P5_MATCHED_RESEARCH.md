# P5 matched W1 / W2-A / W2-B / W2-C research cost experiment

**Unqualified local observation, NOT a native Rust/PoN benchmark or production/security acceptance.**
Owner: M01/M02/M17 research. All four arms share the same synthetic
318-byte header-derived challenge and the exact same dense canonical
64x64 A/B and TaskId; W2-C alone adds its independent security hash
cost. Source:
'formal/pon-nakamoto-v1/w2_candidate_comparison.py'.
Controls:
'formal/pon-nakamoto-v1/test_w2_candidate_comparison.py'.

Run from the repository root:

    python3 formal/pon-nakamoto-v1/test_w2_candidate_comparison.py
    python3 formal/pon-nakamoto-v1/w2_candidate_comparison.py \
      --seed 3 --samples 4 --security-bits 8 12 16 \
      --security-cap 65536 --out /absolute/new-matched-research.json

The file is create-only and retains all capped/exhausted attempts; no
failure is converted to a successful work proof. This driver is an
ordinary Python process and does **not** open a real Node, implement
a real STARK/SNARK, or verify any model benefit.

## One local source-equivalent Python observation

The below values were obtained from a separately staged local Python
research copy on October 25, 2026, Python 3.13.5, one non-exclusive
container process, one fixed seed with no error bars. They are
reproducibility hints, not a run of exact-source Rust binaries. All
times use process_time_ns and exclude independently unmeasured GPU,
network queue, signing, block State, SQL, setup/energy and actual
physical host isolation.

| Operation | Observed CPU, ms | Correct interpretation |
| --- | ---: | --- |
| W1 honest full proof | 75.602 | A full canonical W1 transcript was generated |
| W1 honest full verification | 77.052 | Native production Rust costs may differ radically |
| W1 false transcript reject | 79.986 | Full CPU rejection amplification remains a service risk |
| W2-A create 4-index sampled sidecar | 62.821 | Extra research witness work |
| W2-A verify valid sampled openings | 14.889 | Smaller CPU but **not a sound full proof** |
| W2-A verify an unsampled corrupted tile | 14.314 | False claim accepted by the early filter |
| W2-B construct full witness | 144.616 | 131072-byte full-replay witness, no succinctness |
| W2-B verify full relation witness | 151.980 | No cost advantage or cryptographic proof |
| W2-C honest security Hashcash search, bits 8/12/16 | 0.460 / 1.375 / 32.973 | Only independent non-neural security search |
| W2-C false trace security Hashcash search, bits 8/12/16 | 0.213 / 0.283 / 82.152 | Search variance, not universal attacker cost |

At bits 8/12/16 the false-W1 arm found a security nonce under the
original finite cap but still **failed W1 Transcript verification**.
It does not create a verified proof/chainwork, and a sufficiently
expensive security ticket could also exclude honest low-power peers.
A GPU/ASIC may produce hashes much faster than Python; observed CPU
ratios cannot establish minimum adversary spend.

## P6 externally reproducible public fixtures

'formal/pon-nakamoto-v1/w2_research_vectors_v0.json' pins canonical
TaskId, original 49188-byte proof digest, full transcript digest,
131072-byte tile witness digest, Merkle root and W2 security tickets.
The Python reader and an **independently encoded Rust test**
'trnm-crypto-primitives/src/pon_work/w2_research_vectors.rs'
verify selected exact hashes under the unchanged SHA/field wire
semantics. The Rust test must still be built/executed on exact-source
Rust and is not an external expert's independent cryptographic review.

**Decisions:** W2-A sampling fails full-computation soundness; W2-B
currently is full replay rather than a proof system; W2-C buys an
independent non-useful-work security puzzle. No W2 construction
qualifies public PoN admission or production. P1–P6 remain OPEN.
