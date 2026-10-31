# Quantum miner / PoN difficulty sensitivity — bounded research (2026-10-31)

**Status: HOLD / no production activation / not quantum-resistance evidence.**

The repository's existing [development reference arithmetic](../../formal/pon-nakamoto-v1/reference.py) defines work as \`floor(2^256/(target+1))\`, a 16-block retarget with an approximately 4-fold bounded change, and 11-ancestor median-time / future deferral. This new sensitivity exercise imports those exact reference functions and the current [devnet configuration](../../config/pon/devnet-v1.json); it does not edit consensus.

Run on a full checkout:

\`\`\`sh
python3 -m unittest discover -s scripts/ci -p 'test_pq_quantum_daa_scenarios.py' -v
python3 scripts/ci/pq_quantum_daa_scenarios.py --epochs 4
\`\`\`

The harness compares an assumed header timestamp increment of 1 second with the nominal 10 seconds across four retarget epochs, granting each hypothetical header a matching wall clock. It checks each timestamp through \`timestamp_state\`. These two branches do **not** use the same elapsed wall time, physical mining budget, proof production, network delay or fork-choice competition, so comparing their cumulative chainwork is **not an executable attack**.

| Epoch | Nominal per-header chainwork | Fast-timestamp per-header chainwork | Fast-timestamp ideal sqrt-search index |
| --- | ---: | ---: | ---: |
| 1 | 2 | 2 | 2 |
| 2 | 2 | 7 | 3 |
| 3 | 2 | 31 | 6 |
| 4 | 2 | 123 | 12 |

Those are integer-reference calculations under the uniform-search *proxy*, not measurements. Each column is per header at that epoch's target; the simulator also returns complete cumulative values and exact target hex strings. Because integer targets and work truncate, the result is not exactly 4x at each epoch. For a single known target, the model labels \`ceil(2^256/(target+1))\` an expected *classical trials proxy*, and \`ceil(sqrt(proxy))\` an **idealized quantum search index**. It does **not** convert the index to actual Grover iteration counts, reversible gates, logical qubits, fault-correction cycles, or quantum seconds. Existing W1 is a complete mathematical/transcript relation with amortizable setup and structured legal algorithms, not necessarily independent random-oracle trials. Consequently neither proxy bounds the actual cheapest miner.

## Required real qualification (all unclosed)

1. Pin full W1 statement, selectable challenge/material families and cheapest *legal* classical CPU/GPU/ASIC implementations. Charge common task construction, matrix/material load, reusable setup, all misses and complete producer time.
2. Construct a **reversible, complete** W1 success oracle with honest transcript/commitment validation and all public-data access. Charge construction, work registers, uncomputation, repeated queries, final readout and verified release of a complete valid block. Report quantum gate depth, total gates, logical/physical qubits, error correction and wall time for a declared hardware model; a proposed circuit only gives an upper bound on some attack strategy, not a hardness lower bound.
3. Feed equivalent actual work/time budgets into **the real** timestamp validation, DAA, cumulative-work selection, median deferrals, adversarial timestamps, deep reorg, withholding and propagation. Demonstrate which schedules are genuinely executable. A schedule that passes isolated timestamp checks but requires impossible block production cannot be counted as an attack.
4. Freeze the victim and attacker cost models **before** sweeping tasks, batch sizes, challenge reuse, hardware and historical material. Reproduce on separate hosts, with failures and timeouts retained.
5. Obtain independent worst-case adversarial analysis. Unchanged work arithmetic does not imply unbounded quantum immunity, nor does a finite adversarial test establish a security theorem.

These scenarios are explicitly conditional on the quantum miner / difficulty-manipulation observation of Bailey and Sattath (2024). They do not assume that observation automatically transfers to the complete Trillionnium W1 work relation.

No ML-DSA signature, STARK proof, quantum cost model, nor this script alone can authorize PQ-128, claim the chain is quantum-resistant, or set any production flag.
