# Quantum miner / PoN difficulty sensitivity — bounded research (2026-10-31)

**Status: HOLD / no production activation / not quantum-resistance evidence.**

## Current continuation and the scope of this historical table

The table below preserves the original 2026-10-31 sensitivity calculation.
The current [quantum research implementation](../../formal/pon-nakamoto-v1/QUANTUM_DAA_RESEARCH.md)
also has a fixed-public-context hierarchical W1 reversible construction,
a cheaper legal prefix-restricted construction, literal nonce censuses, and
resource-derived conditional event experiments. Native-size macro execution,
reduced actual leaf-gate execution, declared hardware resources, and real native
Node packet execution remain separate evidence classes. None is an observed
fault-tolerant quantum miner or a universal quantum-cost lower bound.

The 2026-11-06 continuation repairs binary64 measurement sampling in both the
network and literal-domain paths: an exact integer draw samples the represented
probability, including probabilities below `2^-53`. Grover amplitudes remain
floating-point approximations. New v2 measurement/campaign namespaces prevent
old seeded traces from being reinterpreted as runs of the corrected sampler.
The resource model also refuses a declared complete Toffoli decomposition depth
smaller than its own T-layer depth. A new explicit single-quantum-miner policy
finishes the current Grover iteration after an adopted competing tip, then pays
readout, verification and any proof on the original header. Paired seeded
scenarios retain equal declared time/resource inputs; they do not establish
real quantum production rates or multi-miner correlated-fork security.

The [native DAA controls](../../trillionnium/crates/trnm-pon-node/tests/daa_adversarial_schedule.rs)
exercise complete PNW1 packets, shorter/harder versus longer/easier forks, and
equal-work active-tip preservation across authenticated reopen. Their logical
timestamps do not establish a real-time attacker resource share or an economic
advantage. The [independent reader](../../scripts/pon_daa_schedule_reader.py)
recomputes full proof transcripts/products and required chainwork; it does not
itself execute native database admission or authenticate the execution host.

Bailey--Sattath's [v2 paper](https://arxiv.org/html/2403.08023v2) uses an idealized
search model and provides a variant respecting bounded difficulty adjustment.
A four-fold clamp alone is therefore not a quantum security argument. Applying
that attack to W1 still requires changed-target challenges and actual marked
sets, paid preprocessing and mining, admissible publication, and real fork
selection under the same elapsed-time and resource budgets. The original
qualification obligations below remain open at that end-to-end level.

The repository's existing [development reference arithmetic](../../formal/pon-nakamoto-v1/reference.py) defines work as \`floor(2^256/(target+1))\`, a 16-block retarget with an approximately 4-fold bounded change, and 11-ancestor median-time / future deferral. This new sensitivity exercise imports those exact reference functions and the current [devnet configuration](../../config/pon/devnet-v1.json); it does not edit consensus.

Run on a full checkout:

\`\`\`sh
python3 -m unittest discover -s scripts/ci -p 'test_pq_quantum_daa_scenarios.py' -v
python3 scripts/ci/pq_quantum_daa_scenarios.py --epochs 4
\`\`\`

The harness compares an assumed header timestamp increment of 1 second with the nominal 10 seconds across four retarget epochs, granting each hypothetical header a matching wall clock. It checks each timestamp through \`timestamp_state\`. These two branches do **not** use the same elapsed wall time, physical mining budget, proof production, network delay or fork-choice competition, so comparing their cumulative chainwork is **not an executable attack**.

The actual reference implementation retargets at heights **16, 32, 48, 64**, using the **previous** 16 ancestor headers; the first such window includes genesis. Thus the boundary block already has the adjusted target. The numbers below represent each epoch's *last (retarget-boundary) block*, not a flat difficulty for the entire epoch.

| Epoch / boundary height | Nominal boundary chainwork | Fast-timestamp boundary chainwork | Fast-timestamp ideal sqrt-search index | Fast-timestamp 16-block epoch chainwork |
| --- | ---: | ---: | ---: | ---: |
| 1 / 16 | 2 | 7 | 3 | 37 |
| 2 / 32 | 2 | 31 | 6 | 136 |
| 3 / 48 | 2 | 123 | 12 | 588 |
| 4 / 64 | 2 | 485 | 23 | 2,330 |

These are integer-reference calculations under the uniform-search *proxy*, not measurements. Total cumulative chainwork is 3,091 vs 128 after 64 hypothetical blocks under **different** assumed elapsed wall times; the ratio is not a demonstrated physical cost advantage or executable fork. The simulator returns exact target hex strings and complete per-epoch and cumulative values. Because integer targets and work truncate, the result is not exactly 4x at each epoch. For a single known target, the model labels \`ceil(2^256/(target+1))\` an expected *classical trials proxy*, and \`ceil(sqrt(proxy))\` an **idealized quantum search index**. It does **not** convert the index to actual Grover iteration counts, reversible gates, logical qubits, fault-correction cycles, or quantum seconds. Existing W1 is a complete mathematical/transcript relation with amortizable setup and structured legal algorithms, not necessarily independent random-oracle trials. Consequently neither proxy bounds the actual cheapest miner.

## Required real qualification (all unclosed)

1. Pin full W1 statement, selectable challenge/material families and cheapest *legal* classical CPU/GPU/ASIC implementations. Charge common task construction, matrix/material load, reusable setup, all misses and complete producer time.
2. Construct a **reversible, complete** W1 success oracle with honest transcript/commitment validation and all public-data access. Charge construction, work registers, uncomputation, repeated queries, final readout and verified release of a complete valid block. Report quantum gate depth, total gates, logical/physical qubits, error correction and wall time for a declared hardware model; a proposed circuit only gives an upper bound on some attack strategy, not a hardness lower bound.
3. Feed equivalent actual work/time budgets into **the real** timestamp validation, DAA, cumulative-work selection, median deferrals, adversarial timestamps, deep reorg, withholding and propagation. Demonstrate which schedules are genuinely executable. A schedule that passes isolated timestamp checks but requires impossible block production cannot be counted as an attack.
4. Freeze the victim and attacker cost models **before** sweeping tasks, batch sizes, challenge reuse, hardware and historical material. Reproduce on separate hosts, with failures and timeouts retained.
5. Obtain independent worst-case adversarial analysis. Unchanged work arithmetic does not imply unbounded quantum immunity, nor does a finite adversarial test establish a security theorem.

These scenarios are explicitly conditional on the quantum miner / difficulty-manipulation observation of Bailey and Sattath (2024). They do not assume that observation automatically transfers to the complete Trillionnium W1 work relation.

No ML-DSA signature, STARK proof, quantum cost model, nor this script alone can authorize PQ-128, claim the chain is quantum-resistant, or set any production flag.
