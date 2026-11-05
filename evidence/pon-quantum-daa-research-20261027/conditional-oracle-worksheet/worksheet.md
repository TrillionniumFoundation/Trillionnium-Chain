# Conditional resource worksheet: W1 quantum trace hashing

**Research worksheet only. No full W1 quantum oracle was built, compiled, simulated or run. This supplies neither an attacker cost lower bound nor a hardware share, attack rate, production timing or post-quantum security qualification.**

Frozen relation: `65c97a95cab4702a368855397c65413e2a754b97`, `trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs`, SHA256 `3ed29941eb0b9959bdeb0cd4e59d2565bbd4b82b70c9cc94d0cd46065c16b874`. No Rust/build or main-repository edit was performed. Arithmetic below was evaluated by a small Python worksheet; this is not quantum-circuit execution.

## 1. Exact classical transcript size

The frozen stream appends the 16-byte `TRNM-PON-TRACE1\0` domain, 32-byte challenge and 32,768 LE32 prefix accumulators (`pon_work.rs:297–322`). This is **131,120 bytes**, including the NUL. Under the standard SHA-256 padding rule, it becomes 131,136 bytes, or **2,049 compression blocks**. It is one streaming hash, not 32,768 independent hashes. The count describes this execution of the frozen function, not a proven minimum number of operations for every adversarial algorithm. [S2]

## 2. What the published SHA-256 number actually covers

Amy et al. explicitly assume one 512-bit block and an initial state of constants (§5). Table1 gives optimized round **3,020 T**, stretch step **744 T**, core **228,992 T**, T-depth **70,400**, and **2,402 logical qubits**. The core number is exactly `64*3020+48*744`. Their specific Grover oracle computes and reverses the core, adds an equality marker, then separately accounts for diffusion (§7.1). These are not the costs of a general clean, arbitrary-chaining-state compression interface. [S1]

Do **not** multiply their full-search cost, published oracle cost, or 2,402-qubit width by the transcript count. In particular, a later block has a quantum previous-chain value. Feedforward, preserved input, garbage cleanup and storage between blocks must be explicit.

## 3. One defensible conditional component ledger

The following is a candidate construction to export and verify, not an already-measured circuit. Assume the published generic round/stretch circuits remain correct for arbitrary chained inputs, with their temporary ancillas clean, and no hidden fixed-IV or phase specialization. Preserve the old chain state; copy it into a zero work-state register; expand the schedule; run64 rounds; add the old state to the eight output words; reverse the schedule so its extra words are clean. The original block and old chain state remain available.

For the added feedforward use a simple Cuccaro modulo-2^32 adder: `2n-3=61` Toffoli gates at n=32 [S3], conservatively decomposed at7 T each [S4]. This deliberately forgoes newer relative-phase, temporary-AND and cross-block optimization.

| Conditional ledger item | T count |
|---|---:|
| 64 round components | 193,280 |
| 48 schedule steps, compute and reverse | 71,424 |
| 8 feedforward additions,61 Toffoli each,7 T each | 3,416 |
| Candidate clean compression | **268,120** |
| 2,049 forward clean compressions | **549,377,880** |
| Forward trace and its literal inverse | **1,098,755,760** |

This is not the blind `2049*published_hash_count` calculation: it explicitly adds schedule cleanup and feedforward and states the proposed interface. Nevertheless, **the generic interface, gate export, ancilla cleanup and compositional correctness have not been independently synthesized or validated**. The number is a conditional design subtotal, not a verified upper bound for a working complete W1 attack, not a security lower bound, and not a recommended best attack. If those component assumptions fail, retain only the symbolic ledger and rebuild the circuit.

Literal inversion is one sufficient design strategy. Measurement-based cleanup and phase-aware optimizations can lower T cost when their conditions hold [S4]; they cannot simply be asserted for arbitrary intermediate state. Thus `2*T_forward` is not a universal minimal uncomputation cost.

## 4. Space and checkpointing are not free

A simple retained-history design keeps all 2,049 outputs until the phase decision and reverse pass: that chosen design allocates **524,544 logical bits for chain-state registers alone**. Materializing the entire unpadded message takes another **1,048,960 bits**, although fixed-domain bits may be hardwired and message words could instead be generated and regenerated. Neither is an unavoidable minimum. Neither includes field/noise workspace, routing, factories or error-correction qubits.

Releasing those registers requires a justified reversal or checkpoint schedule. Bennett's reversible pebbling supplies time-space tradeoffs, not a W1-specific free reset [S5]. A smaller-memory circuit must charge each SHA recomputation and each regenerated transcript segment. Its checkpoints may also need the field accumulators, PRG/sampler counters and rejection/compaction state, rather than merely a256-bit digest. No exact complete width/depth is claimed here; **2,402 qubits is not a W1 width estimate**.

## 5. Missing work in a complete oracle

For one fixed, valid task A/B, public preprocessing is allowed: task commitment and AB may be cached; structured/zero/matrix-algebra improvements may be amortized. No classical verifier timing, replay multiplication count or proof-generation time establishes what the miner must pay for each quantum candidate.

A complete coherent candidate function still needs the actual header challenge; bounded noise expansion; exact arithmetic and prefix order; ticket hash; valid-input handling; and target marking. The field is **q=4,294,967,291**, not modulo2^32. The Cuccaro feedforward budget above applies to SHA arithmetic only. Noise sampling admits canonical words, compacts accepted outputs and fails at128 hash invocations per label (`pon_work.rs:194–220`). A classical average loop count is not automatically the width/depth of a coherent implementation with those branches.

There are four512-word noise arrays. The no-rejection classical path invokes64 hashes per label. Each domain-separated noise-hash message is66 bytes and occupies two SHA compression blocks, so even this path has512 additional compression calls before accounting for the transcript; an always-unrolled128-per-label schedule would have1,024. These are classical path facts, **not** a synthesized quantum sampler budget. A coherent sampler must preserve its failure semantics, branch history and accepted-order compaction.

Preprocessing also matters to the header: in a fixed-header search changing only its final nonce, constant earlier SHA blocks can have their midstates prepared classically. Do not force an adversary to rehash those constant blocks merely because the native verifier does. The final ticket is a threshold predicate; the paper's exact equality marker and256-bit-input diffusion are not automatically its circuit. A nonce-only search has a finite64-bit register; other legal header freedoms require explicit binding and accounting.

Write the full per-iteration ledger as

`T_iter = T_F + T_F_inverse + T_threshold + T_reflection(k)`.

Only for a chosen symmetric unitary implementation may one substitute `T_F_inverse=T_F`. A Grover iteration count depends on the actual marked fraction among valid inputs, the coherent search family and stopping/restart policy. Noise failures, block races, partitions and changing targets are not removed by a hash gate count. Equivalent proof representations remain the same ticket; proof salt adds no free search choices.

## 6. Physical budgets remain unfilled

After a complete logical circuit and schedule exist, fix an explicit total failure budget, physical gate/measurement times and error model, connectivity/routing, code distances, decoder/control latency, and magic-state factory configuration. Resource conversion depends on these choices; Beverland et al. separate logical program resources, code/factory selection, and physical estimates, and name remaining architecture assumptions. [S6]

For a chosen schedule, factory supply must cover its T demand and logical layers must fit its runtime. These constrain that implementation, not all attackers. No seconds, physical qubit total, effective network share or quantum DAA safety claim is defensible from this worksheet. The useful next gate is an exported **clean arbitrary-IV compression** tested against FIPS vectors and random chained blocks, then a two-block compute/phase/uncompute circuit, before attempting the exact W1 sampler/field relation and optimizing its actual memory schedule.

## Primary sources verified

- **S1:** Amy et al., SAC2016, revised2016-11-30, §5/Table1 and §7.1. https://jmschanck.info/papers/20161130-preimage.pdf ; archive https://eprint.iacr.org/2016/992 . Retrieval refs: `turn97view1`, `turn98view1`, `turn98view5`, `turn100view0`, `turn100view1`.
- **S2:** NIST FIPS180-4, §§5.1.1,5.2.1,6.2. https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf . Refs: `turn98view0`, `turn101view2`.
- **S3:** Cuccaro et al., *A new quantum ripple-carry addition circuit*, §4.1/Table1. https://arxiv.org/pdf/quant-ph/0410184 . Refs: `turn100view2`, `turn101view3`, `turn101view4`.
- **S4:** Gidney, *Halving the cost of quantum addition*, Quantum2,74(2018), page2. https://quantum-journal.org/papers/q-2018-06-18-74/ ; https://arxiv.org/pdf/1709.06648 . Refs: `turn102view0`, `turn102view1`.
- **S5:** Bennett, *Time/space trade-offs for reversible computation*, SIAM J Comput18(4)(1989), author institutional abstract. https://research.ibm.com/publications/timespace-trade-offs-for-reversible-computation ; DOI https://doi.org/10.1137/0218053 . Ref: `turn100view3`.
- **S6:** Beverland et al., *Assessing requirements to scale to practical quantum advantage*, §§III.3–III.4, AppendicesF/G. https://arxiv.org/html/2211.07629v1 . Refs: `turn100view4`, `turn101view5`, `turn101view6`, `turn102view2`.

The source references are supplied for root to reopen and verify before final citations. No secondary news or unsupported repository count was used.
