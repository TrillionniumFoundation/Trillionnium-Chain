# Neural work: concrete experimental relation and security boundary

Owners M01/M02/M03; model input owners M10/M11 and Hepta. The selected architecture
remains Nakamoto-style useful neural work. Production work qualification is false.

## Defined and implemented profile

[W1 — WORK_PROFILE](details/WORK_PROFILE.md) specifies n=64, rank8, q=4294967291,
canonical u32 arithmetic, all transcript steps, exact49188-byte certificate, challenge,
ticket and decoded useful result. Rust and separately coded Python implementations
produce identical vectors. The profile configuration is part of the genesis parameter
hash; there is no floating-point tolerance, proof-randomness nonce or output/template cycle.

A complete work certificate contains historical verification inputs. The signed integer
bridge is demonstrated on a real trained model's partial inference contraction, not a
made-up score or a claim that old fine-tuning itself secures a new parent block.
Model quality and local authority are separate proofs. New learned output enters later
transactions, never the current header's post-state calculation.

## What remains unqualified

The candidate uses full recomputation and is not succinct. Measured cheap forged
transcripts can pass its preliminary ticket predicate while rejection costs a full
verification. Worst-case adversarial computation, cross-attempt precomputation, low-rank
shortcuts, hardware advantage, uniform independent lottery assumptions and public-network
DoS remain security work, not an activated profile. Native and Python parity is not an
independent external review. The configuration distinguishes executable candidate from
production-eligible work rather than saying every implementation must forever be absent.

[Performance and acceptance](details/PERFORMANCE_ACCEPTANCE.md) binds raw cost samples,
negative observations and external obligations. The peer-facing production verifier
must not accept a JSON boolean, TEE quote or evaluator vote as work. No old BFT or
hash-only fallback is provided. The real experiments use the defined transcript check;
they do not replace it with a successful stub.
