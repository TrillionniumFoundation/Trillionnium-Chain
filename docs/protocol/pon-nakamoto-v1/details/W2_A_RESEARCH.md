# W2-A Merkle prefix-sampling negative experiment

Status: **research only; no consensus, mining, network, FinalUse, or production authority**.
Exact first development base: Chain #328 / 630f871293e48588e0a1ceae7ceb64973d3ec31d.
Source: 'formal/pon-nakamoto-v1/w2a_merkle_sampling.py'.
Controls: 'formal/pon-nakamoto-v1/test_w2a_merkle_sampling.py'.

## Defined sidecar and what it checks

The existing W1 oracle emits 512 deterministic intermediate 8x8 tiles in
(bi,bj,bk) order. The experimental sidecar computes 512 domain-separated leaf
hashes over each index and 256 canonical tile bytes, then a 9-level
fixed-size SHA-256 Merkle tree. The root, existing canonical A/B TaskId,
and 32-byte parent-bound challenge deterministically select 1..32 distinct
indices. Openings bind exact index, tile and nine siblings, with left/right
branch direction and level explicitly hashed. 512 divides 2^32, so the
single-u32 modulo step has no index bias; repeated indices are skipped.

The local verifier recomputes W1's challenge-expanded A'/B' from trusted
canonical A/B and checks all committed Merkle openings and exact prefix
tiles for the selected coordinates. Its successful Boolean has **only**
the meaning "these particular opened prefix tiles match their arithmetic".
It DOES NOT establish a valid W1 transcript, final product, ticket,
any chainwork, or a W2 proof-of-computation statement.

## Executed local Python experiment (not an external reviewer)

Five unittest methods actually ran locally with results 5/5 pass:
normal W1 reference trace parity, tampered leaf/sibling/order refusal,
changed task/challenge refusal, local CPU comparison, and a **positive
attack counterexample**: change one of 512 leaves, commit a new root,
choose its deterministically derived sample set, and exhibit an unobserved
corrupt leaf. A complete source-rooted Rust native comparison was not
run in that local Python environment.

A one-run Python process-CPU comparison on the same dense 64x64 A/B,
challenge bytes 00..1f (numbers below in milliseconds, approximate):

| Opened tiles | W1 full reference CPU | Sidecar production CPU | Filter CPU | One-tile falsification missed? |
| ---: | ---: | ---: | ---: | --- |
| 1 | 77.703 | 63.469 | 12.792 | yes |
| 4 | 77.703 | 67.740 | 16.850 | yes |
| 16 | 77.703 | 71.585 | 20.316 | yes |

These costs are **not** parallel runs, full network costs, final prover time,
external validity proofs, or normal hardware benchmarks. The per-cell
arithmetic is recomputed only for sampled prefixes. The sidecar already
demands extra producer work and can exceed the old end-to-end cost if
correct proofs require both the sidecar and full W1 verification.

## Critical adversarial limitations

1. A signed exact W1 final transcript SHA-256 digest is **not authenticated**
   by passing these Merkle samples. A producer can commit fake unsampled
   leaves; the local regression intentionally proves one example.
2. The producer chooses a root prior to sampled-index derivation and can
   potentially grind roots/alter unused leaves to shape the sampled set.
3. The sidecar has no bounded versioned network encoding or independently
   reviewed commitment security, and no current-genesis authority.
4. The current protocol's proof bytes are exactly PNW1. Sidecar bytes
   **must not** be appended or silently introduced into consensus and any
   transport introduction would require a fresh framed profile.
5. Even if sampling catches common fake transcripts earlier, honest nodes
   still owe full W1 verification before admitting blocks. A peer without a
   sidecar cannot be marked as invalid on a legacy W1 network.

**Result:** W2-A can be considered a research prefilter, not a repair of
permissionless proof-cost hardness. W2-B needs a complete, non-grindable
cryptographic proof of the actual transcript and product; W2-C would explicitly
separate consensus-security PoW from neural-work evidence and could not
rebrand its hash work as useful neural computation.

W2-A's local success NEVER closes PN1, P5, P6 or A03.
