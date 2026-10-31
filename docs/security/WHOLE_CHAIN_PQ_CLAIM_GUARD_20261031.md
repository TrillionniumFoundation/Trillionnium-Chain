# Whole-chain post-quantum security — strict HOLD gate (2026-10-31)

This is a **research-only security-claim guard**, not a PQ-128 attestation, production consensus gate, cryptographic proof, or authorization mechanism. The native development candidate retains its explicit NO ACTIVATION boundary.

Run from the repository root:

    python3 scripts/ci/test_pq_chain_claim_guard.py -v
    python3 scripts/ci/pq_chain_claim_guard.py

The guard checks actual negative authority and activation assertions in the source-controlled project boundary, mainline and devnet configuration, and the existing PQ source corpus; it checks the canonical ML-DSA research frame size and unqualified legacy transaction ceiling. It returns a deterministic **HOLD / UNQUALIFIED** report with process status 0 only when the current protected negatives are intact. Unsupported promotion, silent classical fallback, missing source, invalid or duplicate JSON fields, symlink substitution and an introduced PQ-128 W1 guest claim are refused with process status 2. A green test of this guard never means the network is PQ-safe.

## Six separate acceptance gates

| Gate | Current boundary | Evidence needed to close |
| --- | --- | --- |
| Authorization | NPQ6 account/task and PNQ2 transport are separate; Hepta V1 is Ed25519 and the new [ML-DSA V2 research verifier](HEPTA_PQ_HANDOFF_V2_20261031.md) is not wired to all Hepta owners or FinalUse; Cell provider discovery V2 is ML-DSA. | Trace every authority-producing entry, including governance, release and recovery, to a current externally pinned PQ trust root; reject cross-profile downgrade and revoked generations on real effect paths. |
| Proof PQ-128 | No production-qualified W1 security parameter proof in the active candidate. | Freeze exact relation, verifier, guest/compiler hashes, commitment/FRI/Fiat–Shamir settings, recursion and security model; obtain independent quantum-soundness argument and worst-invalid-input cost. Groth16/fake receipts cannot satisfy PQ-128. |
| Quantum mining and fork choice | Current cumulative-work/DAA incentives have no full adversarial quantum lower bound. | Test cheapest valid complete W1, data loads, reversible oracle/uncompute, challenge amortization, Grover advantage, retarget/timestamp manipulation, reorganization and propagation on equal attack budgets. |
| Migration and rollback | Classical ownership transition and local durable ledgers do not automatically resist total database rollback. | Bind early PQ ownership, historic liabilities, old nonce floors, cross-reorg recovery, external monotonic anchor and independent cold-restart adversarial tests. |
| Capacity and invalid input | Research TPQ1 signature frame is 3487 bytes; original devnet maximum transaction remains 2048 bytes. | Full native NPQ6 block and mempool capacity, invalid-signature CPU cost, wire/relay amplification, p95/p99, RSS and recovery under fixed hardware/traffic constraints. |
| Independent end-to-end | Existing exact negative assertions exclude production, WAN, entire PQ node, quantum hardness, rollback and Hepta FinalUse claims. | At-head source/lockfile evidence, independent crypto review, reproducible deployment, WAN/fault benchmarks, economic attacks and authorized activation process. |

This guard does not create permission, switch profiles, sign an artifact, accept a proof, change chainwork or modify the consensus rules. All six gates remain UNQUALIFIED. This research-only v1 guard must not be weakened to force a green release; any later upgrade requires a reviewed new security schema and independently verifiable evidence.

References: NIST FIPS 204 (ML-DSA); RISC Zero 3.0 cryptographic security model (RISC-V 96-bit, recursion 99-bit, Groth16 not quantum-safe); Bailey & Sattath (2024) quantum miner / difficulty adjustment research. None is a proof of full Trillionnium-Chain security.
