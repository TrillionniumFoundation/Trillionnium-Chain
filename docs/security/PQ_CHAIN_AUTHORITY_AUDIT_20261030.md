# Chain-level post-quantum assurance: open authority inventory (2026-10-30)

This is a **negative audit gate**, not a certification and not a new consensus profile.

## Observed open authority boundaries

| Boundary | Observed owner | Missing proof |
| --- | --- | --- |
| Hepta admission handoff | `trnm-research-protocol/src/hepta_handoff.rs` uses Ed25519 | Algorithm-agile/PQ signer, exact canonical schema, owner/final-use equivalence and no downgrade |
| Cell discovery advertisement | `trnm-data-availability/src/cell/discovery.rs` uses Ed25519 | PQ provider identity and verified endpoint, replay, rotation and expiry |
| W1 transparent proof | `w1-risc0/backend-manifest.json` declares `pq_128_security_qualified=false` | Independently reviewed FRI/Fiat–Shamir/recursion/hash composition and exact target security |
| Chain PoN | cumulative-work fork choice | Quantum cheapest-miner lower-bound, complete reversible oracle including preparation and uncomputation, retarget/timewarp/fork economics |
| Account / task / governance / recovery | explicit native PQ research profiles coexist with older profiles | Exhaustive active authority graph, migration cutoff, old-key liability, reorg and no-downgrade observations |
| Storage and replay | SQLite owner + local journal | External monotonic/threshold witness under full, internally consistent store rollback |

The claim `chain_post_quantum_qualified=true` is **not authorized** by this
inventory. Source-level marker disappearance is not independent review or
cryptographic certification.

## Non-regression audit

```sh
python3 scripts/security/pq_claim_gate.py --root . --assert-unqualified
python3 -m unittest discover -s scripts/security -p 'test_pq_claim_gate.py' -v
```

The gate deliberately always reports `pq_chain_qualified=false`.
A missing/malformed known source or optimistic production flag makes the
`--assert-unqualified` check nonzero; existing unqualified classical
development profiles are reported but **not** treated as production-breaking.
No active listener, mining, ledger or signature behavior changes.

## Closure requirements (separate work)

1. Inventory every authority-producing entrypoint and its chain of signers to
   an explicitly versioned cryptographic root, including network and Hepta.
2. Introduce new authenticated profiles with a strict migration transition;
   signatures under obsolete roots cannot independently authorize new actions.
3. Verify native ML-DSA vectors, forged/expired/replayed/cross-network data,
   nonce, old-store recovery, reorg and migration with exact wire-size budgets.
4. Separately certify W1 proof parameters and quantum work economics with
   independent assumptions; proof construction success is not a 128-bit claim.
5. Challenge fully consistent rollback using an independent monotonic anchor;
   local journals alone cannot prove freshness after full snapshot rollback.
6. Record independent review, workload and release activation evidence.
