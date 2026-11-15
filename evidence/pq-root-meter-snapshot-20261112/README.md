# PQ Root paid-meter snapshot consistency continuation — HOLD_NO_GO

Date: 2026-11-12 UTC. **Not** a native acceptance, not an external attestation, and not a probability bound. No production permissions were activated.

## Source and byte identities

* Stacked parent: [#925](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/925) exact `5ffab5968ae1a9cf2e11d756535d9b18961872a2`.
* Parent reader Git blob `73b8e61ab87d11063fd6bf68f9c65b2a120a86fd`; parent test Git blob `58cd328dc05ad2995ac1f046b9a4c4eb8272b44b`.
* New reader on authenticated Hepta host `ai395`, SHA-256 `dcee6d784e7af1f18ccbb89cb18a00eeed32983352197979cc111889bb77cbc0`; new tests SHA-256 `024a2eab229bf06cb19e6fbcda479edd03533ea6eb3ab7cdaf4fd17483d6028f`.
* Hepta durable native execution `1a1cd853846-2564-12e2`: `python3 -m unittest -v test_pq_root_campaign_readback`, **34 tests**, all pass, exit 0. New failures are synthetic negative controls, not independently witnessed paid work. No original native campaign was started in this continuation.
* Historical V4 qualification record blob `0ea59b3c80d852e8395db9b845ebe7c4fc872062`, bound to different source `0d99924005b70b1308bf3e62c53e9300fbb4aac4`; cannot qualify this head.

## Raw original hostile-meter observations

Read-only full-manifest/ZIP-SHA verification of exact original #890 [Actions 43104547221](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43104547221), source `53e1b98a7955898b9feff4778f7136c0fd0199c8`, ZIP SHA-256 `9a2c2250205c6a5fe18524451addf56115aafbf951d9a5c2fd3f6056988e437e`; and #914 [Actions 43077271521](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43077271521), source `c51c553d196d7ed3e3e8cac9caf4db1a8c478526`, ZIP SHA-256 `8edd9a303fc7ac3de0e97f6dbfa40b734df5a49489a9bce783769b6240f5f982`. Each ZIP: 1,765 manifest payload entries independently hash/length verified.

* 18 original phases, **7,813** actual-flow samples; 12 hostile phases had **4,732** budget samples; 24 actors ready in all 12 hostile phases; **zero** hostile phases observed depletion.
* Smallest hostile sampled paid stored credit: **1,774,657,378 ns**; original stored bucket maximum **2,000,000,000 ns**, original start reserve **100,000,000 ns**.
* In **67/7,813** samples, the outer stored-credit meter and inner actual-flow credit differ although the inner ledger balance equation holds. These might be differently timed snapshots and are *not* independently proven malicious or incorrect accounting. They do show why a single `balance_identity_verified` flag does not authenticate cross-snapshot equality.
* Original `cpu.max=25000 100000` corresponds to 0.25 core, while the paid bucket refills `250,000,000 CPU-ns/wall-second`, also 0.25 core. **Conditional only:** if all paid debits share this exact CPU-limited domain, no other reservations reduce the stored credit and CPU is accounted precisely, sustained CPU debit alone cannot outrun refill. Verify owner/cgroup accounting scope and timing before treating this as a feasibility theorem. Do **not** change refill, quota or depletion gate to make tests pass.

## Narrow reader change

For *claimed* successful depletion, require the original versioned paid-budget profile and positive integer fields, verify the ledger identity `initial + credited_refill - paid_cpu_debit - booked_reservation == stored_credit`, bind `remaining_paid_credit == stored_credit + booked_reservation`, match the **outer** meter credit to inner ledger credit, and require observed credit below the original 100,000,000 ns start reserve. Reject changed profile, mismatched snapshots, unbalanced debt, noninteger/bool amounts and an insufficiently depleted bucket. These are **necessary consistency checks only**, not source authentication, proof that debits were actually paid, a proof of budget depletion or a sufficient acceptance criterion.

## Original gates remain FAILED / unchanged

Original native campaigns remain **0/3**, original stages **0/9**, window confirmations **3/27** across each source candidate's three resets, receiver/client equality **0/9**, hostile depletion **0/6** per original three-run campaign. Neither run has independently verified unique paid FinalUse. Hold 30 s/phase, 0/24/24 attackers, 21 business blocks, 0.25 CPU, 2 GiB, zero swap, 256 PIDs, fixed root-owned parent. On `ai395`, `/sys/fs/cgroup/trnmponpublic.slice` is absent, so this host is **not** a substitute for the original acceptance environment.

External evidence still missing: independent real operators, devices, key and recoverable backup custody; a freshness source surviving simultaneous owner/anchor rollback; real native M15/FinalUse provider API/payment/resource/reorg accountability; explicit safe versioned cryptographic migration; and an actual eight-domain multi-key, multi-epoch, shared-oracle, lifetime quantum bound covering the full chain. The actual `2^-128` bad-event bound is **not established**. **HOLD_NO_GO / DENY_ALL**.
