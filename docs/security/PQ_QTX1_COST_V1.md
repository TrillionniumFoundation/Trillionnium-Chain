# PQN1 native QTX1 process-inclusive validation and wire budget (one-host research)

This is a **single-host, sequential, process-inclusive CLI latency experiment** with genuine ML-DSA-65 keys and signatures. It is not a resident native Rust transaction service, full-node TPS, WAN validation, effective PoN work security or an independently reviewed benchmark. The source is additive to the #424 research PR and has no authority or activation effect.

Reproduction from the repository root:

```sh
cd formal/pon-nakamoto-v1
python3 pq_qtx1_cost.py /new/empty/path/cost-report.json
```

The program constructs valid and invalid QTX1 frames using inherited `pq_envelope.py` and `test_pq_native_qtx1.py`, compiles the exact C verifier with C11/OpenSSL, uses a fresh disposable real ML-DSA-65 key, executes **64 trials each for five scenarios** in fixed-seed randomized order, asserts the exact accept/reject outcome and records actual wall and child-process CPU deltas. Each invocation opens the public key and launches its own process; no batch, resident cache, I/O transport, ledger state, confirmation, or consensus proof is included.

Scenarios: valid full-signature QTX1; genuine frame with one bad signature byte; otherwise-valid frame with caller balance exhausted; wrong-magic cheap failure; and valid maximum-512-byte memo. Report fields include p50/p95/p99 wall and CPU readings in nanoseconds and exact signed byte lengths. These distributions are **not** performance guarantees on other hardware.

The observed smallest normal signed QTX1 is 3,631 bytes (the fixed fixture with 18-byte memo is 3,649 bytes); maximum memo is 4,143 bytes. At 256 maximum-memo transactions, even payload bytes alone total 1,060,608, exceeding the installed 1,048,576-byte block ceiling by 12,032 bytes, before any header or work certificate. The installed 2,048-byte transaction limit rejects all these research frames. No runtime/consensus parameter is changed by this experiment.

**Mandatory production blockers:** transaction signature cost should be measured inside an audited long-lived Rust M01/M06 verifier including native state, fee accounting, conflict scheduling, proof verification, full roots and actual P2P propagation. Optimize the worst-case invalid-signature fanout and cross-node adversarial cost; do not infer chain TPS from this process benchmark. PQ account migration, native consensus, HSM, independent WAN/power-loss, and PoN quantum effective-work security remain HOLD_NO_GO.
