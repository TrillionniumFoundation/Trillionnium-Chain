# External monotonic rollback witness — bounded research reference (2026-10-31)

**HOLD / NOT CONNECTED TO A NODE / NOT A PQ-128 OR RECOVERY QUALIFICATION.**

This reference specifically models **total rollback of an internally self-consistent database**. An application cannot detect that attack using a nonce, hash chain or latest head stored only inside that same restored database. A fresh response from a surviving independent monotonic witness supplies the comparison point.

## Reference contract

- Each authenticated observation binds a 32-byte network context, **external observation sequence** (not chain height), state root and operation-journal root. Reorganizations may move the chain tip backwards, but the externally witnessed observation sequence only increases.
- The witness refuses alternate state at a previously observed sequence, skipped sequence, sequence rollover, bad context, and missing genesis. An exact retry is idempotent.
- Before accepting a restored node as current, an *independent verifier* must supply a freshly generated unpredictable 32-byte challenge, obtain the **current** external witness reply, authenticate it with a pinned out-of-database trust root, and require exact equality of the state and journal digests and external sequence.
- Missing witness, a local DB ahead of witness, replayed old reply, malformed frame, bad authentication, inconsistent roots or stale complete DB all cause **REFUSE**. A successful match is not a final-use, spend or consensus authorization.
- Reference frame: fixed 204 bytes, a PQR1 version, SHA-512-HMAC tag over domain-separated fixed width bytes; the **64-byte demo HMAC key and witness state must exist exclusively outside the compromised database/trust boundary**. The visible fixture key is only for tests. HMAC is used to demonstrate integrity in a contained test; it is NOT a replacement for ML-DSA production identity, a remote witness, HSM/TPM, or an independent quantum security proof.

Run locally:

    python3 -m unittest discover -s scripts/ci -p 'test_pq_external_rollback_oracle.py' -v

## Unclosed conditions

Production still requires: a truly independent durable monotonic root with fault-resistant persistence and authenticated (PQ-appropriate) challenge-response; authenticated current witness identity/rotation/revocation; exactly-once external publication/ack before effects, crash cutover and atomicity policy, reorg/side-effect compensation, node bootstrap and historical migrations, cross-process tests that restore the **entire** DB and replay external receipts, independent adversarial review and out-of-band recovery governance.

Witness outage must halt protected operations. This reference has **no native runtime integration** and does not make any deployment rollback resistant. The original six-domain whole-chain guard remains HOLD.
