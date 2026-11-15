# PQG1 real local two-key genesis handoff evidence

Base: `2a29fc75546c97187069c3a9ffe176343ac41650`. Additive research files only; no existing bytes, consensus, main or activation touched. Tests run on one container with real OpenSSL ML-DSA-65 and `cryptography` Ed25519.

- 23 tests PASS, 0 FAIL. Logs: `local-unittest.log`; machine/source hashes: `local-qualification.json`.
- 177 canonical header-byte changes rejected against original independently supplied hash in the test. Also exercised missing escrow, altered source, old-key/PQ-signature substitution, duplicate PQ keys, revoked owners, cross-network/profile replays, expiry, old next_nonce/generation and quarantine.
- The `strict_signature.py` used for local execution is exact Git blob `b0cedca3a0423f2563359a8645ba322f966804dc` from stacked upstream; the existing repo implementation is unchanged.
- Required independent source-head/withdrawal/supply information is **test-provided**, not a real product authority; even a perfectly self-consistent old snapshot cannot prove its own authenticity/completeness.
- No Rust compiler/toolchain in this isolated container; no Rust or full Chain build, physical power failure, WAN, HSM, actual import, quantum work hardness or independent cryptographic audit.
- `HOLD_NO_GO`: no production flag, user secret, deployed service or repo mainline changed.
