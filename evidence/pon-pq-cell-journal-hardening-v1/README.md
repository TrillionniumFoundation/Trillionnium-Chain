# P0 PQ Cell local journal guard — measured code and limits

Base: Chain PR #468 f408fc65f99c2b5445c75e0595e9208c887f7015.
Modified source Git blob: 9edfc22d7831dd84bda3ced8e798fcb5000d5f0a (prior 5dabec97985cebe3de8feff51089267bd8650aea).
New executable adversarial test Git blob: b1f81b556b50adb5c873dad28a26de1992c16496.

Executed on the local copy using Python 3.13.5, SQLite 3.46.1, Linux overlayfs:
- original-source post-open trigger regression: 1 expected FAIL (Reject not raised);
- new scoped journal regressions: 12 PASS, 0 failures, with PYTHONWARNINGS=error;
- compatibility: 27 PASS with real OpenSSL 3.5.5 ML-DSA-65 but an **uncommitted locally recreated TPQ1 helper**. Not exact pinned upstream dependency verification, no native Rust or WAN qualification.

Tests simulate the signed verifier's successful return for isolated journal failure schedules. No fake cryptography is used to claim new signature conformance. Schema/file ownership may still be defeated by a privileged same-UID attacker, entire-volume rollback, or an untrusted parent directory. Local replay accounting grants no Chain, release, custody-reward or Hepta authority.

Keep HOLD_NO_GO, independent_accepted=false, production_activation=false. See docs/security/PQ_CELL_JOURNAL_POSTOPEN_GUARD_V1.md and the retained upstream PR #408/#468 evidence.
