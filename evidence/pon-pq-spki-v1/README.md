# PQL8 native SPKI protocol oracle — executed scope

Repository: TrillionniumFoundation/Trillionnium-Chain.
Parent research SHA: b9f465f9d8b6f14b8d68331cc63185c48ea95078 (PR #481).
Exact tested new Python source blob: 5a9848b4f665002c6d55c465a4f6e8a0a8efa349.
Source path: formal/pon-nakamoto-v1/test_pq_native_spki.py.
Local runtime: Python 3.13.5, OpenSSL 3.5.5, POSIX temporary directory, isolated development keys only.

Executed command:
python3 -m unittest -v /mnt/data/trnm_pq_work/test_pq_native_spki.py

Observed result: 3 tests passed (frozen DER/key-ID vector; malformed DER/OID/length/trailing bytes; real OpenSSL ML-DSA-65 DER and Ed25519 downgrade). No failure.

Independent generated ML-DSA-65 public SPKI: 1,974 bytes, prefix 308207b2300b0609608648016503040312038207a100. Key material is ephemeral, not committed. The frozen non-cryptographic 0x42 public-byte fixture has key ID afc295d8a2307875be792894d57b195f2f9513ede37ac98162232d2a09ca0989.

UNEXECUTED: Rust/Cargo tests at the newly authored Rust blob; exact-tree PQL7 integration tests; public network, GPU work security, physical power loss and independent review. This package proves no PQ production activation or cryptographic signature validity of the Rust preflight.
