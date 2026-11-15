# PQL4 executed research evidence — NOT production authority

Parent: Chain #451 @ `06e689c183d69990e61d26dd61aa96af85eeb233`.

The actual local `PYTHONWARNINGS=error python3 -m unittest -v test_pq_pql4_signed_frontier.py` run passed **12/12 tests**, zero failures, in the environment and exact source identities captured in [`local-qualification.json`](local-qualification.json). Raw executed test transcript is [`local-unittest.log`](local-unittest.log). The code performs genuine OpenSSL 3.5+ ML-DSA-65 signing and verification, all 336 signed header-byte mutation rejects, SQLite snapshot/nonce/fork/effect checks, and **a complete old-database restore** with two outcomes: pinned newer external witness rejects; old witness AND old external pin accept. This last failure is intentionally retained.

This is a reference experiment using a local fixture key and separately caller-supplied anchors; it does not establish independently operated monotone storage, real Chain key custody, source authority, history migration, native Rust, PoN quantum-effective work security, WAN, physical power loss or production acceptance. All activation/qualification flags stay false. The new files are additive and do not change installed consensus or transaction bytes. Do not self-approve or automatically merge into main.
