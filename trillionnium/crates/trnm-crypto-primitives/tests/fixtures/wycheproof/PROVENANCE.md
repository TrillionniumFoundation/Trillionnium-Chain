# ML-DSA-65 independent verification corpus

Unmodified C2SP/Wycheproof verification vectors, Apache-2.0, with the original
license in this directory.

- Commit: `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`.
- Source: <https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/mldsa_65_verify_test.json>.
- Original Git blob: `fa871a3c8c76b0cf871879243ad34fa2cbd79000`.
- SHA-256: `1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034`.
- Exactly 210 cases: 79 valid, 131 invalid.

The test first checks the corpus's specified FIPS 204 context, then checks this
application's pure ML-DSA, empty-context-only policy. Nonempty-context signatures
do not gain an alternative acceptance path. The test asserts both the original
corpus hash and counts so replacing vectors cannot silently lower coverage.

Passing vectors is not a third-party implementation audit or production approval.
