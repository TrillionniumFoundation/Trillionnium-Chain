# Frozen W1 lifetime source-observation fixture

ledger.py is the exact 37,507-byte historical accounting and source-observation
reader from commit 1a14f7d4826363daefac9ec10131c66d7e70ece7, at its original path
scripts/w1_lifetime_ledger.py.

- Git blob: 5e7c8681813baedc88890adacc2fd275b486093a.
- SHA-256: 7e494ba406c63442dfbd17147d006b967cb07d7f6c886ce5779a0f2f05fceef6.
- The reader's selected source baseline is
  7150d96a2112875b4afcf3023361a5cef4a0e4b1. That earlier source commit does not
  contain this reader; it is not the reader's containing commit.

The current scripts/w1_lifetime_ledger.py is a distinct successor and is
unchanged by this fixture. This copy supplies the original pure Python finite
accounting and exact source-pin refusal required by the current source
observation contract. It is neither a restored consensus implementation nor a
protocol entry point or fallback.

The original bytes, pins, arithmetic and default-path calculation are preserved.
Any direct CLI invocation must explicitly pass the repository root:

    python3 tests/fixtures/w1-lifetime-historical-7150/ledger.py --root .

On the current source this command must refuse with exit 2 and a source identity
mismatch. The current observation reader reuses the unchanged function in a
private context with separately reviewed current source identities; it does not
establish historical positive replay, native execution, a complete dependency
closure, an actual lifetime bound, or post-quantum qualification.
