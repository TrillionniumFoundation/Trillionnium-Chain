# Actual 3.0.3 / 3.0.6 control-ID binding regression

This evidence concerns one genuine recursive lift from the frozen complete
W1 execution. It is an internal prefix proof, not a completed W1 proof.
No fake receipt, development mode, remote proving backend, or replacement
toy guest was used.

| Input | Original 3.0.3 runner | Independent 3.0.6 verifier |
| --- | --- | --- |
| Original 223,154-byte lift receipt | Previously saved and cryptographically verified | ACCEPT |
| Same receipt, first external `control_id` byte XOR 1 | ACCEPT | REJECT: `control_id mismatch` |

The altered byte lies at offset 222,676 after the 55,667-word seal.
The seal, claim and inclusion proof remain byte-identical. See
[mutation.json](mutation.json) and the actual
[paired result](paired-result.json).

- [Original real lift](real-lift-0000.bin), SHA-256
  `d2b06a1feca2d15e8dc5741b43f481a82c32d7d3dab01e413d357012467093d3`.
- [One-byte mutant](controlid-mutant-lift-0000.bin), SHA-256
  `7018d8968b3ce0155d24d4d2876487d9f42e5d29ee9f6a7c552d33cedceae0c2`.
- [Legacy raw output](legacy-mutant/stdout.log) and
  [measurement](legacy-mutant/result.json).
- [Hardened valid output](hardened-valid/stdout.log) and
  [hardened mutant output](hardened-mutant/stdout.log).
- [Exact source freeze](source-freeze.json),
  [binary/source identity](build-identity.json), and
  [actual features](features.txt).
- [Build measurements](build/result.json),
  [raw unit-test output](tests/stdout.log), and
  [strict Clippy result](clippy/result.json).
- [Verifier source and usage](../../formal/pon-nakamoto-v1/w1_hardened_verifier/README.md).

The genuine prefix took 24.609 ms to decode and verify with the hardened
binary in this observation; the metadata mutant was rejected in 1.130 ms.
These are single functional-control observations on a shared machine,
not independent throughput or p99 claims. The complete W1 prover was
running concurrently and its original cost ledger remains separate.

The old verifier still checked the actual control ID encoded in the seal
against the permitted control-root inclusion proof. Thus this experiment
establishes a missing binding of external metadata, not an arbitrary
computation forgery. The later verifier explicitly binds both IDs.

All measurements retain actual nonzero exit status for the expected
negative control. No arithmetic model substitutes for the real proof.
