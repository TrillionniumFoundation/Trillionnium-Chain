# Independent hardened verifier for the frozen full W1 experiment

This isolated crate pins `risc0-zkvm =3.0.6` and accepts the same complete
W1 guest statement measured from source commit
`64be7c4ad51d432e7736ad135476262e23e968f5`. It is a research verifier; there
is no Node dependency or consensus admission entry point.

The original prover and its costs remain pinned to the original 3.0.3 backend.
This crate changes the independent verifier, not that guest, its execution
session, the work relation, or the source identity of the ongoing experiment.

## Fixed statement and acceptance

The guest image words are:

```
4203990569 1706128024 889896351 2751765305
3434005897 1411617246 870515685 3215144349
```

The frozen guest bytes have SHA-256
`6b58409420f2bd3f7a733de531ce20144580b259fde8ca9362b43d9728a8772c`.
The [verification code](src/main.rs) requires all of the following:

- At most 16 MiB of fixed-integer bincode with no trailing bytes. The outer
  Succinct tag is checked before deserialization, excluding recursive
  Composite wire objects, Fake receipts and Groth16 receipts.
- A real recursive STARK accepted by the explicit frozen Poseidon2 profile
  below for the exact image and a successful `Halted(0)` execution, including
  the original complete output commitment and empty assumptions.
- The original 16,818-byte journal with its domain, exact canonical 318-byte
  public header, trace, valid target/ticket, unique `header + trace` work
  identity, and all 4,096 canonical product field elements.
- No development-mode or environment-selected proof path. Cargo enables
  `std` and `disable-dev-mode`, with default SDK features disabled. It enables
  neither a prover nor the client feature.

The full W1 computation is checked inside the fixed guest, whose source
calls the original complete native W1 relation. The public journal checker
alone has no authority. Changing proof bytes or proof randomness creates
zero additional work tickets.

## Frozen verifier parameter profile

Both full verification and the recursion-only diagnostic use one explicit
context: `poseidon2`, no development mode, and succinct verifier-parameter
digest `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013`.
The digest is independently present in the
[retained complete-proof readback](../../../evidence/pon-w1-complete-succinct-20261028/measurements/fresh-hardened-full-gate/stdout.log)
and the upstream
[3.0.6 parameter stability test](https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/receipt/succinct.rs).
The SDK still verifies the actual seal, control inclusion, claim and full image;
matching untrusted metadata alone never accepts a proof.

The context retains the existing allowed control root and explicitly removes
other hash suites and unused segment/Groth16 verifier entries. It checks the
trusted parameter digest before each verification, so an SDK upgrade cannot
silently select another profile. A changed profile needs a separate declared
candidate and real receipt validation. There is no retry under another suite.

The original execution segment limit was 18; the pinned SDK control root's
allowed maximum is 22. This change preserves that existing root and its receipt
compatibility. It does not reinterpret a prover setting as a verifier bound,
shrink the allowed control set, alter the frozen guest or generate a new proof.

This is a reproducibility and acceptance-boundary improvement. It does not
establish post-quantum Fiat–Shamir soundness, a 128-bit security argument,
production admission, or practical benefit over native W1. Historic
measurements continue to identify their historic verifier source; they are not
new-source validation.

## Commands

From the repository root, after installing the locked public Rust packages:

```sh
cargo build --locked --release --manifest-path formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml
cargo test --locked --release --manifest-path formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml
cargo clippy --locked --release --all-targets --manifest-path formal/pon-nakamoto-v1/w1_hardened_verifier/Cargo.toml -- -D warnings
```

The resulting `trnm-w1-hardened-verifier` binary has explicit commands:

```sh
trnm-w1-hardened-verifier verify HEADER.bin FULL_RECEIPT.bin
trnm-w1-hardened-verifier benchmark HEADER.bin FULL_RECEIPT.bin
trnm-w1-hardened-verifier controls HEADER.bin FULL_RECEIPT.bin NEW_CONTROL_DIRECTORY
trnm-w1-hardened-verifier verify-recursion LIFT_OR_JOIN.bin
```

`verify-recursion` is solely an integrity diagnostic for internal receipts.
It prints `complete_w1_claim: false`; a successful prefix check cannot satisfy
the full `verify` command. The `controls` command first verifies an actual
full receipt, then preserves every altered input and reports `ACCEPT`,
`REJECT` and `PANIC` separately. A panic fails a negative control.

`benchmark` measures 100 repeated verifier calls and 100 decode-plus-verify
calls for one already generated proof. These measurements do not establish
a prover tail or a production population's p99.

## Actual security regression

The [paired evidence](../../../evidence/pon-w1-verifier-hardening-20261028/README.md)
contains a genuine 223,154-byte recursive lift receipt from the full frozen
W1 execution, a one-byte metadata mutation, both versions' actual results,
the source/lock identity, build observations and feature inventory.

The original 3.0.3 verifier accepts the changed external `control_id`.
The pinned 3.0.6 verifier accepts the unmodified receipt and rejects the same
mutation with a control-ID mismatch. This confirms a specific metadata
binding gap and its repair; it does not demonstrate an arbitrary W1 forgery.

Official references:

- [3.0.5 hardening release](https://github.com/risc0/risc0/releases/tag/v3.0.5).
- [Control-ID binding change #3687](https://github.com/risc0/risc0/pull/3687).
- [Pinned 3.0.6 release](https://github.com/risc0/risc0/releases/tag/v3.0.6).
- [Earlier guest `sys_read` advisory](https://github.com/risc0/risc0/security/advisories/GHSA-jqq4-c7wq-36h7).

The frozen guest already uses platform/kernel 2.2.3, above the earlier
`sys_read` advisory's fixed 2.1.0 versions. That separate issue must not be
conflated with the later verifier hardening.

Actual per-stage soundness figures, complete proof costs, full receipt
validation and benefit comparisons belong to the frozen full experiment.
Transparent STARK construction by itself establishes neither QROM soundness
nor whole-chain post-quantum qualification.
