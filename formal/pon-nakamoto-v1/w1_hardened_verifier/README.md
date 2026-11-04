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
  Composite wire objects, Fake receipts and Groth16 receipts. The declared seal
  length must fit the actual bounded input before serde can reserve a vector.
- The explicit `trnm-w1-risc0-3.0.6-poseidon2-join-v1` profile from
  [profile.rs](src/profile.rs). Only the measured Poseidon2/final-join construction
  is installed in an initially empty verifier context. Its fixed parameter
  digest must also match the compiled SDK; SDK defaults cannot silently widen
  the profile, and other SDK-supported hash suites fail before seal replay.
- The fixed depth-eight control inclusion path, an index below 256, and
  canonical Poseidon2 digest words in its leaf and every sibling. These are
  checked before hashing, including in the integrity-only diagnostic.
- A real recursive STARK accepted by those explicitly pinned parameters
  for the exact image and a successful `Halted(0)` execution, including the
  original complete output commitment and empty assumptions.
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

Public-journal decoding is now an early rejection filter. It checks the exact
expected header, canonical product words, trace, ticket and work identity before
expensive seal verification. The tentative identity remains private until the
complete cryptographic check succeeds. A syntactically valid journal, valid
prefix, failed seal or wrong profile never returns verified work.

### What this proof does and does not replace

The frozen guest source is still `64be7c4ad51d432e7736ad135476262e23e968f5`.
Recompiling today's native dependency tree does not reproduce or qualify that
old image: the current optimized W1 kernel has changed. A fresh saved-proof
comparison therefore identifies the frozen guest and current native source
separately. Finite native/reference equivalence tests are not a compiler proof.

Node admission additionally checks the branch-required target, parent state,
task window, authorization and state transition. In particular, its signed-task
path checks `hash("artifact", A)` and `hash("qualified-task-input-v1", B)` against
the eligible manifest. The old journal does not expose these two commitments.
Binding the complete header and `task_id(A,B)` is not an implementation of those
Node checks. Removing A/B from Node's input requires a new statement/image and
explicit equivalent commitments; this profile introduces no proof-only Node
entrypoint. Native full W1 remains the comparison and ordinary admission path.

### Frozen construction and security analysis

| Component | Explicit selection or remaining obligation |
| --- | --- |
| Final receipt | Succinct recursive STARK; final control is the measured `join.zkr` |
| Final control ID | `7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e` |
| Verifier parameter digest | `ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013` |
| Proof hash suite | Poseidon2 from the exact locked `risc0-zkp 3.0.5`; W1's SHA-256 domains are unchanged |
| Native W1 field | `4294967291 = 2^32 - 5`; full integer execution preserves this modulus |
| Proof-system field | BabyBear `2013265921`, extension degree 4; it is not a replacement W1 modulus |
| FRI component | Locked zkp source selects 50 queries, inverse rate 4, fold 16 and minimum degree 256 |
| Upstream estimate | Upstream comments describe 97 conjectured component bits; this is neither the full recursive proof's proven bound nor quantum bits |
| Accepted recursive parameter root | The original SDK default root/digest is retained; observed segment limit 18 does not authorize changing the root to a max-18 set |
| Quantum security level | Unknown; the executable reports `quantum_security_bits: null` and no qualification |
| Production admission | Absent; no consensus dependency, fallback, activation or release qualification |

The `profile` command emits the compiled outer/effective-inner control roots,
protocol and circuit info bytes, exact image, selected hash and parameter digest.
These values identify the evaluated construction; they are not a soundness proof.
Changing any accepted program, hash, root, image or receipt kind requires a new
profile and new evidence. The existing internal `verify-recursion` diagnostic
uses its separately labelled integrity-only contract and cannot satisfy this
full profile.

Both full verification and the integrity-only diagnostic obtain the same
Poseidon2 parameter digest from `profile::context`. The digest is independently
present in the
[retained complete-proof readback](../../../evidence/pon-w1-complete-succinct-20261028/measurements/fresh-hardened-full-gate/stdout.log)
and the upstream
[3.0.6 parameter stability test](https://github.com/risc0/risc0/blob/v3.0.6/risc0/zkvm/src/receipt/succinct.rs).
The context starts empty and installs only the pinned succinct construction;
matching untrusted metadata never replaces actual seal, control, claim and
image verification. There is no retry under another hash suite.

The original execution segment limit was 18; the retained SDK control root's
allowed maximum is 22. Preserving that root does not reinterpret the prover's
execution limit as a verifier bound or shrink the recursive program set. The
full profile additionally pins the final join while keeping the existing
frozen guest and receipt; it does not generate a new proof.

Historical measurements retain their historical verifier source identity.
They do not qualify newly composed source or establish post-quantum
Fiat-Shamir soundness, a 128-bit security argument, production admission or
practical benefit over native W1.

The [QROM reduction framework](https://eprint.iacr.org/2025/2166) is conditional
on the actual interactive oracle reduction and commitment/extraction properties.
Mapping this AIR, every recursive layer, Merkle encoding, Fiat-Shamir transcript,
oracle-query budget and concrete security loss to its premises remains open.
In particular, the actual Poseidon2 and unpadded internal hash call shapes must
be reviewed at their use sites; a hash-family name alone is insufficient.

The [Reed-Solomon proximity counterexamples](https://eprint.iacr.org/2025/2046)
invalidate specific near-capacity conjectures, not every proven FRI regime.
Any candidate parameter analysis must identify which proven or conjectured
bound it uses. [WHIR's implementation](https://github.com/worldfnd/whir) calls
itself an academic prototype and defaults to a conjectured-list setting;
neither that default nor a `security=128` argument qualifies a W1 backend.
No pairing/Groth16 wrapper is accepted by this profile.

The [offline source map](../../../evidence/pon-w1-transparent-profile-20261104/security-map.json)
checks seven locked package archives and 37 selected files, extracts the concrete
parameters and independently recomputes the verifier-parameter digest. Its saved
receipt inspection uses partial wire parsing and a hash-bound historical verifier
log. This is not a full dependency audit, fresh cryptographic verification or a
quantum security proof. The application-level canonicality checks are evidenced
separately by the exact wrapper source, executable and real rejection controls.
The map's SDK default hash-suite list is not this profile's allowlist. Pinning the
final join also leaves all 27 programs under the original recursive root in scope.

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
trnm-w1-hardened-verifier profile
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

The [independent native package](../w1_native_cost/Cargo.toml) builds the existing
`w1-native-cost` source without the methods package, guest compiler or prover.
Run the [saved-proof comparison](../../../scripts/w1_transparent_compare.py) with
the two actual binaries and retained full input/receipt to reproduce the native
versus candidate boundary. Its results keep proving, propagation, confirmation
and stale-block costs unobserved unless separately measured. Receipt/witness byte
ratios alone do not describe a complete Node wire package, especially while Node
still needs the original A/B input.

The earlier [complete-proof experiment](../../../evidence/pon-w1-complete-succinct-20261028/README.md)
retains its failed benefit gate: one 256,886-byte receipt versus a 49,188-byte
native witness, and 30.0526 times the native decode/full-replay median on that
historical fixed sample. Its interrupted proving costs and one-proof scope are
not overwritten by a fresh verification-only comparison.

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

The current profile also closes a reproduced malformed-input crash in the
locked SDK's control inclusion path. Replacing the first sibling digest word
with `0xffffffff` made ordinary verification exit with a Poseidon2 assertion
panic (101). The profile now rejects that input before hashing. Regression
tests cover both invalid field boundaries in every sibling word, the diagnostic
leaf, path lengths and unused index bits. This is a controlled-rejection repair,
not evidence of an arbitrary proof forgery or a complete fuzzing campaign.

Actual per-stage soundness figures, complete proof costs, full receipt
validation and benefit comparisons belong to the frozen full experiment.
Transparent STARK construction by itself establishes neither QROM soundness
nor whole-chain post-quantum qualification.
