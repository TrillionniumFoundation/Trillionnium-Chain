# G1-R4 Safety, signer, checkpoint and anti-rollback package v1

Status: **`BLOCKED_UPSTREAM`; A05-owned reference coordinator is `MODULE_CLOSED_CANDIDATE`; no Gate promotion**

Package ID: `G1_R4_SAFETY_CHECKPOINT_V1`
Agent: `A05`
Candidate base:
`feature/chain-g1-r4c-full-gap-closure-20260829@6e0189e351015ef3230f217ca7ff86149baedcf0`
(tree `efea864cb2fbc4835a59a089b3dbab8934e71231`).

## 1. Existing foundations retained

This package does not replace the existing stores:

- SafetyStore already owns exact durable SafetyState records and tag-3
  finalization context, but explicitly cannot detect a whole-namespace rollback
  without an independent watermark.
- SignerJournal already persists an exact intent before invoking a producer and
  returns a signature only after its signed event and watermark are durable,
  but explicitly does not perform SafetyRules or bind the complete
  Safety/Application cut.
- the external watermark authority already provides a separate-process
  append-only CAS boundary;
- the external node-checkpoint adapter already provides a separate-process
  whole-node checkpoint CAS;
- whole-node checkpoint types remain inert public data and correctly grant no
  signer, persistence or CAS authority.

The missing A05 slice is the final coordinator that joins those facts before a
signing request can escape.

## 2. Candidate coordinator delivered

The new standalone reference crate is located at:

```text
trillionnium/crates/trnm-whole-node-checkpoint-types/
  reference-r4-coordinator-v1/
```

It implements:

1. exact namespace and store-identity binding;
2. exact Application target/body/JMT/receipts readback checks;
3. exact Safety tag-3 epoch/view/height/body/application/state readback checks;
4. exact durable prepared SignerJournal intent/signing-root checks;
5. monotonic application, Safety, signer, checkpoint and external-watermark
   sequences;
6. Application-store, Safety-store and signer-journal identities retained in
   both the checkpoint and external watermark across restart;
7. an opaque permit that carries the same namespace/store/custody/process
   bindings and exposes read-only accessors only;
8. a mutually bound checkpoint/watermark target;
9. a three-state recovery classification:
   - both predecessor: return data-only CAS plan;
   - both exact target: issue opaque permit;
   - mixed or unknown: permanently fence;
10. exact response-loss replay after restart;
11. same-height conflict, height/round rollback and sequence rollback rejection;
12. an opaque `SignaturePermitV1` with private fields and no `Clone`/`Copy`.

The crate owns no key, signature producer, persistence backend, socket, HSM/KMS
adapter, automatic repair or activation switch.

## 3. Independent model evidence

The separately authored Python model executed:

- 3 positive paths:
  - exact dual-readback permit;
  - response-loss exact replay;
  - monotonic successor;
- 15 negative paths:
  - application-root mismatch;
  - wrong Safety tag;
  - signing-root mismatch;
  - namespace substitution;
  - checkpoint-only commit;
  - permanent fence after mixed commit;
  - watermark-only commit;
  - unknown third state;
  - durable-sequence rollback;
  - same-height target conflict;
  - non-durable application readback;
  - signer custody-policy mismatch;
  - process-generation mismatch;
  - Application/Safety store-identity substitution on reopen;
  - mixed startup.

All independent Python cases passed.

## 4. Rust evidence state

The source-shape gate verified:

- balanced Rust delimiters;
- dependency-free standalone Cargo manifest;
- `forbid(unsafe_code)`;
- thirteen retained Rust unit tests;
- no `Clone`/`Copy` permit;
- private permit fields;
- no signature producer, private-key or automatic mixed-cut repair surface;
- all three typed upstream requests remain explicit `BLOCKED_UPSTREAM`;
- all thirteen listed package artifacts match their committed SHA-256 values;
- production and activation constants remain false.

The current execution environment has neither `cargo` nor `rustc`. Therefore no
Rust compile, test, Clippy or rustfmt result is claimed locally. The exact gate
fails with `RESUME_REQUIRED` unless those tools are present; the optional
`--allow-missing-rust-toolchain` mode is diagnostic only and never green
promotion evidence. A dedicated exact-head trusted-runner workflow is included,
but its presence or a queued/skipped run is not successful evidence.

## 5. Required upstream interfaces

Open typed requests are recorded in:

```text
docs/development/interface-change-requests/
  A05_G1_R4_INTERFACE_REQUESTS_V1.json
```

They require:

- A03 non-forgeable Core finalization/JMT permit;
- A04 fresh durable application/JMT readback;
- A06 independent-process cross-store crash and rollback matrix.

Until A03 and A04 are accepted and A06 executes the integrated process matrix,
the freely constructible reference readbacks are test data and cannot become
signing authority.

Observed upstream heads at final revalidation were A03 PR #21 at
`1b9543b3b22cc959d0ea2b3123c349761adada32` (tree
`3c0ae054f358b45f5801ee8111d1833aee40dbd0`) and A04 PR #9 at
`f38df4ec81cb76f92c709d8cd45311e164fa5753` (tree
`bf7bbf43b8a783ffc443b1105f8f53aa406efff1`). Both remain Draft
`BLOCKED_UPSTREAM`; neither interface is treated as accepted.

## 6. Commands

Diagnostic model/source checks in an environment without Rust:

```bash
python3 scripts/ci/check_g1_r4_safety_checkpoint_v1.py \
  --allow-missing-rust-toolchain
```

Exact package gate:

```bash
bash scripts/ci/check_g1_r4_safety_checkpoint_v1.sh
```

## 7. Terminal result

```text
A05_owned_coordinator_shape = MODULE_CLOSED_CANDIDATE
store_identity_substitution_mutant = rejected
A03_core_finalization_permit = BLOCKED_UPSTREAM
A04_application_JMT_readback = BLOCKED_UPSTREAM
A06_integrated_process_matrix = BLOCKED_UPSTREAM
rust_compile_test_clippy_fmt = RESUME_REQUIRED
g1_r4_exit = false
```

## 8. Non-claims

```text
safe_vote_authority=false
production_signature_authority=false
private_key_handling=false
whole_node_operational_integration=false
external_anti_rollback_complete=false
g1_r4_exit=false
g1_exit=false
production_candidate=false
production_consensus_activation=false
release_ready=false
```
