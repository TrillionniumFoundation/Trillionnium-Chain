# G1-R4 Safety/checkpoint coordinator reference v1

Status: **candidate-only; no signing, persistence, activation or production authority**.

This standalone, dependency-free reference crate defines the final type-state
join required before a signer adapter may receive a request. It does not replace
the existing SafetyStore, SignerJournal, external watermark authority or
external node-checkpoint CAS. Instead, it requires exact readbacks from all of
them and returns an opaque, non-`Clone` permit only after both the whole-node
checkpoint and external watermark are freshly observed at the same target.
Both records retain the exact Application-store, Safety-store and signer-journal
identities, so reopening under a substituted store configuration fails closed.
The opaque permit repeats the namespace, store, custody and process-generation
bindings and exposes no writable or signing surface.

The freely constructible readback records in this reference are test data. A
production composition must replace them with non-forgeable carriers owned by
the A03/A04 stores and must execute the A06 process crash matrix. No raw key,
signature producer, HSM/KMS adapter, automatic mixed-cut repair or production
constructor is present.

Local diagnostic model:

```bash
python3 model.py --self-test
python3 tests/test_model.py -v
```

Exact package gate, which requires Rust tooling:

```bash
bash scripts/ci/check_g1_r4_safety_checkpoint_v1.sh
```

Exact-head trusted-runner workflow:

```text
.github/workflows/trnm-g1-r4-safety-checkpoint-v1.yml
```

A workflow definition, queued run, skipped run or stale-head success is not
module-closure evidence. Only a completed successful run on the exact package
head can satisfy the Rust compile/test/Clippy/rustfmt evidence requirement.
