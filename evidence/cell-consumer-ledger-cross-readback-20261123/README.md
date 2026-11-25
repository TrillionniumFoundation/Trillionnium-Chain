# Archived model-use and evaluation-fee reconciliation

A development Node paid 2,000 development units for one paired evaluation. A separate Hepta engineering study recorded one simulated acceptance and one simulated rejection after real local model runs. The frozen releases have different studies, admissions, freeze commitments, candidate manifests and paired requests. Both scopes identify engineering fixtures. [Field comparisons, original operations, digests and outcomes](READOUT.json)

The readback verifies 12 files of predictions and receipts and both native signed operation identifiers. The ledger's paid subject is the funded evaluation delivery. That evaluation added zero future successes. The Hepta fixture verifier independently reopens the SQLite admission, 14 model files, cold selection, process outputs, original reports and simulated native delivery records. Both subsequent model calls returned the byte `1` and had different run and effect receipts. No outside effect observer or external payer is present in these materials. The external amounts remain unknown. [Funded evaluation originals](../cell-released-pair-funded-evaluation-20261123) · [Hepta originals and independent verifier](https://github.com/TrillionniumFoundation/hepta-private-ci/tree/60347d4d1687147ddf7c1e12350711583dac5918/qualification/paired-consumer-use-20261123)

Two older HEPLCP02 histories were also replayed from their original binary selection and completed checkpoints, freeze, expected bindings and native readback. The selected candidate and retained incumbent each had another run under the same original principal, agent and Cell. The two independent-consumer gates remain open and neither original operation has a funded mapping. Their complete native bundle descriptors have a different schema from the plain paired-model manifest. The reader makes no translation between these identities. [Native learning and business reader](../../scripts/cell_learning_business_join.py) · [Economic owner](../../scripts/cell_learning_business_economics.py)

## Reproduce

Check out the Hepta fixture commit `60347d4d1687147ddf7c1e12350711583dac5918` locally. From this Chain checkout supply its original fixture directory to the Python 3.11+ commands below. The audit pins the original ZIP, its upstream verifier, both legacy bindings and the separate native evaluation release. It opens no network connection and writes an explicitly scoped public JSON summary to stdout. The controls create temporary copies.

The console schema is `trnm.archived-consumer-ledger-cross-readback-public-summary.v1`. It reports field equality, verification counts and the unverified business scope without publishing payment amounts, operation identifiers, subjects or nested original evidence. The internal `compare()` API still returns the complete verified v1 report, and the original `READOUT.json` is unchanged. The `dev_circuit_evaluation.py verify` command similarly publishes `trnm.development-evaluation-public-summary.v1` after all original signed-fee and amount checks succeed; its internal `verify()` API remains unchanged.

```sh
study=evidence/cell-consumer-ledger-cross-readback-20261123
original=/path/to/hepta/qualification/paired-consumer-use-20261123
python3 -B "$study/compare.py" "$original"
python3 -B "$study/test_compare.py" "$original" -v
```

The original Rust entry `funded_plain_paired_intake_reopens_paid_native_operation` commissions a development evaluation. The distinct test `retained_plain_paired_intake_reopens_the_same_payment_from_copied_stores` reads copied Node/M12 stores. The comparison uses the existing Python verifier on retained native exports. [Original Rust entry points](../../trillionnium/crates/trnm-pon-node/tests/native_task_operation_v2/circuit_evaluation.rs) · [Original Python readback](../../scripts/dev_circuit_evaluation.py)

The Hepta live consumer interface checks distinct request and outcome grants against the protected issuer. A participant-reported effect and a local run retain their own scope. The independent use, externally observed effect, external payment, learning reward and consensus credit are all unverified here. [Consumer implementation](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/ba793d104013f773facf36cb8b0edfe7f3b6739b/scripts/cell_experiments/paired_consumer.py) · [Protected issuer](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/7039)
