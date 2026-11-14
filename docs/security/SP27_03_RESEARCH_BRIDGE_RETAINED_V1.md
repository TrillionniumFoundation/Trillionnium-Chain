# SP27-03 retained research admission bridge

Status: HOLD / NO-GO. This example grants no execution authority, FinalUse,
post-quantum qualification, native Node execution or production activation.

## Selected reusable component

The [native example](../../trillionnium/crates/trnm-research-protocol/examples/sp27_03_authorization_adapter.rs)
retains the exact 10,458 bytes from Chain revision
`b6f26452d060bf167cd10aa2343844f4e5712bb6`, Git blob
`904bc4107709a8e052285795a7a65ad775265e6e`, SHA-256
`67e35ac1089421d020dc823914ee5e2c410c4bbea0b69d306fd52340ff54a7dc`.
It calls the existing `SignedHeptaAdmissionV1::sign`,
`from_canonical_bytes` and `verify_for_context` APIs. It introduces no library
entry point, default Node caller, effect dispatcher or deployment job.

The executable consumes one JSON request of at most 65,536 bytes, requires the
exact 17 native admission fields, bounds the encoded envelope by the original
native limit, and limits an externally supplied authority snapshot to 64
identities. Unknown fields and malformed requests fail with an input error.
Verification records a verdict; a positive verdict is not an execution permit.

The two deterministic fixture seeds are public research inputs. The example
does not accept or load a private deployment key. Its V1 signature experiment
is Ed25519 and makes no post-quantum claim. Content generation is not
authorization incarnation. The consumer must independently supply the current
expected admission, chain, signer pins and time; the example does not establish
their provenance or continued validity at an external effect.

## Original input controls and separate consumer

The original 11 input/consumer controls remain in the companion
[fixed Papers source](https://github.com/TrillionniumFoundation/hepta-papers/tree/303f3358e8b36f4c6e9453ea5cf3c40e822154e9/research/sp2027/03_reorg_safe_model_adoption/joint).
Their exact source closure is:

| Input | Git blob |
| --- | --- |
| [test_contract.py](https://github.com/TrillionniumFoundation/hepta-papers/blob/303f3358e8b36f4c6e9453ea5cf3c40e822154e9/research/sp2027/03_reorg_safe_model_adoption/joint/test_contract.py) | `5f3905186e22926f681852151438828bb369db99` |
| [joint_consumer.py](https://github.com/TrillionniumFoundation/hepta-papers/blob/303f3358e8b36f4c6e9453ea5cf3c40e822154e9/research/sp2027/03_reorg_safe_model_adoption/joint/joint_consumer.py) | `f3409fcc44e23e80f59c2dc0ce49dfeceee454ae` |
| [input05/actual_recovery_handoff.json](https://github.com/TrillionniumFoundation/hepta-papers/blob/303f3358e8b36f4c6e9453ea5cf3c40e822154e9/research/sp2027/03_reorg_safe_model_adoption/joint/input05/actual_recovery_handoff.json) | `da0ab1c04a9d8c2306cb899720979a2ba56d9ff4` |

The handoff's SHA-256 remains
`03bb46885541ca3c369394afcc06552ad89179fbaac869fb72d4ac156d798ac2`.
Its missing original clocks stay null. Reading that handoff performs no new
recovery, model forward or native end-to-end run.

Five controls check the complete operation/descriptor/request join and retained
missing-clock/non-authority boundary. Six controls exercise the actual adapter
against a temporary controlled SQLite sink: generation versus incarnation,
resigned input substitution, requested versus observed content, stable operation
with changed intent, signature corruption, and owner/incarnation changes that
must not rekey the business operation. A missing adapter executable is an error,
never a successful mock or skipped control.

The companion consumer keeps its current authority, counter effect and
completion in one SQLite writer transaction. That is a bounded experiment's
assumption, not a remote-service guarantee supplied by this Chain example.
This consolidation does not install the companion sink as a Chain product API.

## Reproduction and evidence boundaries

Use the fixed companion source files above in an isolated directory. Build the
real example from a clean Chain source, then point the original controls at
that executable:

```sh
bash scripts/project-preflight.sh
cargo build --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --example sp27_03_authorization_adapter
cargo test --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --lib --tests --all-features
cargo clippy --locked --manifest-path trillionnium/Cargo.toml \
  -p trnm-research-protocol --all-targets --all-features -- -D warnings
SP27_03_NATIVE_ADAPTER=/absolute/path/to/sp27_03_authorization_adapter \
  python3 -B /absolute/path/to/original-consumer/test_contract.py
```

Record the current source tree, binary identity, raw stdout/stderr and actual
exit status for each new execution. The original branch's native and joint
receipts remain historical observations at their original source revisions.
Their old passes, violations and UNKNOWN outcomes are not current-tree results.

SP27-02's receiver measurement harness has a different purpose and does not
replace this admission decoder/context-verifier bridge. Neither component
supplies independently surviving freshness, current Hepta ownership, external
provider reconciliation, arbitrary exactly-once effects or public deployment
qualification.
