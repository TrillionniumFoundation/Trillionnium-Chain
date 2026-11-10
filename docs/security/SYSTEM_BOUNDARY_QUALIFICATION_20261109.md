# Common-candidate security evidence boundaries

Status: **HOLD_NO_GO / DENY_ALL**. This is an M14 review snapshot, not a new
development plan, consensus rule, proof, runtime adapter or authority. The
[existing development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains the sole plan.

## Candidate and four evidence levels

The reviewed common source is Chain M14
`ac8501a85a770ba34f34e1bed507ca747e5c3f8d`, tree
`3f321d412ab7eb1f5c03f18ba21201e96a3db144`, paired by its existing closure
record with Hepta `71738345326b98d88b738250d2b84ecbcb466eb8`.
A later documentation or implementation descendant needs its own source
identity. The two defensive patches developed alongside this review cannot
inherit M14 native execution results. Neither the pair nor this review
identifies an ordinary loaded daemon, model, loader or evaluator.

These levels are separate; a later level cannot be inferred from an earlier one:

| Level | Required observation | Meaning in this review |
| --- | --- | --- |
| `source_present` | Relevant files and exact declared source/profile identities exist | Source observation; not execution or correctness |
| `mechanism_tested` | Original named controls execute with retained outcomes and tested identities | Bounded mechanism evidence; not the complete application operation |
| `same_operation` | Original operation, candidate, loaded bytes, complete version, owners and all required stages are linked | Same-operation record; still requires specialized authentication and native readers |
| `qualified` | Every acceptance and security premise has its own candidate evidence | Unestablished; no promotion or external-effect authority |

## Existing defensive reader

The current [qualification reader](../../scripts/ci/chain_hepta_qualification.py)
already binds a separately supplied `--plan-sha256`, exact Chain/Hepta source
pair, locks, profile, campaign and build/load closure. The packet cannot choose
its own plan. Different source pairs and missing identities produce explicit
issues. Recognized native command receipts are checked against both before and
after source identities; a zero child exit with failed source collection cannot
become a successful stage.

This reader deliberately has no full native outcome adapter. Every record keeps
`RAW_OUTCOME_UNVERIFIED`, `result_payload_verified=false` and
`current_materials_consistent=false`. It preserves failure, timeout, ignored,
filtered and unknown attempts, and always returns `HOLD_NO_GO` and `DENY_ALL`.
Retained-binding consistency is not an authenticated execution certificate.
`source_url` is provenance text, not a source pin or authorization.

The [48 qualification controls](../../scripts/ci/test_chain_hepta_qualification.py)
already cover different-branch rejection, independent plan pins, packet-selected
plans, preserved failed attempts, same-source/different-iteration rejection and
UNKNOWN effect handling. The
[13 command-binding controls](../../scripts/ci/test_chain_hepta_command_binding.py)
cover the retained command-source contract. This review adds no parallel
qualification tool or automatic source-anchor updater.

## Consensus and research-side source gaps

| Material | Exact observed source | M14 evidence level and remaining gap |
| --- | --- | --- |
| Actual fixed-probability cost contract | [M14 contract](../../formal/pon-nakamoto-v1/fixed_probability_contract_v1.json) | `source_present`: eight classical and eight quantum rows retain `lower=null`, `upper=null`, `status=unproved`; `native_consensus_credit=false`. All-legal-strategy physical cost and credit calibration remain open. |
| Joint time, target and required-credit audit | [Retained joint audit](../protocol/pon-nakamoto-v1/details/JOINT_CONSENSUS_DAA_AUDIT_20261108.md) | `source_present`: complete relation and finite reachability observations keep their original scope. They do not supply resource tails, native CP/CG/CQ or a six-confirmation failure probability. |
| Fixed-success classical query frontier, PR #838 | [Evidence child `99c55cba`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/99c55cbaa5eac18420d401172a0a0a1c1aa28715/evidence/pon-fixed-success-frontier-20261109) | Separate source cohort. Its independent Bernoulli membership-query theorem is not an actual W1, quantum, correlated-help or physical-resource certificate. Its reported controls are not M14 executions. |
| Joint consensus qualification and dynamic participation, PR #843 | [Evidence child `0ff81958`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/0ff81958a611d2c0be54d2ca839b955ae7cb2772/evidence/pon-joint-consensus-qualification-20261109) | Separate source cohort. `joint_consensus_qualification.py` is absent from M14. Its 23-file reviewed map binds #835, not M14. Its 18 unknown environment inputs, 13 open obligations and native failure bounds remain unresolved. |

The #843 source map includes native Cargo.lock SHA-256
`05cce83ab22c3085ff18ba8107b28bed70349fa56176784eab033897c282216c`.
M14 instead pins
`759c42c62d7b9a72d93c533039b5bf47f3508efabf1f1ee63f5eee59b9b9e55f`.
Updating JSON hashes and the reader anchor merely to suppress this difference
would discard the independent-review boundary. Integration requires review of
the changed source scope and new exact-source execution; the old result cannot
be carried forward as a current candidate pass.

At #843 delivery head `0ff81958a611d2c0be54d2ca839b955ae7cb2772`, the
[work/time contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42631719762)
and [classical/quantum credit contract](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42631720525)
workflows completed successfully. The
[required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42631719519),
[original native campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42631719498)
and [priority acceptance](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42631719659)
completed with failure. These are workflow-level observations; this review
does not infer individual phase results or root causes. They cannot be combined
with M14 or successful research controls into a common pass.

## M14 service outcomes and learning source gaps

The actual M14 head `ac8501a85a770ba34f34e1bed507ca747e5c3f8d` has completed
failures for the [original campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693805359),
[public Host pair](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693805049)
and [required baseline](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42693804931).
The Host job records failed execution and retention steps. These terminal
workflow observations do not establish individual confirmation counts or one
unique root cause, and do not qualify either subsequent defensive patch.

Two separate learning-side source gaps also remain. M14 has neither
`scripts/cell_learning_business_join.py` nor
`scripts/cell_learning_business_economics.py`; the
[#840 files at `675cdfc1`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/675cdfc114a00e8a971f4f229528f71973d52d73/scripts)
provide structural learning/business readback with explicit false authority
fields, not an authenticated payment or FinalUse certificate. Their existence
and controls cannot be inherited by M14.

Hepta [#5566 at `2bb02f14`](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/2bb02f144c9405791281c2cbfa5e7fd39a591b05/codex-rs/hepta-agentd/src/learning_iteration_evaluation_evidence.rs)
contains original trainer/evaluator readback and current-clock revalidation;
its [qualification summary](https://github.com/TrillionniumFoundation/hepta-private-ci/blob/2bb02f144c9405791281c2cbfa5e7fd39a591b05/qa/evidence/daemon-learning-785b/qualification-summary.json)
attributes behavior tests to `baab1f7f`, not the maintained/evidence head, and
keeps ordinary bootstrap, publication and production authority false. That
readback file is absent from #5569 source
`e6c3812f0f47667f6fac2b7b56b43f51c6966592` and its later observed head
`300ebaaedd9ec578ffcd2bc341c2394ead6a92c8`. These source-specific absences
prevent treating the combined side branches as one assembled, tested ordinary
learning operation. `source_present` in one branch cannot establish
`mechanism_tested`, `same_operation` or `qualified` in another.

## Promotion conditions retained

Consensus still requires all-legal-strategy cost envelopes with joint initial
state and public help, time/target/credit composition, dynamic participation,
complete delivery, honest progress and adversarial credit tails, and native-to-
model reductions for CP, CG, CQ and lifetime composition.

The common application boundary still requires one original operation to
connect authorized task, real training, independent evaluation, Selection or
NoUpdate, complete retained version, installation, ordinary FinalUse, an
independent consumer's next task, payment/cost reconciliation and cold recovery.
Component tests and cross-branch receipts do not close those stages.

Independent operation and recovery remain external acceptance obligations.
Several keys, processes or directories cannot establish independent
administrators, backups, networks, power or recovery procedures. Authentication
binds a message to a key; it does not authenticate honesty or remove shared
failure and collusion.

This review preserves `qualified=false`, all native security probabilities
unknown, all production and FinalUse qualification flags false, and
`authority=DENY_ALL`.

## Local review observations

On M14 reader and test bytes, original direct script commands completed:
`python3 -B scripts/ci/test_chain_hepta_qualification.py` (48 methods) and
`python3 -B scripts/ci/test_chain_hepta_command_binding.py` (13 methods).
These are structural tests; no model, payment, consensus campaign or native
security qualification was executed by them. Concurrent work in the shared
checkout is not relabeled as an exact frozen native run.

An earlier `python3 -B -m unittest` invocation with both filesystem test paths
failed before execution with `ModuleNotFoundError` for sibling imports. The
direct commands above use the original script entrypoints. This invocation
failure is retained separately from subsequent successful controls.
