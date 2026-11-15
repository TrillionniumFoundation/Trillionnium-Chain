# HEPLCP04 completed-use engineering evidence

This corpus retains original native actor bytes for qualified local choices.
The reader and every report remain DENY_ALL, NOT_EXPORTED and HOLD_NO_GO.
They grant no model-use, evaluation, mining, payment, release or production authority.

## Native source and retained bytes

The producer is Hepta source 93fc43f6e87c4514485adcb01a7ffec8ad3b632f,
tree 1de575fdbba23d25c483f539a15b455c9e8859cb. The native run owner observed
seven selected targets pass with exit 0 and an unchanged clean source after
execution. Its 1,035 filtered tests are outside that seven-target denominator.
The later separate trainer/NoUpdate target is outside this captured run.

The complete [native stdout](native-readbacks/native.stdout) is 235,411 bytes,
SHA-256 3e7ee2dcd9019949256a2987a3c8612d976952a58503d7050198adaab11a5261.
The [manifest](native-readbacks/fixture-manifest.json) pins every captured and
derived file. Each of the twelve local markers retains the exact JSON slice,
byte offset, byte length and SHA-256 from that stdout. Legacy retained/adopted
markers remain in the complete log and are listed as excluded exports; they
are not local-choice positive cases.

| Native phase | Local choice | Model used | Evaluation / proposal | NoUpdate |
| --- | --- | --- | --- | --- |
| local_defer_cold | DeferCandidate | Parent | Qualified / UpdateCandidates | false |
| local_retain_cold | RetainParent | Parent | Qualified / UpdateCandidates | false |
| local_adopt | AdoptCandidate | Candidate | Qualified / UpdateCandidates | false |

For each phase the corpus retains INITIAL, Selection, completed checkpoint and
native readback exports, their original checkpoint bytes, fixture-derived
freeze/expected JSON and the completed-use review. The INITIAL wire is native
production-codec serialization of new(request, owners), constructed by the
exporter from the retained request and stage owners. The freeze is derived from
those INITIAL bytes. This does not establish custody before dispatch.

The qualified evaluation/proposal evidence is a controlled fixture. The native
tests exercise actual actor journals, CURRENT/publication and FinalUse
mechanisms. This corpus does not independently verify real model training,
quality improvement, complete costs, signatures, Root scope, an independent
consumer, settlement or production activation. Native test success is recorded
by the run owner; the collector does not infer it from marker presence.

## Completed use and output ACK are distinct observations

These three local phases use empty output deltas. Their original readbacks have
no pending work or delivery. The joined report therefore records:

    completed_use_observed = true
    pending_work_and_delivery_clear = true
    output_ack_event_verified = false

An empty pending state cannot distinguish no output from an explicit output
acknowledgement. The pending-work and pending-output negative controls are
labelled hostile mutations. They are not native pre-ACK cuts. The legacy
ordinary actor ACK phases are kept outside the local-choice denominator.

The report preserves the final receipt's evidence commitment and observation
time, and binds its observation exactly to the original native use. It keeps
model STOP and terminal-episode observations separate. Defer and Retain preserve
their distinct local-choice signing payloads even though both use the parent.

## Python validation and exact-source scope

The [retained test stderr](validation/tests.stderr) records 19 tests run in
2.738 seconds, all passing. The [capture stdout](validation/capture.stdout)
records 32 corpus files. [Validation metadata](validation/result.json) records
both exit codes, the actual input pin and the four tested source-file hashes.

That run used base commit c2d67c5cf1ebb4caac525802362d5746b8fd957d plus the
uncommitted C2 changes. Its source scope is the dirty C1 worktree and the listed
file hashes. The metadata explicitly retains
tracked_worktree_source_verification=false. The integration owner records the
subsequent exact C2 committed source and full validation gates separately.

Coverage includes all three original choices; a rehashed Defer/Retain swap;
pending-state mutations; final checkpoint, committed receipt, publication,
model-reset and distinct-run substitutions; frozen-request/prefix changes;
actor/time/version/bounds checks; missing or duplicate exports; denied authority
escalation; and the CLI's five independently pinned materials. Mutation encoders
are used only for negative controls. Missing positive fixtures are hard failures.

The original [missing-fixture failure](validation/cloud-missing-fixture-original.log)
is preserved as 1,321 original bytes, SHA-256
d4c4bef1fd99746476e5a076d615e9771bb042dc3ab1480f30d7ad6c3e648e38.
It records zero tests and a missing-file error before the native fixtures were
available. It was copied from the recovered original file, without rebuilding
or relabelling its output.

Run the retained corpus from the repository root:

    python3 -B scripts/test_cell_learning_local_use_join.py -v

The [collector](../../scripts/capture_cell_learning_local_use.py) accepts the
complete native stdout and an explicitly declared source commit, and creates a
new output directory. It preserves original native bytes; its expectation pins
are fixture-derived. The [completed-use contract](../../docs/development/specs/pon/CELL_LOCAL_DECISION_COMPLETED_USE_V1.md)
defines the reader's cross-material checks and authority boundary.

## Retained tested source hashes

| Source file | SHA-256 |
| --- | --- |
| .github/workflows/pon-learning-outcome-composition.yml | 9d9b9cb19054cf6801ffafc14d4ed9da00f44026bb9bb7c80f62af1f988156a2 |
| scripts/capture_cell_learning_local_use.py | e7546bf1e936f519af7a31f54b3e29e3fe15cc5f7ebd2eeadc877442f66731ab |
| scripts/cell_learning_local_use_join.py | 7af37cdad0913a56ae31484e5fc46975de3a0328fc89197cc0aad9869a8700e4 |
| scripts/test_cell_learning_local_use_join.py | fd9241c32e40d065d41a0fd8acdb49805238ed2acef942e21bc1dfd2d7947032 |
