# Cell adoption evidence continuation — 2026-11-08

This continuation starts at Chain `a2a317d6a0b0d3008868e447c4cbe719d1bc4893`
and the ordinary-host boundary. Its engineering results do not establish a
complete model evolution cycle, independent operators, settlement, installation
or ordinary-host FinalUse. Qualification remains **HOLD_NO_GO**.

## Control-material implementation and retained review finding

The first publication, `b3ff1d3c7428a6a080650d3fc754075c3ab6f4b2`, added
seven-role material review and composition with the original signed V3
parent/NoUpdate verifier. Its exact-source release-finality suite passed 117
tests; 43 source-integrity negative controls passed. The complete tracked tree
matched before and after. The original ten parent tests and signed-learning
join also passed. Native Cargo source and lockfile were unchanged.

The subsequent adversarial review found a real material-review omission: a
role signing key could be relabelled under a different controller in the
reviewer policy. The original report still denied independence and FinalUse,
but incorrectly classified the supplied review materials as complete.
[The retained reproduction](control-review-findings.json) identifies the
original commit/blob, observation and exact reproducer. The correction rejects
that cross-collection alias; a consistently mapped role key remains excluded
from reviewing its own control separation. The expanded reference suite has
120 tests, including two new reviewer-alias controls and one explicit
learning-actor/control association disclosure.

The review also retains the missing original actor-to-control association.
Sharing a campaign/source pair is insufficient to prove that the signed V3
learning actors are the controllers in a separate material manifest. The
combined report explicitly keeps `learning_actor_control_binding_verified`
false and lists that acceptance obligation.

## Original native use exports and separate Chain review

The original Hepta actor implementation was frozen at
`2c2a3adbcc4d6d6784e4ba76106bb1beb700e3bd`, tree
`319737f613f1a9f786df78c4fb79e9c32cac5542`, native subtree
`5287bca8328bbea7feb92a0fb8cc0c616104adc5`. On ROG, all five selected original
actor tests passed. Nextest's other 744 tests were outside that selection and
are not counted as executed. The selected run took 8.342 seconds after its
build; build plus run took 180.187 seconds within the recorded two-CPU / 8-GiB
envelope. The source tree matched before and after the tests; the tested native
binary's identity is retained with the run.

The [capture manifest](native-readbacks/capture-manifest.json) binds each of
four original stdout records to exact byte offsets in the retained
[native log](native-readbacks/native-controls.txt). The JSON was copied without
reformatting or a trailing newline. It covers retained parent / adopted
candidate, each pending output and after ACK. Original receipts, publications,
complete manifests, cost records and journal observations are preserved.
Cold recovery asserts the same export without re-execution. Current withdrawal
and revocation refuse export; the original before-use zero-execution controls
remain alongside the new after-use checks.

These are **original native engineering fixtures**, using controlled test
workers and authority fixtures. They do not execute a real trained model or
independent evaluators. One operator's ROG tests do not establish independent
control, protected installation, actual settlement, or production FinalUse.

The separate [Python reader](../../scripts/cell_adoption_readback.py) checks the
original native domains and bindings with 26 tests. Negative controls include
changed task/input, prior learning cut, wrong parent/candidate, failed receipts,
wrong dispatch witness, zero native digests/nonce/epochs, overlong grant window,
duplicate fields, float/bool byte aliases, and substitutions of a download or
exit-zero report. The historical real SmolLM 64-forward NoUpdate result remains
a negative input; it is not relabelled as native FinalUse.

The fixture expectations are explicitly derived for engineering tests. In a
qualified run they must instead be independently retained by the original
supervisor. The [reader contract](../../docs/development/specs/pon/CELL_ADOPTION_READBACK_V1.md)
explains this distinction and the original intent/request boundary. Each
successful material report still denies current permission export, issuer
authentication, complete learning, independence, installation, settlement and
activation.

## Ordinary-host diagnostic

[The actual current-call diagnostic](ordinary-host-readiness.json) invoked the
original handoff loader without independently supplied owner configuration.
It returned `NOT_CONFIGURED`, reported no required Fleet/Agentd environment
bindings in that invocation, and created no output directory. This is bounded
to that call. It is not an exhaustive claim that no deployment or configuration
exists elsewhere, and it is not a model-loading experiment.

The original transport record remains immutable and cannot be promoted to
installation/use by this review. Actual protected installation, independently
qualified owner inputs, current authorization, real model loading and the
next task's exact version observation remain separate acceptance requirements.

## Reproduction

```sh
bash scripts/project-preflight.sh
python3 -B formal/release-finality-v2/run_conformance.py --out /absolute/new-directory
python3 -B formal/release-finality-v2/check_existing_learning_owner.py
python3 -B formal/pon-nakamoto-v1/test_model_generation_sequence_parent.py -v
python3 -B scripts/ci/test_ci_source_integrity.py
python3 -B scripts/test_cell_adoption_readback.py -v
```

Retained source-integrity logs include expected negative-fixture `FAIL` records;
their surrounding tests must reject those fixtures. They are not hidden
failures of the candidate's source identity.
