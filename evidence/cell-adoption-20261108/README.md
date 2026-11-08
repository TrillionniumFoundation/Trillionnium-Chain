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
```

Retained source-integrity logs include expected negative-fixture `FAIL` records;
their surrounding tests must reject those fixtures. They are not hidden
failures of the candidate's source identity.
