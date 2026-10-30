# Initial diagnostic and runtime-fixture CI failures

Source `abe552b6d2a408adbf82e27c817b4f914a7322a2` is the parent of this repair.
The original runs and their conclusions remain failures.

## Independent model diagnostic

Run [40485837206](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40485837206),
job `122127272384`, failed in the source/setup step with
`KeyError: 'MODEL_DIAGNOSTIC_OUT'`. Writing `GITHUB_ENV` makes a value available
to subsequent steps; it does not export that value to Python in the same shell.
The exact committed-source check passed before this error. Model download,
training and evaluation did not execute. The conditional upload was not reached;
[the original log archive](original-ci-logs.tar.gz) and [jobs.json](jobs.json) preserve the retrieved job evidence.

The workflow now exports the same output directory immediately after appending
it to `GITHUB_ENV`. [check-ci-env-repair.py](check-ci-env-repair.py) extracts the
actual old/new source-step shell lines and resource-probe command. Separate real
shell executions reproduce the old error, pass the repaired same-step probe,
and pass a fresh subsequent shell receiving the exact environment-file value.
[The result](same-step-environment-control.json) also checks unchanged public
model input helper, wheel lock, original pilot, model family and production
runtime validator. The 15-minute job and 10-minute model step limits remain.
This local control does not execute a model or qualify a future CI result.

## Parent-bound model evidence matrix

Run [40485837111](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40485837111)
failed in all four matrix jobs (`122127272084`, `122127272571`, `122127272658`,
`122127272501`). The new material suite failed during `setUpClass` with missing
`libz.so.1`, executing zero tests. The strict complete-roster reader correctly
refused. The original setup and candidate-observer suites passed in the retained
x86 and ARM head logs in [the original archive](original-ci-logs.tar.gz).
[Matrix metadata](parent-jobs.json) retains all four jobs and their steps.

The fixture had matched `DT_NEEDED` names only against basenames in
`/proc/self/maps`. System Python maps the actual versioned file, which can have
a different basename from its SONAME alias. The fixture now resolves an alias
only inside directories containing already mapped files, and only accepts one
unique real file that is already mapped into the current test process. Missing
or ambiguous matches fail. It never invokes a loader or executes an input file
while assembling the fixture. The production validator is byte-for-byte
unchanged and still statically validates declared material without execution.

The local copied system Python 3.12.3 reproduced the zero-test fixture failure
([before](system-python-fixture-before.log)), then the unchanged cold-interpreter
test actually passed ([after](system-python-fixture-after.log)). The primary
Python 3.12.14 passed all thirteen material tests with zero skips and the strict
[roster readback](runtime-material-test-readback.json), plus eight original Cell
controls and four registration controls. The copied model environment lacks pip,
so the complete thirteen-test system-Python/ARM CI result still needs a new run.
No test or assertion was skipped or relaxed to turn the old run green.

These changes repair test and CI preparation. They do not establish model benefit,
ordinary Hepta installation, complete cold Torch execution, independent operators,
next ordinary task consumption, or I10 completion. The prior all-yes candidate,
full-tune SIGKILL, and three failed Cell batches remain unchanged.

[The archive inventory](original-ci-logs.json) binds all three retrieved logs.
The original blank timestamp lines contain trailing spaces; the initial full
staged whitespace check reported these lines. Archiving the unchanged bytes
preserves them and permits the source whitespace check to remain strict.
