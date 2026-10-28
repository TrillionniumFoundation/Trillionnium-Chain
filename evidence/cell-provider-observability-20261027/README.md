# Provider evidence and finished-worker admission, 2026-10-27

This is a scoped M09 source correction and diagnostic increment on
`21e3ccb5b7e5f3e60cc7e79db676e9708bea3a59`. It does not qualify a full model
transfer, native installation, independent custody, public service or production
activation. The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Preserved failure and what it establishes

The original controlled model batch 003 retained eleven objects, 272,189,870
payload bytes and 269 chunks. Its [fetch diagnostic](prior-003/fetch-release.log)
reported a TCP response-header reset (`errno 104`) after four milliseconds of
that request. The [original handoff](prior-003/handoff.json) remains failed.
Its provider stderr was empty, and provider stdout/final serving counters were
not retained by the old failure cleanup. The [provenance receipt](prior-003-provenance.json)
hashes the exact copies and confirms that no original file was modified.
**That observation alone cannot identify the reset's cause.**

The c960 source used for that run and the 21e source have identical blobs for
both relevant files: serving `735c1c1d7c3f16de77acf8b5f9e3f79da769574e` and
handoff driver `fd0181b614885dd369f311f5a71cf829a31cf68c`. Their unchanged
network limits are separate from the new diagnostic controls.

## Two concrete changes

The Python driver now directs provider stdout and stderr into exclusive raw
files from process startup. The listener reader polls the existing file under
the original five-second announcement deadline. It does not consume a PIPE
whose unread tail would disappear on an exception. A terminal receipt records
the actual child PID, argv, return code, cleanup actions and log digests on all
normal cleanup paths. The serve-observation receipt includes only reports the
provider actually emitted. A killed process may have no final report; this is
recorded as `not_emitted`, with no fabricated counters. A failure while writing
provider evidence is additionally recorded in the outer handoff when possible.

The native server originally reaped completed handles only before `accept`.
A worker could finish between that reap and the accepted socket's admission
decision. Its returned reader was still unavailable in the parent array, so an
already completed slot could be counted as overload. The fix performs one more
nonblocking `is_finished` scan only when the array would otherwise be full.
It joins only finished handles. Still-active full capacity continues to drop
the accepted socket immediately; there is no request queue, wait-for-capacity
path, additional response or silent retry. Accepted-connection accounting,
shared response-byte accounting and original absolute deadlines are unchanged.

This does not promise that every honest connection succeeds at peak capacity.
A worker still active at the final admission check remains occupied under the
original overload contract. The deterministic counterexample does not establish
that batch 003 encountered this particular scheduling window.

## Actual controls

- The [original-loop control](race-original-window-loopback.log) ran the actual
  native M09 test binary, with real SQLite readers and localhost TCP requests.
  A test-only completion barrier sits between the original reap and accept;
  both admitted workers are known finished before the third accept. The
  original logic reports one overload and fails the zero-overload assertion.
  The [red source](red-serving.rs), [compilable red test source](original-window-serving-tests.rs)
  and [binary/command receipt](race-original-window-loopback-terminal.json)
  are retained. Removing the test-only hook exactly reconstructs the
  [original serving bytes](original-serving.rs); production semantics were not
  changed for the red observation.
- After the minimal fix, the [fresh native suite](fixed-serving-fresh-suite.log)
  passed **11 tests, zero failed or ignored**, using the exact locked/offline
  21e Cargo graph. These include the new scheduling control, real two/four-slot
  overload refusal, exact and one-byte-short response budgets, absolute service
  deadlines, partial-write accounting, worker-panic joining, corrupt-cache
  repair boundaries and foreign-cache refusal. The [receipt](fixed-serving-fresh-suite-terminal.json)
  binds the executable and [source manifest](fixed-native-build-invocation.json).
- [Six real subprocess controls](python-provider-controls.log) cover normal
  exit, a genuine SIGTERM handler's final stdout/stderr, SIGKILL escalation,
  non-UTF8 and incomplete output, early nonzero exit and no-provider-started
  evidence. These small Python child processes are not native Cell services.
- [Five retained deadline/consumer tests](python-deadline-controls.log) still
  pass. They retain the original 35-second acceptance rule and refusal to treat
  an unsupported or arbitrary consumer receipt as authority.
- [Strict Clippy](m09-strict-clippy.log) passed for every target of the native
  M09 crate on the same locked/offline graph. Changed Rust formatting, source
  inventory and twenty new relative documentation links also passed. This does
  not certify the rest of the workspace or a final remote CI run.

The transfer cap is still 35 seconds, finite provider lifetime 45 seconds and
explicit provider/consumer concurrency two. Failure cleanup retains terminate,
five-second wait, kill and five-second wait. No full model retry result is
claimed by this source package. A later batch must use a fresh output directory
and bind its own binary, source and unchanged limits.

## Failed observations remain visible

[Initial observations](initial-observations.json) record a Python test whose
partial-output precondition was not established before its short test timeout;
the corrected control waits for actual nonempty output before testing a missing
newline. The production announcement timeout was never changed.

The [initial native compilation](race-red.log) failed because the new test-only
hook initially lacked `pub(super)` visibility. After that test fix, the default
sandbox [refused the localhost bind](race-original-window.log); this is not the
native scheduling counterexample. Auto-review then authorized only the local
ephemeral-socket test, which produced the retained semantic red result.

The first green suite returned success but Cargo replayed the old failed
compilation's [cached diagnostic](retained-cached-initial-diagnostic.jsonl).
That observation is preserved in [its original log](fixed-serving-suite.log).
Only this isolated target's M09 owner artifacts were then cleaned; the complete
fresh compile/suite passed without the stale diagnostic and produced the same
test executable digest. No failed observation was rewritten as success.

## Reproduction

Use Rust 1.95 and the repository's exact Cargo lock graph. Native tests require
permission for temporary localhost sockets, and create their own temporary
SQLite fixtures. The canonical commands from the repository root are:

```sh
bash scripts/project-preflight.sh
python3 scripts/ci/test_llm_cell_handoff_deadline.py
python3 scripts/ci/test_llm_cell_provider_evidence.py
cargo test --manifest-path trillionnium/Cargo.toml --locked -j 1 \
  -p trnm-data-availability --lib cell::network::serving::tests -- --test-threads=1
```

The offline run used the recovered native vendor directory; invocation and
terminal receipts retain the actual commands. To reproduce the original
scheduling failure, use a separate checkout of the pinned base, substitute only
the retained red serving and compilable red test files at their original paths,
and run `completed_after_reap_before_accept_reuses_slot_without_a_queue`.
It must fail the overload assertion. Do not replace the original model batch's
source, binary or evidence in place.

## Frozen release CLI for the next distinct observation

The native `trnm-cell` release binary was built from clean source commit
`57fbdfeead5cfa1436eeef0d1691ee9933246d4d` with Rust 1.95, the original
locked dependency graph, offline vendor inputs and one build job. The
[source-input manifest](release-build-invocation.json), [build terminal](release-build-terminal.json)
and [raw build log](release-build.log) retain the exact invocation and all M09
source hashes. The 3,167,448-byte binary has SHA-256
`e9b71c605cb15f37dc6522a19fffc428f455381122b76ba051c4e7d3ba3b2bb1`;
its actual [help invocation](release-binary-help.log) exited zero.

The [004 handoff](release-to-004-handoff.json) pins the separate executable and
driver and retains all original transfer/lifetime/concurrency limits. The
model-family configuration, release helper and runtime worker are byte-identical
to the original c960 inputs. This only makes a fresh observation reproducible;
it is not a claimed model-transfer result and does not revise batch 003.
