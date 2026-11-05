# Portable read-only replay of the failed hosted attempt

This helper audits stored evidence for GitHub run `41951536925`, attempt `1`,
intent `6bdaf9598d72c118798eb51a03db2e1c0e7c8507`, frozen source
`f388f46d9df150a3599b9d961b48918b3ff1fb48`. It does not execute a model,
reproduce training, score predictions against targets, initialize an authority,
reserve a trial, retry the workflow, or change an acceptance decision.

The independently confirmed result remains **aborted, spent 1 of 1**. The first
pretrained loader produced its child output, but strict supervision failed on a
missing RSS observation. No phase was accepted; the other eleven phases never
started. A successful replay means these failed-attempt records are consistent.

## Inputs

Use a checkout or exported source tree of exactly
`f388f46d9df150a3599b9d961b48918b3ff1fb48` as `--source-root`. The helper verifies
all **609** source hashes in the independently pinned published registration.
It also checks four fixed configuration files consumed by `contract_wire`:

| Configuration | SHA256 |
|---|---|
| `config/pon/ledger-v1.json` | `6755e36aab0ab9f4743da331a8dcd3374d657ff80f027ecf28db922e6d5ea39a` |
| `config/pon/work-profile-v1.json` | `03f7537b2fc3fa0c2f7036dd73d7088ba1ce50eafe6f2c907087d30385320880` |
| `config/pon/model-family-v1.json` | `30b250db074e7fbb5776c1474371258a6110cc1742e0e9970232a799ab790ca1` |
| `config/pon/devnet-v1.json` | `4491b96ead11a020e8d71f27713368b65e663eef5cfc6fd0800a166b0c2a20d4` |

The original hosted admission checked the complete Git checkout. These four
additional pins close the inputs used by this offline verifier; they do not
change the original registration, its `source_hashes`, policy, plan, or trial.
The helper checks every source byte it uses. It does not claim that unrelated
files elsewhere in a supplied source directory reproduce the entire Git tree.

Place the original evidence and audit history in one case directory:

```text
artifact.zip
artifact/                         # the 26 original extracted files
published-registration.json
independent_artifact_review.py
independent-artifact-review-final.json
independent_artifact_review.first_run.py
independent-artifact-review.json
portable_artifact_review.py
```

The four original audit files are required to preserve the first audit parser
failure and its correction and to verify that all original 189 checks and the
substantive final findings are reproduced exactly. The helper pins their raw
hashes; do not edit those files to adjust local paths. They are historical
evidence, while `portable_artifact_review.py` accepts explicit paths.

## Command

Use CPython 3.12 with its standard library. No model dependencies or downloads
are needed. The isolated flags are mandatory. Choose a fresh output path and a
writable temporary directory outside both the source and artifact directories.

```bash
case_dir=/absolute/path/to/hosted-run-41951536925
source_root=/absolute/path/to/frozen-source-f388f46d
replay_output_dir=/absolute/path/to/replay-output
mkdir -p "$replay_output_dir"

python -I -S -B "$case_dir/portable_artifact_review.py" \
  --source-root "$source_root" \
  --artifact-dir "$case_dir/artifact" \
  --archive "$case_dir/artifact.zip" \
  --registration "$case_dir/published-registration.json" \
  --audit-history-dir "$case_dir" \
  --output "$replay_output_dir/replay.json" \
  --temporary-root "$replay_output_dir"
```

Every path is an argument; the helper has no hardcoded scratch or tmpfs path.
Output is create-only. Existing output is refused, not overwritten.

After verifying source bytes, the helper creates a fresh temporary source
directory containing only the **13 necessary verified files**, with read-only
file permissions. Pure validators and their configuration reads use this
snapshot, avoiding original-directory bytecode caches, unverified import paths,
or later reopening of unbound source/configuration paths. The source snapshot is
hashed before and after use and then removed.

SQLite replay uses separate byte copies below `--temporary-root`, opened with
`mode=ro&immutable=1`, `trusted_schema=OFF`, and `query_only=ON`. The helper never
calls `TrialLedger.inspect()` or starts a writable ledger transaction. Copies
are checked for unchanged bytes and absent sidecars, then removed. Original
artifact and ZIP hashes are compared before and after the review. Model and
tokenizer library imports are blocked.

## Observed validation

One portable read-only replay was executed against the original downloaded
artifact. It returned exit code **0**, with **203** successful evidence checks:
the original **189 checks were identical**, with 14 additional portability,
source snapshot, history-preservation, and result-equivalence checks. The final
state remained `CONSISTENT_FAILED_ATTEMPT_EVIDENCE`, `aborted`, `spent=1`,
`maximum=1`, three journal events, zero accepted child receipts, and eleven
unstarted phases. No model or tokenizer library was imported, and no original
artifact, ZIP, historical audit script, or historical audit report was changed.

`portable-replay-validation.json` records the exact invocation, hashes and
comparison results. `portable-artifact-review.json` contains the complete
replayed observations. The original failed and corrected audit reports remain
unchanged. No quality score or late-exit reinterpretation was added.
