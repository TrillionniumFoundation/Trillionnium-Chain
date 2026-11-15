# Native source inventory reconciliation - 2026-11-08

The initial publication retained a real native complete-path observation and
explicit HOLD. Its dedicated [native component CI passed](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599855).
Other CI correctly refused a stale generated native source inventory. This
follow-up fixes that source-accounting integration without changing the
measured relation, Node implementation, full-path tools or qualification.

## Exact source and repair

Tested commit: `6e48656b51fc9bd85de386b3f01f41daa6e35069`.

The repair integrates `96a241bf43f6a46d35dfb3d4ced9594ed8ceca75`,
runs the official `scripts/refresh_distributed_source_inventory.py` generator,
and synchronizes only the generated inventory's exact PQ blob pin:
`7c71aacb00920a8711c9028c8854bba3d22a098e`.

The generated inventory now includes the native full-path example, native
wrong-context regression, and the integration branch's history-stage diagnostic.
No assertions, required source paths or qualification thresholds were relaxed.
The publication of this report changes evidence and a plan link only.

## Validation

All 17 recorded commands passed on the tested commit. The 333 selected tests are:

| Scope | Passed |
| --- | ---: |
| Complete-path collector/reader controls | 52 |
| Native Node regressions | 10 |
| PoN kernel tests | 135 |
| Source-integrity controls | 43 |
| Repository controls | 50 |
| PQ source-pin controls | 37 |
| Imported history diagnostic controls | 6 |

This is a selected scope, not an assertion that every workspace test or every
hosted workflow passed. The exact locked default/all-feature Cargo graphs,
workspace formatting, focused strict Clippy (including the imported diagnostic),
generated inventory, PQ pins, repository/Markdown checks and before/after raw
source guards also passed. Exact commands, exits and timings are in
[commands.json](commands.json), [results.json](results.json) and
[validation-summary.json](validation-summary.json).

All original stdout/stderr bytes are retained in the
[lossless validation archive](complete-validation.tar.gz). The archive was
read back and compared byte-for-byte with every original member. Its member
digests and the published files are recorded in [index.json](index.json).
[Source before](source-before.json) and [source after](source-after.json)
retain the exact tested tree and raw-byte audit.

## Separate CI outcomes remain separate

[The observed old-head CI records](old-head-ci-observations.json) retain the
initial inventory failures and the distinct existing qualification failures.
In particular:

- The [PQ inventory refusal](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599520/job/128659842410)
  and [repository-truth refusal](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599483/job/128659842601)
  are the source-accounting issue repaired here.
- A [historical pressure artifact lookup](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599526/job/128659842480)
  still lacks the original artifact. A replacement is not relabeled as that artifact.
- The [original confirmation target](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599483/job/128659842597)
  and [fresh-service deadline qualification](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599621/job/128659843327)
  remain unsuccessful under their original criteria.
- The [original three-round campaign](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42457599512/job/128659842532)
  retains all three failed outcomes. The compared integration commits did not
  trigger that workflow, so this report does not assert an inherited cause.

The original [measured complete-path evidence](../pon-native-fullpath-20261108-a1a69c624/README.md)
is unchanged: measured source `a1a69c624db33205a69973b98a6db0f7d22e0782`,
7.322108454 seconds through independent readback, one new depth-zero development
block, zero progress satisfying the original four-second/six-successor condition.
No additional timing sample is claimed by this metadata repair.

Security and performance qualification remain HOLD. The observation is
COMPONENT_OBSERVATION_ONLY; no compressed proof qualification, quantum search
cost theorem, production activation or complete hosted-CI success is asserted.
