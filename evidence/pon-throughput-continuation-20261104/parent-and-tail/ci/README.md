# Workflow wiring and actual Node registry evidence

This directory retains auxiliary workflow validation and actual `libtest`
registration output. It contains no native test execution, cost measurement or
binary. These checks do not qualify the separately retained
[M06 component measurements](../state/README.md) for a newer source revision.

## Retained checks

The original [static report](workflow-wiring-static.json) records three YAML
files, 44 shell syntax checks, seven embedded Python compile checks and 18
synthetic transcript-reader cases. The synthetic cases exercise the reader's
acceptance/rejection rules; their generated lines are not native test receipts.
The check preserves the old workflow steps, command parameters, deadlines and
49-test PQ roster while adding the required scope, canonical, prefix and append
controls. The historical report still says that native registry counts were
awaiting confirmation because it was produced before the new Node listing.

The subsequent [registry report](workflow-wiring-registry.json) and
[build registry identity](node-build-registry-counts.json) bind the actual lists
to the locally compiled Node ELF SHA-256
`dd6a1dee07568ba26022ccd690933af13788696e1925e442fe3ba471927f856f`, on base
`73ab6e9a83bcc836e261d93f9bb23ceafe556758` plus dirty native source manifest
`f56cc35bd9c9462c931776cc4e08fedeeaa7c73df5f00b2907cc2a057bc81381`.
Only `--list --format terse` and `--ignored --list --format terse` were invoked
for this check. The ELF digest was unchanged before and after listing.

| Registered namespace | Total | Ignored |
|---|---:|---:|
| `pre_write` | 12 | 1 |
| `post_write_readback` | 35 | 1 |
| `native_authenticated` | 103 | 2 |
| `append_readback_tests` | 2 | 0 |
| Complete Node library | 1,029 | 28 |

All 50 Node selectors in the updated original-workspace selection were present.
Its only selected ignored test was the new publication-cost observation. Listing
that test is not executing it. The M06 test ELF was only located, not executed or
qualified for this newer head by the registry check.

Raw [complete registry stdout](workflow-node-registry-all.stdout),
[stderr](workflow-node-registry-all.stderr),
[ignored registry stdout](workflow-node-registry-ignored.stdout) and
[stderr](workflow-node-registry-ignored.stderr) remain byte-for-byte copies.
[Copy integrity](copy-integrity.json) records the source and destination SHA-256
for all eight copied inputs, including the original static-check script.

The later [thirteen-control static check](catalog-fence-static.json) is separate:
it checks the candidate workflow counts 13 / 36 / 104 and all thirteen source
names, with 19 synthetic reader cases. Its [receipt](catalog-fence-static.receipt.json)
records the helper command, script digest and byte-identical retained report.
It does not extend the earlier ELF's twelve-control registry or assert native
execution on the later source.

The subsequent [pin-checked static report](catalog-fence-pinned-static.json)
additionally verifies all sixteen actual Git blob pins in the retained recent
source step. Only the reviewed `store.rs` and `native_authenticated.rs` literals
differ from the comparison base; the path list and all other bytes of that step
match. Its [receipt](catalog-fence-pinned-static.receipt.json) identifies the
updated helper and retained output. Both thirteen-control reports remain static
checks, with the new native registry still separate.

## Auxiliary static replay

[workflow_wiring_static.original.py](workflow_wiring_static.original.py) is the
unchanged script that produced the historical static report. Its original
scratch paths and then-current `HEAD` comparison are retained for provenance.
[workflow_wiring_static.py](workflow_wiring_static.py) is a separately identified
parameterized derivative for replay from a checkout with Python 3, PyYAML and
Bash. It defaults to the repository containing this directory and comparison
base `73ab6e9a83bcc836e261d93f9bb23ceafe556758`:

```sh
python3 evidence/pon-throughput-continuation-20261104/parent-and-tail/ci/workflow_wiring_static.py \
  --expected-pre-write-count 13 \
  --output-dir /tmp/trnm-workflow-static-replay
```

Use a fresh output location. The count flag defaults to the historical twelve;
the example checks the next thirteen-control candidate, which adds the final
catalog-fence control. The retained twelve-control report and old ELF registry
remain unchanged and do not qualify that candidate. `--repository` and
`--comparison-base` can be specified explicitly. The helper records its comparison
base, expected count and workflow hashes
in a new report. It permits only literal source-pin hash updates on the existing
guard commands: the old and new path lists must match, every new literal must
equal the actual `git hash-object` result, and every other byte of that step must
match after normalizing only those hashes. Other retained steps must match.
It executes shell syntax and synthetic reader checks, never Cargo,
native tests, timing observations or an old ELF. Later intentional workflow
changes can require a new comparison base or an updated static checker; they do
not rewrite the retained report or grant native acceptance.
