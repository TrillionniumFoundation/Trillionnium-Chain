# Exact source-binding repair validation

Executed source: `8079efb7bbc121688f15c4327b2bc286e26845c3`, tree
`68182c8bcac37fe8e6493bf350f0ec0f1bae5f3d`.

All ten recorded commands completed with integer exit zero and identical
complete tracked-source observations before and after each command:

| Original complete suite | Actual tests passed |
| --- | ---: |
| CI contract | 177 |
| Lifetime budget | 58 |
| Raw source integrity | 43 |
| PQ source integration | 59 |
| Chain claim guard | 55 |

Lifetime, corpus and claim inspectors, distributed source inventory and the
complete repository/link gate also passed. The corpus contains 1,076 pins and
984 required paths. No Rust tests were rerun in this Python/configuration
campaign. Original native runs remain attributed to `81f89b01` in the
[hosted evidence](../pq-cell-retained-key-20261110/README.md).

Each command's original JSON receipt retains its command, actual exit, complete
source identity and raw-log hash. Logs are losslessly compressed;
`gzip-originals.json` supplies their original names, lengths and hashes. The
initial staged observations in the earlier packet are not added to these
counts or relabelled as executions on this committed source.

## Independent retained-byte check

The retained verifier and its report checked the complete original evidence
directory: 58 listed files plus the manifest, 55 selected members, 16 gzip
originals, all seven downloaded ZIPs and 908 member hashes. Four original Rust
shard commands, successful integer exits and unchanged head/merge source
records match. The new 1,159-byte doctest fixture equals the original retained
member; both historical fixtures remain unchanged. The runtime Git subtree at
`8079efb7` equals `81f89b01`. This does not authenticate independent execution
or sum the 437 child/parent harness summaries.

From a checkout retaining these objects and original evidence, run:

```sh
python3 evidence/pq-cell-retained-key-repair-20261110/verify_pq_cell_evidence.py \
  --root . --candidate 8079efb7bbc121688f15c4327b2bc286e26845c3 \
  --output /tmp/pq-cell-evidence-verification.json
```

`--downloads` optionally verifies the complete downloaded ZIPs as well; they
are identified by the original packet's archive index and are not duplicated
here. The report retained here includes that additional check.

## Concurrent target advancement

The target branch advanced from `ac8501a` to
`da1374a200022bc14dc2bd325cc9ba29dbcd24ab`, producing a PR merge conflict and
zero new hosted runs on `8079efb7`. The live-ref and PR observations are
preserved. Integration preserves both real Git parent lineages, the updated
campaign reader and declared custody review, and both test/documentation
changes. The combined descendant requires its own source-bound validation;
these `8079efb7` results are historical for that descendant.

**HOLD_NO_GO:** no Cell performance or model-quality gain, independent custody,
physical recovery freshness, actual external-effect integration or complete
PQ lifetime/QROM qualification follows. Bounds remain null and production
activation remains false.
