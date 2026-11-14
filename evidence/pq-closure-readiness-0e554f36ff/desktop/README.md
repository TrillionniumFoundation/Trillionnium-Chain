# C2 desktop readiness observations

This packet preserves the independent desktop validation of commit `0e554f36ffdde3053a5eb1756eb5e526b1935032`, tree `753cdbad6714f00d8ccb9ddbb47f0fd71280ee62`. The full 71-test readiness suite completed successfully with real GNU time available. The primary runner still failed because its inventory command contained an incorrect pathname. A separate, bounded supplemental observation executed the correct inventory command successfully. The original failure remains unchanged.

## Observed results

| Observation | Result | Retained record |
| --- | --- | --- |
| Primary desktop preparation | 18 commands: 17 exit zero, inventory command exit 2; original `all_commands_passed: false` | `primary/summary.json` and `primary/failure.json` in the archive |
| Readiness suite within the primary observation | 71 unique outer tests completed, 71 successful, no skips; terminal `OK`, process exit zero | `primary/public-readiness-tests.receipt.json` and original stderr |
| Supplemental inventory correction | Correct path and both surrounding source checks exit zero; three commands total | `supplemental/summary.json` and per-command receipts |
| Source observations | All four before/after JSON records are byte-identical and identify C2 as a head checkout | `primary/source-before.json`, `primary/source-after.json`, and corresponding supplemental records |
| Protected original checkout | Original C1 commit, tree, branch, HEAD-file digest, index digest, and clean status were unchanged through these observations | Original C1 before/after records in both archive sections |

The incorrect primary command was `python3 -B scripts/ci/refresh_distributed_source_inventory.py --check`. The supplemental command was `python3 -B scripts/refresh_distributed_source_inventory.py --check`. The supplement did not rerun the 71-test suite or rewrite the original records. Its `combined_required_publish_validation_complete: true` describes the two retained observations together, not an uninterrupted all-green original run.

The earlier [cloud observation](../cloud/README.md), including its three GNU-time environment errors, remains a separate observation. This packet does not change those results.

## Exact source and execution identity

The protected native C1 checkout was `/home/qian-qi/work/chain-pq-closure-20261111-d4d2`, at `c09dbbe9921da12db8bf7240a8a95a0e9a789e50`. The validation created an independent full shared clone at `/data/chain-pq-closure-20261111-d4d2-publish`, with its own HEAD, index, and worktree, then imported and fast-forwarded the supplied C2 bundle. Object sharing is documented in `primary/object-sharing.json`. The original native checkout was not fast-forwarded by this task.

The four retained `verify_ci_source.py` results each report **27,912 tracked entries and 2,554,108,569 tracked bytes**, with `tracked_worktree_verified: true`, tested head C2, and no prospective merge identity. These are retained results of the original full-source verification. This compact archive does not contain a copy of the 2.55 GB worktree, and the portable verifier does not re-execute that scan.

The 71 actual success IDs were parsed independently from the original unittest stderr and matched to both the original receipt and the exact C2 test-source AST. The source roster identifies `scripts/ci/test_public_readiness_evidence.py`, Git blob `ba6c3badfcd5f173bce619b51c84334eeb9e866d`, 120,969 bytes, SHA-256 `a5d6d7cc039b85d4c49865fec5866e7891d967446b35a145a66bf66825875696`. Nested subprocess controls are not counted as additional outer tests.

The original observations preserve Python, operating-system, selected environment, GNU-time binary/version, and five OpenSSL provider-file identities. The provider record is host dependency context. This packet contains Python/source gates and no Rust native workload results.

| Durable H job | ID | Idempotency key |
| --- | --- | --- |
| Primary preparation | `1a1c9047868-135c4-37f` | `pq-closure-c2-publish-validate-0e554f36ff-d4d2` |
| Inventory supplement | `1a1c908b0f1-135c4-39d` | `pq-closure-c2-inventory-correction-0e554f36ff-d4d2` |
| Original-byte packaging | `1a1c90c7cf9-135c4-3a8` | `pq-closure-c2-desktop-evidence-pack-0e554f36ff-d4d2` |

The primary summary was finalized at `2026-11-11T05:14:48.177366+00:00`; the separate supplemental summary at `2026-11-11T05:16:09.934222+00:00`. The H read receipts retain lossless stdout/stderr byte ranges. `eof` describes the retained stream extent, not a separately queried process-status result; the original failed runner is evidenced by its `failure.json` and actual traceback.

## Archive and verification

`desktop-originals-0e554f36ff.tar.xz` preserves **110 original files / 167,957 bytes**, plus the packaging index. The archive is **46,844 bytes**, SHA-256 **`3827db21e693108967c13af7d6c79fcd287aa0d591c2e31fb177b62ff5a7c82a`**. Its original H path was `/data/pq-closure-c2-desktop-originals-0e554f36ff-d4d2.tar.xz`. The first and only binary-read chunk had the same size and SHA-256 and reached EOF; its immutable-read version is retained in `h-transfer.json`.

The archive includes the unchanged primary and supplemental receipts/logs, both original harnesses, and the 25,432-byte input bundle. `archive-index.json` records each original path, length, and SHA-256. `h-process-observations.json` preserves upload, launch, and read tool records separately from the original command evidence. No repository files were changed while creating this packet.

To verify the packet without a checkout:

```sh
python3 -B verify_desktop.py
```

To additionally reproduce the roster derivation against an available Git object database containing C2:

```sh
python3 -B verify_desktop.py --repo /absolute/path/to/checkout
```

The verifier checks archive/member identities, exact command order, summary/receipt agreement, each raw stream hash, the preserved original failure, supplemental binding to the original summary, 71 actual unique successful IDs and terminal completion, all four source records, original C1 protection, input bundle/harness identities, and lossless H read cursors. `desktop-observation.json` retains the actual local packet verification and its command. `DESKTOP_SHA256SUMS` covers the delivery files other than itself.

This packet ends before the separate publisher's push or PR update. Its original `push_performed` and `pr_edit_performed` fields remain false. It does not reclassify C1 native results as C2 results, establish whole-chain post-quantum qualification, or authorize production activation. C2's changed corpus pins are compilation inputs for some Node targets; their native validation belongs to separate observations.
