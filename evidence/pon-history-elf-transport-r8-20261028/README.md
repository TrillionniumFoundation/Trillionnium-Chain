# History ELF preservation receipts — 2026-10-28

**The two authorized transport rounds preserved all nine original ELF paths as
eight exact gzip payloads. Three cached artifacts retain an explicit `UNKNOWN`
source binding. No new native test, build, PQ or service qualification is claimed.**

This small package records the original preservation operations. Its
[summary](transport-summary.json) binds every original path, size, SHA-256,
mode, device/inode, timestamps, compressed path and compressed SHA-256. The
[raw receipt ZIP](raw-transport-receipts.zip) preserves all 26 small source
receipts, plans, scripts, per-file verification records and terminal results;
the [member manifest](raw-files.json) gives the exact bytes and SHA-256 of each
member. All ZIP members were fully read back and checked.

The eight ELF gzip payloads themselves remain at the paths in the summary.
They total 228,569,814 bytes and are deliberately separate from this 62,581-byte
receipt archive. Every gzip was hashed again during collection. The original
transport receipts record complete decompression, exact expanded length and
SHA-256 equality before each raw unlink; collection did not repeat those large
decompressions or execute any recovered ELF.

## Source identity and its limits

| Original path under the History target | Source binding retained |
| --- | --- |
| `history-r8-baseline-189ba3-node` | Clean `189ba3adfd9a22c7cfc1537eab535e9eb7c442df`, tree `ff572fb27e4fb5df9a80b3e2ec5096c697964200`; original input manifest and execution receipts |
| `history-r8-candidate-node` | The same base **plus the recorded dirty source manifest/diff**; original failed candidate observation retained |
| `history-r8-candidate-corrected-node` | The same base **plus the corrected dirty source manifest/diff**; no clean final-commit build is asserted |
| `debug/deps/trnm_pon_node-e4b33f49275e9dec` | Exact same bytes/SHA as the corrected r8 artifact; its existing gzip was fully reverified and reused |
| `debug/deps/trnm_pon_node-9e86f7cb7a9d0a67` | Original compilation `2e5240e62d450f34ee39fb3dec95bb81fd2d8288`; identical measured artifact at `48aa81da0435e55504503b25ccaaf58db013d94f` |
| `debug/deps/public_v3_multiprocess-b925461c415cbaf8` | Exact original deadline-correction artifact record; its enclosing manifest records final executable source `fe43f7c7f8971df37cbb7eda7080dac8ae4887aa` |
| `debug/deps/trnm_pon_node-08929c1b7ad6a8fb` | **UNKNOWN**: no exact source-to-ELF mapping found in the retained receipts searched |
| `debug/deps/public_v3_service_campaign-e481bec33ffabc71` | **UNKNOWN**: no exact source-to-ELF mapping found in the retained receipts searched |
| `debug/deps/trnm_pon_node-71eea7016073a858` | **UNKNOWN**: no exact source-to-ELF mapping found in the retained receipts searched |

Compiler-generated filenames and timestamps are not treated as source proof.
All historical source observations remain historical; none qualifies the current
PQ cancellation candidate. The summary records collection at `7c324398041d05e14c80a7d3a973991de69fbabe`
only as the packaging source, not the source of these old binaries.

The original native measurements, failures and controls remain in the
[History checkpoint package](../pon-history-checkpoint-r8-20261028/README.md)
and the retained `pon-history-owner-next-20261027/phase-qualified` receipts.
Their six source receipt files were byte/hash checked during this collection
and copied into the ZIP without modification.

## Actual transport costs and storage observations

| Round | Paths | Wall time | CPU time | Peak RSS | Observed available-byte change |
| --- | ---: | ---: | ---: | ---: | ---: |
| Three named r8 artifacts | 3 | 12.929987 s | 12.876045 s | 15,183,872 B | 1,479,213,056 → 1,767,534,592 B |
| Six explicitly named dependency artifacts | 6 | 19.337260 s | 19.269042 s | 16,363,520 B | 1,872,080,896 → 2,359,648,256 B |

These are concurrent filesystem observations. They are not exclusive accounting
of bytes released by this task. In particular, the 76,400,896-byte
`trnm_pon_node-71eea7016073a858` had two hardlinks. Only its explicitly authorized
`debug/deps` path was removed; `debug/trnm-pon-node` remains at inode 528262.
That unlink did not free the underlying payload. The summary preserves this
distinction and confirms the unapproved alias still exists.

Both rounds used the declared 120-second wall, 45/50-second soft/hard CPU,
256-MiB address-space and 1-GiB free-space bounds. For each regular, non-symlink
authorized source, the procedure completed gzip creation, full decompression
and SHA/length checks, rechecked source identity, persisted the verified receipt,
then unlinked only that raw path. Original source, logs, other archives and the
root PQ/W1 targets were outside the unlink scope.

## Ownership and reproducibility boundary

Root confirmed the History executions were terminal and that other active work
used different targets. Scoped checks found no known task-owned process using
these paths. Some other process executable links were unreadable; the receipts
explicitly retain that limit and do not claim global process observability.

The archived collector never runs an ELF and never unlinks one. Restoring an
artifact for a later authorized test requires expanding its recorded gzip,
checking the expanded length and SHA-256 against the summary, and restoring its
recorded mode. A successful restore alone supplies no current-source or test
qualification. WP2B paid-depletion, original fixed-Host service and independent
WAN acceptance remain open.
