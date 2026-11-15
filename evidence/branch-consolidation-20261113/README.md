# Historical raw records retained during branch consolidation

Status: **HOLD — historical records only**.

The [custody manifest](raw-records-manifest.json) maps ten original files to their unchanged raw bytes. It records the source commit and path, original Git blob and mode, raw path, SHA-256, and byte length for every file.

Eight original execution captures contain zero bytes. They are retained as `.json.raw`; they are absent JSON output, with no result invented or substituted. Two original Markdown documents contain references from their historical source contexts. Their original bytes are retained as `.md.raw`, and their `.md` paths now contain explicit HOLD indexes linking to those bytes.

The original branch heads remain in the merge history. All original manifests, logs, errors, and companion records remain unchanged. Historical manifest path and hash entries describe their original snapshots; the custody manifest provides the explicit current storage mapping. An index at an original Markdown path is a new document and is not the historical source document.

The repository checker is unchanged. Raw preservation does not confer runtime, security, release, or production acceptance and does not change any original failed or held observation.

## Preserved original files

| Original path | Raw bytes | Length |
| --- | --- | ---: |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-head/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-head/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-head/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-head/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-merge/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-merge/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-merge/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-arm-merge/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-head/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-head/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-head/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-head/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-merge/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-merge/admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner.execution.json.raw) | 0 |
| `evidence/pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-merge/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json` | [Raw file](../pon-pq-system-continuation-20261101/hosted-initial/workspace/original-x64-merge/authenticated_large_parent_original_schedule_supplementary_denominator.execution.json.raw) | 0 |
| `evidence/pon-pure-workpackages-20261027/successor-readback-20261027/codeql-review.md` | [Raw file](../pon-pure-workpackages-20261027/successor-readback-20261027/codeql-review.md.raw) | 51333 |
| `qualification/pq-hardening-source-review-20261110/identity/PQ_BOUNDARY_HARDENING_20261110.md` | [Raw file](../../qualification/pq-hardening-source-review-20261110/identity/PQ_BOUNDARY_HARDENING_20261110.md.raw) | 30415 |
