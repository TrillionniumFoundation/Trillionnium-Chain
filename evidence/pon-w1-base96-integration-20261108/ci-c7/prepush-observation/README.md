# C7 pre-push remote observation

This is one bounded, read-only observation. It does not rerun CI, dispatch a workflow, change a branch, patch a source guard, or overwrite the earlier C6 snapshot. Independent Git/API calls are not an atomic snapshot; commands.json preserves the start/end time, exit and raw-output hash for each call.

Observation window: 2026-11-08T08:10:27.088242+00:00 through 2026-11-08T08:10:46.546382+00:00.

Local frozen candidate: 40a3a45d6b8afc5c4706c5235fec47634f4aabbe. Actual target ref: 91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c. Actual PR-head branch ref: 2bdd252aa6c300b7431b9ee897b254b7953cf562. Actual PR merge ref: 7b4a63b6f08687e93270407772951aa71087ca3d.

The PR API base field was 62d2d90c9e1f4c8450c89843f1e08360a24283ce; the API field and actual named Git ref are separately retained. No expected event identity is rewritten from either observation.

C6 query: 105 returned checks, 103 completed, 2 nonterminal. Status/conclusion counts: {"completed:failure": 58, "completed:skipped": 3, "completed:success": 42, "in_progress:None": 2}. Enumeration complete within this read: True. No all-CI-pass claim is made. The query uses filter=all; prior default-latest IDs and transitions are retained separately.

C6-failure-metadata.json preserves every returned failure's metadata, including IDs, names, source, timestamps, URLs and original check output. No full job logs, artifacts or step metadata were downloaded in this observation. New failures are not assigned causes from the old snapshot.

Existing base96 History workflow runs are recorded only by their returned source, run ID, state and conclusion. No individual replica outcome or successful 4105-block business execution is inferred from workflow-level state.

manifest.json pins the published-safe regular UTF-8 files, excluding itself. This external bundle is separate from D4 and from all source worktrees.
