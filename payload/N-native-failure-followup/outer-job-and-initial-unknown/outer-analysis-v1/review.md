# N x64 cross-cost: original outer-log boundary

This is a new N sample, run 43582713392 / job 132415017426 / head 5a4b7fe8de1adce803184f262fd9f704ead1930c. The original complete job log was obtained through one bounded official gh GET and retained unchanged (184,799 bytes, SHA256 154555d87f24fbaed2609d14b18837c228256c65af29633eb42f611b9e291c81). HTTP headers were not requested; completeness is based on the actual gh exit 0 plus both stream EOFs, not an invented provider log digest.

Both newly observed cost jobs failed step 12, Execute exact native from-zero service controls. The x64 step ran 10:15:55–10:21:40Z; arm64 10:15:43–10:21:14Z. The x64 original log shows the protected host controller invoking run_from_zero_native.py. Its controller record at line 1355 reports no host/controller failure, no final host errors, successful format/compile preparation without timeout, and systemd_run_exit=1. Line 1356 reports the step's exit 1.

The native inner error is absent from this outer stream. This evidence does not prove CONFIRMATION_TARGET, actual four-second/sixteen-worker execution, or a particular CPU/performance defect. Native source-before/after bytes also remain unread. The one relevant artifact explicitly named by the original upload log is 14109658844, 9,884,207 bytes, upload digest 10447497968910ffe69e51bd541f6dfe988293a86a2ab583120f3a25788c40b4. Its metadata must be checked before any separate authorized retrieval; no artifact has been requested here.

No source, stage, refs, CI execution or remote state was changed. No C0 archive or older log was downloaded.
