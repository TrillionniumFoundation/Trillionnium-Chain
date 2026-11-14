# Exact dc42 failed Linux repository-truth original records

This directory contains 37 original files copied read-only from the explicitly requested ROG lane directory: 34 stdout/stderr streams for 17 steps, summary.json, and source-before.json/source-after.json. The original summary contains the step list; no separate steps.json was present, and none is synthesized.

Each source file was read through the configured binary API with a fixed file version and independent chunk SHA256. Every Mac destination was created only if absent. All 37 final sizes and SHA256 values match the original summary or the fixed source-read receipt. The two original source-verification receipts are identical.

The original lane failed (exit 1) on exact dc42; its repository-truth child elapsed 6.677 seconds under the unchanged 2700-second bound. Source verification succeeded before and after. Copying these records grants neither a passing full lane nor hosted qualification.

No ROG shell command, ROG archive operation, source or Git ref write, test rerun, repair, or Host workload was performed for this copy. The initial multi-file read requested an absent steps.json and was rejected as a batch; this is recorded in expected-whitelist.json and did not modify or fabricate originals.

copy-verification.json, transfer-receipts.json and EVIDENCE_INDEX.json are new transfer metadata, not original lane output.
