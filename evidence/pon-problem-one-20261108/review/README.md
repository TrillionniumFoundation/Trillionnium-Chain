# Independent Problem 1 review

The unchanged `independent_review.py` enumerates 729 assignments of three possible work labels to six successful reception rows across two receivers. It compares anchored and unanchored results with separate constraints derived from the fixed experiment packet roster. The anchored reader accepts exactly one assignment; the structural reader accepts six injective assignments. All rejected assignments retain costs and attempts and produce no chainwork.

The same script also checks a valid service completion, branch reorganization, and ordinary generic budget close. The first reviewed patch incorrectly reported no reconciliation even though original local completion and current branch monetary outcomes differed. `service_work_reviewed_snapshot.py` retains the exact pre-correction source. The unchanged check reports the failed requirement in `independent-review-before-owner-correction.json`; after the correction it passes in `independent-review-after-owner-correction.json`. Both record exact SHA-256 inputs and stability across execution.

These are finite synthetic accounting checks, not new native campaigns, cryptographic authenticity, physical cost lower bounds, external customer demand or a task-supply liveness theorem. No source implementation was modified by the reviewer.

Reproduce from a checkout containing the reviewed dependencies:

```bash
python3 -B independent_review.py --root /absolute/checkout --service-source service_work_reviewed_snapshot.py --output /absolute/new-before.json
python3 -B independent_review.py --root /absolute/checkout --output /absolute/new-after.json
```

Output files must not already exist. The before record deliberately contains a false requirement result; preserving it documents the review correction.
