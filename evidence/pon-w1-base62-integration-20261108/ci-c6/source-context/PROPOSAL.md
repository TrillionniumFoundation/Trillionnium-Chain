# Expected-base proposal status: no code patch

## Observed problem

The C6 run declared event base62 and candidate C6 while the actual PR merge had ordered parents base96 and C6. The original strict guard correctly refused that mismatch. The source-bound failure is established from original logs and metadata; the underlying GitHub state/cache/update mechanism has not been inferred beyond the retained values.

## Current action boundary

Actual CI-context code work is paused. No patch was prepared or applied, no source guard was relaxed, and no old expected value was overwritten. The original event and failed jobs remain unchanged.

The smaller route under independent review is a new C7 candidate that normally integrates the already observed base96 into the head, freezes a new source identity, and receives new CI events. That would be a separate attempt. A new commit alone does not prove a consistent event: the new event's declared base/head/merge, actual merge parents and tested source must be read back and checked before reporting qualification. The clean hypothetical d73 tree is not a substitute for that readback.

## Constraints if a later context-layer change is explicitly chosen

Any new context protocol would require its own source version and new run. It would resolve a specifically named, trusted target repository/branch ref before execution, bind the observation and event provenance to the current run/attempt, and keep the exact guard authoritative. It may not derive an expected base from the actual merge parents, silently prefer a newer value, borrow a context from another attempt, or retrofit C6's original event.

Required refusal controls would include wrong repository/ref, stale candidate, absent expected values, wrong or reversed parents, wrong merge SHA/tree, tampered context digest, cross-run/attempt reuse, and target-ref movement during context acquisition or validation. Unknown or inconsistent observations must remain failures. These are proposed controls only; none was run by this diagnostic task.
