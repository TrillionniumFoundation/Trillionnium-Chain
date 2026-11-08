# Base 9417 historical-cache static review

Reviewed immutable base 9417e495165865ef6c1288b39084856e31020634 against direct parent 91c1b7da0f0b1f41c088d9ac0b2ee160b550b80c. This is a narrow source review, not execution qualification of the later C8 merge.

No specific new correctness issue was found in the reviewed eviction-preference delta. The Legacy snapshot anchor and its first six replay descendants may be preferred for retention, but the cache still has at most eight entries and seven preferences. A changed anchor clears preferences, and byte budgets override preferences.

An entry is selected only by exact block and the current SQL root. Both historical replay and execution parent binding still validate the supplied actual State. The unchanged-candidate helper canonically encodes and compares every actual key/value on a hit; a difference returns to the original full preparation path. The final computed root is compared with the fresh expected root. Internal tree mismatch preserves the full-root fallback. No cached State or validity result is returned.

The source retains snapshot canonical-byte checks, delta before-value checks, continuity, progress/cancellation, SQL damage and rollback checks, and final-writer failure without block publication. The added assertions cover an 18-block replay, a fresh SQL snapshot anchor, a fork and the original branch, warm/cold cancellation at the same twelfth checkpoint, retention rotation and byte-pressure eviction. They extend two existing tests: the module still has ten test methods and no ignored methods. No test or Cargo command was run by this review.

The 2 MiB payload and 16 MiB retained accounting limits describe optional software material. They do not bound total Node RSS or establish complete process-tree resource accounting. This review establishes no performance, 4105-block History deadline, deployment, cryptographic or protocol qualification. Exact C8 source and its original controls still require separately recorded execution.

Raw immutable Git-object copies, original parent diff, command provenance and successful read-helper terminals are retained. All repository source worktrees, frozen C6/C7 evidence, source guards and operations were left unchanged. See summary.json for the reviewed scope and suggested exact-source test filter.
