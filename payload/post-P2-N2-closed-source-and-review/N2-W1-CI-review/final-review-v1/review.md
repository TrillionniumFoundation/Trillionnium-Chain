# N2 W1 CI static compatibility review

Decision: accept the three exact N2 blobs. P2 is byte-identical to N for all three paths, so this selection does not overwrite a later same-path P2 implementation.

The rank job corrects its stale count from 14 to the existing independent 19-name factorial-kernel roster and invokes the strict named validator. All original commands, budgets, source identity checks, and head/prospective selection remain unchanged. Batch controls remain nine.

The clock guard now checks the original absolute endpoint rather than additionally constraining a rounded subtraction. The producer computes min(started + wall_seconds, common deadline). Exact duration subtraction, strict completion before the endpoint, finite/nonboolean values, common 120-second report deadline, cancellation and settlement requirements remain enforced. The legal float roundtrip is paired with three explicit rejection subcases.

The file has 31 existing test methods in both revisions. Thirty methods have identical source and AST; the one existing clock method retains its original checks and adds the four cases described above. No tests or native workloads were run by this review, and it establishes no 4-second campaign qualification.

The adjacent review.json records exact selected blobs, source hashes, named roster and fixed revision identities. Parent source/consumer/producer indices and the 4,368-byte diff remain unchanged.
