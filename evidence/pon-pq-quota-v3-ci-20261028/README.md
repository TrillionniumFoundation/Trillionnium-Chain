# Actual NPQ3 and retained NPQ2 CI: runtime passed, strict Clippy failed

The exact published source is `809b012a92e319f1932c2e15852e9ebfc12fdddc`,
tree `351f941cd4b9266eaea752d5d8121e037b8f9be4`, in draft
[PR 527](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/527).
Its tree is identical to the retained local source `194f641264ba5c6fa073a3cfe90c6eb5ea3abba2`.
The full-source checks before and after both actual runs verified all 5,942
tracked entries and 769,464,014 bytes. They did not execute tests themselves.

| Original run | Actual runtime results | Overall terminal |
| --- | --- | --- |
| [NPQ3 40615932201](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615932201) | Six new M06 cases; four new Node cases and nineteen actual complete-W1/reference/admit/SQL phase observations; retained NPQ2 capacity 2, Node 9 and NPQ1 Node 6 all passed, with no ignored new cases. | **FAIL** at warnings-denied Clippy. |
| [NPQ2 40615932239](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615932239) | Retained NPQ2 capacity 2, Node 9 with 196 phase observations, and NPQ1 Node 6 all passed. | **FAIL** at the same warnings-denied Clippy diagnostic. |

Both runs also passed the complete selected M00 library (46 passed, 2 pre-existing
ignored observations) and M06 library (88 passed, 6 pre-existing ignored
observations). Neither ignored count is a new-case success. All actual command
records retained their exact source fences. The
[machine receipt](original-failure-receipt.json) records the command outcomes,
required executed names, artifact and executable hashes. Both downloaded ZIPs
passed their advertised SHA256 and every ZIP member's CRC; every internal
artifact hash and each retained decompressed native executable hash was checked.
The original ZIPs, complete job logs and manifests remain in the publication
archive; the original artifact IDs are in the receipt.

The [NPQ3 raw Clippy diagnostic](npq3-clippy.log) and
[NPQ2 raw Clippy diagnostic](npq2-clippy.log) identify the same manual saturating
subtraction in `migration.rs`. The successor replaces the existing unsigned
`if deadline > source_height { deadline - source_height } else { 0 }` expression
with `deadline.saturating_sub(source_height)`. Existing future-deadline and
liability checks stay in place. This is the same arithmetic for less-than,
equal and greater-than inputs; no migration, consensus or signature domain is
changed. No lint allowance, test assertion, native selector, reader or budget
is relaxed. This repaired source still requires its own actual original CI.

The retained [M06 log](npq3-quota-authority.log),
[Node log](npq3-native-quota.log) and
[nineteen phase records](npq3-native-quota-phases.json) are results of the failed
original workflow, not a successful workflow or an execution of the later
repair. They establish the finite quota composition only. Other authority
owners, independent migration trust and source retirement, physical I/O,
whole-chain PQ, full P1 and production activation remain unqualified.
