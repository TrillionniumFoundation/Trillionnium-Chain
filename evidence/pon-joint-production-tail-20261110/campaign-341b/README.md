# Source341b original campaign: complete report recovery

Original [run 42815422144](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42815422144)
artifact **13779423325** has now been downloaded completely: 71,446,778 bytes,
SHA256 `b02a44181e54f57c834a37ffd7d6726f98b23c51b81e0b800d12e8c536c2d96f`.
Its 1,766-member directory is retained. This supersedes the preceding packet's
statement that only the artifact census had been recovered.

The complete three original reports, all root-level small receipts/logs and
three failure records are retained losslessly as 56 deterministic gzip members.
The full original ZIP, databases and executable are not duplicated in Git.
`supporting-receipts.zip` stores the small gzip members; three complete report
gzip files remain separate. The original report bytes total about 129 MB before
compression; no report was truncated or normalized. Only bytes/JSON were read;
no archived command, executable, database, input workload or campaign was run.

Build succeeds; **all three original attempts exit 101**, complete success 0/3.
Each attempt records no phase startup errors and no report validation failure.
Independent arithmetic from each full report agrees with its original phase
readback:

| Phase | Confirmed / scheduled rounds | Observed / scheduled rounds |
| --- | --- | --- |
| baseline | 1 / 3 | 2 / 3 |
| from-zero | 0 / 3 | 1 / 3 |
| late-product | 0 / 3 | 1 / 3 |

These same counts occur in all three attempts. Each phase window is 30 seconds;
all nine phase criteria are false. Unobserved scheduled rounds remain
unobserved, not successful or independently diagnosed failures. These are
confirmation rounds, not unique transaction TPS, CP/CG/CQ probability trials or
an all-legal-strategy theorem. No unique cause is inferred from aggregate
failure, elapsed time, receiver timeout or missing later observation. Concurrent
#880/#884's History-boundary diagnostics remain separately scoped; no helper
change or failure classification was copied into this branch.

All campaign source receipts bind tested source
`341b7b6195a44d3f4a758c98f846457567ac1de3`, tree
`eb37d4499ca92121a81ef9c0af1e7b221d5f85b1`. The retained 12,601,232-byte
executable in the original ZIP was hashed, without executing it, and matches
the before/after SHA256
`a1b0c4e61d46e5e59187b3fd2620cdc24f66fb8905d1c43ab81b619055601205`.
No rebuild or new native execution is claimed. Controller and per-phase Host
budgets retain their original separate records; they are not conflated.

Run `python3 verify.py` for retained-member/hash and raw-report arithmetic
consistency. Add `--original-archive /path/to/13779423325.zip` to independently
verify the complete ZIP digest, exact retained member equality and executable
hash. The default check does not claim possession/authentication of the omitted
original ZIP or binary. The manifest excludes itself. Failed attempts, original
argv, raw stderr/stdout and report digests remain unchanged.

No source, pin, threshold, acceptance rule or production activation changed;
no workflow was manually retriggered and no ROG task resubmitted. All 13 actual
joint obligations remain open; native CP/CG/CQ, six-successor and lifetime
bounds remain null, qualification **HOLD_NO_GO**.
