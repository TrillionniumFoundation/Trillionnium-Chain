# N2 metadata integration review

The immutable inputs are N=5a4b7fe8de1adce803184f262fd9f704ead1930c, N2=096c6b5f9b952c49389fd975515744074ba61317, and P2=1e54c4ff66a92827c83bea8715f59f6b299e98cf. N2 has exactly N as its parent and changes seven paths. This review owns four metadata paths; the three W1 workflow/control files are reviewed separately.

## Selected integration

Keep the complete P2 Hash-use JSON and reader. N2 fixes six stale inputs in its own inherited mapping. Five of those are already the same as P2; the sixth is store.rs, for which P2 deliberately retains the reviewed 391,470-byte implementation (SHA256 591827...), while N2 binds its different 391,556-byte implementation (ae54...). The selected P2 source map and the incoming N2 source map each match all 31 of their own actual immutable Git blobs. Retaining P2 keeps its selected source implementation and corresponding H1 identity together.

All 19 use semantics, all 31 paths, the original review-base context, qualification denials, and strict reader checks remain typed-identical. The three reader ASTs are identical after replacing only the one reviewed map-digest literal. No function, mathematical parameter, byte ceiling, source ceiling, nesting ceiling, or qualification flag changes. This is a closed declared-use inventory and does not claim complete-callgraph review.

The distributed-source inventory is already byte-identical in N2 and P2: 1,740 entries, including both current PQ JSON files. No additional inventory edit is needed for these inputs.

Use P2 as the corpus baseline. It has 2,606 pinned blobs and 2,510 required paths. N2's complete corpus would remove the B1 original collector carrier and substitute 40 existing pin values, including the P1 policy-prefix source and current21 correspondence. The supplied external patch changes only the three W1 pins, conditional on selecting those exact independently reviewed N2 blobs. It preserves every other pin, required path, ordering and typed field. It is not applied to a worktree; any later root plan/report edit needs its normal final pin refresh.

## Evidence and limits

The captures include all four full source files at all three commits, exact bounded diffs, typed deltas, source-mode/OID/size/SHA tables, and a content-address-checked batch of 32 unique blobs (1,336,463 bytes) covering the two actual 31-source sets. The old N map matches 25/31 of its actual inputs; N2 and P2 each match 31/31.

All operations were fixed local Git reads and external evidence writes. No fetch, source/worktree modification, refs/config mutation, stage write, repository helper import, test execution or qualification occurred. Full original gates must run on the eventual selected merge, independently of this static conclusion.
