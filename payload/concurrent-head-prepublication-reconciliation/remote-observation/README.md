# Concurrent candidate advance: one read-only observation

The six read-only queries were issued once in parallel; compare/commit results needed no additional pages. Git's full heads advertisement and PR847 independently report candidate 5a4b7fe8de1adce803184f262fd9f704ead1930c. Main remains dd6e1c3cbeacbdc532b0679297835b3a0aac78f0. The requests form a bounded non-atomic time window and do not lock refs or protection.

The original summary preserves a local baseline-parser KeyError (the frozen manifest stores sha directly). frozen-map-difference-overlay-v1.json corrects the normalization from the same immutable original manifest and same raw advertisement; it makes no further network request. This is a genuine remote candidate advance, not just a discrepant PR API value.

Commit and comparison JSON were projected by the recorded gh --jq queries to retain identities, parents, trees, author/committer, messages, stats and filename/status/change metadata; patch bodies were not retained. Commit API identifies 5a4's two-file tip change. C0..5a4 compare reports 14 ahead commits with C0 as merge base; these are graph differences, not a claim that all commits were newly authored after C0. Recent push events are only the first 100 repository events and may lag; their absence cannot prove no push.

No fetch, source/ref/object edit, publication, PR change, CI trigger, rerun or cancellation occurred. The old archive's current advertisement and new execution tag absence are recorded for this observation only. The earlier b9cc missing-object observation is not rewritten by its current remote tag advertisement.
