# Lifetime query-tail accounting observations

Status: HOLD / NO-GO. No actual cryptographic bound or activation is established.

The execution source is local Git commit `6b9495d0c712040d4426895037d6ca6201f9af49`, tree `cfd4aa6c66b86e8445162100fc221cf9d4e629f2`, based on #844 at `f0b9c984ea8e9b8d0139a63495d9c41bc70b60e9`. Publication may use different commit metadata; source-tree equality is checked and earlier execution is not relabeled.

Six complete Python suites passed 369 tests: composition 57 (original 36 plus 21), legacy budget 58, root register 42, claim guard 49, CI contract 108, and PQ source integration 55. The normal composition inspector passes with all actual bounds unknown. The source inspector was rerun after exact retained README materialization and passes with 775 source pins and HOLD. Hash snapshots before/after the API-materialized execution agree, and tracked state remains clean.

First macOS execution remains failed. Default temporary directories traverse a symlink and the source reader correctly refuses those fixture paths; no source-reader check or assertion was relaxed. A real TMPDIR under the task work directory permits the same tests. Sparse checkout omissions were materialized from exact committed Git blobs; direct GitHub retrieval failed and API retrieval/connector transfer retained byte identities. The first source-inspector refusals and failure logs remain in the archive. The initial Python 3.9 preflight failure is also retained by HeptaRuntime job `1a1c430440a-cf39-16b`; subsequent work uses installed Python 3.14. Source/validation job identities are `1a1c434e184-cf39-188`, `1a1c438f546-cf39-1a7`, `1a1c43cf74b-cf39-1bd`, and `1a1c4424d93-cf39-1da`. Interrupted transient-workspace observations are not reused as committed-source passes.

The nested Linux observations are separate materialized-subset observations, including their initial missing-example refusal and later 206-test pass. They are not an independent full-repository or native qualification.

`observations.tar.gz` retains complete original record files. `files.json` lists every member's length and SHA256; each member was reopened and compared byte for byte. `qualification.json` preserves the required null/false fields.

Rust, wire formats, keys, original native acceptance workloads and authority are unchanged. Native workspace tests, strict Clippy, original campaigns, external custody, production gates, concrete lifetime/query bounds and shared-oracle/event-coverage proofs are not requalified by this Python continuation. Existing failures remain unresolved.
