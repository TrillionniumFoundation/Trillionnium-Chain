# Exact legacy evidence reader for current PQ source layout — 2026-10-28

**The source-reader blocker is repaired: all 50 tests pass, with all original
44 test methods retained.** This gate still qualifies only its original legacy
storage evidence. Recognizing the guarded PQ backend in source does not verify
PQ storage, crypto, authorization paths or a public deployment.

## Failure and exact repair

On base `189ba3adfd9a22c7cfc1537eab535e9eb7c442df`, the old reader required a
three-variant `StateBackend`. Current source contains a fourth, guarded
`PqNetworkV1` variant, an exact PQ DDL extension/domain and `pq_network: None`
in ordinary openers. The original 44-test invocation failed with 49 subtest
failures and 18 errors, mostly at `durable backend variants`. Its raw output
is preserved, together with every subsequent failure and correction.

The reader now accepts two complete known source contracts. Lexical code tokens
`PqNetworkV1` or `pq_network` anywhere in the source select the full PQ shape;
the lexical mask removes comments and strings but does not evaluate `cfg`.
Otherwise the complete historical three-variant shape is required. A failed
mapping cannot retry the other branch. Partial enum/impl/owner/module mixtures
therefore fail closed. Source text is not transformed to fit either template.

For the PQ shape, all three literal feature names must exactly equal
`pq-native-openssl`. Every DDL composition and schema-domain literal is checked
separately from masked structural layout. Ordinary and authenticated openers
must select their original backend with `pq_network: None`. PQ peer/request
tables are forbidden in legacy DDL, case-insensitively. Existing owner,
selected-schema rebinding, historical-decoy, storage and artifact negatives
remain in place. See the exact [reader diff archive](../pon-r8-evidence-transport-20261028/original-records.zip).

An intermediate four-variant-only implementation rejected the real historical
three-variant backend when passed to the current helper. That failure is
retained and corrected. The existing `--historical` CLI itself executes the
checker from the measured historical checkout, so this intermediate issue was
a helper compatibility regression, not a regression of that CLI execution.
The final reader was run against the entire unmodified fc23 `store.rs` and
ancestry-index blobs and passed. A separate frozen contract fixture in tests
copies its actual enum, impl and five ordinary opener functions; it is not
constructed by stripping PQ code from current source.

## Distinct immutable schema vectors

Fixing the initial structural blocker exposed a separate old assertion that
incorrectly still treated current legacy DDL as 4,775 bytes. Current storage
already has the exact 629-byte `reorg_lifecycle_v1` line introduced by
`8a35529679c3d176fd7586ab1ecf4e004f25af79`. No production DDL was changed here.

| Source | Exact DDL bytes | Domain-bound schema identity |
| --- | --- | --- |
| Historical fc23, before lifecycle table | 4,775 | `8c2627fa0b06e51742e7e6d40662c61d4b4727e810abc02b24634a8a817dc0e0` |
| Current 189ba3, with lifecycle table | 5,404 | `9cfc36489e0ae98abd0110a9974d5c4f388cab91ebd701f93fba401830fb6658` |

Both vectors use the existing `native-branch-schema-v2` domain and hash their
complete distinct DDL bytes. The frozen historical literals were taken directly
from fc23 Git blobs `97cb5b57e5dd4ad6572f9a619c4df125e7d8d024` and
`ba54ff267db24e7dc1dbbaddf3561ca4b40f58ac`. A separate byte extractor and
independent implementation of the Rust length-framed SHA-256 derivation checked
both identities without calling the tested evidence extractor. Removing exactly
the current 629-byte line yields the historical bytes exactly. The independent
binding and raw DDL files are retained in
[ddl-independent-binding.json](ddl-independent-binding.json) and the archive.

The final tests preserve the historical 4,775-byte/`8c2627…` vector and assert
the exact current 5,404-byte/`9cfc36…` vector. Current real SQLite evidence with
the old identity is rejected for both producer and validator stores. The native
test `old_schema_or_old_namespace_is_refused_without_automatic_migration` also
passed in the separate History package. An old identity is never automatically
migrated or relabeled as current.

## Complete execution record

| Invocation | Actual result | Outer elapsed |
| --- | --- | --- |
| Original reader, original 44 tests | FAIL: 49 failures / 18 errors | 26.432 s |
| First PQ-shape repair, 47 tests | FAIL: 2 old current-size assertions | 162.472 s |
| Corrected two fixed vectors, 48 tests | PASS | 118.515 s |
| Entire actual historical backend through four-shape-only helper | FAIL: variants | 0.383 s |
| Entire actual historical backend through final dual-shape helper | PASS | 0.736 s |
| Final 50 tests, all original 44 retained | PASS, no skips | 119.545 s |
| Existing source-integrity negatives | 34/34 PASS | 2.490 s |

The six added test methods cover exact PQ mapping, literal feature/owner
constraints, PQ table isolation, old identity rejection on current storage,
the independently frozen historical backend, and mixed-generation/downgrade
refusal. Added subcases include wrong/missing/inverted/broadened feature guards,
wrong domains/formats/order/arity, wildcard branches, non-None owners and
comments/ordinary/raw-string decoys. The retained method inventory is in
[retained-test-methods.json](retained-test-methods.json).

All commands and their return codes, timeouts, CPU/RSS and raw stream hashes are
in [commands.json](commands.json). [source-binding.json](source-binding.json)
records the exact tested checker/test bytes. Measurement source is base 189ba3
plus each recorded dirty diff, not a clean committed-source invocation.
[raw-observations.tar.gz](raw-observations.tar.gz) contains full stdout/stderr,
source diffs/manifests, runner and the real historical-blob readback control;
[raw-files.json](raw-files.json) binds every member. The last suite ran with
`nice -n 19` and a 360-second cap in the shared workspace. It did not time out.

No service profile, refill, deadline, proof relation, chainweight, production
crypto or network was changed or executed by this reader repair. Integration
still needs the ordinary exact-commit gates and refreshed source pins. This
source contract is not independent WAN acceptance or evidence that WP3 is closed.
