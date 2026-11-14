# P1 final metadata and documentation closure: independent review

P1 `6a8cd55573065ceb50cdb65a7834615f79b521ae` has tree `cbd6b4552c87af27c72c0189806baeb33ecb8bf5` and sole parent M8 `ed0d35487f2a67239e4d646fd41c2c7acb5cc740`. Its actual immutable Git diff matches the author's 37,875-byte final patch, apart from display-only index abbreviation. Exactly ten regular 100644 paths changed.

## Finding

Source and current metadata closure are correct. One historical-run reporting sentence requires correction: the appended audit document says “53 passed, one failed and four errored.” The original stderr says **Ran 58 tests; failures=1, errors=4**. Two error events belong to subtests under one method, so subtracting all five events from 58 methods is invalid. The raw stream has 54 top-level “ok” methods.

Use the exact original result: **“Ran 58 tests; failures=1, errors=4, including two subtest errors in one method.”** This concerns historical reporting only. It does not affect the 58-method roster, later 200 current-consumer passes, source, probabilities, limits, source identities or qualification. Root has accepted a narrow normal successor documentation correction; this receipt does not assert that the successor exists yet.

The preserved raw stderr is `/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1/current-consumer-validation-v1/original-frozen-budget-58.stderr`, 16,485 bytes, SHA-256 `6fc70d6c1b733db71a2a70514f2f07f09daec6e86c7410d6cb337abde2b4b523`.

## Independent immutable-source checks

- Frozen V1 budget, V1 source lock and V2 composition are byte-identical to M8. Their original 0315e07c…, 094dcae8… and 5b527fbd… SHA identities remain intact.
- Every one of the current map's 21 paths was read from both immutable commits. Exactly PublicV3 changes; all 20 other bytes and hashes remain unchanged. Its committed source equals the previously reviewed 438,782-byte `0fd32665…` candidate.
- The raw current map SHA is `4f234fbff89fdf5693b4d7b82676a46574f92e297fdd535101110a76b9abb3e0`. Independent canonical serialization of the 21-path map produces `e8b0d9ceb227e95a045cee1b9224719c8b9ac9c416f8f503218bfee0160d57dc`.
- Typed JSON comparison finds exactly two correspondence fields and two current composition fields changed. Each of the two readers changes only its two corresponding string literals; normalized AST and all other source text are identical. Mathematical rules, exact field/type checks, fixed paths, caps, historical identities and false qualifications are unchanged.
- Corpus changes only eight existing Git OID pins, each independently equal to its P1 blob. Required paths and all other data are unchanged.
- The audit and sole plan are append-only. The two security documents change only the two current digest strings, without rewriting historical narrative.
- The original six Python control files for 58/25/60/57/7/33 are exactly equal to M8. Current-consumer-v2's five source inputs and final-contract-v1's ten source inputs are unchanged across their respective runs and exactly match committed P1 bytes.

## Closed execution receipts reviewed, not rerun

All 23 selected raw streams (145,824 bytes) were read with stable regular-file/size/SHA checks. They support these separate facts:

| Receipt | Actual bounded outcome |
|---|---|
| Mac Rust build | 11 existing Darwin fixture compile errors, zero executed Rust tests, HOLD |
| Independent Linux serial | Three new controls and the original golden pass under RUST_TEST_THREADS=1; strict Clippy passes |
| Independent Linux default followup | Same three and one controls pass under the declared default harness; Clippy is not repeated |
| First Mac budget invocation | Ran 58; failures=1, errors=4, including two subtest errors in one method |
| Canonical temporary directory followup | 58 + 25 + 60 + 57 methods pass, zero failures/errors/skips |
| Policy / Hash-use | Original 7 and 33 pass |
| Actual current inspectors | HOLD and activation=false |
| Actual corpus | HOLD_NO_GO and node_activated=false |

Linux's retained SQLite I/O warning about a nonabsolute RUSTC is present in the original streams. No SQLite/native qualification follows from the component controls. The original producer identifies the Linux source as M8 plus the exact uncommitted one-file proposal; it is not falsely relabeled as a full committed P1 campaign.

The Hash-use reader still declares 19 uses and 31 sources and does not select PublicV3. A pass does not prove complete callgraph coverage. Structural prefix savings and successful component tests do not establish a four-second performance improvement or hosted qualification.

No tests, project helpers, source edits, Git writes, stage writes or network queries were performed for this review. The first inspection parser's 53-count assertion failure is retained; it exposed the documentation mistake and was corrected only in the external read-only analysis.

## Evidence

`static-metadata-closure.json` records all ten old/new blobs, all 21 source rows, frozen files, typed deltas, reader AST comparisons, corpus pins and receipt-to-P1 mapping. `closed-log-documentation-review-v2.json` records the 23 exact raw stream identities and parsed observations. `final-review.json` contains the final scope and single finding. The original execution logs remain at their closed producer locations and are not recopied here.
