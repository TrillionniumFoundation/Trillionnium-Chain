# Native parent Frontier across its metadata INSERT — 2026-11-18

Research continuation of the original Chain liveness experiment. This source candidate preserves one already verified, bounded subtree Frontier through the private native owner's one passive metadata INSERT. Its real F0 result is **PENDING** at publication. It does not claim four-second acceptance, complete physical cost, independent operators, native Hepta adoption, or production activation.

## Actual failure that remains in the record

The preceding production candidate is [PR #962](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/962), source `1380eaae3c902b3e17d5e5a7d73bf242b0366562`. Its unique original [F0 run 44356270247](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44356270247) observed **1/6 confirmations inside the original 30-second phases and 0/6 within four seconds of their scheduled starts**. Baseline provided the one confirmation; the ROOT phase provided none. All six confirmation rounds and 42 planned business-packet exposures remain in the denominator.

[PR #963](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/963), immutable evidence head `e2c2f4b7f7066357fa0ad4b5af09858c7caacad8`, preserves the provider ZIP, all 443 inventory entries, original and independent readers, original controls and cost dimensions. The ZIP SHA-256 is `ba7317fdbc7da70965c277323ca0a4321ab5692945322bc906c086b92d6bc872`. That failed observation and all earlier failures remain unchanged.

## Concrete loss and the bounded change

The previous helper proved that its native metadata INSERT leaves the complete parent account Root unchanged, then retained the corresponding child whole-Root result. It discarded the original parent's sealed Frontier. A later actual active-tip read with a different account Root therefore had to traverse the full graph again even where the original parent graph had just verified shared subtrees.

The change is inside the existing private `PostWriteReadback::save_publication_record`. Only after all existing old-owner, same-`BEGIN IMMEDIATE`, connection/observer, context, actual parent binding, complete-Root, actual no-account-delta, passive-schema, exact single-write, and new-scope checks succeed, it moves the existing Frontier if `Frontier::is_for(parent.id, &parent.accounts)` matches the same previously verified parent.

The Frontier retains its original source Record.id and complete Root. It is not cloned, serialized, relabeled as the child, grown, or carried to another transaction. The fixed 16-subtree/4-KiB bound and four nominated record slots remain. An absent Frontier or a different original source uses the existing full graph reader.

The original metadata-table DDL and sole original PK autoindex checks remain, including the real catalog, `index_list`, `index_xinfo`, BINARY key and rowid. Trigger/view, TEMP/ATTACH, writable-schema, foreign-key and additional metadata-index programs cannot qualify. The helper still owns its one literal INSERT; it accepts no caller-supplied unchanged claim or replacement transaction scope.

Every consumer still checks current SQL State, current records and deltas, complete Root, actual visited node/path/edge bindings, original progress/cancellation, the last callback, and current scope. Additional or no-row writes, reversed DDL, owner/transaction changes and consumed-result invalidation retain their original refusal/fallback behavior. Partial results cannot mint a new complete graph or replace the original Frontier.

Only two Rust files and their two current source-contract blob pins change. Historical heads, required paths, workload, service targets, budget, controller limits and original assertions retain their original values.

## Real before/after control

A new native fixture uses actual signed transactions to fund 64 accounts, produces a real second account Root by transfer, keeps the actual earlier tip active, and admits a working-only metadata child. It compares the original `Node::check_active_before_commit_with_readback` with and without the optional transaction-local graph facts, using the same actual SQL/State and original reader.

| Actual source | Original active-reader progress checks | Scoped progress checks | New regression outcome |
| --- | ---: | ---: | --- |
| Unmodified #962 production | 164 | 164 | FAIL, exit 101 |
| This two-file source | 164 | 68 | PASS |

These are actual progress callbacks in this finite native fixture. They are not CPU time, a physical-cost total, or a four-second public-service result. No synthetic callbacks or credit are added for skipped repeated graph work.

The full failing stdout/stderr, pre-build source hashes and baseline test source are retained. The original full baseline test source was reconstructed from its retained original file plus exact submitted addition and accepted only after matching its original pre-build SHA-256 `25fc3b60356670bcef191cbf8a8bbc59fc0898b0491f0506ea2e254be461e952`. This reconstruction did not modify the later compilation source. The baseline executable identity is explicitly UNKNOWN because its target was subsequently rebuilt.

## Native verification and source integrity

| Final source suite | Actual result |
| --- | --- |
| Authenticated store (includes 8 new Frontier controls) | 140 passed; 1 existing ignored |
| Original transaction-scope controls | 14 passed; 0 existing ignored |
| Detached admission | 23 passed; 1 existing ignored |
| Legacy admission | 8 passed; 0 existing ignored |
| Task-output Root parity | 2 passed; 0 existing ignored |
| Original native account store | 37 passed; 5 existing ignored |
| Strict Clippy (node and SQLite boundary libraries) | passed with warnings denied |
| Formatting and diff checks | passed |

The six disjoint native suites total **224 passed and 7 existing ignored**. The separate eight-case focused run is a subset.

The eight new Frontier cases are included in the authenticated-store count. They are not eight additional unique passes. They cover another actual source with the same Root, another actual Root, an un-nominated fifth record, extra/no-row SQL and reversed DDL at all four metadata stages, missing shared subtrees, the final parent callback, partial cancellation and final readback, the outer consumed-result write fence, and four additional metadata-index programs with deliberately matching expected catalogs. An unrelated archive index preserves the qualified path. Existing connection, transaction/savepoint ABA, current State/delta, corruption and callback assertions remain.

The native checkout's Git HEAD remains `7e3e454f9b18d5d135e72cc5ea373e04fc5a2ef8`, with the explicitly recorded previous candidate changes and this two-file delta. It is not represented as a clean checkout of the subsequent publication head. All 1,702 tracked compilation files were SHA-256 checked before and after the tests and again after the final original suites. The publication files are matched byte-for-byte to those final tested files.

The original source checker checked all 2,617 current pins and returned **HOLD_NO_GO**, with cryptographic acceptance and activation false. The unchanged original omission/mutation negative control passed. This is source integrity only.

- Production file SHA-256: `728effe2a6fedae09766cbee5fb1dbfb2bf9b8baf914586d5baa652614967440`.
- Frontier test file SHA-256: `4fab7ad3886d9a70be229c1717dd9e58432e5b6a507f3c81af6680bf83594fe8`.
- Two-file patch: 22,965 bytes; SHA-256 `86b551eabde18bff5a938d7e62087208ef6adf1ef26d10a60489486fece43491`.
- Final source-contract SHA-256: `fcfd91f6fa26d80af2861b959de895f093a16e88848dc86ae7a4adab1445341d`.
- [Native original records](native-originals.tar.xz): 212896 bytes; SHA-256 `9f38359c327d935f4bec287b37a348339fe35e0d2ec96297a9c10e0c8f39695e`.
- [Native artifact receipt](native-originals-receipt.json) records the exact final files and archive scope.

The archive retains all baseline failure, candidate and final-control stdout/stderr/results, exact sources, before/after compilation hashes, compiler/Cargo/lock identities, final executed ELF hashes, original source checker/control, full source-contract before/after and its two-pin change record. It does not contain ELF bytes or any physical-cost estimate.

## Next original F0 and cost boundary

The next observation is one dispatch of the unchanged `pon-fixed-host-root-f0.yml` on this frozen head: 1,024 seed transfers across four seed blocks, one baseline and one valid-work ROOT phase, all six scheduled confirmations and 42 business exposures, 24 ROOT actors, the actual public 0.25-CPU/2-GiB parent, original controller ceilings, 30-second phases and four-second scheduled targets.

Original source/reader controls, full artifact inventory, actual service receipts, original business outcomes, actual CPU intervals and recorded controller boundaries will determine that result. Different provider runners and different completed work prevent a causal speed claim from raw cross-run totals. Nested CPU intervals must not be added to their parent intervals.

Complete physical energy, physical I/O/network use, concurrent whole-system memory, storage byte-seconds, monetary price and full research overhead remain UNKNOWN. Provider-reported zero billable milliseconds is not evidence of zero physical use or a known zero monetary price.
