# Original e8/f35 failure readback

This research checkpoint preserves four complete decoded original job logs and
their exact source-bound observations. It changes no production source, original
native command, workload, resource budget, timeout, predicate or activation field.

## Retained actual failures

- e8 runtime head job 126318926226: the DA invocation ran all 174 tests,
  173 passed and the existing sequence slow-setup test failed. Ready completed
  at 352.277086 ms and setup completed at 352.316746 ms. The following single
  announcement returned WouldBlock/errno 11 after 202.308773 ms under the
  unchanged 200 ms client budget. Server initialization success is not an
  end-to-end request qualification. The consuming phase remains unresolved.
- Frozen f35 recent-batch head x64 job 126322034412: History actually returned
  6 passed / 0 failed / 3 ignored. Its original workflow still required 4/2.
  Both new inline History identities appear in that invocation. Existing owner
  be0d5f97 corrects this denominator and the complete account-control identities;
  no later source is qualified by these results.
- f35 campaign job 126322603645: source build succeeded; all three original
  native attempts exited 101 after 110.082108314, 110.858545610 and 110.125683366
  seconds. There were no recorded phase-startup, report-validation or
  finalization errors. Original 30-second phases, 0/24/24 attackers, 21 business
  blocks, 4 seed blocks and 1,024 signed seed transfers remain unchanged.
  Inner confirmation counts are not inferred from the outer receipt.
- f35 F0 job 126322033940: execution and finalization steps both exited 1.
  The outer log does not expose the complete inner failure; no cause or
  denominator is fabricated.

READBACK.json binds the original commands, exact source/tree, returned log bytes
and current pending #699 composition. These are UTF-8 hashes of the connector's
decoded logs, not independent ZIP or native-binary hashes.

## Bounded original artifact inspection

The research-only push workflow reads exactly two existing failed f35 artifacts:
campaign 13287158757 (60,599,441 bytes) and F0 13287122967 (19,665,544 bytes).
The input manifest freezes both SHA-256 digests, run IDs, source commit and tree.

The reader checks GitHub artifact/run/commit metadata, downloads with a new
request that does not forward the API Authorization header, verifies exact ZIP
bytes/digest, rejects unsafe/duplicate/special/encrypted members, and streams
every member through CRC and SHA-256 checks. No archive member is extracted or
executed. Required current source receipts are checked. Campaign native binary
and each original run report are matched to the original controller hashes.

Declared bounds are 96 MiB compressed total, 512 MiB declared/returned decoded
total, 256 MiB per member, 16 MiB per selected JSON, 64 MiB retained selected JSON
per archive, 10,000 members per archive and 2 MiB printed projection. These are
stream/metadata bounds, not claims about codec internal buffers or peak RSS.
The workflow has a 15-minute timeout and read-only contents/actions permissions.
No Rust build or original native experiment is launched by this reader.

Only a selected diagnostic projection is printed. Packet/signature/state-row
payloads and environment/command strings are omitted; arbitrary strings are
hashed. Recorded receiver rows are summarized per operation and dispatch class,
with all recorded numeric samples included in each statistic and null counts
retained. Nested stage costs are not additive and these are not network/business
latency qualifications. Budget-sample projection explicitly keeps only its count
and endpoints; the complete original samples remain in the verified archive.

## Reproduce and qualification boundary

The independent metadata/ZIP/JSON controls run first using:

```sh
python3 qualification/original-artifact-readback-20261104/readback.py --self-test
```

The workflow then runs the same script with an explicit output directory and
the read-only GitHub Actions token. It verifies the research source before and
after and runs the original project audit preflight. All output is retained,
including failure; successful readback is never labelled native success.

The current local executor is unavailable. This script has not yet been run
locally. Its initial hosted result is pending and must be read back at its exact
research commit. #699 7d5321a5 original Actions continue independently.
DRAFT / SHADOW_ONLY / DENY_ALL / HOLD_NO_GO remains in effect.
