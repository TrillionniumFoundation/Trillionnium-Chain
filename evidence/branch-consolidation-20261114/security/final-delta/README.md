# Incremental Git-object review

The initial frozen delta contains 1,105 new objects: 411 blobs, 631 trees and 63 commits. All 411 new blobs (130,927,248 raw bytes) were scanned and their Git content addresses recomputed. Every declared new pattern returned zero matches. The exact new regex definitions are in run-v1/patterns-and-scope.json; the unavailable earlier scanner is not claimed equivalent.

The first fsck returned 2 while coordinator Git writes were concurrent. All ten reported missing objects were absent from the frozen enumeration, later readable, and present in merge 96643a2dd8a90cded0059216cae15e2cd620c77b. A stable read-only full fsck returned 0 with unchanged refs. Both original logs and authoritative terminal receipts are retained. Dangling objects were not deleted.

Two merge blobs created after the original enumeration were separately and explicitly scanned (1,006,072 bytes, all patterns zero). This supplemental receipt does not rewrite the initial 411-blob result. Later report, evidence, documentation and archive objects are excluded.

The original baseline inventory, summary and three marker-only triage results are copied unchanged. ZIP payloads were not recursively decompressed. No result claims exclusion of every possible secret.

All archive members are bound by receipt-index.json. Its own hash and the ZIP hash are in the external delivery.json, avoiding a self-reference.
