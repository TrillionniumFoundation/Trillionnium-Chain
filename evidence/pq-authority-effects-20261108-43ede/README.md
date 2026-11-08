# PQ authority effects — execution record

Base delivery: `01e2c4c010c3cf65d1cf094368961efc1abab445` (#796).

The [source review](../../docs/security/PQ_AUTHORITY_EFFECTS_20261108.md) describes
the changes and their authority boundary. Whole-chain PQ and production acceptance
remain HOLD. The original failed 32-command observation is retained in the parent
delivery; it is not overwritten or relabelled.

## Retained original hosted failure

[Readback](prior-head-hosted-pq/readback.json) binds original artifact `13612169408`
from run `42468358532`, job `128693038187`, to its GitHub-reported ZIP SHA-256. The
provider download received four HTTP 504 responses and exited 22 before provider
construction or native Rust PQ tests. The ZIP is unchanged; the extracted progress
log is stored as lossless gzip to retain its carriage returns exactly.

Fresh source-bound execution receipts are recorded separately from this original
failure. Source-check success alone does not certify native execution or deployment.
