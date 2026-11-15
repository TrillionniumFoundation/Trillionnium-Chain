# Continuation from c3: branch preservation and unresolved native gates

This directory records the 2026-11-15 continuation from
`c3e53d2ff55d41b1e5ea2b01f97efaf61a2fd636`. It does not promote a prior
run to acceptance of changed source. All production, activation, resource
fairness and whole-chain PQ qualifications remain false or unknown.

## History and current remote state

[The native ancestry readback](current-ref-audit.json) covers 900 observed
branch names and 884 distinct tips. Every tip is an ancestor of c3. This
non-atomic observation does not replace the earlier 908-name, 892-tip
[disposition ledger](../ledgers/all-908/all-908-branch-dispositions-v1.json).
The 296 terminal dispositions in that ledger remain historical review
records, including their explicit source-body and native-qualification limits.

The remote annotated tag `archive/all-branches-20261115-c3e53d2ff55d`
has tag object `959b6f27c5e0d0baede9f8e3669ec8bfa415b8e0`, targets c3,
and retains the original 908-name manifest. Native Git object reads checked
that identity. It must not be moved or relabelled as an archive of a successor.

PR 847 remains the integration path. Protected main requires linear history,
conversation resolution and the strict repository-truth, protocol-contract,
fuzz-smoke, external-evidence-contract and rust-baseline checks. The repository
automatically deletes a merged PR head. A successor therefore needs its own
verified remote history archive before merge, followed by a fresh exact-tip
comparison before deleting remaining branches. This record authorizes no
main-protection exception. The separately protected obsolete branch also
remains present at this observation.

## Original CI failures

[The original CI readback](original-ci-readback.json) records all 21 terminal
jobs from run 43658725402: 15 success, six failure. Head and prospective
protocol-contract failed. The prospective Rust runtime shard failed, causing
its fan-in to fail. Both architecture cost jobs failed. Their consistency job
passed; consistency of failed reports is not native acceptance.

Four original confirmation artifacts were downloaded and their complete ZIP
SHA256 values matched GitHub's digests. All four report unchanged four-second,
16-worker pressure windows with zero independently confirmed transactions.
The corresponding attack-free phases each confirmed one transaction. The
head/prospective/x64/arm64 pressure phases replayed respectively 2/2/4/5 history
pages, although seven honest submissions were recorded in each. No false
packet was accepted. The unchanged parent limits were 0.25 CPU, 2 GiB RAM,
zero swap and 256 PIDs. Neither source checks nor faster component measurements
discharge these failed finite liveness gates.

The original prospective DA test expected six responses (2,070 bytes) and
observed five (1,725 bytes). The first header read timed out after 205.829 ms.
Its original client 200 ms and server 250 ms limits and exact response
assertions remain unchanged. The added test-only timing observer is diagnostic,
not a runtime repair. It records accept, read, SQLite and write stages without
request bodies or keys. Instrumented test builds have real observation overhead;
logs must be ordered by their common-origin timestamps and checked for overflow.

## Checkpoint frame-read correction

The old checkpoint reader reused a socket timeout for successive partial
reads. [The retained original observation](checkpoint-frame-original-observation.json)
showed a valid frame accepted after 6.0004 seconds despite the server's five
second read setting; a concurrent normal request timed out. The owned diagnostic
job and its daemon had already terminated when the observation was collected.
No additional active slow-input experiments were used for this correction.

The new private frame reader applies one monotonic budget to the header, body
and all partial reads. It rejects a frame that completes at or after the
deadline, preserves the 4,096-byte limit and error stages, and retains owner
revalidation before any journal operation. Connect, response writes and serial
request scheduling are outside this change; it is not whole-service availability
qualification.

[The offline validation receipt](checkpoint-frame-offline-validation/receipt.json)
contains exact commands, toolchain, source hashes and log hashes. Nine finite
memory-reader/fake-clock tests passed; 26 other library tests were filtered out.
Package formatting and strict all-target/all-feature Clippy passed. No socket,
daemon or real waiting was used by those nine tests.

## Canonical client encoding

The typed Submit client can construct the exact existing JSON envelope from
already bounded lowercase hexadecimal input. A private witness avoids decoding
the same envelope again. Nonmatching, escaped, oversized and other request
types retain the original serialization/validation path; profile isolation
retains its original error precedence. Packet decoding, cryptographic checks,
signed domains and server admission remain authoritative.

The lowercase check uses bounded 64-byte blocks. It short-circuits between
blocks, so an invalid first byte does not cause a full maximum-sized scan.
The new controls compare exact bytes/errors with the original oracle and cover
all byte values, block boundaries, operation mismatches and size limits.

[The actual-input component benchmark](client-canonical-experiment/summary-original-payloads.json)
uses all 16 distinct 99,043-byte requests from the original head report, matched
to its recorded digests. In 12 release-profile paired rounds, the old
serialization plus owned validation median was 142.27 microseconds and the
new typed/vectorized path was 6.75 microseconds. The paired saving was 135.64
microseconds per call. These are helper measurements, not native acceptance.
Workers may issue up to 1,024 calls each: a faster client can increase pressure,
so multiplying the saving by an old completed-call count is not a prediction
of the four-second system outcome.

## Current bindings and local limits

[The current binding receipt](binding-continuation-receipt.json) records the
reviewed changes. The current 21-source map changes only the PublicV3 digest;
its new map SHA256 is
`77729ed60da423795f27b56c2cf0c7b79dfa89927c3acff05ed7f54e04693fb5`
and its canonical source digest is
`acc25714b88e67bbd827ce424d71d57ee3a6b43f5f0ba80f52d95a0c1acf6bd4`.
The frozen V1 model, V1 source lock, V2 composition and root register remain
byte-identical. The corpus adds the two new modules and the previously unpinned
DA equivocation test, yielding 2,609 pins and 2,513 required paths. The native
embedded source inventory includes both modules.

[The source-validation receipt](source-binding-validation-20261115/receipt.json)
records 25 current-map, 60 composition, 113 corpus-integrity and 43 tracked-source
controls passing, plus the repository and inventory checks. These ran on the
runtime/current-binding delta before this documentation was added. They are not
the full hosted repository-truth lane.

The local full-workspace/all-target/all-feature test build did not complete:
node rustc processes received SIGKILL at jobs=2 and again at jobs=1. No Rust
semantic diagnostic or kernel OOM attribution was obtained. The DA 941-test
binary had not been produced, so that suite was not executed. Completed cache
executables are compilation outputs, not test passes. Local OpenSSL 3.5.7 also
differs from hosted 3.5.9; local Unix pathname binding is unavailable and the
original cgroup hierarchy is absent. Those limits cannot be repaired by
renaming a reduced graph or changed environment as original qualification.

The final source requires its own retained controls and original hosted gates.
Protected-main merge and the requested single-branch state remain pending at
this record.

## Concurrent f34 reconciliation and dependency-bound follow-up

The publication lease check found that PR 847 had advanced to
`f34f432c6c533c651ab74f69f4f43aef326eedcb`, a single child of c3
with tree `d2c34fb4474aba3c268163abe1ec94211b8e9c7f`. No remote write
was attempted against the stale c3 head. The complete local c3 delta was
preserved in a native stash and an independently hashed tar archive before
fast-forwarding the working branch and reconciling the five current-binding
conflicts. No incoming runtime or tests were discarded.

[Independent Legacy review](concurrent-f34-legacy-review.json) covers all
incoming changes in the nine named runtime/test files. Removing only the
added diagnostic plumbing restored the complete bytes of five existing files
to c3. The optional 16-stage observations preserve Host, SQL, publication,
deadline and cancellation checks; enabled observation has real overhead and
does not confer durable-operation or consensus authority. This is static
review, not execution of the incoming native tests.

[The combined map](f34-binding-reconciliation.json) and
[independent composed-source review](concurrent-f34-composed-binding-review.json)
retain both f34's `store.rs` and the local `public_v3.rs`. Their other 19
declared paths are unchanged from c3/f34. The current map SHA256 is
`5328f618642aa14125b6325ebcc2285f8be85cf39843a11c6d9157863a0c27c6`
and the source snapshot is
`f9991545b8b43b870559106d7be807d286f4b2ac555a2a10dbaf6c6e850ac8fd`.
The composed corpus has 2,613 pins and 2,517 required paths. The earlier c3
map receipts above keep their original identities and are not overwritten.

The incoming commit added six authenticated-module tests while its workflow
and source-roster check still required 97. Both repository-truth jobs in run
43690736511 failed that exact 103-versus-97 mismatch. The current guard now
requires all 103 unique successful executions, including the exact six added
names, the original 25 post-write controls and all five current-account
controls. The four original 97-test logs and their hashes remain historical
inputs to the frozen c3 guard; the current guard rejects them. Synthetic
103-line inputs only test the parser and are not native execution evidence.
No native command, feature, ignored-test execution, deadline or downstream
Clippy requirement is removed.

The initial client helper used newer serde_json/memchr/zmij than the repository
lock. Its original results and this limitation remain preserved. A separate
[dependency-bound follow-up](client-canonical-experiment/dependency-bound-v2/summary.json)
reused the actual completed release dependency artifacts named by the failed
c3 node build, including serde_json 1.0.149, memchr 2.8.0 and zmij 1.0.21.
Its [provenance](client-canonical-experiment/dependency-bound-v2/provenance.json)
closes 31 fingerprint nodes and checks 15 crate archive digests against the
original lock, with 1,697 installed source-file comparisons. The unchanged
small helper was compiled and run once. Across the same 16 actual requests
and 12 paired rounds, the old path median was 143.591 microseconds and the new
path 6.898 microseconds; the paired saving was 136.593 microseconds. This
resolves that dependency-version caveat for the component comparison, not the
four-second system gate.

The actual default-feature release node library-test attempt also received
SIGKILL after 341.333 seconds. No crate unit tests ran and the later TCP controls
were not started; [the receipt](client-canonical-experiment/validation/receipt.json)
retains that failure. The new helper result does not replace it.

[The bounded credential-shaped scan](credential-pattern-scan.json) read
35,573 tracked text files and excluded 6,112 binary, large or nonregular
entries. Its only match was a rejection test appending a private-key header
literal, without key material. [The authenticated code-scanning API read](code-scanning-readback.json)
returned no open alerts. Neither observation is a comprehensive secret audit
or proof that the composed source has completed CodeQL analysis.

## Composed-source validation before publication

The [fresh 900-name observation](prepublication-branches-f34.json) differs from
the earlier 900-name mapping only at the integration candidate. Native
`git merge-base --independent` over all 884 distinct observed tips returns
only f34, proving that the incoming candidate retains every observed tip.
The observation remains non-atomic; final cleanup must compare tips again.

The composed-source full-workspace, all-target, all-feature strict Clippy
command completed with exit zero, with the changed Rust bytes identical
before and after checking. [Its receipt](combined-f34-validation/rust-receipt.json)
and [actual SQLite native build fence](combined-f34-validation/sqlite-native-build-fence.json)
are retained. Whole-workspace formatting also passed. The preceding check
had been stopped after an empty loader-path component caused the native
boundary to refuse qualification; its original output remains in
`combined-f34-validation-loader-refusal`. The successful check used an
absolute loader directory and did not override a fence or run native tests.

The first combined Python run passed the 25 current-map, 60 composition and
113 corpus controls, then correctly refused three stale DA source hashes in
the current 44-path authority map. [The original refusal](combined-f34-source-validation/receipt.json)
is preserved. [The reviewed correction](authority-current-binding-reconciliation.json)
updates only those three hashes and the reader/test lock literal to
`67583ec38887eabe00536dc4cd5ec7cc7fd48acc4397a52165bf4f591c9fa4a7`.
The declared 44 paths, historical revision label, route semantics and all
qualification fields remain unchanged.

After that correction, [the retained controls](combined-f34-authority-corrected-validation/receipt.json)
passed: 18 authority-map, 33 hash-use, 35 joint-qualification, 14 current-W1
and 43 tracked-source tests. Repository checks observed 26 workspace packages,
1,621 active Rust files and 8,628 valid local links at that point. The embedded
inventory and diff checks passed. Separately,
[the roster/CI review](concurrent-f34-ci-review.json) retains the 18 roster,
225 CI-contract and nine Legacy diagnostic source-control passes.

These local observations do not replace the required hosted native tests,
the original four-second pressure window, or the original DA time limits.

The final [independent current-binding review](current-binding-independent-review-after-authority-repair.json)
checked all 2,613 corpus blobs and the 2,517 required paths. Its broader scan
classified 3,125 path/digest relations across 83 configuration JSON files:
3,091 directly matched current bytes; 32 intentionally retained frozen,
historical or initial-observer identities, and two referenced a historical
PDF identity inside a JSON record. Those two indirect identities also matched
their March PDF records. No further active current binding mismatch was found.
Raw reference scans remain attached so historical hashes are not silently
relocked. The original frame-test stdout is stored losslessly as gzip with
its decompressed digest recorded in the adjacent `log-storage.json`.
