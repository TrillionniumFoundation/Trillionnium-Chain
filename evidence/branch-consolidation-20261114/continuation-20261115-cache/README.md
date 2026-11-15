# Bounded negative-cache continuation, 2026-11-15

This continues the reviewed candidate
`32989461a183dd5cc723100721e409a5450b72e3`, tree
`e5785f836110110fff9f8569f2e737c3ea72ce29`. It changes reuse of exact negative
mathematical facts. It does not establish the original four-second business
confirmation gate, proof security, production activation or completed branch
cleanup. Historical failures and qualifications remain in force.

## Published source and history observations

[The independent publication readback](published-329-readback.json) records a
normal candidate fast-forward from f34 through the specified ProfHepta channel.
Main remained `dd6e1c3cbeacbdc532b0679297835b3a0aac78f0`; protection was unchanged.
Two consecutive complete observations at 08:59:35–08:59:37 UTC returned the same
900 branch names and 884 distinct tips. These observations are non-atomic.
The [native ancestry receipt](postpublication-329-ancestry.json) records a real
successful `git merge-base --is-ancestor` check for each of the 884 tips against
the published candidate. The distinct original 908-name snapshots and older
archive objects are retained in the
[independent history review](final-e578-history-archive-independent-review.json).

The original per-blob publication and subsequent read-only recovery failures
remain separate observations. A batch tree write ultimately produced the exact
reviewed native tree; it did not change the sealed source to accommodate a
transport error. The failed archive pagination check also remained read-only.
Archive completion and future main/cleanup outcomes require their own readbacks.

## Observed cache collision

The f34 head artifact's [passive analysis](f34-protocol-head-passive-analysis.json)
and [per-call collision analysis](cache-collision-cost-and-design.json) record
two different full proof keys sharing the original direct-map slot. Each
underwent 20 full replays, while the other 14 inputs each underwent one. The
40 colliding-key replays strictly alternated without overlapping intervals;
publication was retained and neither contention nor poisoning was observed.

After excluding each key's necessary first replay, 38 repetitions accumulated
47,508,285 ns of full-work calling-thread CPU. Only 37 finished entirely within
the original four-second window, totaling 46,179,030 ns. Connection 419 ran from
3.995611549 to 4.093898728 seconds; its 1,329,255 ns cannot be accurately split
at the deadline from the saved report. The outer dispatch CPU includes the
full-work measurement and must not be added to it.

These figures are not a promised net saving. Cache hits still pay the original
cheap checks, full-proof digest, exact-key comparison and cancellation check.
Faster refusals can also increase the closed-loop pressure rate. Only the
unchanged native campaign can establish its own confirmation outcome.

## General bounded policy

The cache divides its original slot vector into `ceil(capacity / 4)` balanced
continuous sets, each containing one to four entries. Every original capacity
from 1 through 256 is supported and all slots remain usable. Lookup checks the
complete 32-byte key. Insert prefers an existing same key, then the first empty
slot, then the earliest expiration with stable first-slot ties.

The retained structures, constructor, key domain and verification entry remain
byte-identical to the parent. The 256-slot, 32 KiB retained-object and 30-second
limits remain unchanged. Lookup does not extend expiry. `try_lock`, poison and
contention behavior, original cheap checks, `BeforeReplay`, mathematical error
eligibility and all native replay checkpoints remain intact. More than four
distinct keys in one set can still evict one another; this is no cost guarantee
for arbitrary new proofs.

## Focused native validation

[The original validation receipt](cache-validation-receipt.json) records 19
passing cache tests: all 13 retained controls plus six new regressions, with
zero failures or ignored tests. Another 212 crypto library tests were excluded
by the explicit cache filter and were not executed in this focused run.
Strict crypto Clippy over all targets/features with `-D warnings`, crate
formatting and whitespace checks also passed. No node test binary, daemon or
pressure campaign was run by this local experiment.

[The independent source review](cache-independent-review.json) and
[byte-boundary comparison](cache-boundary-byte-review.json) preserve the exact
scope. Original stdout/stderr bytes are retained losslessly in
[the log bundle](cache-native-log-bundle.json); its Base64 entries include
original filenames, lengths and SHA-256 values without newline normalization.

## Current binding identities

Exactly two existing records change in the 145-input current W1 closure; no
path, manifest, lock, image or saved proof is added or replaced. The 50,313-byte
current map has SHA-256
`b8249228d4399f12f58cb593599536b2831bb11145af59b74b7217435a68d6c1`.
The profile-binding JSON's own digest is a separate file identity; the derived
selected profile descriptor used by the workflow and command is
`2b107d47346897e951fe690b154ec6e927ce22de5b422fc52379df48fdd15cb4`.

Current reader, profile, upstream-policy, route, hash-use and corpus bindings
must follow these exact bytes. The first Python checks detected stale derived
workflow/route/hash-use identities; those original failures are retained
separately from corrected runs. Frozen work-cost observations, V1 material,
historical comparisons and all false/unknown qualification flags remain intact.
The final committed source still requires its own head and prospective CI.


## Final local validation and archive readback

[The final source-validation receipt](cache-final-source-validation-receipt.json)
records all 113 corpus tests passing, plus seven successful positive readers:
corpus, current mapping, upstream policy, selected proof profile, route,
hash-use, and repository/Markdown inspection. All 24 recorded inputs remained
stable. The repository check covered 26 packages, 1,621 Rust files and 8,648
Markdown links. This test result covers the named source inputs; evidence files
added afterward are separately checked when sealing the publication tree.
Together with the latest five-suite result, 243 source/binding tests passed.
The [first binding attempt](cache-python-attempt-1-receipt.json), corrected
[second attempt](cache-python-attempt-2-receipt.json), original logs and source
snapshots remain separate, lossless observations.

[Full-workspace verification](cache-workspace-validation-receipt.json) read the
locked, offline Cargo graph: 26 members and 183 resolved packages. Strict
all-target/all-feature workspace Clippy with `-D warnings` passed in 171.329
seconds, and workspace formatting passed. All 1,649 recorded Rust and Cargo
input files remained unchanged. This did not run the whole workspace test
suite or the original four-second native pressure campaign.

The final [current-binding review](cache-current-binding-review.json) confirms
30 historical baseline files stayed byte-identical. Fifteen existing corpus
pins were updated while preserving the 2,613-pin/2,517-path roster. The audit
narrative was already outside that roster and was not silently added. The
first pre-write refusal and all intermediate observations are retained in
[the binding-originals bundle](cache-current-binding-originals.json).

The archive publisher completed successfully at 09:42:53 UTC through the
specified ProfHepta channel. The new annotated ref is
`refs/tags/archive/all-branches-20261115-32989461a183`, tag object
`a082b993b485e813665d2a3fb66e06d4889d443f`, pointing to archive commit
`58467b8113724607a66b5c510f79b110833364c2`. Its ordered parents are the published
candidate `32989461a183dd5cc723100721e409a5450b72e3` and old archive
`5f57c4e1e2b7ae95a7b0651d7674979d3f44b90b`. The archive tree is exactly
`e5785f836110110fff9f8569f2e737c3ea72ce29`.

[The independent native readback](archive-329-native-final-readback.json)
recomputed the tag object ID, matched all 285,606 annotation bytes to the API
including the final LF, verified the embedded request and 900-name snapshot,
and independently confirmed all 884 distinct tips are ancestors of the archive.
The annotation SHA-256 is
`9b878968757681bd25931afb096184d5e5ff8f200b6ea9b88a42f365a080d423`.
[The complete publisher readback](archive-329-final-mac-publication-readback.json)
preserves its two remaining writes and successful terminal identity. Main,
the candidate branch and prior tags remained unchanged in these observations.

The earlier pagination refusal performed no writes. The next attempt created
the archive commit exactly once and then stopped because GitHub's commit JSON
omitted its final message LF. A native object read proved the original 319-byte
message unchanged. The recovery validated the actual prior Mac records before
reusing that commit and creating only the tag object and ref. Tag message
comparison remained exact; neither archive commit nor unknown write was replayed.

## Remaining hosted and platform limits

The [09:36:35 required-CI readback](ci-required-readback-093635.json) still showed
f34's four Rust shards running and C329's required run pending with zero jobs.
Local source checks, Clippy and archive custody do not satisfy those hosted
head/prospective gates. A later published candidate requires its own exact
source run, final archive and protected-main merge before branch cleanup.

[The separate macOS cleanup review](macos-cleanup-unresolved-static-review.json)
retains a real failure in one subcase of the original 26-test suite. Subsequent
12-, 14- and 32-test suites passing do not replace that failure. The five owner,
test and workflow files were byte-identical between f34 and C329, so this is not
attributed to an observed C329 source regression. A possible Darwin exit-state
race is supported by primary-source inspection, but the specific root cause
and exact runner-kernel correspondence remain unconfirmed. No fix or active
probe was performed as part of this cache continuation.

[The evidence index](evidence-import-index.json) identifies the exact saved
files. Original log/JSON bundles retain source bytes with individual lengths
and SHA-256 values. Historical qualification flags remain unchanged; this
continuation does not assert completed main integration, branch cleanup,
production activation or cryptographic security qualification.
