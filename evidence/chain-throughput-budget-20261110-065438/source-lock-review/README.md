# Exact source-lock continuation for the original-budget changes

## Published implementation anchor

The current source maps name the published implementation commit
`b7e38fdc2e43c468692abc52aec03737f2df7f1b`. Its tree is exactly
`b75d318fc7b7b027a810f4a70a9cd91e0b3930f8`, the same tree as the local
`9029f2ab…` checkpoint reviewed below. GitHub commit metadata differs from the
local commit; source bytes do not. The published commit is now also present as
an exact locally verified Git object.

`publication-github-commit.json` and `publication-github-tree.json` retain
independently fetched GitHub Git-data responses. Reconstructing the root tree
from its 23 entries reproduces its Git hash and exact local tree bytes. Complete
GitHub file responses for `consensus.rs`, `ingress.rs`, and `store.rs` were
decoded and independently hashed; all match the published Git blobs and working
files. `publication-source-readback.json` records those comparisons.

Every declared lifetime and authority path was then read from the published
commit, required to be a regular Git blob, and compared again with both the
working file and the local review in `mapping.json`. All 15 and 44 paths match;
`publication-reanchor.json` retains every comparison. No per-file hash, source
set, route, effect scope or qualification flag changes in this reanchor. Only
the source revision labels and their dependent table/lock identities change.

The current lifetime lock-byte SHA-256 is
`af0ceb6ae756031305b9b73f1b6695664c830558fed7a13b6c2e7ff255592f92`.
The authority canonical table digest is
`414662f49bd42d1026abb774a5d5862e8976a5faf1013142fab722acfe520f08`.
The positive authority control names this published revision; the existing
stale-context test additionally refuses the local `9029f2ab…` label. The local
190-control observations below retain their original source and are not
relabelled as executions at a published commit.

## Local pre-publication binding

The initial local implementation source checkpoint was
`9029f2ab2c6382aaaf096b841a20fbf335f4b172`, tree
`b75d318fc7b7b027a810f4a70a9cd91e0b3930f8`. The initial source lock revision used that
existing commit. The local follow-up changed the declarations and their source
review; it did not claim they were already contained in the implementation
checkpoint. It did not execute native tests or establish business acceptance.

Before changing the maps, both existing inspectors were run against this
frozen source and returned exit 2 with a source-lock mismatch. Their exact
stdout/stderr are retained in `before-rebind-guards.json`. The earlier hosted
e4abb lifetime failure and original 4-second confirmation failure remain in
[the CI origin readback](../ci-origin/README.md). They are not relabelled by this
maintenance.

### Declared source comparisons

For every one of the existing 15 lifetime paths and 44 authority paths, the
review read `git ls-tree` at the exact checkpoint, required a regular blob with
mode `100644` or `100755`, read `git show <revision>:<path>`, and compared the
bytes with the current file using the existing descriptor-bound
`pq_source_reader.read_regular`. The prior map's path digests were also matched
against `git show` at their respective declared source revisions. Every
comparison matched; all per-path mode, Git blob, old SHA-256, new SHA-256 and
working-file identities are in `mapping.json`.

| Map | Prior revision | Changed declared paths | Retained scope |
| --- | --- | --- | --- |
| Lifetime, 15 paths | `66b7064be597039ce871b5b12ad5568850a2dd46` | `consensus.rs`, `store.rs` | Same events and source set; the research manifest changes only `experiment.source_revision` |
| Authority, 44 paths | `893738947a50dc42819b56e632192de4f9f24fa0` | `ingress.rs`, `store.rs` | Same seven routes, source sets, effect scopes and false qualification flags |

The local pre-publication lifetime source lock had byte SHA-256
`b648db90d21471e58897d17e6a837065d87c2fd3fab391ffc559a5a13129e1e4`.
The corresponding authority checker fixed canonical table SHA-256
`aeb80e5df748f56ad960cd9f5dabfd6ae004e03e80a63c1ce0f935db2d865abb`,
computed from exactly `{"source_revision": revision, "files": source_files_sha256}`
with sorted keys and separators `(',', ':')`. The prior map remains a historical
record; the existing stale-context test now also rejects its revision label.

## Review of the changed declared sources

The three exact Git diffs are retained as lossless `.patch.gz` files with their
commands, original names/digests and compressed delivery names/digests in
`source-diffs.json`. Decompression reproduces every original byte. The initial
staged whitespace check treated literal unified-diff blank context markers as
trailing whitespace; `patch-delivery.json` retains that failure and the
round-trip-verified packaging repair. No source or whitespace rule changed. The prior `store.rs` bytes are identical
in both old maps, so its single visibility diff describes both comparisons.

`consensus.rs` differs from the lifetime baseline only in its test module:
the existing arithmetic-vector body is factored into a helper and a test reads
the versioned `consensus-domain-v2.json` vectors. Production consensus code in
that file is unchanged. This pre-existing difference caused the retained e4abb
lifetime refusal; the current work does not erase that failure.

`store.rs` changes only the visibility of `state_at_with_progress` to
`pub(crate)`. The state reader's body, committed state and transaction rules
are unchanged. The existing recent-batch workflow's whole-file pin is updated
to this exact checkpoint blob, `4d2de868f0632532267dcbc2ecef4c018d8c2804`.

`ingress.rs` carries a held control and a detached progress callback through
the existing shared admission helper. Only after the Node writer is dropped
does detached M06 execution use the detached callback; it keeps the same
worker accounting. Preparation, capacity fallback, reacquisition and commit
retain the held callback. Ordinary Submit supplies the same callback for both
positions. The related History helper remains outside this curated authority
map: its completion eligibility and original-account/deadline requirements
must be assessed with the implementation source and native controls. A source
lock cannot establish their runtime behavior.

The generated native source inventory additionally includes the two new test
modules. The existing cross-branch source corpus retains all prior entries,
updates only reviewed changed bytes, and adds the detached-History test module
alongside its existing History owner sources. These source records are not a
claim of complete PQ dependency coverage. The fixed maps still leave the
research event probabilities and shared-primitive query budgets unknown; the
actual lifetime bound is null and all qualification/activation flags remain
false.

## Validation of this maintenance tree

All 12 commands in `checks/results.json` returned exit 0. Their complete
stdout/stderr, exact command arguments, elapsed durations, and before/after
digests of 17 relevant source/configuration files are retained in `checks/`.
Those monitored file digests were unchanged during every command. The source
checkpoint is local `9029f2ab…`; these results do not identify a later published
commit or establish that native compilation or confirmation passed.

| Existing control | Actual result |
| --- | --- |
| Lifetime budget unit tests | 58 methods passed |
| Authority/effect register unit tests | 18 methods passed |
| Cross-branch corpus unit tests | 59 methods passed |
| Whole-chain claim guard unit tests | 55 methods passed |
| Lifetime, authority, claim and corpus inspectors | All four returned success within their existing HOLD scope; corpus checked 1,080 source blobs |
| Distributed native source inventory | `--check` passed |
| CI workflow contract | Passed |
| Repository integrity and links | Passed |
| Patch whitespace | `git diff --check` passed |

The 190 Python test methods preserve the existing adversarial controls. The
authority stale-context control also refuses the prior `8937389` source label.
The lifetime result retains four unknown shared-primitive query budgets and a
null actual lifetime failure bound. The authority report still declares
incomplete coverage and no qualification or activation. A parallel read-only
source review independently compared the exact declared Git blobs and map
fields and found no additional changes to those boundaries.

## Incremental checks after publication reanchor

The published revision reanchor and the frozen component-runner files were
checked again without repeating the earlier 190-method suite. All nine
commands in `publication-checks/results.json` returned exit 0: the 18 authority
unit methods, the lifetime/authority/claim/corpus inspectors, native source
inventory check, CI contract, repository integrity and patch whitespace. The
corpus inspector again read 1,080 exact source blobs and retained `HOLD_NO_GO`.
The three new component-runner files matched the final reviewed SHA-256 values
in the separate component-runner evidence.

Each command retained before/after digests of 23 source, configuration and
evidence files. Eight commands observed no change. During the initial
repository check, the evidence root README gained the component-runner link;
that command returned exit 0, but its file-stability observation is retained as
false. No source, configuration or other monitored file changed. Only that
affected command was repeated. `publication-checks/repository-repeat.json` and
its stdout/stderr retain the new result: exit 0, all 23 file digests stable,
6,652 local links, 1,475 Rust files and 26 workspace packages. The initial
observation remains unchanged.

These are local Python/static observations on the dirty follow-up tree anchored
to published source `b7e38fdc…`. They do not turn the earlier local 190 methods
into published executions, establish native compilation or a native test
roster, or qualify business confirmation, sustained throughput or activation.
