# PN0–PN6 continuation: source repairs and measured W1 refusal cost

Date: 2026-11-01. **All seven strict PN exits remain HOLD.** This is an execution
record under the existing development plan, not a replacement acceptance plan.

The actual starting Chain source is
[`cea95fb44d8152a0eb1138727619fcced056f496`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/cea95fb44d8152a0eb1138727619fcced056f496),
tree `22df9ea34daaf960fdfe6c154f043a47c82c338c`, on existing
[PR #559](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/559).
The observed Hepta companion is [PR #4497](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4497)
at `f0f1f16898c2f9737461a28752b421fe52e65ee7`, tree
`81d52b6ea085a2b4e913cbea027d8198febc3046`. The separate Chain #674 diagnostic
stack and Hepta #4368 PQ migration stack were inspected as separate candidates;
their code or test outcomes were not silently imported into this combination.

The final Chain source is the Git commit containing this record. Its exact
commit/tree is frozen by the companion's explicitly selected V5 profile and
recorded in the two PR checkpoints after remote readback. A document cannot
contain the hash of its own containing Git tree. The historical snapshot fields
in the compatibility matrix remain historical, and its native qualification
fields remain unfilled.

## Changes made

### PN0: repair the actual source checks and configuration record

The recent-batch workflow had stale whole-file pins for `store.rs` and
`store/native_authenticated.rs`, and still required 58 tests after the source
added 15 post-write controls. It now checks the actual source bytes and requires
one log from the original invocation with 73 unique successful test names,
including exactly 15 under `post_write_readback::tests::`, and one successful
73/0/0 summary. The command, matrix and original 25-minute job budget are
unchanged. The arithmetic cache pin also follows the reviewed PN2 edit below.

The corpus's stale Cell document pin and the changed workflow/arithmetic pins
were synchronized to their actual bytes. All **346** pins now match. This
checker intentionally still reports `HOLD_NO_GO` with cryptographic acceptance,
whole authorization migration and activation false.

The existing [16-configuration matrix](../../qualification/pn-convergence-20261031/PROFILE_COMPATIBILITY.md)
and [37-source inventory](../../qualification/pn-convergence-20261031/profile-compatibility.json)
were refreshed against the observed published sources. Three source references
had changed. An independent review additionally caught that the Hepta URLs still
pointed to b93 after their inspected commit had been advanced to f0f1; all 16
Hepta URLs were corrected. That initially missed review issue is preserved in
the review record. Every combined native result remains
`UNQUALIFIED_COMBINED_PAIR`.

The prepared Hepta companion adds a new explicitly selected V5 record over
42 actual Chain execution/data files, binds both the Chain commit and tree,
and selects that same source for training and the evidence reader. The existing
V1–V4 records and c165 historical native job retain their own source scope. The
current installed-host job is connected to actual current-source PQ startup,
durable History, growth and original from-zero entry points, within its existing
60-minute budget. Its native results are pending; Python controls are not a
successful model or installed-node run.

### PN1: retain constant-work rejection for malformed proof lengths

The original negative-cache wrapper hashed the complete caller-supplied proof
slice before the verifier's fixed-width check. It could therefore perform linear
hash work for an arbitrarily long invalid slice, although the original verifier
immediately returns `Length` unless the width is exactly **49,188 bytes**.

The private cache-key helper now returns no key for other lengths and delegates
directly to the unchanged verifier. The original Length/version/task/target error
order, absence of a cancellation callback for bad lengths, valid-width behavior,
and Transcript/Product-only negative caching are retained. The new regression
also checks that malformed inputs leave the cache empty.

This finding is bounded to the public Rust library API. The ordinary and PQ wire
decoders already constrain the proof width, and the public V3 rejection cache is
optional and off by default. This record does not establish a reachable oversized
proof attack against the ordinary public ingress. Fresh forged transcripts still
require their original full replay; the existing counterexample remains covered.

### PN2: avoid encoding the same immutable State twice

`ArithmeticCache::complete` encoded its complete actual State and, on a miss,
`complete_root` encoded that same immutable State a second time. The only caller
now passes the first result as `Option<&[u8]>`. A too-large input remains `None`
and uses the original root calculation. It is no longer encoded a second time
up to the same 4 MiB retention bound and then discarded.

The State is a `BTreeMap<String, serde_json::Value>` with no user serializer or
progress callback between these points. The account/conservation checks, root
grammar, original error order, three-entry/4 MiB limits and SQL checks remain.
No validity verdict is reused across calls or transactions. This is a reviewed
source optimization; the original large-state native CPU gates have not been
rerun successfully and are not closed by this change.

## Executed validation

| Observation | Actual result | Scope |
| --- | --- | --- |
| Project development/staged preflight | PASS | Project, branch, 26 package inventory and path ownership |
| Whole workspace Rustfmt 1.95.0 | PASS | Formatting only |
| Existing CI/source controls | 203 passed | Includes deliberate negative receipts; those expected FAIL receipts are not product failures |
| Existing PQ corpus negatives | 34 passed | Source/provenance and false-acceptance controls |
| Actual corpus positive check | 346 pins matched | Overall status remains HOLD_NO_GO |
| New same-log parser controls | 6 passed | Synthetic parser cases only; no native 73-test execution |
| Original WAN evidence reader | 25 passed | Synthetic arithmetic/reader controls; not a WAN run |
| Complete original W1 module, independent native harness | 96 passed, 0 failed, 0 ignored | 17 real source files; no stubs; not the full crypto/PQ package |
| Same W1 harness, strict Clippy | PASS | `-D warnings`, same module scope |
| Full original crypto package, locked/offline | BLOCKED, exit 101 | Missing exact `ml-dsa` package; no full package compile result |
| Prepared Hepta source/diverse/current host/reader controls | 51 + 32 + 20 + 86 passed | Git fixtures and readers; final pin and remote native acceptance reported by companion |

The W1 module test binary SHA-256 is
`e922d7dee5a719e8cd517cc13a42447faecdf9b20aa2aeb7921ef79ea151e74b`.
Rust/Cargo is **1.95.0**, rustc commit
`59807616e1fa2540724bfbac14d7976d7e4a3860`. The harness uses 11 package identities
from the original Chain lockfile; the 10 packages actually compiled on x86_64
were checked against their original checksum-matching crate archives, covering
172 dependency source files. Conditional libc is not compiled on this target.
Neither the workspace lockfile nor the harness lockfile was changed.

The complete workspace has 39 exact registry versions unavailable in the
observed local caches. Its build and strict workspace Clippy remain blocked.
The selected environment's normal Git HTTPS path also failed to connect to its
configured proxy. The source was restored through authorized repository reads:
2,004 current source/configuration/document files and 17 required historical
corpus files were byte-checked. Unrestored historical archive objects mean this
is not a complete local all-files checkout. In particular, `git write-tree`
refused an absent historical evidence blob; publication uses the canonical
remote base tree and exact changed blobs, with an independently calculated tree
digest. No full-checkout source guard is reported as passed locally.

## Actual malformed-width cost observation

Each row is **all 256 calls**, not a per-call number. Allocation and cache setup
are outside the call timer and separately recorded in the raw JSONL. Every call
returns Length, and no progress callback runs. The two source variants were
built in separate fresh targets with the same compiler/profile/configuration
fingerprints and no Rustflags. No timing acceptance threshold was set.

| Proof width | Baseline process CPU, ns | Patched process CPU, ns |
| --- | ---: | ---: |
| 3 bytes | 119,477 | 4,627 |
| 49,187 bytes | 7,430,460 | 3,756 |
| 1 MiB | 161,599,659 | 3,865 |
| 16 MiB | 2,519,313,497 | 7,681 |

Valid cost executables have different SHA-256 identities:

- Baseline: `4137b14657e7016e5b547f0782436ad4eac9ca69285824d3322b6a410fa57978`.
- Patched: `157477825943c484e44fa240f1d449b76b632bf7d837ea63fe64889c67f204c5`.

The first attempt reused a shared target directory while preserving copied
source mtimes. Cargo reused the old executable for both variants. That attempt
is marked `INVALID_SHARED_TARGET_REUSE` and retained under
`pn1/invalid-shared-target-cost-attempt`; it provides no patch-effect evidence.
The valid comparison was rebuilt from scratch in two independent targets.
These measurements establish the narrow API behavior on this host, not a
hardware lower bound, public TPS, quantum security or service-under-attack result.

## Strict stage disposition

| Stage | Remaining blocker under the original conditions |
| --- | --- |
| PN0 | New source and companion pins require the same actual native build/start/normal/reject/recovery execution; isolated profiles remain distinct. |
| PN1 | Cheapest legal algorithms across structured tasks, hardware/amortization, quantum cost and original-budget honest service under attack remain unqualified. Relation correctness is separate. |
| PN2 | General durable multi-page/fork History, compatible PQ plus growth, bounded authenticated historical summaries and original CPU/deadline successes remain open. `verify_history_with_readback` still scans to genesis; this edit does not solve long-term O(H) scanning. Restart debt rules are retained. |
| PN3 | Complete eleven-object release, original-owner installation, ordinary later use, measured learning benefit and legal no-update require real separate receipts. Ordinary host FinalUse remains Ed25519. |
| PN4 | Source audit found no new confirmed bug in the inspected budget/intent/payment paths. Actual funds, repair/service delivery, contribution rewards and target-side external reconciliation remain unexecuted. Reservations are not funds. |
| PN5 | NOT RUN: no verified three-administrator independence, 72-hour physical WAN duration, or completed independent fault/load/repair/recovery groups. Reader tests provide none of these facts. |
| PN6 | NOT RUN/HOLD: authorization-domain migration, actual keys/history, release-binary upgrade/rollback and a governed activation decision remain open. |

The original >8 MiB `PUBLIC_MUTATION_CPU_BUDGET` failures and long-History
connection-refused observations remain failures. The separate 1,800-second
server-lifetime hypothesis is not promoted into a proven cause by this work.
No main merge, protocol activation, funding transfer or external action occurred.

## Evidence and reproduction

Raw logs, source hashes, compiler identities and both valid and invalid cost
observations are retained under `pn1/`, `pn2/`, `source-controls/`,
`source-review/` and `wan-reader/`. The complete two W1 module harnesses, original
manifest/lockfiles and the cost example are in `w1-module-sources.tar.gz`.
Use a different fresh `CARGO_TARGET_DIR` for each harness; do not share one while
copying source timestamps. The recorded commands run `cargo test --locked
--offline --lib`, strict Clippy and `cargo build --release --locked --offline
--example length_cost` against those manifests. The archive contains the exact
17-file module copies, not simplified successful substitutes.

`MANIFEST.json` binds all retained bytes and explicitly records the incomplete
acceptance status. Internal independent source review is separate from PN5's
independent administrators and physical system experiment.
