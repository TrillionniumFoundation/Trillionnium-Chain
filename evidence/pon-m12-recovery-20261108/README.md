# M12 recovery V3 component evidence (2026-11-08)

Status: **implemented candidate; complete qualification HOLD**. The new opt-in
`NodeGenerationOwnerV3` is connected to the ordinary Node/M12 owner paths. Its
dispatch and settlement decisions require an authenticated witness CAS. The
original V2 entry remains a research API without this backup-rollback guarantee.
The [component specification](../../docs/development/specs/pon/M12_GENERATION_RECOVERY_V3.md)
defines the exact boundary and crash behavior.

## Exact source

- Published and formally retested Git commit:
  `1910baa6c3421cc17ea5578b5eae431038212e88`.
- Git source tree: `7887047307ca2fd0debcae00d6fa93b4cc17c9ce`.
- Earlier locally committed and tested source:
  `d150a6fc446caf5f62b1e5d2a3c3b268053a4ce7`. The published source has exactly the
  same tree. [Its original commit body](local-tested-commit.raw) is retained;
  this local SHA is not presented as a published commit.
- Supplemental source-content SHA-256:
  `28c31b1f1c1c010b947c977a31fc5628871dbbfd4450be48bfce3d2a5702a1b2`.
  This 64-character digest is **not a Git commit ID**.

The published-source runs use the unchanged repository
`record_pq_native_command.py` and `verify_ci_source.py`. Every command's before
and after verification checked all **15,394 tracked entries / 1,683,209,186 raw
bytes**, their modes, and their exact Git objects. The records have matching
before/after identities and a clean worktree. The supplemental development
runner also records source snapshots; those earlier snapshots exclude
`evidence/` and are not a substitute for the official full-source verification.

The earlier local native build used the original optimized release profile.
After fetching the published commit, a guarded `update-ref` changed only the
commit identity after verifying tree equality. The official Node rerun used the
existing binary cache and did not recompile source. No source was edited during
these final runs. No service or production operation was activated.

## Results on the published source

| Command scope | Observed result | Qualification boundary |
| --- | --- | --- |
| Ordinary Node/M12 generation owner, including V3 recovery | 33 passed, 0 failed, 4 ignored | All 13 new recovery controls passed; the four existing heavy provider/proof cases remain unexecuted |
| Native generation settlement state machine | 12 passed, 0 failed, 0 ignored | Includes the new fixed-size blob control, which exercises 12 field/length combinations |
| Retained rollback-witness suites | 52 passed, 3 failed, 0 ignored; Cargo exit 101 | Three independent-process controls did not reach a ready witness because Unix socket creation returned EPERM |
| PQ source-integrity controls | 39 tests passed | Source-binding controls only |
| CI source-integrity controls | 43 tests passed | Includes deliberate failure fixtures; their printed FAIL records are expected negatives |
| Whole workspace Clippy | Exit 0 with `--release --workspace --all-targets --all-features -- -D warnings` | Complete raw log has zero `warning` / `UNQUALIFIED` matches |
| Formatting, embedded source inventory, repository and Markdown links | Exit 0 | 656 pinned source blobs and all HOLD assertions retained; 3,867 local links checked |
| Locked offline main Cargo graph | Exit 0; 26 workspace members, 175 resolved packages | Manifest and lockfile unchanged |
| Locked offline fuzz Cargo graph | Exit 0; 1 workspace member, 147 resolved packages | Separate manifest and lockfile unchanged |

Readable final records and logs are under [official](official/native-owner.json),
including [Node owner execution](official/native-owner.log),
[settlement execution](official/settlement.log),
[the failed witness target](official/witness-retained.log), and
[full workspace Clippy](official/workspace-clippy.log).

The 13 new controls cover complete A-domain restore, retained B-domain reopen
pins, lost/corrupt CAS acknowledgements, local commit without external commit,
post-commit action failure, concurrent local mutation, unavailable or mismatched
witness authority, original deadline expiration, exact settlement-wire replay,
Unknown/cancellation across a real native reorganization, and journal bounds.
They use real Node operations, SQLite commits, ML-DSA signatures and the durable
witness. Provider/verifier values and controller clocks are explicit fixtures.
The two local storage directories do not establish independent control domains.

The three failed retained witness controls are:

- `guarded_npq6_submit_recovers_after_invalid_signature_and_independent_process_restart`
- `guarded_npq6_valid_submit_cleanup_preserves_primary_error_and_child_diagnostics`
- `guarded_npq6_valid_submit_exact_replay_and_independent_process_restart`

Each failed at the child `UnixListener::bind` in `combined_tests.rs`, before the
child reported ready. They remain **failed**, not skipped or replaced with a
different transport. A separately collected same-workspace
[socket diagnostic](environment/socket-probes.json) is retained as context only;
it is not source-bound to this suite and cannot turn these failures into passes.
The unchanged original suite still needs execution in a host that supports its
actual AF_UNIX fixtures.

The four ignored cases require actual fresh proof generation, owner cancellation,
timeout/refund/reorganization, or cold reconciliation of an existing provider
operation. No fixture terminal result closes the historical #782 Unknowns.

## Preserved unsuccessful observations

| Observation | Retained outcome |
| --- | --- |
| Early preparation compile | E0599 while source changed during preparation; no tests executed; no qualification |
| First source-frozen Node build | Cargo 101 / rustc SIGKILL, zero tests; also a distinct loader-path UNQUALIFIED warning |
| First offline fuzz graph | Cargo 101 because `libfuzzer-sys` was not cached; locked fetch and offline retry later passed |
| First fixed-blob test compile | E0277 because `unwrap_err` required Debug on the existing dispatch enum; zero tests; the test was corrected without changing that API |
| First all-feature Clippy invocation | Cargo 101 because optional OpenSSL dependency cache was incomplete; locked fetch and later strict runs passed |
| Final retained witness target | 52 passed / 3 EPERM failures; preserved as an unsuccessful command |

Complete source-bound receipts retain these failed attempts. The initial
pre-receipt preparation failures have only the explicitly limited
[transcript observation record](preparation-observations.json); no complete raw
artifact or successful qualification is invented for them. SIGKILL is recorded
as observed; its cause is not inferred from missing cgroup diagnostics.

## CPU, recovery and external-effect limits

Every guard checkpoint fully loads and replays the M12 journal. The extra
replays and ML-DSA exchanges can increase CPU and latency. Existing configuration
and event payloads are limited to 16,384 bytes, records to 4,096, and events to
12 times the configured record limit. Journal identity and metadata/event roots
are now selected into Rust only if SQLite reports blob type and exactly 32
bytes. The new control bypasses stored CHECK constraints and injects 0-, 31-,
33- and 16,777,216-byte values, then checks live and cold refusal before an owner
callback. This closes that application-copy gap. It does **not** close malicious
SQLite-engine total CPU, I/O or memory exposure, or establish the original
four-second / 16-worker service budget.

The witness protects local dispatch authorization. It does not implement the
provider's atomic idempotency boundary or authoritative execution/payment query.
Lost acknowledgements retain the same operation, journal, original deadline,
exact settlement wire and resource cap. A fresh owner may observe an exactly
matching acknowledged head and return Pending; it may not issue another New.
Unknown is never interpreted as not executed or refunded by local expiry.

Independent current binding pins, witness reopen checkpoints and current
revocation authority must survive outside the restored backup set. Restoring
all authorities and all independent evidence together is outside this guarantee.
Ordinary V2 migration, whole-Node recovery, real provider reconciliation,
independent custody and production activation remain HOLD. The outer SHA-512
checkpoint does not upgrade the original V2 SHA-256 event-chain security.

## Raw evidence package

The [raw receipts archive](raw-receipts.tar.xz) preserves every completed
development and official command receipt, full stdout/stderr or combined log,
and source-before/source-after snapshots. It also includes the exact final
development runner and commit-object metadata. The
[archive index](raw-receipts-index.json) records every member's size and SHA-256.
[summary.json](summary.json) provides machine-readable outcomes and source
identities. The readable logs are exact copies of archive members.

Archive SHA-256: `c1c24493c4a23c3e84b7aafee68d8632fb86ab2b23f04641ee13e214ea797c70`.

This evidence commit adds records only. The tested source identity remains
the published source commit above; an artifact commit is not substituted for
the source tested by the recorded commands.
