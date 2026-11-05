# Cell discovery directory contention — 2026-11-05

This is a local deadline regression record for the existing classic and PQ
rendezvous directories in [integration candidate #688](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/688).
It does not close DHT, eclipse resistance, independent custody or WAN gates.
Final combined source/commit qualification is recorded separately; the initial
targeted pass below must not be promoted to a result for later source bytes.

## Defect and repair

The original `accept_verified` and `records` entry points checked the caller's
absolute deadline before taking an unbounded blocking owner mutex. SQLite BEGIN
and COMMIT also retained the connection's fixed busy timeout, even when less
request time remained. A later deadline check could reject a late result without
bounding those earlier waits.

The repair uses `try_lock` under the original deadline, rechecks immediately
after owner acquisition, and caps SQLite waiting by both the original connection
policy and the remaining request time. BEGIN, COMMIT and fresh readback each
refresh that bound; bounded row processing retains deadline checks. Success or
refusal restores the original connection timeout. A post-COMMIT refusal retains
the durable sequence/revision: it is an unknown caller outcome, not a rollback
or permission to repeat an already committed effect.

Source:

- [Discovery module declarations](../../trillionnium/crates/trnm-data-availability/src/cell/discovery.rs)
- [Classic directory and typed fixture](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/directory.rs)
- [PQ directory and typed fixture](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/directory.rs)
- [Shared owner and SQLite deadline helper](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_wait.rs)
- [Shared contention regressions](../../trillionnium/crates/trnm-data-availability/src/cell/discovery/directory_deadline_tests.rs)

Wire formats, signature domains, directory schemas, identity quotas and sequence
rules are unchanged. The one-millisecond mutex backoff and SQLite timeout checks
are cooperative; they do not preempt filesystem operations or establish hard
real-time return guarantees.

## Retained observations

| Observation | Actual result | Source scope |
| --- | --- | --- |
| [Original-production RED](discovery-old-production-red.log) | 0 passed, **12 failed**, 0 ignored; each request remained blocked until its lock was released. | Original production directories from `6ee529046d295e3175f09112492abee373f1f54c`, with test-only fixture additions. [The source record](red-discovery-source.json) retains original and instrumented hashes. |
| [Initial repaired targeted run](discovery-targeted-first.log) | **12 passed**, 0 failed, 0 ignored. | Before the shared test file was reorganized into a single private macro module; this log is not final combined-source evidence. |
| Final combined M09/Clippy/source receipt | **Pending in this local record.** | The integration owner must bind the later source and actual commands/results to their final commit. No historical pass is inherited. |

The 12 cases are the cross product of two signed profiles, lookup/publication,
and three real blockers: another thread holding the owner mutex, a second
SQLite writer blocking BEGIN, and a real SQLite reader blocking COMMIT. Channel
handshakes keep the blocker held until the request has returned or the test's
three-second observation bound expires. Cleanup releases the blocker even on a
failed assertion. Accepted repaired results also check unchanged database rows,
restored timeout policy, successful explicit retry, rejection of the old sequence,
and reopen persistence for the SQLite cases.

The production connection policy remains **100 ms**. For the SQLite contention
controls only, the fixture sets its connection policy to **10 seconds** while the
request still has **100 ms**. This makes failure to honor the request budget
observable without a tight performance assertion. It is not evidence that the
default deployment had a ten-second timeout or that a particular speedup was
measured. The mutex cases do not change the SQLite policy.

The initial test organization loaded one shared source file twice with `#[path]`.
It was subsequently changed to one private module whose test macro expands in
the original classic/PQ test modules. All 12 selectors and assertions are retained;
the initial pass above does not certify this later organization or subsequent
integration changes.

## Reproduce the current candidate controls

From a checkout of the exact candidate selected for verification, with the
repository's pinned Rust toolchain and locked dependencies available:

```sh
bash scripts/project-preflight.sh
cargo test --manifest-path trillionnium/Cargo.toml --locked --offline \
  -p trnm-data-availability --lib directory::deadline_tests -- --test-threads=1
```

The command is a focused regression recipe. It does not replace the repository's
full source, lock-graph, formatting, Clippy and native validation gates. The RED
log preserves an intentional failing control, not an accepted candidate. No
production activation, independent administrator claim, DHT qualification or
72-hour WAN evidence follows from these local observations.

## Completed frozen-source execution

The later completed execution is archived in [the source-bound continuation record](../cell-contract-continuation-20261105/README.md). Its 378 native/doc and 220 Python results belong to tree `155213c2468edc411325f4f1853b471a6b25f355`; the corresponding GitHub source object is `cfa57cd04751427451302b5c10539b3984d7f8db`. This addendum does not rewrite the earlier observations or qualify later concurrent source, a model load, or an external deployment.
