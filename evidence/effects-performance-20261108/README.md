# Native generation prepare preflight: retained evidence and review

The narrow fix has a reproduced baseline failure and a successful 70-test native
service run. The new real-Node test and strict Clippy did not complete: both final
attempts ended during compilation with signal 9. **Permissions/effects and
performance remain HOLD.** This directory records a separate source-review pass
by the patch author, not an independent operator, external security review or
cryptographic review.

## Source and observation identity

| Item | Identity or scope |
| --- | --- |
| Assigned Chain candidate | `7e044b65454f4c9ea505591727332acffb33e7e5` |
| Local source-fix commit | `95786fa7e88f5ef613aa73085bcc07aea41c73da` |
| Assigned private pair | `f1785ca15e41e4e49509a5b211a659e3cbdbf60e`; not executed by this task |
| Successful native scope | Complete `trnm-service-settlement --lib`: 70 passed, zero failed |
| Retained test binary SHA-256 | `36be53a6578dc58152cb0dc0ed600952ea72d40763c7ed918e2ae29700dad8d2` |
| Evidence assembly | Retrospective packaging of the original logs and a new source-review note |

The tests ran before the local source-fix commit was created. The retained hashes
of all three changed files match that commit. The successful binary digest was
recorded after the run; it is not a pre-exec measurement or remote attestation.
This is targeted correctness evidence, not an exact-source qualification of a
later integrated tree. [manifest.json](manifest.json) records source hashes,
commands, exit-code limitations, failed attempts and the binary's retained path.
[source-change.patch](source-change.patch) contains the three-file source change.

## What the fix changes

The previous `prepare` called `claim_generation_task` before local event
validation. A full journal or a rejected anchor could therefore leave a durable
Node task assignment for a journal that had rejected its prepare event.

The [generation journal](../../trillionnium/crates/trnm-service-settlement/src/native_generation_budget_v2.rs)
now shares `State::check_prepare` between preflight and event replay. It calls this
immutable check while holding the existing SQLite Immediate transaction, before
the durable owner claim. The owner claim still commits before the journal append.
No schema, hash domain, operation identity, resource limit or deadline changes.

## Transaction and failure review

| Cut point | Observed code behavior and implication |
| --- | --- |
| Invalid statement before the transaction | Returns before calling the owner. |
| Corrupt journal, foreign schema, or failure to acquire the journal lock | `update` fails before entering the owner callback. |
| Fresh prepare with full capacity, task replay, wrong native context, or stale anchor | `check_prepare` rejects before `claim_generation_task`; no new task assignment or journal event is produced. |
| Competing handles on the same journal | SQLite Immediate serializes load, preflight and append. A successful preceding prepare is seen as an exact replay. |
| Different journals competing for one task | Both may pass their local preflights. The independently locked Node owner database accepts one exact assignment; the other journal is refused. |
| Claim fails before its own commit | No generation event is appended. Whether an owner row exists follows the owner transaction's actual outcome; the caller does not assume success. |
| Claim commits but its readback fails | The call returns uncertainty. There is no compensating owner-row deletion. A retained committed assignment is rechecked on retry. |
| Claim succeeds, then generation INSERT, metadata update, commit or readback fails | The separate owner transaction is not rolled back with the generation transaction. The original assignment remains; a different journal cannot acquire it. |
| Exact same-journal retry after an uncommitted prepare | The same statement, operation and request must match. Current funding, original deadline and anchor checks must still pass. Recovery is conditional, not permission to renew the deadline or repin the task. |
| Failure after a committed dispatch intent | `begin` finds the retained intent and returns Pending; cancellation, verification or terminal failure returns Done. It does not produce another New. |

The [actual Node owner](../../trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2/task_owner.rs)
binds task to `(statement, journal, operation, request)` in a separate SQLite
database derived from the canonical Node database path. Its operation column is
unique. It uses an Immediate transaction, validates the exact stored tuple before
commit, and reads the committed assignment again afterward. The new preflight
does not alter any of those writes, checks or recovery rules.

The later generic append checks do not introduce a hidden normal-capacity
failure for an otherwise valid fresh Prepare. At this source, its Borsh payload
is fixed-width: event tag 1 + anchor 176 + clock 40 + statement 569 + funding 80 =
866 bytes, below the 16,384-byte event limit. Each of the eight event variants can
occur at most once per record under `State::apply`; records are never removed.
With `R < max_records`, a fresh prepare therefore has sequence at most
`8 * R + 1`, below the `12 * max_records` journal limit. `max_records` is restricted
to 1 through 4,096. These are source arguments, not additional measured tests.

## Meaning of a side-effect-free refusal

The guarantee is about business state: no new owner assignment, generation event,
native balance change or dispatch. It does not mean zero filesystem or observer
activity. `NodeGenerationOwnerV2::new` may initialize its sidecar before `prepare`
is called, and preflight reads the runtime clock and native funding snapshot.

The [Node adapter](../../trillionnium/crates/trnm-pon-node/src/store/async_w1_generation_v2.rs)
delegates funding observation to the
[native funding reader](../../trillionnium/crates/trnm-pon-node/src/store/funding.rs).
That reader uses read transactions and rolls them back. The permanent-growth
backend similarly uses
[`growth_current_working`](../../trillionnium/crates/trnm-pon-node/src/store/growth.rs)
with a guarded read snapshot. `check_prepare` itself takes `&self` and mutates no
state. The owner/runtime traits remain trusted integration boundaries; the patch
does not make arbitrary callback implementations pure.

## Recovery limits that remain open

The funding read, owner database and generation journal do not form one atomic
cross-database transaction. Another writer or a reorganization may change funding
after observation. `prepare` performs no physical dispatch, and `begin` rechecks
funding, but this change does not establish an end-to-end atomic revocation
contract.

Cold reopening the retained journal differs from restoring an old valid snapshot
with the same journal identity. The owner table binds identity, not the latest
generation-event sequence or dispatch state. It therefore cannot by itself detect
such a journal rollback. An independent recovery anchor and retained provider-side
operation fence remain necessary for a broader rollback guarantee. The
[native budget boundary](../../trillionnium/crates/trnm-service-settlement/src/native_budget.rs)
already excludes restoring the entire local database from its anti-rollback
guarantee. This fix must not be reported as closing that requirement.

The injected write-failure regression uses the existing trusted `MockOwner`
boundary. It proves the service-side ordering and retained-owner behavior in
that fixture. The added real-Node regression covers actual signed task funding,
three storage backends and cold Node restart, but its native execution is still
unverified because compilation was killed. The source review of the actual
owner transaction is not a replacement for that missing execution.

## Original observations

| Attempt | Result and original output |
| --- | --- |
| Initial offline service build | Missing cached `hex`; [log](raw/baseline-unit.log). Underlying exit code was not retained separately. |
| Original production implementation plus two new tests | 0 passed, 2 failed, 67 filtered; both failures show an unwanted task claim after refusal. [Log](raw/baseline-unit-network.log). The wrapper ended with `cat`, so the underlying Cargo exit code is unknown. |
| Initial broad Node diagnostic | Unrelated integration links encountered ENOSPC/linker bus error; subsequently interrupted, session exit 130. Source changed while it compiled, so it supplies no exact-source result. [Log](raw/baseline-node.log). |
| Separate-target service attempt | ENOSPC before compilation, exit 101. [Log](raw/fixed-service-isolated.log). |
| Fixed complete service library | **70/70 PASS**, exit 0. [Log](raw/fixed-service.log), [exit](raw/fixed-service.exit). |
| First fixed Node library attempt | Normal Cargo loader directory set incomplete; interrupted before test execution, session exit 130. [Log](raw/fixed-node-generation.log). |
| Fixed Node with canonical loader directory | `rustc` killed by signal 9, Cargo exit 101; no test result. The precise cause was not established. [Log](raw/fixed-node-generation-normal-loader.log). |
| Strict Clippy for both crates and their tests | Node `clippy-driver` killed by signal 9, Cargo exit 101; no strict-Clippy pass. [Log](raw/fixed-clippy.log). |

The native builds used Rust 1.95.0 and the existing Cargo profiles. No native
OpenSSL feature was enabled and no provider attestation is claimed. The raw logs
retain the initial SQLite-boundary environment warnings. The final Node attempt
set the absolute pinned `RUSTC` and only the canonical toolchain `lib` directory
in `LD_LIBRARY_PATH`; it still failed during compilation.

The successful service suite includes the two baseline-red cases, a real SQLite
INSERT-failure injection with same-journal recovery, and existing cancellation,
reorganization, Unknown-cost and committed-intent tests. It cannot establish
honest/hostile performance or the original host resource contract.

## Performance audit and storage retention

[performance-entry-audit.json](raw/performance-entry-audit.json) binds the exact
source files for the native full-path collector and the honest/hostile campaign
entries. The assigned candidate's full-path reader remains
`COMPONENT_OBSERVATION_ONLY`; no qualified goodput or tail latency is reported.
The original external-controller resource contract was not available in this
cloud run. Side-branch throughput observations were not substituted.

All original logs and status files are retained byte for byte. Only this task's
rebuildable incremental cache was later removed. Its files totaled 3,470,047,366
logical bytes; this sum is not a measurement of physically reclaimed blocks.
The successful 35,770,192-byte service binary was preserved with the same digest.
[Cleanup record](raw/cleanup-own-incremental.json). No other task's target or data
was removed. `SHA256SUMS` covers this note, the manifest, the patch and every raw
file; it does not hash itself.

The byte-preserved original logs contain trailing whitespace in
`raw/baseline-node.log` and an extra final blank line in `raw/fixed-service.log`.
Those original bytes are retained; a full `git diff --check` reports them.
Source/prose whitespace and the retained-byte hashes are checked separately.
