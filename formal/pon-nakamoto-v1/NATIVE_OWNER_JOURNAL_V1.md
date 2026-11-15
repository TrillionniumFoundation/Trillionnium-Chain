# Persistent native owner observations and unresolved execution debt, v1

Status: **explicit local research interface; global execution attestation,
fresh resource state and confirmation-risk qualification remain HOLD**.

Starting source: `88bce414d7ba7f7f6a60dba03943ee20dc501ed7`.
Date: 2026-11-07 UTC.

## 1. The additional claim

The previous
[`NATIVE_OWNER_OBSERVATION_V1.md`](NATIVE_OWNER_OBSERVATION_V1.md) obtains a
complete currently retained admitted view from an actual native owner. A
series of such snapshots alone does not cover the operations between them,
unadmitted producer outputs, an interrupted call, or a previous incarnation
of the owner.

This extension adds
[`JournaledNativeOwner`](../../trillionnium/crates/trnm-pon-node/src/native_owner_journal.rs).
It exclusively contains its `Node` and exposes a narrow set of actual native
operations. It writes a persistent intent before calling the native method,
retains complete packet artifacts, and writes the actual result with a
complete post-call census before returning a completed observation. The
separate sidecar survives reorganization and reopening. Unfinished intents,
intervals outside a held owner, orphan packet files, and validation-clock
regressions remain explicit facts.

The source scope is an opt-in wrapper around ordinary PNP1 `legacy-task-v1`
owners, with explicit `Legacy` or `AuthenticatedV1` selection. There is no
fallback to another packet, task or storage relation. No default CLI or
public network endpoint installs the wrapper. It does not instrument every
possible caller of the original `Node` API. No native SQLite DDL, native
transaction boundary, consensus weight, signature domain, activation rule,
or confirmation rule changes.

The independently implemented reader is
[`native_owner_journal.py`](native_owner_journal.py). It reads the actual
binary sidecar and every retained packet file, verifies event and artifact
bindings, and recomputes local native score witnesses. It does not accept a
caller-provided `Verified` boolean as a substitute for these reads.

## 2. Files, bounds and authority

Each opt-in owner uses a separate sidecar directory, outside the native
store directory. The sidecar contains:

- `owner.lock`, held exclusively for the wrapper's lifetime;
- `journal.pnoj1`, an append-only framed hash chain;
- `packets/<sha256>.pnp1`, complete native packet bytes, including invalid
  inputs and completed producer outputs that have not been admitted.

The native owner still obtains the original native store lock. The wrapper
does not expose `&Node`, `&mut Node`, `into_inner`, `Deref`, or a callback
that receives its contained `Node`. Methods require `&mut self`; in
particular an unrecorded `Node::make(&self, ...)` cannot be invoked through
this wrapper. A separate original `Node` elsewhere is outside this scope.

The existing census limits remain at most 256 currently admitted rows,
including genesis, and 16 MiB of retained packet bytes. The sidecar adds hard
maximums of 4 MiB per frame, 4,096 frames, 128 MiB of journal bytes, and
64 MiB of packet files. Opening inventories the entire packet directory
within the file-count and byte bounds, including files that no previous
frame references. Unexpected directory entries, malformed packet files, missing referenced files,
budget exhaustion, or inconsistent identities refuse the relevant complete
observation. Bounds are diagnostic scope limits; they are not RSS, physical
CPU, latency, or minimum-work-cost certificates.

Packet files use create-new semantics. Existing content must match its
content address. The observer never truncates a torn journal tail, removes
an orphan to regain a clean state, replaces a failed packet artifact, or
silently returns a bounded prefix as the complete census. A partially
written tail remains available for diagnosis and prevents certification.

The binary format begins with the eight bytes `PNOJ1\0\0\0`. Each frame is:

```text
u32 big-endian payload length
UTF-8 JSON: {sequence, previous_hash, payload}
32-byte SHA256("pon-native-owner-journal-frame-v1\0" || exact JSON bytes)
```

Sequence numbers start at zero and never follow the selected chain's
height or generation backwards. `previous_hash` binds the exact preceding
frame. A checkpoint is `{journal_id, sequence, record_hash}`. The reader
rejects duplicate JSON fields, a missing suffix required by a supplied pin,
an inconsistent chain, and altered content. The binding uses the usual
cryptographic hash assumptions; hashing is not execution authentication.

A matching **supplied** checkpoint is explicitly separate from an
independently authenticated checkpoint. The file cannot prove who supplied
the pin, that the caller retained the newest pin, or that an external
signer observed the physical machine. `trusted_history_anchor` remains
false. An attacker who restores an old database together with an old
internally consistent sidecar can evade a self-contained prefix check.
An independently retained later checkpoint detects that rollback; the
native example exercises both cases.

## 3. Durable event protocol

The persistent event vocabulary is fixed:

| Record | Source and meaning |
| --- | --- |
| `header` | Journal namespace, native context, selected backend, store path and permanently unsupported global/freshness claims. |
| `open_intent` | Durable intent to call the original `Node::open`; new process clock epoch, all earlier unresolved intents, and any orphan packet artifacts found on opening the sidecar. |
| `open_observed` | The actual opened/recovered owner and its complete native census; closes only this opening intent. |
| `intent` | Durable request to invoke `make`, `admit`, `activate_observed`, `confirmation`, or `census`, with exact input identities and caller validation time. |
| `prepared` | Complete native census and packet artifacts obtained before the requested business operation. |
| `terminal` | Original native result or error plus a complete post-call census and its full packet artifacts. |
| `lease_end` | Last complete observation while still holding the native owner. Coverage ends before its subsequent drop. |

For a business call, the implementation follows this order:

1. Check that this wrapper has no unresolved current call and still owns
   the same journal file. Save any complete input packet before invoking
   the native method.
2. Append `intent` and successfully `sync_all` it. Mark the wrapper blocked
   against another business call.
3. Obtain the existing complete native census, copy all non-genesis full
   packets through the original `Node::packet` reader, and check that their
   digests and lengths equal the census. Append and sync `prepared`.
4. Execute the original native method. Its own transaction and error
   behavior is unchanged.
5. Persist any returned full packet. Obtain the full post-call census and
   retain all corresponding packets. Append and sync `terminal`.
6. Return the original native result only after the terminal observation
   has been persisted. Preserve an original `requires_owner_stop` result;
   it does not become permission to continue using the wrapper.

The packet reads after a census need not share its read transaction: their
complete bytes must match that census's content digests and lengths. The
complete native relation/state replay itself remains the original census
operation. No failed row is discarded to make the candidate maximum or
artifact set smaller.

### 3.1 Native opening is an operation

The original `Node::open` executes `recover()`. In the current ordinary
backend this may choose the maximum stored chainwork and activate it.
Opening therefore is not a read-only prelude. Its intent is written before
the original constructor is called; its post-open census records whatever
native recovery actually selected. No wrapper-supplied validation time is
retroactively attributed to an internal recovery step that did not receive
that parameter.

In particular, a census can report a selected chain that is currently
time-ineligible under the supplied validation clock. The journal retains
that fact and the existing census's null raw selection deficit. The reader
does not insert such a selected chain into a valid-view comparison that
requires the selected chain to be eligible.

### 3.2 A real commit and a missing terminal are different facts

The sidecar and the native database do not form one atomic transaction.
Failure after a native commit may return a journal error even though the
native effect remains durable. The caller must not infer rollback of the
native action from failure of the observation API.

`begin_activation` returns a `PendingActivation` that exclusively borrows
the owner. The native activation has really been called. Its
`native_succeeded()` method reports only the live native return; it is not
a completed observation receipt. Only `finish()` obtains and persists the
terminal census/result and returns the completed call's native value.
Dropping the pending value leaves the wrapper blocked. Exiting its process
leaves the durable intent unresolved.

On reopening, an old unfinished intent remains in `unresolved_intents`.
The new epoch can append an actual recovery observation and continue its
own calls, but it cannot append a belated terminal for the previous epoch's
intent. A recovered selected tip equal to the originally requested tip
does not establish that every call, helper, resource use or intermediate
state was observed. The replay state machine derives the unresolved set
from the whole prefix; a later record cannot replace it with an empty list.

The actual subprocess scenario exits with status 23 after native
activation returns success and before `PendingActivation::finish`. This
tests process termination at that cut. It does not certify power-loss
behavior of every filesystem or storage controller.

### 3.3 Orphan artifacts stay visible

A full packet can have reached its artifact file before a terminal record
fails. Reopening scans all packet files, checks their complete bytes and
native packet codec/identity, charges them against the storage limit and
records previously unreferenced artifacts in `orphan_artifacts_at_open`.
The reader also reports files that remain unreferenced at its own cut.

An orphan observation proves neither complete production history nor
effective work validity. It does not insert a block into the eligible
admitted view. If that exact packet is later admitted and appears in a
complete native census, its valid native weight can then be bound to those
bytes. Its earlier gap origin and unfinished production intent remain.

## 4. Clock and lifetime coverage

The journal's frame order is a persistent causal order of these recorded
operations. Each opened wrapper has its own `Instant` epoch and records
elapsed values within that epoch. The native census has its separate
process-local observer identity and `Instant` counter. The reader checks
their respective within-epoch order and the complete owner scope of every
census, including a census returned as an operation result.

The caller-supplied `observed_now` is the actual native validation-time
argument. It is not a physical timestamp. Decreasing it adds a visible
`clock_regressions` entry. Starting a new process, selecting a new journal
nonce, or obtaining owner attempt 1 does not establish a new oracle,
unqueried domain, fresh quantum state, or a zero-stock start.

Every transition from one held-owner epoch to another adds an
`outside_lease_intervals` entry. This is true even after clean closure and
even when the two native snapshots are identical. A snapshot cannot rule
out intermediate production, receipt, deletion, helper activity or a
database-plus-sidecar restoration. The interval has no inferred bound on
physical elapsed time or unobserved operations.

Successful coverage concerns actual **compound calls through this wrapper
during a held-owner lease**. It does not enumerate every primitive query
inside the producer/verifier, every cache/preprocessing access, work before
the first lease, ordinary `Node` calls outside the wrapper, another process
or machine, packets never presented to this owner, or all-world first-ready
events. No field in a new epoch can clear these exclusions.

## 5. Two registries, exact artifacts and native weight

Raw packet observation and effective native work are distinct.

`raw_artifacts` and `raw_artifact_sources` retain the first recorded
observation of each exact packet SHA-256, its record/epoch and source class.
Invalid inputs and orphans appear here. This alone grants no effective
weight. The source classes are:

| Class | First recorded exact-byte source |
| --- | --- |
| `initial_carry_in` | Full packet already present in the first successful native census. |
| `recorded_local_production` | Exact bytes returned by an actually completed, terminal-recorded native `make` call. |
| `external_input` | Exact packet bytes supplied to a recorded admission attempt, including one that is refused. |
| `gap_or_recovery_discovery` | Orphan bytes or newly discovered native state at a recovery/otherwise unattributed observation. |

The first raw class never improves merely because the bytes are produced,
imported, verified or admitted again. Registry entries are deduplicated by
the **native block ID** and bound to their exact packet SHA and native
target-derived weight. A conflicting exact packet binding causes refusal.
Produced-but-unadmitted outputs can be retained in this registry with
`native_relation_rechecked_by_census=false`. They do not enter the admitted
candidate maximum or the reader's map of census-validated packets.

`valid_packet_bindings` is keyed by **exact packet SHA-256**. An entry is
created only when those bytes match a non-genesis row in a complete native
census. The reader recomputes the native block ID from the encoded header
and trace, the proof digest, target-derived weight, transaction-body root,
parent/height/time fields and native context. It checks actual transaction
membership for confirmation outputs. The complete PNW1 and M06 relation
was replayed by the native census; the Python reader does not pretend to
replace that replay or to authenticate an arbitrary serialized export.

This distinction is material. The retained native invalid-product control
changes product bytes while preserving the claimed header and trace. It
has the same native block ID as the valid packet, but a different packet
SHA. A valid signature or resource statement about the invalid SHA cannot
inherit the complete work relation of the valid SHA through their common
block ID.

Weights are the existing native values:

\[
w(B)=\left\lfloor\frac{2^{256}}{T(B)+1}\right\rfloor,
\quad T(B)>0,
\qquad S(C)=\sum_{B\in C\setminus\{genesis\}}w(B).
\]

Values use the native checked 512-bit representation. Genesis contributes
zero. Reorganization, resubmission, reopening, duplicate admission and
future-timestamp maturity do not create another copy of the same block's
weight. Research MU1 `16u` credit is a separate relation and cannot replace
these fields.

## 6. Deterministic execution and fork witnesses

### Proposition 1: what a completed local record covers

Assume the pinned native code executes as specified, the contained `Node`
cannot escape this API, the original owner and sidecar locks are held,
cooperative filesystem exclusivity and `sync_all` semantics hold, and the
native census theorem's assumptions hold. Consider a successful `terminal`
record produced by this wrapper.

Its matching intent and complete prepared view were persisted before the
native business call. Its native result, complete post-call view and packet
artifacts were obtained after that call and persisted before the completed
result was returned. Calls through the wrapper are serialized. Every such
call that reaches the native operation has a preceding durable intent;
every returned completed observation has a matching terminal.

**Proof.** All covered business-call entry points go through `begin`.
The internal census and packet reads are parts of those compound calls,
not separately journaled primitive operations. `begin` blocks the wrapper,
syncs the intent and prepared observation,
and returns only after both succeed. The native call is next in source
order. `terminal` performs the complete post-call observation and artifact
checks, appends/syncs the terminal, and only then unblocks a non-stopped
owner and returns the native result. The pending activation value retains
the exclusive borrow and cannot manufacture a terminal. An early return,
panic, process exit, limit refusal or write failure cannot remove the
already persisted intent. Reopening preserves that intent in a different
epoch. This establishes the stated local call coverage, not coverage of
unobserved intervals or primitive resource operations.

### Proposition 2: strict rollback to a unique native-weight partition

Take a completed `activate_observed` call whose prepared view selected
chain `C`, whose post-call view selects `D`, and which removes a nonempty
suffix of `C`. Let `a` be the exact LCA from the complete checked parent
paths. Native strict selection gives

\[
S(D)>S(C).
\]

Partition `D`'s suffix after `a` using its immutable exact-packet source
classes. Let their native-weight sums be `I`, `P`, `E`, and `G` in the order
of the table above. All counted suffix blocks must have a complete native
census relation binding. Then

\[
\boxed{I+P+E+G=S(D)-S(a)>S(C)-S(a).}
\]

**Proof.** The checked parent path contains each native block ID once. The
registry assigns each ID exactly one source class and one unchanged native
weight. The classes therefore form a disjoint exhaustive partition of
that suffix. Native chainwork is the checked sum of those weights; subtract
the common prefix score and apply strict selection. The reader verifies
the requested eligible target, the original target-versus-incumbent rule,
the generation transition, unchanged retained rows, exact LCA and both
sums.

The activation rule still compares its submitted target with its
incumbent. It need not select the greatest already admitted candidate.
Thus the journal also preserves the complete local maximum and selection
deficit. It does not strengthen the production rule to instantaneous
maximization by recording an observation.

`P` is recorded local production, not global adversarial first-ready work.
`E` and `G` are not zero-cost output classes. Their age, origin and required
resource state may be unknown. The equality is useful precisely because
these quantities remain visible instead of being silently credited to a
new resource budget.

### Proposition 3: observed confirmation loss after an unobserved cut

A reopening can observe that a previously natively confirmed block is
absent even when the previous activation intent lacks a terminal. The
reader reports the observed failure and all unresolved intents. It does
not reconstruct a nonexistent completed activation receipt.

For an eligible observed selected chain `D`, let `M` be the complete local
eligible maximum from that actual census and let `R=S(C_0)` be the recorded
confirming reference score. The established deterministic deficit identity
still applies:

\[
(R-M)_+ + (\min(R,M)-S(D))_+ = (R-S(D))_+,
\qquad M\ge S(D).
\]

The new record supplies actual local native identities, values and causal
order for this identity. It does not supply the all-view availability or
selection-delay envelopes, physical-time cut, honest progress, adversarial
first-ready process, or initial inventory needed by the general common
prefix reduction. A selected time-ineligible chain is reported as such and
is not used to satisfy the identity's eligible-view premise.

### Probability composition remains conditional

The ledger's first-local-observation clock is not the work-tail theorem's
first-global-ready clock. A separately proved certificate must establish
the same relation, native identity/weight, origin and residual state before
connecting any measured subset to that tail process. All remaining
competing weight, unobserved intervals, orphan origins and hidden inventory
need valid uniform bounds. Post-failure measured debts are not
pre-established stopping-time parameters.

For example, if an external argument bounds resource-certifiable weight
by a process `A` and uniformly pays all other competing contributions by
`U`, a deterministic failure witness may imply `A+U>K`. A tail bound for
`A` becomes useful only with an admissible, separately proved bound on `U`
and the correct initial-state/filtration contract. The ledger does not set
`U=0`, provide an upper bound on world inventory, or condition the original
probability law on a future good event. It produces no numerical
six-successor risk value.

## 7. Actual native scenario and executable checks

The dedicated example is
[`native_owner_journal_v1.rs`](../../trillionnium/crates/trnm-pon-node/examples/native_owner_journal_v1.rs),
with
[`native_journal_scenario.rs`](../../trillionnium/crates/trnm-pon-node/examples/support/native_journal_scenario.rs).
It creates fresh valueless local stores and invokes original native
production, admission, state execution, confirmation and activation. The
schedule includes:

1. Actual A1..A7 six-successor confirmation, a real private B1..B8 branch,
   and an unchanged complete Alice view before/after Bob's private work.
2. A complete A8 production output left unadmitted across clean closure and
   reopening, then admitted twice without replacing its first source.
3. An invalid product with the same block ID as a different valid packet;
   tie retention, actual strict rollback, and native reorg observation.
4. A future ancestor with an individually current-time child; validation
   clock regression, deferred activation, and later eligibility maturity.
5. A separate receiver process that admits the actual B packets, really
   commits the competing activation, and exits before its terminal record.
   Reopening observes the actual changed tip and retains the old intent.
6. Actual restoration of an earlier database and sidecar copy. The saved
   later checkpoint refuses the stale prefix. Opening without that pin
   retains all freshness/history/world qualifications as false.
7. Real producer completion followed by terminal-record capacity refusal.
   The packet survives as an orphan, is inventoried on reopening, and later
   passes native admission while retaining its gap origin and old intent.

The resulting `run.json` lists six sidecar directories, full packet
artifacts, checkpoints, actual child exit/stdout, native confirmations and
all unsupported qualifications. The supplied validation times are
controlled inputs, not measured mining rates or propagation delays.

The Rust target
[`native_owner_journal.rs`](../../trillionnium/crates/trnm-pon-node/tests/native_owner_journal.rs)
exercises real Legacy and AuthenticatedV1 owners, the actual subprocess
cut, stopped pending values, exclusive locks, torn tails, wrong pins,
packet corruption, budget failure before admission and after native
commit, and invalid-packet identity separation. Its ignored subprocess
helper is explicitly executed by its parent process-cut test.

The Python target
[`test_native_owner_journal.py`](test_native_owner_journal.py) requires
`NATIVE_OWNER_JOURNAL_RUN` to name the fresh actual example's `run.json`.
Missing native evidence is a test failure, not a skip or a synthetic
fallback. Positive cases use those real artifacts. Negative cases modify
private copies to check gap erasure, altered weights, wrong owner/clock
bindings, missing artifacts, false freshness, transaction membership and
externally pinned rollback.

From the repository root, using the managed Linux toolchain and private
Cargo home/target used by the original SQLite host boundary:

```sh
cargo test --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --test native_owner_journal -- --test-threads=1

cargo run --locked --offline --manifest-path trillionnium/Cargo.toml \
  -p trnm-pon-node --example native_owner_journal_v1 -- NEW_OUTPUT_DIRECTORY

python formal/pon-nakamoto-v1/native_owner_journal.py \
  --run NEW_OUTPUT_DIRECTORY/run.json --output NEW_CHECK_JSON

NATIVE_OWNER_JOURNAL_RUN=NEW_OUTPUT_DIRECTORY/run.json \
  PYTHONPATH=formal/pon-nakamoto-v1 \
  python -m unittest discover -s formal/pon-nakamoto-v1 \
    -p test_native_owner_journal.py -v
```

The example refuses existing output directories. Retained evidence must
identify the exact source, full Cargo graph, toolchain/profile, invocation,
binary and artifact hashes, outcomes and any failed attempts. A local
successful component run does not replace all remote CI gates or the
missing scientific certificates.
