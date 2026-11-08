# Read-only review of the admission root fence and original Host cost

This is a source and retained-record review of commit
`819309fd312298e099642e1253b1d4ba07113e98`, tree
`f9d63abb9e2931fd78e26ccb87e3a7955068f267`.
It runs no tests or benchmark and applies no production patch. The original
four-second / 16-worker and 4,105-block business gates remain unqualified.
The sealed large-parent excerpt was captured while the full 819 native package
was still running; this package neither supplies its terminal result nor replaces
the full source-after obligation.

[REVIEW.json](REVIEW.json) contains exact values, input paths, SHA-256 identities,
and the 16 planned selectors. [SOURCE_SHA256.json](SOURCE_SHA256.json) binds the
23 specifically reviewed source files. [PROVENANCE.json](PROVENANCE.json) records
read-only jobs and preparation errors. Their complete bytes are listed in
[SHA256SUMS](SHA256SUMS).

## 1. What the proposed ordinary-admission change can do

The proposed production patch changes only the final active-State root call in
`store.rs:5156` to select the existing bounded `FullRootArithmetic`. The common
wrapper near line 2894 keeps its original `None` default. The private helper is
renamed from `legacy_reorg_root_arithmetic` to
`legacy_persisted_root_arithmetic`; six production occurrences, including its
definition, and seven existing test calls are covered.

Eligibility remains classical Legacy, excluding PQ Accounts/Application, Growth,
and the Authenticated backend. The original fresh SQL row scan, canonical grammar,
count and per-row bounds, current stored block and root claim, active/slot checks,
ancestry checks, progress callbacks, postwrite schema/no-write/transaction fences,
and atomic COMMIT/rollback stay in their original order. No Host checkpoint is
removed. The cache holds mathematical material, not a State, authorization, root
claim, freshness verdict, or partial update supplied by a caller.

The old final fence reaches `settings.state_root/root_for_config`; the candidate
can reuse exact mathematical work while still calculating from the complete
actual State. Existing read-active, parent-binding, derivation, and reorg paths
already use the separate `commitment_root_arithmetic` owner. A single 2 MiB entry
can churn when parent, child and active States alternate. Contention or arithmetic
refusal retains the original full-root path. The change therefore has a safe
bounded scope, but no measured isolated final-fence saving is established here.

### The original >8 MiB failure is still a failure

The sealed original selector is
`store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner`.
Its explicit genesis contains 2,100 seeded 4,080-byte String cells; it is not
default-genesis historical growth. Complete current key/value payload is
8,625,548 bytes. The original measured dispatch returned a response successfully,
but its native result was `PUBLIC_MUTATION_CPU_BUDGET`.

| Original observation | Value |
| --- | ---: |
| Complete paid CPU | 3,241,575,336 ns |
| Owner-thread CPU | 3,240,364,739 ns |
| Scoped-worker CPU | 1,210,597 ns |
| Already live-debited CPU | 3,241,568,151 ns |
| Settlement residual | 7,185 ns |
| Initial credit | 2,000,000,000 ns |
| Credited refill | 809,635,077 ns |
| Final paid credit | -431,940,259 ns |
| Original dispatch wall | 3,288,895,536 ns |

Owner plus scoped-worker CPU equals complete CPU. Already-live debit plus the
residual equals that same total; these are alternative decompositions, not extra
charges. The credit identity is exactly
`2,000,000,000 + 809,635,077 - 3,241,575,336 = -431,940,259`.
A faster execution also receives less time-based refill, so the old deficit is
not a fixed sufficient saving threshold. Actual unchanged-gate completion must
decide the candidate result.

The active State was observed unchanged after refusal. The test declares
`host_qualified=false` and `all_honest_service_qualified=false`.
The Authenticated supplementary test succeeded separately and does not erase the
Legacy failure or execute the original selector's skipped later arm.

All-zero Legacy `authenticated_arithmetic` observations do not observe the
independent `commitment_root_arithmetic` owner. They neither establish zero root
cost nor show that its cache was unused. The old diagnostic also does not locate
the exact checkpoint at which the budget refusal occurred. No isolated final-root
cost can be recovered from that record.

## 2. How to interpret the 16 future exact invocations

The retained plan requires the original full-819 authoritative terminal result,
complete matching source-after, an explicit clean new source commit/tree, and
root authorization before any new body executes. Each selector runs once with its
original internal assertions, profile, budget and deadline. Every failure remains.

- Exact 01 exercises actual ordinary admission: after warming mathematical
  material, a child INSERT trigger changes an untouched active canonical value
  or the active root claim. Historical parent/child reads remain independent;
  the final fence must refuse and roll back all rows, with original ROOT,
  owner-stop and cold-reopen semantics.
- Exact 02-13 retain existing reorg, profile, snapshot-source, cancellation,
  no-write/schema/ABA, and complete-readback obligations.
- Exact 14 is the original strict large-parent dispatch gate. Native success,
  owner/scoped CPU closure, reference State/packet equality and cold reopen are
  the effect criteria. Original dispatch CPU and wall are complete intervals,
  not isolated root timings.
- Exact 15 is separately named Authenticated supplementary coverage. It cannot
  stand in for the failed Legacy arm of exact 14.
- Exact 16 retains current SQL type/canonical bytes, same-length untouched-row
  corruption, original read checkpoints, cancellation and cold-reopen checks.

Actual Cargo `Running` binary identity, named-test reader, outer denominator,
complete source before/after and binary identities remain necessary. A future
16/16 would be targeted component evidence, not a full-package, four-second
service, History, or TPS claim. The 666 Python controls remain separately
predeclared and must be checked against the future source before execution.

## 3. The Host is shared; the two CPU accounts are different

`run_from_zero_host.py:95-106` launches the real native child under the fixed
`trnmponpublic.slice` with no delegation and no added privileges. Its parent is
`/sys/fs/cgroup/trnmponpublic.slice`, with `cpu.max=25000 100000`,
2 GiB memory, zero swap and 256 tasks. The harness creates the receiver,
16 attack-client threads, Head-reader thread, and independent ledger verifier in
one native process. This ownership statement follows the executed harness and
launcher; it is not a new per-actor kernel scheduling profile. The independent
ledger does not have an independent Host quota.

The receiver uses the original `PublicServer::new` scalar account with 2 s
initial credit and binds that account to its Node. The verifier owns a distinct
Node. At its first remote History import it acquires a cold zero-credit account,
earns the original 100 ms start reservation at 250 ms CPU per wall second, and
then reuses the same Node account across pages. Its approximately 400 ms first
wait is not a repeated CPU debit or a new account for every page.

Both observed pressure runs had zero receiver scalar-CPU refusals. Receiver
credit after shutdown was 1,998,472,035 ns for fresh H and 1,999,883,395 ns for
service x64 M. Receiver token exhaustion is therefore not the observed cause of
these failed confirmations. The kernel quota is still shared by work outside the
receiver's mutation accounting interval, including attack-client construction
and network negotiation, reads, transport and independent verification.

The protected server retains two proof-queue slots, two read-queue slots, two
mutation workers and one read worker. The dequeue mutex preserves FIFO while
obtaining the start reservation and is released before native dispatch
(`public_v3.rs:2240-2317`). The independent read lane remains separate.
Actual complete unique W1 can temporarily protect its current paid operation;
a 4,096-entry exact identity set prevents repeated promotion. Settlement releases
that priority. It does not prioritize later pages, later submissions, another
Node, or a caller identity, and does not promise general distinct-valid-work
fairness.

The independent imports observed here use `Owner::Exclusive`; owner-wait phases
were not entered in the 21 retained rows. Neither CPU-account mutex is held across
Work, root/State computation, SQL or join. Wall minus caller CPU is not a measured
lock-wait duration.

## 4. Actual CPU attribution and its limits

All values below are milliseconds converted from exact nanoseconds in REVIEW.
Each column keeps its original interval. These rows are not complete process CPU
profiles; joined actors and settled requests can include late returns or cleanup
outside the nominal four-second traffic window.

| Pressure report | Receiver paid | Receiver Work | Receiver dispatch excluding Work | Joined attacker clients | Independent replay/RPC outer caller |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fresh H, fresh challenge | 430.357290 | 288.322482 | 142.034808 | 342.947460 | 86.904177 |
| Service x64 M, retained attacks | 226.496228 | 73.494057 | 153.002171 | 263.787975 | 329.496167 |

Receiver Work plus dispatch equals receiver paid CPU; these two components are
disjoint within that measured scope. Body decoding (41.974971 / 50.891079 ms)
and response construction (10.022005 / 11.213043 ms) are nested in dispatch and
must not be added again. Fresh attack construction's 102.849120 ms is nested in
joined attack-client CPU; 0.049492 ms shared material setup is separate. All
214 fresh constructions and submissions are retained, with unique challenges;
the strict fresh reader requires no exact refusal-cache hit.

| Native import scope | Rows | Caller CPU | Host checkpoint CPU | Packet Work CPU | Admission CPU |
| --- | ---: | ---: | ---: | ---: | ---: |
| Fresh H baseline | 7 accepted | 534.997037 | 474.142861 | 432.661929 | 57.194996 |
| Fresh H pressure | 1 accepted | 85.559084 | 78.222604 | 75.300652 | 6.023900 |
| Service x64 M baseline | 7 accepted | 413.636870 | 368.123867 | 333.344715 | 45.077209 |
| Service x64 M pressure | 5 accepted + 1 deadline | 326.423472 | 297.271034 | 279.826748 | 27.153673 |

These columns overlap: Host checks occur inside Work, admission and resource
waits. Commit and M06 root observations are also nested. Calling-thread CPU does
not include any scoped-worker CPU; the M06 root stage is not a measurement of all
persisted or historical roots. The fresh baseline's 542.515822 ms outer replay
and confirmation timer also includes RPC/JSON/final-confirmation work, whereas
its seven replay rows sum to 534.997037 ms.

The fresh pressure page spans 2.459026970-3.858738888 s. Its wall interval is
1.399711918 s and caller CPU is 85.559084 ms; it admits one page without final
activation. The next History RPC fails before another import. In service x64 M,
the last observed import fails during Work before admission; its final-root fence
is never entered. The proposed fence cannot reduce that packet's Work phase.

Kernel/queue contention is consistent with these shared resource boundaries,
but the recorded wall/CPU difference is not enough to separate throttling,
scheduler latency, locks and other waits. Concurrent queue/grant wall totals
must not be added as CPU or as serial critical-path time.

## 5. No further Host shortcut is accepted

Current 819 `history_import.rs:264-271,303-307` already removes an old adjacent
duplicate Host read while preserving every original W1/execution boundary.
Refill waits still perform their required fresh checks. No further same-checkpoint
duplicate live-file fact was identified with a demonstrated substantial saving.

Keeping an old parent directory descriptor is not interchangeable with the
original absolute-path reads: rename/replacement, ancestor search permissions and
mount-view changes can produce different outcomes. Safe openat availability does
not fix that semantic difference. No long-lived limit descriptor, TTL verdict,
skipped checkpoint, weakened Host, changed budget or harness-only priority is
proposed.

Fresh statements that reach native W1 still require full Transcript verification.
An early Product filter cannot establish Transcript validity and changes canonical
error ordering. Existing exact rejection caching helps repeated bad inputs but
does not solve fresh challenges; cheaper refusals can also permit more attempts
in a closed-loop load. Current borrowed canonical-packet decoding remains a
component improvement already present in 819, not evidence of business completion.

The reviewed final-root fence is the only current proposed implementation here.
Its local large-State effect awaits the original test. It does not complete
touched-set/COW state or remove full history/SQL obligations.

## 6. ABBA and source-integration preparation

A full current-source search excluding historical evidence found only the 13
Rust occurrences of the old helper name. The 197-line
`run_legacy_reorg_root_abba.py` and its 59-line, three-control test contain no
helper-name dependency or source-oracle rewrite. The driver binds fixed e70 and
candidate observer/store whole-file hashes to independently built binaries.
The candidate rename naturally changes its store binding; it does not change the
baseline. No Python suite or native ABBA run is required merely for that rename.

The external source-integration v1 script had an unexecuted preparation defect:
a subprocess exception before normal return omitted the command attempt and
partial output from its receipt. The unexecuted v2 records the attempt before
launch, preserves exclusive stdout/stderr files and hashes, marks timeout/launch
failure/interrupted completion with null exit, and rethrows. Its configuration
prefix and full operation tail are byte-identical to v1.

The actual 819 corpus exactly roundtrips through the script's existing indent-2,
default-ASCII JSON format. Its 575 pinned entries and 483 unique required paths
are already sorted. Necessary changes are four exact Git-blob pins, the new test
path, generated native inventory and one existing workflow store-blob literal;
no matrix, resource or gate is changed. The actual refresh script is
`scripts/refresh_distributed_source_inventory.py`.

Read/locator mistakes retained in PROVENANCE are preparation observations, not
native or CI failures. No missing output is treated as success.
