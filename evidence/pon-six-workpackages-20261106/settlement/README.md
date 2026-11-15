# Native Cell effect replay: owner binding and retained failures

This package fixes a local native-owner boundary in the existing single-Cell
retention and repair APIs. The original public-service and full-History gates
remain **HOLD**. Neither a local replay control nor preserved evidence qualifies
public task demand, permanent availability, independent custody or activation.

## Concrete defect and change

The original `storage_service.rs` at `b173c1f52d927522af67df30dd08ecfb2e3a1bb0`
allowed a different Node to obtain an exact existing retention/repair readback.
Its M12 `open_budget`, `reserve` and `begin_effect_in_window` calls correctly
avoided reacquiring funding for an exact retry, but that also left this caller's
native context and recorded owner generation unchecked. A pending physical
success could consequently be marked complete under the wrong Node. This is a
provenance/completion boundary failure; the counterexamples do not demonstrate
another payload copy or a native monetary payment.

The two APIs now call the existing M12 `check_effects` before local mutation.
It authenticates the actual Node snapshot against the journal's network,
parameters, genesis and recorded generation. The original policy, claim,
operation, effect and service window remain bound. New work still requires
current native funding. An exact pending/completed effect may still reconcile
after the original source is removed by a reorganization or cancelled through
ordinary native transactions. A foreign or stale owner cannot complete it.

The original deadline and repair CPU checks surround the added read. Pending
and completed effects retain their target-only readback path. Signed bytes,
stored schemas, native task cancellation/refund rights, budget ceilings and
activation settings are unchanged. There is no atomic commit across the native
chain, M12 journal and physical target, and this does not protect against restoring
the entire host journal from an old copy.

## Native verification

The final machine-readable [verification record](verification.json) lists every
attempt and its exact command, result, source hashes and scope. Whole-repository
committed integration checks are owned by the enclosing package and must not be
inferred from an earlier uncommitted component run.

The retained [RED run](red-native.log.gz) actually compiled and executed four
controls against the unchanged original production file: **0 passed, 4 failed**.
Every failure was the expected `unwrap_err` assertion observing `Ok(Pending)` or
`Ok(Done)` from the foreign Node. This is a runtime counterexample, not a compiler
failure. [Source hashes](red-source.json), the
[original added test source](red-regression-source.rs.txt),
[registration](red-test-registration.rs.txt), [patch](red-owned-source.patch)
and [command](red-command.json) preserve the exact tested boundary. The initial
build's SQLite I/O qualification warning remains in the log; this local owner
counterexample makes no Host-resource qualification claim.

The first all-feature candidate attempt did not execute any native tests because
the offline cache lacked `foreign-types 0.3.2`. Its
[command](green-attempt-1-dependency-command.json),
[log](green-attempt-1-dependency-native.log.gz) and source snapshots are retained.
The locked graph was subsequently fetched without changing the lockfile.

The second all-feature candidate attempt completed the full native storage
owner suite: **20 passed, 0 failed, 0 ignored**, with 1,152 other tests filtered
out. The denominator is the original 15 storage/release/cache controls plus the
five new controls. Its [log](green-attempt-2-native.log.gz),
[command receipt](green-attempt-2-command.json),
[pre-run hashes](green-attempt-2-source-before.json) and
[post-run hashes](green-attempt-2-source-after.json) bind that result to the named
source bytes. All eight recorded source/manifest/lockfile hashes stayed equal
through the command and matched the final local bytes when sealed. The test
body took 11.72 seconds; the command took 655.953185734 seconds including a shared
target lock wait and first all-feature compilation. Neither number is a public
service latency measurement.

There were three test-command attempts in total: one executed RED run, one
dependency failure that started no native test, and one executed GREEN run.
The four expected RED failures remain in this denominator; the dependency
failure is not credited as a native pass.

Five new controls cover three actual Node backends: Legacy, AuthenticatedV1 and
PermanentAccountGrowthV2. Four controls cover retention/repair crossed with
pending/completed history. Each rejects both a foreign context and a stale
same-context owner before journal or payload changes; then exercises real branch
replacement, absent native funding, cold owner/journal/target reopen, exact
recovery with an empty cache, unchanged monetary/resource charges and refusal of
a new operation. The fifth control uses actual signed task cancellations/refunds,
then recovers the old physical repair without redispatch and rejects new storage
or repair against the cancelled sources.

Pending states are explicit local handoff boundaries with actual retained/repaired
bytes. They are not physical power-loss tests. These three backends are not an
executed PQ-network profile or an independently operated storage service.

## Original acceptance evidence remains failed

The [read-only acceptance record](original-acceptance/readback.json) is bound to
the original `b173c1f5` Actions run, not this candidate's new native tests.
No original campaign was rerun or relaxed by that readback.

| Original observation | Result retained |
| --- | --- |
| Four-second attack-free service baseline | 1 of 1 required business transactions independently confirmed; success latency 2.802270278 seconds |
| Four-second service with 16 attack workers | 0 of 1 required business transactions confirmed; `CONFIRMATION_TARGET` remains failed |
| Pressure request denominators | All 16 workers, 257 attack calls, 7 signed Submit calls, 2 History calls/import observations, 21 Head calls and 287 of 287 receiver records retained |
| 4,105-block paid public full sync | 2,331 successful import returns before the original 1,800-second server lifetime expired; the next History RPC returned connection refused |

Successful import returns are not a claim about durable commit counts or business
confirmations. The server recorded its actual `lifetime_expired` exit before its
own shutdown signal. The full test retained exit 101 and all original reader
failures. Its `/usr/bin/time` record reports 337.28 seconds of user CPU, 467.28
seconds of system CPU, 3,218.57 seconds of wall time and 15,868 KiB peak RSS for
that measured command. These are original command observations, not a per-request
allocation or a claim that all resource coverage is complete.

The original public Host keeps `cpu.max=25000 100000`, 2 GiB memory, no swap and
256 pids. Missing all-worker CPU, physical network bytes, per-request peak RSS
and disk-growth fields remain unknown in the retained service report. Nested
dispatch/work/import intervals are not added together. No incomplete or late
operation receives successful confirmation credit.

## Retained bytes and availability limits

Two archives preserve **192 original text/JSON/log members without editing their
bytes**, including the complete confirmation report, failed native manifests,
resource observations and Host control receipts:

- [History raw text](original-acceptance/history-head-raw-text.tar.gz)
- [Service raw text](original-acceptance/service-head-raw-text.tar.gz)

The [History ZIP inventory](original-acceptance/history-head-original-zip-inventory.json)
and [service ZIP inventory](original-acceptance/service-head-original-zip-inventory.json)
cover **4,422 original ZIP members** with individual sizes and SHA-256 hashes.
The original ZIP sizes, hashes, artifact IDs and provider links are in the
readback record. Omitted binary, SQLite and packet bytes remain only in those
original ZIPs; their hashes do not make those bytes permanently available.
This preservation scope does not close the protocol's material-retention gate.

Extract the archives into a new directory and compare every extracted member
against its corresponding original ZIP inventory. Do not execute retained native
binaries or treat a retained report as a new run on changed source.

Original command logs are stored losslessly as `.log.gz`; their native whitespace and failure output are unchanged. Decompress to the original `.log` names when checking historical command-record paths. The shared [log storage index](../validation/lossless-log-storage.json) binds the original and compressed bytes.
