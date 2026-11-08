# Authenticated epoch discovery: source-bound component evidence

This continuation starts from `0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a`
(Cell capability PR #807). It adds an explicit authenticated PQ V3 discovery
profile and a fresh epoch directory. The original V1/V2 implementations and
their permanent high-water semantics remain historical, callable profiles.

The [protocol contract](../../docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md)
and [five-part storage acceptance register](../../docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md)
describe scope. The [sole development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
remains authoritative. Operational qualification is **HOLD_NO_GO**.

## Original-source observations

| Observation | Actual result | Source boundary |
| --- | --- | --- |
| Original discovery regression suite | 52 passed, 0 failed, 0 ignored, 376 filtered | Unmodified exact `0dc13a92...` source; default features; native library selector `cell::discovery::` |
| Desired expiry-recovery red controls | 0 passed, 2 failed, 0 ignored, 428 filtered; Cargo exit 101 | Same original implementation, augmented only with two explicitly failing test modules and their registrations |

The original baseline passed locked/offline workspace metadata and ran with
Rust/Cargo 1.95.0, two build jobs, one test thread and a separate target on shared
Linux x86_64. Full [baseline stdout](baseline/native.stdout.log),
[stderr](baseline/native.stderr.log) and [command summary](baseline/summary.json)
are retained. This selected baseline is not a new complete-crate or all-feature
runtime claim.

Both red controls perform 16 independently reopened durable operations for one
manifest, each using a real valid signature. All advertisements then expire;
the observed clock advances by 601 seconds and the directory reopens. A newly
signed seventeenth identity is still rejected with `discovery identity capacity`.
The directory's explicit test clock is advanced; this is not a 601-second
elapsed-time or WAN campaign. Signatures, SQLite commits and reopen operations
are native, actual executions.
The PQ control uses seventeen real, explicitly pinned ML-DSA-65 keys. There is
no fake verifier and no large single response whose scheduling explains the
failure. The [complete red output](red-controls/native.stdout.log),
[build output](red-controls/native.stderr.log) and
[source/command/log-digest summary](red-controls/summary.json) preserve the failures.

The test sources are retained as
[classic](red-controls/classic_prior_operations_expiry_red.rs) and
[PQ](red-controls/pq_prior_operations_expiry_red.rs). They are evidence files,
not registered tests in the final green suite. To reproduce, use a separate
worktree at exact `0dc13a92...`, copy them into the respective classic/PQ discovery
module directories, add `#[cfg(all(test, unix))] mod <file_stem>;` to each parent,
and run the exact command in the red summary. This is a test-only augmentation
of the old implementation, not execution of a new V3 candidate.

## Initial staged V3 observation

The first 27-file V3 snapshot passed 53 selected native PQ discovery tests:
37 new tests and 16 retained PQ controls, with zero failures, zero ignored and
412 filtered. Native execution took 204.16 seconds; the Cargo command, including
compilation, took 243.02 seconds. Formatting and both workspace/fuzz locked,
offline dependency graphs also passed. This was a staged, source-stable smoke
run, not a frozen-commit or complete-crate qualification.

The [command summary](staged-attempt01/summary.json),
[native stdout](staged-attempt01/discovery-native.stdout.log),
[native stderr](staged-attempt01/discovery-native.stderr.log),
[before](staged-attempt01/source-before.json) and
[after](staged-attempt01/source-after.json) source fingerprints are retained.
The before/after fingerprints match exactly. The complete input bundle's SHA256
is `82e2256d1228b1baf4a07a9962587213eab7c836a9dce24ee4245e99b08b2f78`.
The [provenance record](staged-attempt01/provenance.json) lists log digests and
also preserves the expected stale source-pin refusal before refreshing pins:
`check_pq_research_integration.py` exited 1 on the changed fuzz lockfile. That
refusal is not silently replaced by the later refreshed-source result.

## Review-discovered sequence-selection red controls

Review identified a separate operation-local regression: a higher valid sequence
could disappear from candidate selection when its short lease expired during
collection, or when a full source quota refused its withdrawal. A later lower
sequence from another source could then be selected. The correction retains
the highest actually verified sequence before current-expiry and quota filtering,
without granting durable admission to a refused record or widening any budget.

The first native attempt ran three new real-TCP tests against the unchanged
initial V3 implementation (`auth.rs` SHA256
`7214ea4e588a95cb0043d750123d7ad657ed7cba275ba54f1d4e62535ce7a30b`).
It recorded 0 passed / 3 failed / 465 filtered in 24.60 seconds. Both expiry
orderings reached the intended failure: the old implementation actually selected
the older endpoint. The third test failed at its preparation assertion before
reaching the quota regression; that unexplained setup failure is retained and
is not counted as a confirmed quota reproduction. See the complete
[first stdout](sequence-red-attempt01/native.stdout.log),
[stderr](sequence-red-attempt01/native.stderr.log) and
[source/command summary](sequence-red-attempt01/summary.json).

A diagnostic-only successor kept the same implementation, original deadlines,
records and operation structure. The isolated quota test's preparation actually
completed in 3.266 seconds with two connections, 35,476 received bytes, eight
provider plus two bootstrap validations, and no capacity rejection. The next
operation then reached the intended failure: a quota-refused newer withdrawal
allowed the old endpoint. This run recorded 0 passed / 1 failed / 467 filtered
in 7.75 seconds. See the complete
[diagnostic stdout](sequence-red-attempt02/native.stdout.log),
[stderr](sequence-red-attempt02/native.stderr.log) and
[source/command summary](sequence-red-attempt02/summary.json).
Both attempts retain the complete test and pre-fix implementation bytes.

## New profile and acceptance boundary

V3 changes the signed replay namespace explicitly: fixed epochs, active/history
quota separation, bounded source shares, immutable directory pins, native
bootstrap query/reply authentication and the original aggregate Cell reservation.
It cannot be presented as an automatic repair of existing V1/V2 databases.

New verification records must identify their own frozen source and retain
complete native stdout/stderr, locked graphs, formatting, strict Clippy,
negative source/CI controls and before/after source checks. Independent unsigned
byte vectors establish encoding agreement only. They do not establish an
independent cryptographic implementation or a production security level.

Actual independent operators, shard placement/repair, funded retention,
72-hour WAN cohorts, a persistent TCV1 retained-set owner and ordinary
restricted-loader/device/Hepta next-task execution remain unqualified. Safe
bounded refusal is not service success, and neither original deadline is widened.

## First committed complete attempt: preserved failure

Exact implementation `d4a0643a29ed1a35576a36d88189cadd28929c65` ran all 19
commands on the shared desktop Linux host: **17 commands passed and two failed**.
The [complete command summary](implementation-attempt01/summary.json),
[log manifest](implementation-attempt01/manifest.json),
[source before](implementation-attempt01/source-before.json) and
[source after](implementation-attempt01/source-after.json) retain that result.
The source fingerprints match exactly and the final worktree was clean.

The [complete native log](implementation-attempt01/complete-da-native.stdout.log)
records **463 passed / 5 failed / 0 ignored / 0 filtered** library tests in
642.28 seconds, Cargo exit 101. Cargo stopped before integration tests and
doctests, so this is not complete-crate acceptance. One new high-first timing
control selected the old endpoint, but that fixture had not measured whether
the short lease was still live when received; its precise timing cause cannot
be reconstructed from that run. Four unchanged classical sequence fixtures
failed on their very first long-lease advertisement, with three approximately
200 ms client read timeouts and one server-close EOF. They had not reached the
sequence/conflict/short-lease behavior under test. Their original 200 ms client
and 250 ms server bounds, including the separate 4-second client case, remain.

The [strict lint log](implementation-attempt01/strict-clippy.stderr.log) records
a separate optional-backend build failure: retained OpenSSL tests require the
`ossl350` API, while the run used system OpenSSL headers. The unchanged pinned
preparation script subsequently built isolated OpenSSL 3.5.9, checked the exact
upstream archive digest and ran real sign/verify plus wrong-message rejection.
[Provider metadata](desktop-provider.json), [validated inputs](desktop-provider-validation.json)
and the [complete preparation archive](desktop-provider-preparation.tar.gz)
retain that preparation. It did not change system OpenSSL, run Rust tests or
run the complete upstream OpenSSL suite. Future all-feature lint runs must
explicitly load that run's verified provider environment.

## Observable timing premise and desktop diagnostics

The short-lease fixture now mints its one-second high-sequence record after
receiving the actual query, after key/listener/directory setup. It records the
third source's query arrival and requires it to precede the same expiry; the
serial client exchange order then proves the two preceding authenticated replies
arrived while that lease was live. The third source waits for that exact expiry.
Production `auth.rs` is unchanged by this test correction. TTL 1 s, request 2 s,
overall 10 s, three connections, five validation slots and exact bytes remain.

The [desktop diagnostic summary](sequence-differential-desktop/summary.json)
retains a controlled successor at normal nice 0, the same 200% CPU/12 GiB bounds
and the same persistent ext4 SSD. The four untouched classical controls still
failed (0 passed / 4 failed / 464 filtered, 24.31 seconds). Normal priority did
not resolve their observation; later success must not overwrite this failure.
The revised old-implementation differential recorded 0 passed / 3 failed, but
only high-later and quota-withdrawal reached their target assertions. High-first
explicitly reported a timing-premise failure: the third query arrived after the
short lease. With the fixed implementation, high-later and quota-withdrawal
passed; high-first again failed the premise even though its observed discovery
result was a refusal. That is **2 passed / 1 failed**, not three valid passes.
Complete source snapshots, output, commands and before/after pressure samples
are retained in the same directory. These data do not establish a precise cause
for the earlier uninstrumented failure, nor independent operational capacity.

Full acceptance remains pending a new exact-source complete run. The next
Linux development observation uses an explicitly persistent NVMe temporary
directory and the pinned compiler/backend, retaining every original test and
protocol deadline. All operational qualifications remain HOLD_NO_GO.

## Second complete attempt and strict-lint correction

Exact candidate `939aa069af41d31d41082272d7ae7367ef08f812` was cloned to the ai395
Linux development host and verified with Rust/Cargo 1.95.0. Native temporary
files used the persistent local ext4 NVMe volume, not the host's tmpfs `/tmp`.
The isolated pinned OpenSSL 3.5.9 backend was rebuilt and smoke verified on that
host; its [metadata](ai395-provider.json), [validated inputs](ai395-provider-validation.json)
and [full preparation log archive](ai395-provider-preparation.tar.gz) remain.

The [controlled differential](sequence-differential-ai395/summary.json) passed:
four retained classical cases passed at their original bounds; the unchanged
`7e46e9` tests with pre-guard `7214ea` production source failed all three intended
assertions with both measured live-receipt premises valid; restored `1fac53`
production source passed all three. Old/fixed native runtimes were 4.46/4.10
seconds; the four retained cases took 1.90 seconds. Source-before/source-after
matched and the checkout returned exactly to C2. This does not erase or assign
a precise cause to the preserved shared-desktop failures.

The [complete C2 summary](implementation-attempt02/summary.json) records **18
of 19 gates passed**. The unfiltered [native runtime log](implementation-attempt02/complete-da-native.stdout.log)
contains 468 library tests, 34 integration tests and 13 compile-fail doctests
passing, with zero failures, ignores or filters. Library runtime was 78.37
seconds, the complete Cargo command 89.68 seconds. Strict all-feature lint
advanced past the prior OpenSSL API issue and rejected a redundant unit
expression in the new directory deadline test (`clippy::unused_unit`).
The [original lint failure](implementation-attempt02/strict-clippy.stderr.log)
and all remaining outputs are retained with the [byte manifest](ai395-attempt02-evidence-manifest.json).

The successor only makes that match arm empty, preserving its unit return and
test behavior, and refreshes its one source pin. It adds no lint suppression
and changes no production bytes, signature domains, test deadline or budget.
A new frozen-source 19-gate run is still required before full software acceptance.
All operational qualifications remain HOLD_NO_GO.

Source setup also preserves the initial missing-background-PATH `rustup` failure
and its explicit-absolute-toolchain recovery in the two `ai395-source-setup-*`
directories. The failed attempt is not relabelled as a compiler failure.
