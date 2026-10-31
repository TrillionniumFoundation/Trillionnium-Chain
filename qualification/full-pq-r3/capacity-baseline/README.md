# Original large-state capacity failures: fresh baseline

This directory preserves two **failed original tests** on commit
`da31aff73adadda492da2642bef1f8d3d74be530` plus the six-line observation-only
[source patch](source.patch). The original public mutation CPU limit remains
**2,000,000,000 ns (2 seconds)**. These are valid observations of failures;
they are not passing qualification results. **The optimized candidate's after
measurement is pending and is not represented by this baseline.**

The sole active engineering plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
This directory is evidence for that work, not another development plan.

## Observed original tests

| Original test | Backend | Owner plus scoped-worker CPU | Result |
| --- | --- | ---: | --- |
| `store::detached_admission::tests::admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner` | Legacy (first branch of the same test) | 1,062,225,586 ns / 1.062225586 s | Native operation returned `Ok`; the enclosing test later failed in its authenticated branch. |
| Same test | Authenticated | 2,807,473,643 ns / 2.807473643 s | `PUBLIC_MUTATION_CPU_BUDGET`, original test exit 101. |
| `store::detached_admission::tests::authenticated_large_parent_original_schedule_supplementary_denominator` | Authenticated | 2,791,540,228 ns / 2.791540228 s | `PUBLIC_MUTATION_CPU_BUDGET`, original test exit 101. |

The paired fixture has **8,625,548 actual UTF-8 key and canonical-value bytes**.
Its original early capacity observation is the lower bound **8,391,103 bytes**.
The fixture explicitly seeds 2,100 cells containing 4,080-byte strings in a
custom genesis and uses the original native validator plus one signed admitted
seed block. It does not demonstrate growth from the installed default genesis.

The raw logs retain the actual genesis, state root, admitted parent, original
CPU settlement receipt, worker counts, failure and unchanged false qualification
fields. No budget, held schedule, lease ownership, cancellation gate, recovery
gate or original assertion was relaxed. The authenticated failure aborts each
test before its later assertions can finish; source retention is not evidence
that those later assertions passed.

## Reproducible identities and scope

The tests ran sequentially against one freshly built release/all-features Node
library test executable with one build job, incremental compilation disabled
and one test thread. The build used Rust 1.95.0 and the independently built,
pinned OpenSSL 3.5.9 provider (`version_number=30500090`). The provider environment
must be exported when building; sourcing bare shell assignments is insufficient.

[The source manifest](source-manifest.json) retains hashes of 1,312 source and
configuration files, the exact observation patch, compiler identity, build
settings and executable identity. Its absolute temporary paths describe the
original run. The executable itself is deliberately not copied into this
repository. Its SHA-256 is:

`bfa734cc0a558bae9ffed81abe585dbc7f234e7d5c81bbe298694f1a6cae8c68`

The baseline was measured in a shared host environment. Exclusive hardware was
not established. CPU time here is the original owner plus scoped-worker
settlement, not elapsed wall time or an independent WAN/throughput benchmark.
The samples establish these failures on this fixture and environment; they do
not qualify all allowed key-count/value-size combinations, sustained concurrent
honest service, production release or whole-chain post-quantum security.

## Stage observations

The six added lines sample existing arithmetic observations before and after the
original paid operation. The original owner CPU settlement remains authoritative.
[stage-deltas.json](stage-deltas.json) subtracts the authenticated before/after
counters present in the raw logs. The stage intervals are nested and **must not
be added together** or substituted for the original CPU receipt. Stage CPU
measurements describe the observing thread; the original settlement additionally
includes its scoped workers.

Each failing authenticated operation recorded 16 complete-root calculations,
16 cold roots, zero retained-material uses, 10 complete commitments and five
absent/refused offers. The complete-commitment stage consumed approximately
1.579 to 1.589 seconds, including its complete-state-root stage. Six separately
observed persisted-root calculations consumed approximately 0.449 to 0.473
seconds. These observations motivate the candidate's bounded, exact-leaf
partition arithmetic; they do not establish that the candidate is correct or
fast enough. The original complete-root implementation remains its independent
comparison reference.

## Excluded attempts

Two earlier attempts are preserved separately and are **excluded from every
valid timing sample**:

- [Provider environment not exported](excluded-attempts/failed-provider-environment-not-exported.log): bare sourcing failed to export the provider settings, so the build selected the host OpenSSL 3.0.13 and lacked the gated seed-import API. This was an environment selection error; no signer compatibility patch was applied.
- [Disk full during observation](excluded-attempts/failed-enospc-during-observation.log): a later correctly linked execution exhausted disk space while printing its JSON observation. The partial log is not a complete or valid performance sample. Both valid observations above were run again after disk space was restored.

## Files

- [admitted-custom-genesis.log](admitted-custom-genesis.log) and [exit status](admitted-custom-genesis.status): complete original dual-backend test output.
- [authenticated-large-parent.log](authenticated-large-parent.log) and [exit status](authenticated-large-parent.status): complete supplementary authenticated test output.
- [source-manifest.json](source-manifest.json), [source.patch](source.patch) and [compiler.txt](compiler.txt): exact before-source and toolchain identity.
- [stage-deltas.json](stage-deltas.json): authenticated differences, checked against the raw observations when this directory was created.
- [receipt.json](receipt.json): file hashes, retained scope and explicit after-pending status.
