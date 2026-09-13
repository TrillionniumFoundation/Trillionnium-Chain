# Benchmark manifest and claim contract v1

Status: **candidate harness contract; no benchmark result**.

Every run binds:

- Plan, protocol, source commit/tree, binary, container and SBOM digests;
- exact comparator artifact;
- process → host → operator → region → custody mapping;
- measured link RTT/loss and fault schedule;
- exact workload byte roots, operation mix and enabled verification profile;
- warm-up, duration, replicates, seed, percentile denominator and clock source;
- raw event/metric roots;
- dependency exits, findings and signatures.

## Metric definitions

- committed goodput: transactions finalized and replay-verified per second;
- Order finality: proposal admission to exact three-chain finality event;
- result finality: verified result plus challenge maturity/decision;
- settlement finality: exactly-once economic receipt in authenticated state.

Submitted or ingress TPS is never substituted.

## Fleet completed-run summary schema 4

The bounded LAN collector and its consumers use completed-run summary
`schema_version = 4`. Its `performance.committed_blocks_per_second` is the
authenticated ordinary committed-block count divided by the measured interval
in seconds. It is a block rate, not transaction goodput. The existing no-fault
profile still requires that committed ordinary blocks map exactly to the
finalized height; submitted or unfinalized tail blocks cannot enter that count.

Schema 3 named this block rate `committed_goodput_tps`, which had the wrong unit.
Current consumers reject schema 3, the old field and mixed old/new fields.
Historical evidence remains immutable; a new summary must be derived again
from its exact authenticated raw inputs and receive a new digest. Build-report
schema 3, signed runtime artifact schemas, the no-fault profile, root checks
and independent acceptance requirements retain their existing contracts.

No transaction-rate field is produced by this projection. Even when a workload
contains two envelopes per block, multiplying the block rate by two is not
proof of finalized, successful, replay-verified transactions. Such a metric
requires a separate versioned contract binding actual authenticated bodies,
execution outcomes, finality, replay results and the measurement window.

## Topology naming

A result must separately report process, host, operator, region and custody cardinalities. Seven processes on one host remain one host failure domain. One organization running many keys remains one operator/custody domain.

## Result classes

- `harness-only`: no results, metrics or signatures;
- `measurement`: accepted predecessor exits plus raw traces;
- `surpass-candidate`: measurement plus two independent reproductions and all comparison/safety conditions.

A changed workload, denominator, topology, source, comparator or fault schedule creates a new manifest ID and invalidates prior comparison claims.
