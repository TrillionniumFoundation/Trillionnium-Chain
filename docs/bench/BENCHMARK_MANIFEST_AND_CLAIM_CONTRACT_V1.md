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

## Topology naming

A result must separately report process, host, operator, region and custody cardinalities. Seven processes on one host remain one host failure domain. One organization running many keys remains one operator/custody domain.

## Result classes

- `harness-only`: no results, metrics or signatures;
- `measurement`: accepted predecessor exits plus raw traces;
- `surpass-candidate`: measurement plus two independent reproductions and all comparison/safety conditions.

A changed workload, denominator, topology, source, comparator or fault schedule creates a new manifest ID and invalidates prior comparison claims.
