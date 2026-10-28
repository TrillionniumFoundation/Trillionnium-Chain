# Original native campaign CI: retained failures

This archive preserves all six predeclared runs on two exact source heads. It is
an observation of the original regression, not a new experiment or a replacement
acceptance rule. Both workflow runs failed and remain failed.

| Source head | Workflow run | Original outcomes |
| --- | --- | --- |
| `63ae5018158d62d6c75a3d690ce009b396e8d9bd` | [40489614467](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40489614467) | FAIL / PASS / FAIL |
| `e9c4bb0d3a324b1d79b7b99326512bfb707d0025` | [40490909572](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40490909572) | FAIL / FAIL / FAIL |

The actual release builds completed, tracked source identities and copied binary
hashes remained stable, and the original test ran three times on each source.
The reports contain 1,024 actual signed seed transfers and 21 business blocks per
campaign. All signed business rounds confirmed inside the original pressure
window. All hostile calls were refused. Both final CPU accounting identities and
zero-live-owner conditions were retained. These facts do not override the original
failed predicate.

## Exact failed predicate

For the five failing runs, the only false reconstructed original phase condition
was `depletion_during_a_business_round` in `from-zero`. Actual depletion happened
within the 30-second phase, but after the last business round had finished. The
original schedule, inputs, actor count, CPU budget and predicate were not changed.

| Head | Attempt | Last business round ends (s) | First observed depletion (s) | Original from-zero result |
| --- | --- | ---: | ---: | --- |
| `63ae5018` | 1 | 11.680925092 | 12.090179762 | FAIL |
| `63ae5018` | 2 | 11.512652265 | 10.512952053 | PASS |
| `63ae5018` | 3 | 11.384273631 | 14.673674589 | FAIL |
| `e9c4bb0d` | 1 | 11.401921969 | 15.695277369 | FAIL |
| `e9c4bb0d` | 2 | 11.639962661 | 15.846911302 | FAIL |
| `e9c4bb0d` | 3 | 11.242049139 | 16.503928402 | FAIL |

The time columns use the original phase-relative monotonic clock. They are not
independent network latency measurements. The passing second run is retained as
one original observation; it was not selected to replace the other two.

## Pure PoN boundary

These mandatory legacy regression runs identify
`native-public-evaluation-dev-v1 + continuity_v1 explicit maintenance` and
`public-protected-development-v3`, with **`ticket_bits = 8`**. They are not evidence
for the zero-grinding pure-PoN transport. They do not introduce or recommend that
ticket in the pure-PoN profile. The separately versioned zero-grinding ingress
campaign and its own original inputs remain the relevant pure-PoN evidence.

The scope is one controlled host with separate attacker OS processes and TCP
loopback. There is no independent-operator/WAN, throughput ceiling, cryptographic
hardness, full PQ transaction path, model improvement, release or activation
qualification.

## Retention and reproduction

`observations.json` reconstructs the original common and phase predicates from
the reports and records every failed condition, all three business intervals,
actual final CPU flow and the exact transport profile. Reconstruction agrees with
every original phase verdict. It does not retime requests or recompute a more
permissive verdict.

Each cohort directory contains three complete original aggregate reports as
deterministic gzip files, plus `metadata-and-logs.tar.gz` with original source,
resource, result, command, stdout/stderr and failed-attempt metadata. No report
field is removed from the compressed originals. `manifest.json` records their
original bytes and SHA-256 hashes; the source ZIP identifiers, sizes and hashes
are in `observations.json`. Original binaries and auxiliary per-process files
remain in the fully hashed source CI artifacts.

The exact original predicate is in
[`public_v3_multiprocess.rs`](../../trillionnium/crates/trnm-pon-node/tests/public_v3_multiprocess.rs).
No production source, policy, limit, ignored-test selector or assertion changes
are part of this archive. Future revised experiments require their own declared
inputs and must keep these failed observations.
