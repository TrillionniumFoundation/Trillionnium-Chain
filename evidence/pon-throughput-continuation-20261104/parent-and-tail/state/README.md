# M06 compared-prefix continuation: retained component evidence

**Historical component observations; the candidate is not active by default.**
The later independent [preregistered three-arm experiment](prefix-three-arm/README.md)
returned HOLD: 16 of 18 comparisons passed, but two p95 regressions exceeded the
unchanged 10% limit. Its complete candidate source and single native observation
were archived, and the M06 defaults were restored exactly to 40a/b811. The earlier
two-arm medians below do not qualify or promote that candidate.

These are the original three local invocations, copied byte-for-byte with their
before/after component manifests. They measured the dirty M06 source on base
`40a5ba25e40fd5eda5b04fc1c3811320d438de11`, base tree
`75fe3367c4896a4f2d5f5dd561914613ec999343`, with component manifest SHA-256
`c798afd98869d9a669af92cde9ca7dc6f85fb59a3a05e83917f9937f787bc8c7`.
The manifest covers M06 Rust source/tests and Cargo graph files, not every
transitive source or the whole dirty checkout. Each invocation retained the same
component identity before and after running. These are not measurements of the
subsequently composed `73ab6e9a` Node or its new executable.

## Actual commands and outcomes

The command arguments, working directory, timestamps and process status remain
in each `.run.json`; the `.log` retains combined stdout and stderr.

| Invocation | Native result | Raw log | Command and source binding |
|---|---|---|---|
| Canonical comparison controls | 3 passed, 0 failed | [log](state-prefix-canonical.log) | [run](state-prefix-canonical.run.json) |
| Complete `pon_commitment::` module | 38 passed, 0 failed, 6 ignored | [log](state-prefix-commitment.log) | [run](state-prefix-commitment.run.json) |
| Exact ignored full-binding cost observation | 1 passed, 0 failed | [log](state-prefix-binding-cost.log) | [run](state-prefix-binding-cost.run.json) |

The cost invocation includes complete component binding and output destruction,
with alternating paired arms, 12 samples per arm and 8 bindings per sample. It
uses the original test profile: M06 optimization level 1, protocol and SHA-2
optimization level 3, with debug assertions and overflow checks enabled. Cargo's
overall profile label does not make the M06 package optimization level zero.

## Late-mismatch regression and retained negative result

The preceding [independent observation](../../local-components/state-final-unchanged-binding-cost-summary.json)
retains a 4,096-key last-value mismatch that cost 79.99% more than its own paired
reference. On a mismatch, its fallback still encoded the already compared prefix
again. The new private continuation reuses only the prefix already checked
against actual canonical bytes under the same immutable borrows. It still checks
the mismatching row and every remaining row before root, wire-limit or cache-limit
decisions. The controls retain original error priority, capacity charges,
empty-delta tree checking and expected-root checking.

The following medians come only from the two arms of the new retained run; the
earlier run is not used as a timing denominator. Every case and its sample counts
remain in the [paired summary](state-prefix-binding-cost-summary.json).

| Keys / value bytes | Case | Reference ms/binding | Prefix continuation ms/binding | Within-run change |
|---|---|---:|---:|---:|
| 4,096 / 512 | Unchanged | 14.413685 | 10.048421 | -30.29% |
| 4,096 / 512 | First value changed, same-root hint | 14.742554 | 14.788198 | +0.31% |
| 4,096 / 512 | Last value changed, same-root hint | 14.909491 | 14.736393 | -1.16% |
| 128 / 64 | First value changed, same-root hint | 0.162182 | 0.175555 | **+8.25%** |

The last-mismatch case is near parity with its reference in this run; the earlier
approximately 80% penalty is not reproduced by this fixture after prefix
continuation. This does not establish a universal speedup. The small first-miss
regression is retained, not omitted or relabeled as a gain.

The path remains **O(N)**: actual complete-state validation and traversal remain.
The result does not establish O(k) total work, a physical memory bound, Node-owner
throughput, durable commit latency, public TPS, independent W1 confirmation, WAN
capacity or final-source acceptance. The separate [CI evidence](../ci/README.md)
concerns workflow checks and Node test registration, not a rerun of these M06
measurements.

[Copy integrity](copy-integrity.json) records the actual source and destination
SHA-256 for all seven copied files. The original records were not rewritten.
