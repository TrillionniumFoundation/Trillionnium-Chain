# Eight complete Legacy reorganization cost observations

All eight planned native observations completed in the fixed order
`baseline, candidate, candidate, baseline` twice. Each independently constructs
512 real maintenance PNW1 packets, admits them to two owners, activates the
receiver from genesis, checks the complete resulting State, closes the receiver
and checks the cold-reopened State. No sample was dropped or retried. This is a
local Legacy component observation, not the original 4,105-block public History
campaign or the four-second hostile-load gate.

The baseline is `e70f13448aad715286fb8eb56fc802b09db643a3`; the tested candidate
is `a9efd4cba7546a8ef1e854ee0acdce9f5903ac2d`, tree
`807e589d4cb8c2c0d2c2123e8e4ff0870d6a1eb7`. The same tree is available as
`b59610295776ea44694ecef97d9f0e1de40bba0c`. Both native binaries use Rust
1.95.0 and the unchanged release profile, with no additional RUSTFLAGS. The
observer source is identical in both builds; native embedded source hashes,
binary hashes and complete candidate-checkout identity are checked before/after
attempts. The baseline is separately bound to its Git source objects, build
receipt and native embedded hashes.

## Observed medians, four attempts per implementation

| Scope | Baseline | Candidate | Candidate / baseline |
| --- | ---: | ---: | ---: |
| Receiver activation wall | 1.227694237 s | 0.916976377 s | 0.746909 |
| Receiver activation process CPU | 0.960835229 s | 0.704091528 s | 0.732791 |
| Whole native process wall, external capture | 71.622880503 s | 71.456950834 s | 0.997683 |
| Whole native process CPU, external wait4 | 70.012572500 s | 70.023786500 s | 1.000160 |
| Whole native process maximum RSS | 23,580 KiB | 23,580 KiB | 1.000000 |

Activation wall and CPU decreased by approximately 25.3% and 26.7% in this
fixture. Whole-process cost is effectively unchanged: preparation, including
all packet construction and W1 admission, dominates this workload. These eight
observations establish no statistical tail-latency, sustained throughput or
original-resource acceptance claim. Stage intervals are nested in the complete
native process and must not be added to it. Medians are not additive either.

The full campaign took 597.000666626 seconds, including source checks and
orchestration. [manifest.json](manifest.json) retains every attempt, all phase
values, whole-process CPU/RSS observations and the parent's/cumulative reaped
children's costs. These resource scopes overlap; they are not a simultaneous
global resource total. Physical energy, complete network/disk costs and global
peak memory remain unknown. The shared development container has different
CPU/memory limits from the original Host and performs no paid public RPC load.

## Build provenance and retained limitations

[Source bindings](source-bindings.json) bind both build receipts and executable
identities. Native executable bytes are not archived in this directory; their
identities and raw reports are retained. Reproduction requires rebuilding the
specified commits and creating fresh build receipts, not reusing an old
receipt for a different executable.

The first candidate build failed because a shared release target reused the
baseline M06 metadata, whose root method was private. No source was changed to
hide that error. Clearing the three changed packages rebuilt M06, Cell and Node
from the frozen candidate; the retry succeeded. Both attempts are retained in
[validation](../validation/README.md). Build CPU and peak-memory observations
were not captured and remain unknown. The original 512-block observer, the
300-second attempt cap and the five-second termination grace are unchanged.
