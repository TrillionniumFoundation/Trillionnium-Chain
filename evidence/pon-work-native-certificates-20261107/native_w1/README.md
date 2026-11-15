# Actual native W1 bridge execution

Date: 2026-11-07, America/New_York. Starting source:
`2789e9d9999920d858c1b65d3bff29122079cb4e`.

The existing native `pon_work_io` and `pon_zero_io` examples were built and
executed from the independent continuation checkout. No Rust production source,
W1 namespace, transcript, proof grammar, workspace lockfile or default consensus
rule was changed by this component. The bridge probe has its own research
namespace and does not implement the MU1 outer lottery.

## Observed checks

`build-observations.json` retains the exact command, exit status, elapsed interval
and stdout/stderr hashes for the pinned toolchain, locked/offline Cargo graph,
release build, selected strict Clippy and selected Rust formatting check.
The workspace lockfile remained byte-identical. Cargo home and target directories
were private to this run; an existing populated cache was copied before use.
No network resolution was used.

The initial inherited-PATH probe could not locate Cargo. Its failure is retained
in `logs/initial-path-observation.txt`; it ran no compiler or test. The subsequent
actual absolute Rust 1.95.0 toolchain was used for all successful build checks.

`bridge_probe/result.json` records 21 actual native subprocess calls, one-unit and
two-unit sets, and 10 controls. Every generated positive certificate is the full
49,188-byte W1 proof. Native scalar, native prepared and independently coded
Python proofs agree byte-for-byte. All designated native refusals occurred,
including a correct product with a false transcript, a correct transcript with
a false product, task/index/unit-count transplants, and incorrect proof length.
Legal structured zero work produces the same complete certificate; unsupported
nonzero input is refused by the zero-only producer.

All raw native inputs/stdout/stderr are retained under `bridge_probe/` and tied
to the binaries and source hashes in the result. Recorded wall intervals include
process startup. They are neither a hardware qualification nor a lower bound
on the least costly legal strategy.

## Native execution source boundaries

`native_execution_source_facts.json` pins the actual node sources and identifies
the admission, owner release/reacquisition, current-clock rechecks, activation,
recovery and local request-observation paths. Ordinary activation compares its
submitted candidate with the incumbent; the explicit recovery path scans for a
global maximum. Existing observer clocks are local monotonic diagnostic clocks,
not a global inventory of all ready forks and parent-binding events.

This audit did not reexecute the node or infer instantaneous global maximality,
all-branch availability coverage, a complete clock-bound execution certificate,
minimum W1 cost, a quantum resource tail, native common-prefix security or a
six-successor risk. The MU1 outer relation must separately bind these native
unit statements and check its own aggregate lottery. Those qualifications remain
explicitly false in this bridge result.

The probe and reproduction instructions are in
[the native bridge component](../../../formal/pon-nakamoto-v1/native_w1_units_probe/README.md).
