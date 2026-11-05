# W1 statement v2: material binding and bounded fresh-proof experiment

This continuation repairs the previously missing raw A/B commitment binding in
the research statement. It preserves the native complete W1 verifier, its original
work identity and the Node current-parent qualification checks. It creates no
proof-only Node admission path and changes no security or production qualification.

## Exact statement and implementation

[RELATION_ABI.md](RELATION_ABI.md) records the 49,506-byte input, distinct
`TRNM-W1-ZK-JOURNAL2\0` domain and 16,882-byte journal. The guest executes the
full current native W1 relation before publishing the original `artifact` and
`qualified-task-input-v1` commitments. The shared extraction helper uses the
same byte ranges and hash domains as the pre-existing Node checks. Parent-state
eligibility, signed manifests, expiry, execution and commit authority still
belong to the ordinary native Node path.

The new independent [verifier](../../formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs)
requires the caller's separately supplied 64-byte expected A/B commitments and a
compiled image ID. It reuses the hardened v1 construction and wire checks: only
Succinct transparent receipts, the fixed Poseidon2 suite, final join control,
parameter digest and canonical control inclusion path. Full image/claim/journal
verification is required before returning any work ID. The original v1 profile
retains its original fixed image and remains a separate control.

The isolated `methods-v2` and `host-v2` packages build the new guest without
rebuilding or relabelling the historical v1 guest. Current production ML-DSA
dependency edges required synchronization of the research host and guest-v2
locks. Earlier failed locked/offline attempts remain recorded in
[module-environment-observations.json](module-environment-observations.json).
The historical v1 guest lock and proof files are unchanged.

## Validation records

- [Native relation tests](native-relation-tests.txt): ten original/v2 controls,
  including independent scalar verification, unchanged lottery identity,
  cross-version substitution, artifact mismatch and noncanonical field values.
- [Native Node controls](native-node-qualified-tests.txt): actual signed task
  eligibility and incorrect model/input materials retain their original refusal.
- [Artifact helper tests](native-artifact-tests.txt) and strict native Clippy
  [checks](native-clippy.txt) / [relation checks](native-relation-clippy.txt).
- [Input declaration](input-declaration.json) and
  [expected commitments](expected-artifacts.bin) are independently calculated
  from the original fixture A/B bytes. This fixture declaration is not evidence
  of a registered current-parent task manifest or Node admission.

The [recovered locked build](build-v2-recovered.json), two retained host tests,
strict all-target Clippy and formatting checks actually completed successfully.
The [fresh guest identity comparison](guest-v2-recovered-identity.json) matches
the independent verifier's compiled image and the actual 375,928-byte guest.
The earlier executor interruption remains an
[incomplete build observation](interrupted-locked-build.json); an existing binary
was not treated as evidence that the interrupted command succeeded.

The independent verifier's [validation](v2-verifier-validation.json) includes
its two actual historical-proof/material controls, strict Clippy and a locked
release build. Seventeen staged-observer tests subsequently passed using an
explicit owned tmpfs temporary directory while retaining the original 1 GiB
free-space floor. Disk-floor failures on the overlay filesystem remain recorded.
A follow-up audit repaired unknown process membership being mistaken for an
empty session. The retained [result record](lifecycle21-result.json) reports
exit code zero for the expected 21 controls; its raw `lifecycle21-direct.log`
was not included in this source snapshot. Permission/parse errors and unknown
group probes now fail closed with retained
errors and cleanup attempts. Normal ENOENT/ESRCH exit races remain distinct.
The pre-proof native observation contains 1,000 full replays, but no new proof.
This source checkpoint still requires the fresh complete proof and its 58 actual
saved-receipt controls; creating those controls does not count as executing them.

The [concurrent integration](concurrent-source-integration.json) preserves all
40 changed paths from the advancing PR branch, including the separate historical
PQ inventory work. Node source and the sole plan merge cleanly; the active Node
source pin is recalculated from the combined bytes. Earlier native tests retain
their original source scope until final integrated-source checks are observed.

## Fresh experiment and honest measurement boundary

The [staged procedure](../../formal/pon-nakamoto-v1/w1_zkvm/STAGED_PROVER.md)
uses one monotonic deadline through preparation, complete execution, each segment,
recursive compression, independent fresh verification, actual local serialization
and loopback byte transport, then 1,000 native / 100 fixed-receipt replays.
The maximum budget remains 7,200 seconds, each new segment 300 seconds,
checkpoint disk 256 MiB and available-disk floor 1 GiB. Failures, cancellations,
late exits and unobserved stages are retained. PID namespace-aware ownership
prevents a child process from disappearing from measurement simply because the
host `/proc` PID differs from the executor's local PID.

A successful local transfer measures only the declared experimental envelope on
127.0.0.1. Post-find publication, real network propagation, Node receipt admission,
confirmation, stale-block risk and aggregate process-tree peak RSS remain null
unless independently measured. Native and proof replays check the same v2 work
subrelation and explicit expected artifacts; they do not measure parent-state
qualification or establish a proof-population cost distribution.

## Security gate

The separate [exact-source component budget](../pon-w1-qrom-budget-20261105/README.md)
reproduces upstream error expressions and shows why the current construction's
parameter evidence cannot certify the explicit research error budget of 2^-128.
Those component expressions are not attack costs or an instantiated QROM proof.
Full recursive quantum security, end-to-end benefit and production acceptance
remain unqualified. Native W1 remains the engineering baseline.
