# Finite public V3 local service campaign

`tests/public_v3_service_campaign.rs` records each actual client call in a
finite mixed workload using the existing public V3 server, client and Node
APIs. It adds a saved current-V3 workload and restart observation to the
existing original connection-work sustained campaign and V3 socket tests.

Two server epochs each contain 65 attempts: 16 honest Head probes, eight
ordered honest PoolStatus/PoolSubmitBundle/Submit/Head calls, 16 paid malformed
Submit calls rotating eight public development guest keys, eight paid
false-transcript W1 Submit calls rotating another eight guest keys, 16 unpaid
invalid four-byte prefixes, and one deliberately closed pre-admission socket.
All 130 attempts are retained. Four
valid transfer transactions pass the actual persistent pool and are mined by
the separate local producer across the two epochs. The receiver performs its
normal full admission. After each epoch, its actual state is compared byte
for byte with the producer state.

Between epochs the server is stopped and joined, the receiver Node and its
database handles are dropped, and the same persisted receiver is reopened.
The active tip and state root must survive this same-process owner/server
restart. The second epoch starts a fresh public-server lifetime. There is no
process kill, physical power interruption or remote operator in this campaign.

Before each epoch, the local producer constructs a real valid empty candidate
on the receiver's known retained parent, then runs the normal W1 verifier on
that reference. The attack changes only the final claimed transcript digest.
A bounded hash-only search finds a different digest whose ordinary
header-bound ticket meets the unchanged target. All eight attack requests in
that epoch use those exact forged bytes. Construction, reference-verification
and ticket-search times, the exact reference/forged packets and the number of
search trials are saved separately. This preparation is a concrete local
fixture; its cost is not a lower bound for the fastest attacker.

## What the finite target means

The fixture uses the current V3 policy digest, eight admission bits, a 2,000 ms
cookie policy and a 500 ms client deadline. The development service target is
a maximum 2,000 ms gap between successful honest Head completions. The maximum
includes the beginning/end of each observation window, all failed attempts,
idle scheduling and the gap across the actual restart. It is recomputed from
the complete per-attempt times; neither failed probes nor restart downtime
are omitted. The inter-epoch gap also includes preparation of the second
false-transcript fixture. All planned honest mutation calls must succeed.
Malformed and false-transcript paid packets must remain rejected, the injected
socket-close call must fail, and native state equality and shutdown resource
release must hold. Each epoch must observe at least one signed
`WORK:Transcript` refusal from the forged-packet lane, with corresponding
server full-work start, finish and failure counts. Other forged-packet
attempts may be refused by resource budgets or fail before full work; their
outcomes remain in the same eight-attempt denominator. The target does not
require every attack request to start full verification.
Response authentication is checked by the native V3 client during each call;
the report retains its decoded reply, not a separately replayable signed frame.

These finite measurements do not establish a service-level agreement, tail
confidence, steady-state saturation, fairness under arbitrary guest identities,
independent operator ownership, WAN performance, or work-profile hardness.
The separate malformed and false-transcript lanes exercise early packet
rejection and actual full W1 transcript rejection under mixed service. This
short campaign does not replace the original sustained false-transcript
campaign or establish an adversarial resource bound. All public, independent, resource-fairness,
work-qualification, physical-power-loss and activation flags remain false.

## Save and validate a source-bound observation

From a clean committed checkout with the pinned Cargo dependencies available:

```sh
python3 scripts/run_public_v3_service_campaign.py --out /absolute/new/observation-directory
python3 scripts/ci/check_public_v3_service_campaign.py /absolute/new/observation-directory
```

The destination must be new and outside the checkout. Normal Cargo environment
variables select an installed toolchain/cache/target directory. The runner
builds the exact native integration-test executable with `--offline --locked`,
records the compiler and selected build options, hashes the executable before
and after execution, runs the actual test, and runs six negative-validation
tests against the actual resulting report. Source commit/tree and the complete
existing qualification source inventory are bound before and after execution.

The directory retains build/run/negative-test logs, the request report, both
closed native stores and their file hashes. A failed command preserves its
logs and any report/store already produced; the final validator rejects the
bundle. The report and bundle use explicit V2 schema names. Existing V1
observations remain unchanged and are checked using their matching source
version. `--historical` permits a past committed source inventory for the
understood schema without claiming the evidence was collected from the
current working tree.

The report validator checks exact record fields and attempt denominators,
actual honest/paid-call overlap for both paid attack lanes, stage-cost nesting, completed-write counts,
the ordered pool/block transaction bytes, packet-header/ACK/final-state
bindings, restart observations, shutdown resources and recomputed gap/target
results. It checks that only the claimed trace changed, independently
reproduces the bounded header-bound ticket search, binds each full-work
request to the retained fixture and reconciles signed transcript refusals
with the server work counters. Overlap means measured client-call intervals;
it is separate from the observed full-work rejection and does not establish
overlapping verifier CPU spans. Negative tests mutate failures, sequence/counts,
gaps, wire/ACK bytes, trace/ticket inputs, work counts, restart state, authority
flags and numeric types. File and source hashes bind
recorded bytes; they are not cryptographic execution or hardware attestations.
The native run supplies full verification and byte-state equality; the Python
report check does not independently rerun all W1 proofs or the complete ledger.

For the default workspace test run, the native test uses a temporary directory.
`TRNM_PUBLIC_V3_CAMPAIGN_DIR` instead selects a new saved native directory; the
runner sets this variable itself after removing inherited `TRNM_*` controls.
The test is part of normal `--all-targets` execution and is not ignored.
