# W1 admission resource contract r16 — component implementation and retained service gates

Status: **Draft / HOLD**. This change reserves classical authentication CPU in the
existing receiver intake epoch and repairs shutdown accounting. It does not make
a fabricated W1 transcript valid, remove its expensive-rejection asymmetry, prove
an accepted-work cost lower bound, or establish anonymous public-service fairness.

## Exact source and concurrent work

Implementation plus retained-test call repair: `2cd7353187bb58347ae7cbf884fef7aa2d05f610`.
Initial implementation commit: `45d84f4acb5222920b535252ff5609ca8a445a68`.
Frozen implementation tree for the recorded validation: `3f5e11d87787bc0329bbf443f60d02786e1598ce`.
The work began on `3d1b6507671ec694ce58e86d4063a125c8deeb66` and preserved
concurrent parent `adebe0bd78e6e1bdb55a599179ffe2313997170e`, which added the
standalone primitive-harness Cargo lock and its original CI evidence.
The prepared continuation targets integration candidate #688. It has not been
pushed: the connected GitHub API returned HTTP 403 with
`Sorry. Your account was suspended` while reading its current branch reference.
The exact response is retained in `github-publication-block.json`. No alternative
credentials, access-policy change, remote write, new PR or new hosted-CI run was
attempted after this denial. Local commits and an applicable bundle/patch archive
preserve the work for review and later authorized publication.

Source receipts bind all 10,685 tracked entries / 1,026,937,130 bytes to this
implementation. An evidence-only continuation retains these observations and documentation; it
does not relabel this implementation test run as execution on a later tree. The
archive records the evidence source separately from the implementation receipt.
The locked graph contains 26 workspace members and 180 all-feature packages;
the lockfile SHA-256 is
`39ab5baeecb55c5445e6bbbbb359cb4ddcddd75a237e19ec243dc2f0f92849be`.
Rust 1.95.0, the unchanged repository test profile and two Cargo build jobs were
used. The original provider preparation built pinned OpenSSL 3.5.9 and exercised
actual ML-DSA valid/wrong-message controls. The original physical Host profile
was not available on this local machine.

## What changed and why

The existing parent already verifies the caller before spent-Cookie insertion
and paid body/work grants. New real loopback TCP controls preserve this ordering
for a victim caller signed by an attacker and for exact signed solutions moved
across operation/body/connection contexts. The original victim request remains
usable. The victim Submit control includes a real signed native transaction
block. Cross-operation/body controls use Head-to-PoolStatus and same-length
History requests and assert that work never starts. These controls do not
replace ledger signature checks or one-use business authorization.

Classical Cookie signing, caller verification and response signing now reserve
CPU before the actual cryptographic call. One shared account belongs to the
existing `ListenerIntake`: 2,000,000,000 ns burst, 250,000,000 ns/s refill,
100,000,000 ns start reserve, and at most two concurrent intervals. Listener
clones/key changes cannot create fresh credit; cold process credit is zero.
There is no new lifetime request/byte cap. Failed signatures pay their actual
calling-thread CPU. Panic, missing/moved clocks and checked arithmetic failures
remain unknown and prevent further starts. A synchronous call retains its
reservation until it actually returns; excess known CPU remains debt.

Temporary authentication-capacity exhaustion retains only the already bounded
Hello/Solution in its original queue and deadline. Challenge issuance tokens
already spent are not refunded. A real zero-credit, single-connection Head test
finishes without a client retry and records its three authentication intervals.
The earliest Node check rejects substitution of an already bound CPU domain
before State/profile reads while leaving a failed first setup unbound.

The last ordinary listener or History reference rechecks both current scalar
and authentication accounts under the Node lock. An earlier clean snapshot
cannot erase later debt/unknown cost. Conversely, an earlier Busy snapshot
cannot poison a later fully settled epoch. Normal listener completion reports
its own actual joined lifecycle; error/unwind retains the original crash fence.
Continuous-owner close requires actual listener release and settled accounts;
known live local helper intervals return transient Busy. Accounting faults use
the existing held-descriptor durable FaultSink. A new listener cannot perform
pre-authentication under a prior CleanClose anchor without the existing trusted
owner workflow producing its next real journal event/view.

The signed resource revision is r16. Exact historical r10--r14 raw and r13/r14
arithmetic vectors remain unchanged; correctly signed predecessor Cookies are
still rejected. The separate r15 proposal is not merged by this change. Raw
campaign selector spellings are historical; the recorded policy ID is the
actual profile identity. The independent vector config SHA-256 is
`9113980f13a3620cf9ca5a3c665f781bb3bf1a3c0d58bd1e5e958b185ad66c22`.

The new phase-reader v4 keeps all three original scheduled business rounds
(t=1/5/9 seconds; original 30-second phase) in the completion denominator.
Timely success requires matching retained confirmation observations, the
necessary depth/work relation and strict deadline. The reader does not
independently verify W1, exact target-derived chainwork, native execution,
verifier independence or the attacker budget. Successful-only empirical tails keep
known/unknown sample counts. All-offered p95/p99/max stay null for missing,
failed, unknown or phase-error outcomes. Scheduled latency includes scheduling
wait; actual-start latency is labelled separately. Three samples are not a
population p99 guarantee. Retained v1/v2/v3 outputs remain reproducible.

## Actual local validation

| Observation on frozen implementation | Result | Retained evidence |
| --- | --- | --- |
| All-target, all-feature locked Cargo compilation | PASS; unchanged repository profiles | [First final-source run](logs/r16-workspace-all-features-corrected.log) |
| Complete workspace runtime, original tests retained | FAILED, exit 101: 4,344 passed / 77 failed / 70 ignored across 385 targets; 18 targets failed | [Complete no-fail-fast log](logs/r16-workspace-complete-denominator.log), [readback](r16-workspace-readback.json) |
| New authentication/startup/lifecycle regressions | 25 passed, 0 failed, 0 ignored; included in the complete run | Same complete log/readback |
| Strict Clippy, all targets/all features | PASS, `-D warnings` | [Clippy log](logs/r16-strict-workspace-clippy.log) |
| Rust formatting | PASS, `cargo fmt --all -- --check` | [Format log](logs/r16-final-format.log) |
| Canonical repository/links and reference model | 50 repository tests and 29 reference tests passed; 3,457 Markdown links checked at implementation source | [Canonical check](logs/r16-final-canonical-plan.log) |
| Source-integrity counterexamples | 43 passed | [Source tests](logs/r16-final-source-integrity-tests.log) |
| PQ/source contract counterexamples | 37 passed; 568 exact source pins match; qualification remains HOLD_NO_GO | [Counterexamples](logs/r16-final-pq-source-tests.log), [pins](logs/r16-final-source-pins.log) |
| Current/historical resource policy reader | 7 passed | [Policy tests](logs/r16-final-policy-tests.log) |
| Phase-reader complete-cohort counterexamples | 69 passed | [Phase tests](logs/r16-final-phase-tests.log) |
| Exact retained-artifact reader compatibility | 19 passed; historical artifact, not new native execution | [Artifact reader tests](logs/r16-final-retained-artifact-tests.log) |
| Original fixed Host acceptance | Not executed: required Host unavailable | [Actual readiness refusal](original-host-readiness.json) |
| Publication/hosted CI | Blocked; no remote write or new run | [Actual GitHub response](github-publication-block.json) |

The retained `public_v3_from_zero` target also passed its five executed controls;
its explicit original four-second/16-hostile control remained ignored. The
four-distinct-trace control asserted all 512 scalar transcript tiles were replayed
before rejection, rejection by ordinary/limb/native admission, and unchanged Node
stats/active state. Per-case timing stdout is not retained for this successful
libtest invocation, so no native cost ratio is inferred here.

The 25 new controls comprise three real loopback TCP boundary tests, 17 account
and shared-epoch lifecycle tests, two startup-domain tests and three
continuous-owner lifecycle tests. Their pass result does not change the complete
workspace failure result or qualify public-service throughput.

A further 37 applicability negative tests passed. That run began before the
retained-test call repair and is not presented as an entirely post-final-commit
run; its tested applicability subjects were unchanged. See the ledger's exact
scope and the [applicability log](logs/r16-applicability-negative-tests.log).

The original completed workspace remains failed. Its 77 failed tests are
classified by the actual retained failure stage, not automatically blamed on the
environment or called pre-existing:

| Directly supported failure observation | Count | Limit of attribution |
| --- | ---: | --- |
| Explicit OS `EPERM` in checkpoint/peer/witness socket paths | 19 | Responsible security/kernel policy is not established |
| Checkpoint daemon exited without retained child cause | 3 | Unknown original cause |
| `/sys/fs/cgroup/cpu.stat` missing (`ENOENT`) | 1 | Failure precedes the real-input parser |
| `PUBLIC_HOST_PROCESS_UNAVAILABLE` after abstract socket bind | 6 | Error mapping omits the concrete errno; this is not the capacity-exhausted code |
| `PUBLIC_HOST_KERNEL_PARENT` refusals | 6 | Some occur in sync/local History import after earlier native/network success; see per-test stage |
| Observation CLI first-ready stdout EOF | 5 | Original child stderr/exit not retained; original cause stays unknown |
| Worker descendant cleanup/reaping incomplete | 36 | Direct cleanup failures; no demonstrated Host/socket or environmental root cause |
| Worker adapter error classification mismatch | 1 | Actual Retriable vs expected NonRetriable; missing error context prevents a shared-cause claim |

No baseline comparison was executed. The worker crate, its direct workspace
dependency `trnm-types` and Cargo.lock are byte-identical to the integration
parent, but this does not turn these observed failures into passing tests.

A separate, unchanged observation-CLI binary rerun retained 1 pass/5 failures.
Each of its five newly recorded first-service argv was then replayed once with
the original arguments/deadlines: all returned exit 2, zero stdout and
`PUBLIC_HOST_PROCESS_UNAVAILABLE` before cold authentication-budget construction.
This narrows the current startup stage without retroactively assigning a cause
to the original five EOF failures or demonstrating the later business assertions.
The [additional diagnostic](diagnostics/observation-cli-startup/diagnostic.json)
and [original raw diagnostic archive](diagnostics/observation-cli-startup/original-diagnostic.zip)
retain commands, exit statuses and streams. Four originally created zero-byte
observation outputs are preserved as raw files in that ZIP; they have not been
rewritten into successful JSON. The archive excludes DEV key and native store
files. These additional invocations are not added to the 4,344/77/70 denominator.


Commands are recorded in `validation.json`; retained stdout/stderr are under
`logs/`. The early retained-artifact argparse/EXDEV failures are described in
`acceptance-notes.md`; their full raw stdout was not retained. Native
fault-injection controls and synthetic negative-credit settlement examples
verify the state machine; they are not measurements of attacker CPU or global
fairness. Cross-thread mutation-finish tests use a real different thread and
naturally produce an unreadable owner interval. Continuous tests use the
existing unqualified native/journal mechanism fixture, not a production owner
attestation. Ignored and filtered tests receive no execution credit.

## Failed observations remain visible

- The first development Node build failed at an ambiguous test-only mpsc channel
  type. The fixed declaration names `channel::<()>`; no assertion was removed.
- The next development V3 suite recorded 215 passed, three failed and one ignored.
  All three failures were stale current r14 digest assertions after the fresh
  r16 contract. Current vectors were updated; r14 was added to the correctly
  signed predecessor rejection set. Those earlier results do not qualify the
  later committed implementation.
- The first all-feature workspace build on exact implementation `45d84f4ac`
  failed at a retained `fence.complete(true)` test call after the method became
  `complete()`. Commit `2cd735318` updates that call and its exact blob pin;
  the earlier compile failure and its clean source receipt are retained.
- The first repository/canonical-plan check after renaming the current revision
  test refused its old applicability selector. The exact selector and its
  documentation binding were updated together; no callable check was removed.
- A retained-artifact compatibility invocation first omitted mandatory pins,
  then encountered EXDEV in hardlink fixture setup. The successful retry used
  same-filesystem TMPDIR and the identical original artifact pins. The original
  fixture/test assertions and artifact bytes were unchanged. These two early
  invocation/setup failures are recorded in `acceptance-notes.md`, without a
  retained full raw stdout log.
- Additional final validation failures, if any, are retained in the validation
  ledger and original logs; a subsequent successful run does not erase them.

## Original resource and service acceptance: still open

The real local Host capture refused `FIXED_PARENT_IDENTITY`,
`KERNEL_OBSERVATION_UNAVAILABLE`, `ORIGINAL_FINITE_LIMITS` and
`REVIEWED_UNIT_BYTES`: `/sys/fs/cgroup/trnmponpublic.slice` and the reviewed unit
were absent. **The original 4-second / 16-hostile Host test did not run locally.**
No synthetic cgroup receipt, widened limit or substituted loopback test was used.

The original full three-run 0/24/24 campaign, full History, capacity/churn and
independent WAN qualification remain separate gates. Retained historical
failures remain failures. The historical campaign readback is not performance
of r16, even though this reader can reproduce and explain its incomplete cohort.

Once repository access is restored, the existing PR workflows supply the exact
subsequent route; they have not run this unpublished candidate:

- `pon-priority-acceptance.yml`, service-model matrix: the original
  `run_from_zero_host.py` -> `run_from_zero_native.py`, with 0.25 CPU, 2 GiB,
  zero swap, 256 PIDs, four seconds and 16 hostile workers unchanged.
- `pon-native-campaign-qualification.yml`: three complete original 0/24/24 runs
  with exact source, binary, Host and raw/readback artifact bindings.
- `pon-fixed-host-root-f0.yml`: a separate ROOT diagnostic, which cannot replace
  either original gate above.

The authentication sublimit is an overlapping limiter, not extra Host capacity.
Mutation-response signing is already inside mutation CPU; read-response signing
has no mutation owner. The two accounts cannot be summed into total Host CPU.
Kernel-parent observations must cover reactor, all descendants, material/State,
cleanup and recovery; unmeasured overhead remains unknown. Controlled close
guards are not complete durable billing of every process/embedding operation.

There is no separate response-authentication reserve. Saturation can still lose
an ACK after a valid native commit; the completed ledger outcome remains factual
and must be reconciled. Busy, timeout, cancellation and unknown cost are service
outcomes, never new invalid-block or chainwork facts. Receiver identity stays in
local admission; consensus packets remain forwardable, and the independently
expected business consumer remains bound by its own task contract. No activation,
merge, protection change, independent operator acceptance or economic conclusion
is authorized by these component results.
