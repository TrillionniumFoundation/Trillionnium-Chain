# Complete W1 proof attempt — 2026-10-27

**Work package 2A: NO_GO.** The actual local recursive-STARK prover did not
produce a receipt within the preregistered 3,600-second process limit. There
was one planned proof attempt, zero completed proofs, and one timeout. The
complete-relation source prototype, actual guest execution and native-cost
baseline are retained; none substitutes for a completed cryptographic proof.

The [readback](readback.json) states the outcome and missing measurements.
The [original process summary](actual-proof-attempt/process-summary.json),
[exact input](actual-proof-attempt/proof/input-0.bin),
[header](actual-proof-attempt/proof/header-0.bin),
[original command](actual-proof-attempt/proof-process/command.json) and
[source identity](actual-proof-attempt/source.json) preserve the actual run.
The empty original host observation stream is intentional: the process was
terminated before it emitted a terminal proof row. No receipt was discarded
or substituted.

## Exact statement and measurement identity

The proof attempt ran source `65c97a95cab4702a368855397c65413e2a754b97`.
Its native host SHA-256 is
`de867e2b77079b8d73b890823d3b3cc23f6b6d810660a5291216b32d886b43d5`.
The [static source bindings](static-source-bindings.json) retain the original
tree, official backend archive/binary hashes and the exact embedded guest.
The retained [guest ELF](guest/full-w1-guest.bin) is 349,796 bytes, SHA-256
`f40b91c5be0ea5b9cae5a10cb93989fe9412239524e24a7c1aec17c629cdb8d8`;
its bytes occur unchanged inside that measured native host.

This experiment consumes the original 318-byte PNH1 header and 49,188-byte
PNW1 witness. It invokes the original complete native W1 verifier, preserving
canonical field decoding, the task and target, bounded noise, every transcript
prefix, product reconstruction and the ticket. Its 16,818-byte journal binds
the full header, trace, ticket, original block identity and all of C. It adds
no proof-randomness ticket or chainwork. Block/parent/transaction/DA admission
remains outside this isolated research workspace.

The controlled input uses deterministic dense matrices and maximum target.
It measures one full verification relation, not the full production mining
search distribution or a lower bound against structured tasks, preprocessing,
alternative algorithms, specialized hardware or quantum computation.

## Actual observations

| Observation | Result | Scope |
| --- | ---: | --- |
| Planned / completed cryptographic proofs | 1 / 0 | All attempts retained |
| Process wall time | 3,600.081027159 s | Original 3,600 s limit; actual SIGTERM, no SIGKILL escalation |
| Prover CPU lower bound | 7,182.52 CPU s | Last original `/proc` reading before termination |
| Prover process lifetime high-water RSS observed | 2,478,088,192 B | One real prover process; not aggregate process-tree peak |
| Actual valid guest execution | 12,693,395 user cycles, 59 segments | Execution only, no cryptographic receipt |
| Guest execution elapsed | 359,796,799 ns | Same guest image and complete public journal |
| Independent original native verifier | 1,000 complete calls | Same exact saved input |
| Native verifier sample median | 693,803.5 ns | One fixed fixture, concurrent local experiments |
| Native verifier sample nearest-rank p99 | 1,559,635 ns | Observed sample quantile, not a production-tail guarantee |
| Native verifier sample maximum | 6,346,603 ns | Every sample retained |
| Proof bytes / actual crypto-verifier time / prover p99 | Unavailable | No completed receipt; values remain null |

The [native baseline](native-baseline/readback.json) retains all 1,000 raw
durations and its separate source/binary hashes. It excludes fixture creation
and the experimental journal construction. W1 proving and M06 work were
concurrent on this host; this is not an isolated production throughput test.
Generating a proof and replaying W1 are different operations, so their ratio
is not an end-to-end throughput estimate.

### Resource accounting limitation discovered during the timeout

The original host `wait4` record contains only about 0.233 CPU seconds and
111,165,440 bytes of peak RSS. Those are **not total proving costs**. The host
and prover were terminated together; the external prover was not first reaped
by the host. Its CPU and memory are therefore absent from that direct-host
rusage. The original record is retained unchanged.

The separate [process observations](actual-proof-attempt/prover-proc-samples.jsonl)
record the actual prover PID, birth tick, cumulative user/system CPU, RSS,
kernel `VmHWM`, and eventual process disappearance. The observer started late
and sampled every five seconds. Cumulative CPU and `VmHWM` include earlier
process lifetime, but the final unsampled interval and other processes remain
unmeasured. The reported CPU is a lower bound and the memory is a single
process observation. Neither is a production resource-budget authority.
The successor experiment runner now makes the direct-host limitation explicit;
it does not relabel this historical run.

## Correctness controls and adversarial review

The three native relation tests passed: complete native/reference equivalence,
omission-class rejection and public-statement binding. Actual guest execution
of the valid input matched the native journal. Wrong task, product and
transcript executions each exited 1 with the corresponding original guest
panic. Their original records still say `guest_rejection_established=false`:
the executor returned an error, and a generic executor error is not promoted
to a successful cryptographic rejection test.

The [second code-review pass](same-operator-code-review/review.md) found no
omitted native W1 check or added lottery identity. It did find that decoding
a general SDK `Receipt` before checking the Succinct type allowed rejected
Composite variants to recurse before the byte-bound rejection. Successor
`ce04877b6cab8109fee51c7013bf1c8127978946` checks the pinned fixed-int wire tag
before general deserialization. Both parser tests passed, including a
4,096-level, 213,084-byte Composite input rejected before recursive parsing.
This review used the same operator and tools; it is not independent external
security acceptance. The successor fix was not in the earlier timed-out host.

Host workspace strict Clippy passed after the explicit guest-compiler wrapper
fix in `d2aa63db3`; the actual guest still builds with the RISC Zero compiler.
The initial host-Clippy wrapper leaked into the nested guest build and failed
with a missing target `core` library; that failed log is retained. Guest
compilation was not skipped, and no empty image was substituted. Formatting
also passed. The earlier guest dependency/MSRV setup failure, explicitly
stopped in-process C++ build and first locked-client failure remain in
`setup-and-validation` alongside subsequent successful builds.

## Acceptance boundary

The prototype has not demonstrated a complete cryptographic W1 proof, a smaller
proof, cheaper verification or useful proving latency. This specific CPU,
segment-limit and two-thread configuration fails package 2A; it does not prove
that every complete proof architecture is impossible. Further configurations
must be declared and measured as new experiments, retaining this timeout.

SDK hash suites, Fiat–Shamir/QROM soundness, native admission integration,
minimum attack cost and whole-chain quantum security remain unqualified.
The original full W1 verification path remains the integration path. No
readiness or production-activation flag changes.
