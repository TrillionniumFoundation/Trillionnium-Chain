# Per-evaluation CPU ownership, 2026-11-28

This development change follows the actual #1014 source commit
`cdc0f90c27a461833e552bfc1a39d4485507e89b`. It repairs a concurrent accounting
error in the ordinary, Circuit and historical Python evaluation adapters.

The old meter subtracted two process-wide `RUSAGE_CHILDREN` observations.
A waiting job could therefore absorb CPU from an unrelated child reaped by a
concurrent evaluation in the same parent. The retained original control
observed 368,424,000 ns for the waiting job and 316,352,000 ns for the busy job.
The original 16 attempt controls all passed despite this missing case.

The new meter uses only `wait4` for the owned PID. The exact final-source
control observed 74,968,000 ns for the waiting job and 343,765,000 ns for the
busy job. An earlier candidate observation is also retained, with 39,333,000 ns
and 407,329,000 ns respectively. These short controls demonstrate attribution;
they are not a performance benchmark or an end-to-end cost measurement.

## Stored contracts and failure behavior

New evaluations write intent v2, attempt v2 and cost v3 namespaces. Old cost v1
remains historical and incomplete. Old cost v2 requires its original attempt
v1, intent v1 and process-wide CPU scope; it is not promoted to owned-child
accounting. New and old namespaces cannot be interchanged by changing only the
cost document and rehashing it. A readback checks retained statements and
digests, not execution authenticity.

Each child starts its own session. Logs remain exclusive files, not pipes.
On timeout or interruption, the owner kills that still-unreaped leader's
process group before `wait4`. It never uses `Popen.wait` or `Popen.poll` as a
competing reaper. A lost reaper (`ECHILD`) leaves CPU unknown and never signals
a potentially reused PID. Failure to spawn or obtain per-PID usage records
`cpu_ns: null`, not zero. Original execution failures survive receipt failures.

The optional wall timeout is explicitly retained in the launch intent. It
defaults to `null`; existing evaluation-driver deadlines and CPU caps are
unchanged. A zero exit observed after an explicitly selected wall deadline
does not produce a successful cost. Normal child exit does not clean up
unwaited descendants. Descendants that escape the process group are outside
this owner. These boundaries remain deliberate, with
`cost_completeness_verified: false` and no execution authority.

## Actual validation and remaining gates

The final source passed 60 evaluation/intake/identity/runtime tests, including
25 attempt controls. They use real independent concurrent jobs, a CPU-consuming
waited descendant, both one-MiB log streams, a real wall timeout with a forked
descendant, interruption cleanup, lost reaper refusal and historical namespace
readback. Original paid ordinary, Circuit and historical fixtures still read
successfully. All 43 original Git/source-integrity negative controls also
passed in their independent fixture repositories. Their logs are retained.

Two preparation failures remain failures: the first broader evaluation run
had 47 controls with four errors because historical fixture originals had not
yet been materialized; the first source-integrity run had 43 controls with 17
errors because its unchanged support modules were absent. After retrieving the
exact original files, the complete runs above passed. No refusal was relaxed.

The local source is a SHA-verified selective materialization of the actual Git
commit, tree, manifests and required fixtures. It is not a complete build
checkout. The original project preflight passed for all 26 package manifests.
Cargo and Rust were unavailable here, so the complete native Cargo graph,
strict Clippy, Rust formatting gate and the externally provisioned paid model
execution remain unexecuted on these new bytes. Their exact-source CI gates
remain required. No model efficacy, payment authorization, consensus credit,
normal-path descendant containment or deployment qualification is established.
