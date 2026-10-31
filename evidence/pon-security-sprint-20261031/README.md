# Pure PoN security continuation — 2026-10-31 UTC

This integration preserves pure PoN Nakamoto fork choice and complete W1 work.
It contains a demonstrated mining-liveness repair, a narrow allocation reduction
inside current kernel checks, and earlier rejection of inconsistent public
claims in the separate complete-W1 research verifier. It does not qualify an
open network, minimum work cost, practical succinct proof economics, or quantum
security. The only development plan remains
[the existing plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).

## Results and exact boundaries

| Lane | Actual observation | Remaining boundary |
| --- | --- | --- |
| [Mining and effective work](cost/README.md) | The unchanged regression fails before the repair and passes afterward: a valid future tip no longer suppresses a permitted real-wall-clock child; a genuinely future median still waits. | No global cheapest-solver, timestamp-attack profitability, sustained service or throughput claim. |
| [Native History kernel checks](history/README.md) | The first compiled source passes 19 kernel controls. Five fresh quota-file reads show a small scoped allocation-cost reduction. All production code is identical in the final source; later test-only changes retain a stronger measurement precondition and remove an unnecessary indexed loop. | Local rebuild failures remain preserved. Later ARM exact-head and ARM/x64 actual-merge CI execute the final kernel source with 19 passes and the one named manual measurement ignored; source-before/after agree. Those jobs subsequently fail an obsolete authenticated-test count before strict Clippy. Whole-workflow and finite-service gates remain open. |
| [Complete-W1 proof receiver](proof/README.md) | Real Composite proof acceptance, the original 16 mutations, eight receiver cases, 24 paired claim observations and 21 native host tests pass. Strict Clippy and formatting pass. | Matching public claims still require full cryptographic verification. Valid and worst consistent-invalid proof costs remain roughly one second in these observations. This research verifier is not a node admission backend. |

The mining baseline used local commit `c69749680d7fd8dd2334d284f0e9a6823cf38a18`;
its production code was unchanged from `7da4964d`. The fixed native execution used
`298ecbaf08db571f98253e38fb6aed9c18146006`. Both use the same test bytes, real
signed transactions, complete work, native admission/activation and an actual
SQLite reopen. Its original two-second timeout remains; the positive failure is
not a failed compiler setup. Later packaging commits retain the exact observed
executables and losses/errors rather than rerunning or rewriting that baseline.

The proof experiment uses the original 62-segment, 15,862,780-byte Composite
receipt, not the previous 256,886-byte Succinct experiment. Its reference arm is
the original SDK order inside the same candidate executable. Rebinding the outer
journal, breaking a late public continuation link, or changing a nonfinal public
exit took 1.11–1.24 seconds in that reference and 19.88–24.40 ms with a fresh
prepared context. Reusing only the private fixed context yielded 3.78–4.03 ms.
Coordinated claim forgery and a corrupted seal with matching public claims still
entered the complete SDK and were refused, at 1.17–1.55 seconds in the candidate
observations. These single, warmed shared-host observations are not statistical
or end-to-end network throughput measurements. The complete relation, fresh
trace, expected statement and fixed image are unchanged.

## Integration

The prior recovery tree is now actually published as
`cf84391a474ee1f3ac78f4a907bd95184b816a54`. Its tree equals the local `7da4964d`
base used by the three lanes. [Integration records](integration/README.md)
separate that publication from this later code. Cherry-picking retains each
lane's measured source identities; changed commit metadata does not convert an
old execution into a new-head execution.

The existing protocol-contract lane retains all selectors and adds the native
mining timestamp target. Its negative controls reject omission, duplication,
replacement and a skip of the counterexample. The focused native workflow also
requires both named cases, retaining all its original steps and resource bounds. The existing complete-W1 receiver
workflow retains its original proof, controls, budgets and eight cases, then
adds the public-claim experiment and independent metadata reader. The original
admission driver already includes `host_kernel_parent::` in its actual native
`pure-runtime` gate, so final-source controls remain part of its exact-source
x64/ARM64 execution.

The changed `store.rs` file has a fresh literal Git blob pin in the existing
recent-batch workflow. The pin still requires the actual bytes. The generated
distributed-source inventory adds the three new Rust source/test inputs. No
source-identity, ordered-parent, original deadline, quota or security predicate
is relaxed. No new signed protocol domain or stored node schema is introduced.

The earlier `cf84391a` V5 runs passed on both x64 and ARM64. The original
admission campaigns on both architectures still failed their finite-service
predicates; real distinct hostile identities and successful individual honest
submissions did not suffice to establish the full confirmation/service
contract. Those are prior-source results, not outcomes of the new kernel or
mining implementations. The PR's stale base metadata was refreshed to actual
`main`; old prospective-merge failures remain failures.

## Open research and acceptance

Correct-product/false-trace work remains a rejection-cost problem; these changes
do not grant false work acceptance or establish unrestricted Sybil fairness.
An observed fastest implementation is still not the global minimum legal W1
cost. Hardware, structured tasks, preprocessing, batching, task selection,
external-demand shortages and quantum work advantage remain security inputs.
Proof correctness still does not prove a minimum amount of expended work.

The original finite-service campaigns, exact committed-source CI, independent
acceptance and any production activation remain separate gates. No stake,
quality/evaluator-weighted chainwork, independent Hashcash, automatic BFT/hash
fallback, fake proof, deadline extension or activation is introduced.

The [selected earlier-head CI readback](integration/cf843-hosted-readback/README.md)
retains exact artifact members and provider logs, including the independent
dependency-policy, data-availability and from-zero confirmation failures.

The [confirmation timing readback](integration/confirmation-lateness/README.md)
locates the earlier x64 baseline overrun in independent replay: native depth/work
confirmation succeeds, but the round ends at 36.5714 seconds against 30 seconds.
That failure is separate from the ordinary pool-miner timestamp defect.

The [published-source native readback](integration/2a69-hosted-readback/README.md)
retains both completed final-kernel observations and the workflow-count failure.
Correcting the stale 20/22 and 56/60 rosters adds exact named requirements and
readback controls; it does not relax native test assertions or service bounds.

The [published-source W1 receiver job](integration/2a69-hosted-readback/w1-receiver-124412661337/README.md)
also completed with all original and new controls, strict host Clippy and full
source guards. Its independent hosted record preserves the same worst-case
rejection boundary: matching public claims still require about 1.2 seconds of
complete SDK verification for this historical Composite fixture.
