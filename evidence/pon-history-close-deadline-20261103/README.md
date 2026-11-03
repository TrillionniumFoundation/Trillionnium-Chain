# History completion deadline candidate, 2026-11-03

This is the historical recovered-candidate snapshot. Subsequent execution is
recorded separately for [3898/8a74](validation/README.md) and the later
[b280 composition](validation-b280/README.md). The original pending/failure
record below is retained for its original source and time.

This candidate repairs the ordinary History wrappers' successful return after
mandatory CPU settlement and epoch closure. It is based on parent
`45962558a7133375b16c0ac2600f2edb4a115585`, tree
`8d1d6c4e18e395dfc842c3401844a8ddcd4c01d9`. That parent retains composed
`116a3caf6046dd0db3caf1d0797e636c35c877b8` and the concurrent PQ witness
pre-CAS consistency checks. All concurrent root-value, subtree, Cell-readiness,
PQ-operation, witness and source-lock changes remain in that parent. **Compilation and runtime acceptance are pending. All-blocker closure
and public activation remain false.**

## Retained behavior and correction

Both `metered_observed` and `scoped_observed` previously returned their saved
native result after the required finishing work. A successful native result
could therefore be returned without another original-deadline check after
that finishing work.

Each helper now applies `control.alive()` only to a previously successful
result, after its mandatory cleanup has returned successfully. The existing
error priority remains:

1. CPU settlement or epoch-close failure;
2. the original native operation failure;
3. an expired original deadline on the remaining success path.

The check uses `alive()`, so it adds no new Host/resource observation after
account settlement. It allocates no new CPU budget and refunds no paid work.
The epoch guard is marked closed before the final time check. An error after a
real native COMMIT retains the durable packet or activation facts for the
existing exact-identity reconciliation path. No rollback is inferred from that
outward error.

This is a cooperative result fence. It cannot preempt an already running
filesystem/SQLite call, guarantee a wall-time bound, or establish public
confirmation throughput. The separate continuous owner path is outside this
small change.

## Three unexecuted ordinary controls

The new Linux test module is `ingress::history_import::tests::deadline_controls`.

| Control | Assertions prepared in source |
| --- | --- |
| `metered_expiry_preserves_native_errors_and_settles_the_original_account` | Refuse a late success; preserve an original native error; settle the same CPU account once; retain its balance identity; do not re-read Host authority. |
| `scope_expiry_preserves_cleanup_native_error_and_cold_reopen` | Complete epoch cleanup even after expiry; preserve native-error precedence; cold reopen without falsely recording an abandoned epoch. |
| `late_admission_keeps_committed_identity_paid_cpu_and_exact_retry` | Reach a real valid-packet COMMIT before a bounded local wait; refuse the late result while retaining packet bytes and paid CPU; reconcile the same identity without another W1 verification; cold reopen with the reconciled activation. |

These controls expire the deadline before native completion and then require
cleanup to finish. They do not separately measure a timely native result that
expires only inside CPU settlement or epoch close. The production placement
covers that interval statically; separate execution evidence for it is absent.
Cleanup-error precedence is retained by the unchanged existing `?` operations,
not claimed as an additional executed case.

The third control contains an approximately five-second bounded local wait.
The controls use normal local state and one valid packet. They are not public
service or work-cost experiments.

## Source recovery and verification status

The editing agent ran the project preflight before editing on `f66f7f7...`.
The two affected existing source files are byte-identical in the composed
`116a3ca...` and `4596255...` parents, and the project boundary, AGENTS and
preflight-script blobs are unchanged between these parents. No fresh command
execution or preflight is claimed for the recovered combined source.

The execution environment became unavailable before building or running the
candidate. The production patch and module include were recovered from their
editing records. The recovered production blob matches the recorded
`57616573bf` prefix. The new test file was recovered from its original patch
text, with two long assertions wrapped manually; its earlier local formatter
run does not qualify the recovered file. The exact recovered candidate still
requires formatting, strict Clippy, native controls and clean-source checks.

The embedded native inventory was reconstructed from the fixed parent's full
tree using the checked-in generator's rules. Rendering the unchanged parent
first reproduced its existing inventory exactly; the new module was then
added. Source pins update the two existing blobs and bind the new module while
preserving all four concurrent PQ source/document pin changes.
These are source-composition checks, not executed Python/Rust verification.

The [status record](status.json) binds the prepared source blobs and explicitly
keeps the unexecuted gates pending. No environment variables, secrets,
protected-branch settings, acceptance budgets or runtime authority were added.

## Other remaining blockers

The earlier `116a3ca...` source has a successful
[CodeQL aggregate check](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/116a3caf6046dd0db3caf1d0797e636c35c877b8/checks)
and [exact-source export](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41686753028).
Those results bind that earlier source and do not qualify this new candidate.

A separate static review found that the ordinary signed-DAG integration invokes
the strict public History importer without arranging its required actual Host
context in the runtime job. A possible fixture delegation through the existing
trusted launcher needs its own bounded source/binary/selector binding and actual
Host verification. That change is not implemented or accepted here. The
original deadline/resource assertions must continue to determine its outcome.

Original public-service windows, rejection-cost economics, cheapest legal work,
heterogeneous/quantum assumptions, independent operators/evaluators, model gain,
long-term custody, external effects, whole-chain PQ and release qualification
remain separate open gates. This candidate does not mark any of them accepted.
