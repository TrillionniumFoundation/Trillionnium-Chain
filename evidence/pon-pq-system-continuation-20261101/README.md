# PQ system continuation evidence

Whole-chain status: **HOLD / UNQUALIFIED**.

This directory records the reconstructed native candidate, not the earlier lost
working copy. The source, contracts and remaining gaps are described in
[the security record](../../docs/security/PQ_SYSTEM_CONTINUATION_20261101.md).

Native execution records are collected against exact source commits. A
missing or still-running record is not a pass. Original failures and environmental
blocks must remain distinguishable. The five network controls are first executed
against the original implementation plus the test additions; the reconstructed
fixed candidate is then executed separately. External witness tests must be run
on the actual combined source, including real PQ effects and cold reopen.

The dedicated CI repeats the named controls on x64 and ARM for both the candidate
head and its ordered prospective merge. It retains raw command logs and source
checks; child-process harness entry points are excluded from the meaningful
control count. Existing broader tests and original capacity budgets remain in
force. No prior internal code review or source-check result is an independent
cryptographic audit or production acceptance.

## Reproduced original behavior

The baseline plus only the five recovered tests is local Git commit
`e34f2d2f63ea0d10232b3440e93ce20e508e8a73`, tree
`64e27258405f82aa41b80d040a581626c19b0f6b`, parent
`5606a97104f9cd3243befc2921ccace3fae2c369`. The exact local object and test
sources are retained in [the base64-encoded Git bundle](red/red-source.bundle.base64) and
[the tests-only patch](red/tests-only.patch). This local commit is not mislabeled
as a remote GitHub commit. Decode the bundle with standard base64 before Git
import and verify its [encoding receipt](red/red-source-bundle-encoding.json);
this lossless text encoding preserves the exact local Git objects.

The locked, offline Rust 1.95.0 all-features Node library build completed in
314.899 seconds using the original crate optimization, debug assertions and
overflow checks. The actual binary SHA-256 was
`3ce9c3807c8a3872e5c96bb5a468dcc4c0b787535a020d454acf6beb902401d9`.
See [the compiler artifact](red/recovered-network-red-binary.json) and
[the build record](red/recovered-network-red-build.json).

The five tests executed with loopback sockets permitted: **1 passed, 4 failed,
0 ignored**, libtest duration 11.22 seconds, command exit 101. All four failures
are behavior failures; none is a socket sandbox denial. Full
[raw output](red/recovered-network-red.log) and
[before/after source record](red/recovered-network-red.json) are retained.

| Control | Original implementation result |
| --- | --- |
| Elapsed deadline before durable charge and cached replay | FAIL |
| Deadline while waiting for the signature owner lock | FAIL |
| Signed expiry while waiting for the owner lock | FAIL |
| Cancelled intake before allocation/connection credit | FAIL |
| Failed signature remains charged; valid same-sequence PQ transfer changes balance by 42 and survives cold reopen | PASS |

The failed baseline is expected evidence of the defect, not a successful gate.
The fixed combined candidate must independently pass these same controls and
its actual external-witness tests before component success can be recorded.

## Initial candidate build: failure retained

The first combined native build used local commit
`ed31b019525963456e0e84eb5f0862ef6ee0186a`, tree
`f5cdc9a1c46ef01a722ab472e89a2a7b80ca17aa`. Published commit
[`82a576f111f686ffaa5e4eff015bf6b83bb7cec2`](https://github.com/TrillionniumFoundation/Trillionnium-Chain/commit/82a576f111f686ffaa5e4eff015bf6b83bb7cec2)
has exactly that tree. The [raw local commit object](initial-source-build/green-build-source.commit)
retains the precise locally tested identity without inventing a GitHub commit.

The original locked/offline Rust 1.95.0, all-features Node library build exited
101 after 311.128 seconds. Rustc received SIGKILL; the environment's shared
8 GiB cgroup was at its memory limit, and its OOM-kill count changed from 5 to 6.
Those counters are shared observations, not a per-process kernel attribution.
The complete [build log](initial-source-build/green-build.log),
[before/after source receipt](initial-source-build/green-build.json),
[resource/failure observation](initial-source-build/green-build-failure-observation.json)
and [file index](initial-source-build-members.json) are retained. Source-before
equals source-after. This invocation produced no candidate test executable and
executed **zero** native controls. A build attempt named `green-build` is not a
GREEN result.

## Concurrent upstream composition

After the initial source was frozen, #678 advanced to
`64cb26b53ed82be14049000387040ba119f00e1e`, tree
`1eccfeefc4f68f3b82e721ba08b9a80248e2860e`. Both real upstream commits were
reconstructed from authenticated Git data and verified by object SHA. The
combined source preserves both branches' constructor fields, the bounded
full-root arithmetic work, its original test controls and workspace CPU workflow,
and all new PQ controls. Overlapping source pins were recomputed from the
actual combined files. The original sole-plan entry was retained.

The subsequent candidate must be built and executed independently. Neither
this merge nor a source-integrity pass turns the failed build into native
acceptance; all original service budgets and six whole-chain gates remain open.

## First actual combined execution: 36 / 37, one real I/O failure

Local source `444ae3ed6d3951396dc421e7b26548191962ef9f` has the exact
`b4d4cca6da8244cf9c7d479eca0974559f4a1005` tree published as `d2fabdd3757b89db84763d632aeedfe84f9fce4f`.
Its one-compiler-job build completed under the original Rust 1.95.0 profile,
locked versions and provider. The actual Node test artifact has opt-level 3,
debug assertions and overflow checks enabled; features are `default` and
`pq-native-openssl`. Its SHA-256
`dc7555f7d02631ff73db0d1d4011eaf2df1d9ce636f6271782922ea78ee972d8`
was unchanged before and after all selected executions.

All 37 meaningful selectors ran independently with permitted local sockets:
**36 passed, 1 failed, no child harness counted**. Every command's source-before
equals source-after. The five original network controls passed. All 25 guarded
store controls and the actual NPQ6 transfer / separate witness-process cold
restart passed. The six witness-core controls had five passes and one failure.

The sole failure was
`pq_rollback_witness::tests::slow_drip_write_obeys_one_absolute_deadline`: an
8 MiB write with the original 40 ms absolute budget did not return within the
unchanged 500 ms assertion while the peer continued draining slowly. Its native
exit is 101 and named-reader exit is 1. The raw log SHA-256 is
`70e6071cd53b1ed9ba11817a1319f79f5ecec3a6a3f31678bbb2076a6a4de99e`.
Remaining-interval socket timeouts did not prevent a single progressing blocking
write from overrunning the absolute deadline. That earlier implementation is
not accepted as bounded I/O.

The [member manifest](initial-native/manifest.json) indexes the complete original
command logs, source receipts, exact-name reader outputs, compiler artifact,
summary and a Git bundle retaining the local source identity. Their
[lossless archive](initial-native/records.tar.gz.base64) is a deterministic
tar/gzip/base64 representation; no raw log was trimmed or changed. Run
[restore.py](initial-native/restore.py) with a new output directory to validate
the archive and every restored file's size and SHA-256 before writing it.
The executable itself is not embedded; its actual compiler record and measured
before/after digest are retained.

The follow-up replaces blocking socket calls with per-call `MSG_DONTWAIT`
receive/send and repeats the same absolute deadline on every retry. It enables
only the existing `rustix` dependency's `net` feature in the Node crate: this
changes the feature graph, while versions, lockfile, compiler profiles and
business budgets remain fixed. Socket descriptor mode and timeout options are
not mutated. Complete received CAS evidence is still reconciled before a late
live-use refusal; sent-but-uncertain errors still invalidate authority. The
40 ms budget, 8 MiB load and 500 ms assertion remain unchanged. Fresh native
validation of this new source is required.

Two separate discovered integration issues are also corrected: the public
readiness source reader now recognizes the exact V4 namespace without accepting
V4 state as legacy readiness evidence; its original 51 and four added tests
passed in the isolated repair. The M06 callback test serializes its own
`try_lock` probes under its existing trace mutex, so concurrent probes cannot
produce their own false lock-retention failure. The real lock assertion and
execution/cancellation/reference comparisons remain in place.

The CI uploads completed native-control records before the retained full Node
suite, making a failed control inspectable while longer regressions continue.
The complete original suite and strict Clippy remain required.

## Exact 0959 controls and the later upstream composition

Published source `0959b694539b2e6427c6bfc2422b45c23b63cde4`, tree
`49ffbac079b5c549050b5e876b02f70ce5b37d14`, was executed locally and on all four
x64/ARM source-head/actual-merge lanes. Each execution passed all **37 / 37**
meaningful controls; the unchanged slow-write counterexample passed. The tested
base was `64cb26b53ed82be14049000387040ba119f00e1e`, with actual prospective merge
`2c1235118b4962c00efc7a774dbb0532cf46cf24`. This is 37 distinct controls and 148
hosted executions. The local artifact's before/after SHA-256 is
`428d91424bfaf99eb32945e82299852837bf5690c32b1671f34fc59ad4c5c773`.
Exact local strict Clippy, formatting, the retained M06 callback control and 55
public-readiness reader tests also passed. These are component results, not an
independent combined Chain/Hepta or whole-chain acceptance.

The same 0959 source still failed all eight original-workspace large-state
executions with `PUBLIC_MUTATION_CPU_BUDGET`; all eight reactor-exit controls
passed. All four from-zero lanes passed their five native controls but failed
`CONFIRMATION_TARGET`: the original pressure window confirmed 0/1 while each
attack-free baseline confirmed 1/1. Complete source-bound records are retained
separately from the candidate so its tested source is not rewritten.

During this collection, #678 advanced to `456d23a778d91b6f3cfee60ee997f8f51d3216bc`.
Its canonical encoding, prepared history queries and guarded post-write readback
changes are composed without replacing the PNQ2 Current/root/CAS guard. The only
merge conflicts are overlapping derived workflow/source hashes, recomputed from
the actual combined bytes. The original capacity budgets, 4,105-block lifetime,
35 upstream semantic controls, 37 PQ controls and all HOLD flags remain intact.
The earlier 0959 results cannot qualify this new combination; fresh native
source-head and actual prospective-merge records are required.

## Exact 473 controls: preserve the recovery deadline failure

The subsequent source is `473a7b9bbff5215600950067b46da05cfd31bf5e`, tree
`4582411d869113af3aac356d078d8adf4440c612`. Its tested base is
`456d23a778d91b6f3cfee60ee997f8f51d3216bc`; the actual prospective merge
`ee78bb676f60865735ee4bef37a165a6f8bd1fd7` has the same application tree.
The [PQ run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41367207755)
and [original workspace run](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41367207721)
retain their first-attempt source identities and unmodified selectors.

| Exact lane | PQ controls | Selected original-workspace semantic controls | Reactor-exit controls | Original capacity controls |
| --- | --- | --- | --- | --- |
| x64 source head | 37 / 37 PASS | 35 / 35 PASS | 2 / 2 PASS | Both FAIL |
| x64 actual merge | 37 / 37 PASS | 35 / 35 PASS | 2 / 2 PASS | Both FAIL |
| ARM source head | **36 / 37** | 35 / 35 PASS | 2 / 2 PASS | Both FAIL |
| ARM actual merge | 37 / 37 PASS | 35 / 35 PASS | 2 / 2 PASS | Both FAIL |

The ARM-head failure is
`store::pq_rollback_witness::tests::witness_outage_latches_owner_without_refunding_or_charging_quota`.
Cold reopen and equality with the retained external head succeeded. The first
legal 31-byte charge after that reopen returned `PQ_WITNESS_DEADLINE` at
`store/pq_rollback_witness/tests.rs:274`; the final charged-byte assertion was
not reached. The exact raw log SHA256 is
`726f88a35e0f95a4807058634c9d41410bc006d4c53096f8b6bf8752540fc887`.
This phase uses the ordinary in-process witness fixture with no injected delay.
The original 250 ms per-exchange limit remains unchanged. The receipt does not
locate the internal Current/CAS deadline site or establish an environmental
cause; earlier successes cannot replace this failed recovery positive case.

Each original workspace lane built the complete locked Rust 1.95 workspace
with `--workspace --all-targets --all-features --no-run` in the original test
profile. The actual compiler records retain Node opt-level 3, M06 opt-level 1,
debug assertions and overflow checks. All eight large-state capacity executions
failed `PUBLIC_MUTATION_CPU_BUDGET`; all eight reactor-exit controls and all 140
executions of the 35 semantic controls passed. This is selected execution from
the full workspace build, not a complete runtime-suite result.

The four [from-zero business lanes](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41367207809)
(protocol head/merge and cost x64/ARM) each passed their five exact native tests
but failed `CONFIRMATION_TARGET`. Each attack-free baseline confirmed 1/1;
each 16-worker pressure phase confirmed 0/1 in the original four-second window.
There is no post-window drain credit or changed deadline. At this checkpoint,
the complete `473` Node-suite outcomes remain pending; no local command still
running is represented as a completed pass.

The earlier `0959` complete Node outcomes are independently preserved in the
[immutable phase 2 archive](https://github.com/TrillionniumFoundation/Trillionnium-Chain/tree/1fa9526d139945f97a4a6823f08550439a6d19d9/evidence/pon-pq-system-continuation-20261101/final0959-phase2):
879 passed, 2 failed and 22 ignored in each of its four lanes, with strict Clippy
success. That delta verifies its 568 unchanged phase 1 file references and 16
new raw Node/Clippy files, reconstructing all 584 complete artifact files.
Its evidence-only publication tree is not a newly tested application source.

## Preserve the concurrent 9ceff source without inheriting acceptance

The next composition adds `9ceff0e073f001e6ea4ac9ea929f477aca8ebf36`, tree
`d2aa5d52f02ecc3e3e9780b064c9b814f8280fe4`, whose parent is the same `456d` base.
Its full-root arithmetic reuses equivalent canonical encoding only after the
complete State grammar pass and retains the independent serde root. It adds
two exact semantic selectors to the same original workspace workflow. Its
callback test uses a separate probe mutex, preserving our own-probe serialization
while adding real-held-lock refusal, four concurrent probes and actual
worker-count assertions. The production arithmetic lock, worker execution,
original CPU/state/History/business budgets and witness deadline are unchanged.

Retain all seven upstream files and all candidate-only source bindings; update
only the actual overlapping derived hashes. The upstream 456d outcome documents
remain historical records, not acceptance for this composition. The new source
has not been built or executed here. It requires fresh exact-head and actual
prospective-merge validation. The `473` recovery, capacity and confirmation
failures remain retained; no source composition or selected success closes any
whole-chain PQ gate or promotes any of the eight machine assertions.
