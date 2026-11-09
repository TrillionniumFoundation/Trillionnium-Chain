# Original-owner resource admission continuation

Status: **HOLD_NO_GO**. C1 passed the selected native and static verification
below. These component results do not qualify every ingress path, a physical
resource bound, a positive honest-service lower bound, complete proof-backend
economics, PQ128, or production activation.

## Source and purpose

The real integration base is PR #812 at
`7e044b65454f4c9ea505591727332acffb33e7e5`. The observer CPU envelope is selectively
ported from PR #802 at `cc09d6dc311596a9d9a45c64e9392caff4a75c0b`; #802 is not
represented as an ancestor of #812. Existing r14 signed profile bytes, original
native validation, deadlines and activation gates remain unchanged.

The [local resource owner contract](../../docs/development/specs/pon/RESOURCE_OWNER_ADMISSION_V1.md)
and [machine-readable scope](../../config/pon/local-resource-owner-v1.json)
describe `pon-local-resource-owner-v1`. One fixed, hash-chained journal retains
execution and cleanup reservations, original operation bindings, class
allocations and replay state across process exits. Its bootstrap, committed
and recovery allocations are finite; V1 has no automatic or manual refill.

The real local packet observer binds actual packet bytes, the original
operation, active parent, complete observer options and absolute deadline.
Adopted stores reject the ordinary unbound packet-observer entry. This is
explicit local adoption, not a new meaning for signed public-v3 r14 or proof
that every other Node entry shares the account.

## Frozen C1 identity

| Item | Exact observation |
| --- | --- |
| Tested implementation commit | `8fed7514193e06058f4eaf18f362a8fb968ce96f` |
| Tested tree | `1ebc5d4c252eacb727da67945892a9ae0b8d76c4` |
| Authoritative checkout | Complete original-source checkout on ai395, dedicated development branch |
| Complete source receipt | 23,333 tracked entries; 2,380,365,122 bytes |
| Source before/after | Matched; unchanged across retained C1 verification |
| Dependency graph | Locked offline resolution: 181 packages / 26 workspace members |
| Toolchain and test profile | Rust 1.95.0; executed Node library test artifact has original optimisation level 3 |
| Qualification | Selected component verification; `HOLD_NO_GO` remains |

The [validation summary](validation-summary.json), [C1 native record](c1-native/)
and [C1 static record](c1-static/) retain commands, source observations and
original outcomes. The separately retained [core run record](core/run.json) and
[core test log](core/resource-owner-tests.log) keep their own execution identity;
that observation is not added again to the C1 count. These counts do not claim
that all workspace native tests were executed.

## Native and static outcomes

### Selected native suites

| Selected suite | Passed | Ignored |
| --- | ---: | ---: |
| Durable resource-owner core | 23 | 0 |
| Scalar CPU accounting | 60 | 0 |
| Native root rejection | 7 | 0 |
| Original r14 profile compatibility | 1 | 0 |
| Native packet observation | 15 | 0 |
| Accepted-task controls | 4 | 0 |
| Observer process envelope | 4 | 0 |
| **Reported selected total** | **114** | **0** |

All selected native tests passed, with zero reported failures or ignored cases.
The core controls include durable reservation/replay semantics, retained unknown
principal, one-time claims across actual subprocesses, completion prerequisites,
conservative reconciliation, measured-overrun debt, lane limits, corrupt
journals and original-owner file boundaries. The node and envelope suites
exercise the actual observer integration and retained native checks. They do
not cover the complete original Host/History/pressure matrix or a measured
full-path rejection-cost comparison.

### Source and static gates

The four retained static suites report **43 + 50 + 57 + 151 = 301 passes**.
All **11 retained gates** pass. Strict Clippy passed across the workspace,
all targets and all features with `-D warnings`; formatting also passed.
The locked graph and complete source-before/source-after identity were checked
on C1. Keep the 301 static passes separate from the 114 selected native passes;
this record does not assert a combined count of unique workspace tests.

Workspace-wide lint and formatting describe their own scope. They do not turn
the selected native roster into a full-workspace test run or establish a
whole-chain cryptographic security result.

## Retained setup and preliminary failures

An initial setup preflight on an existing sparse checkout failed because its
preflight script was not materialized. No source edit was performed there.
The subsequent independent complete clone passed base and development-branch
preflight. Preparation observed Rust/Cargo 1.95.0 and system OpenSSL 3.5.5;
that preparation alone was not a native test result.

The partial local editing snapshot supplied preparatory diagnostics only.
The [preliminary index](preliminary/README.md) and
[hash-verified metadata](preliminary/local-resource-owner-preliminary-metadata.json)
retain the original failures:

| Attempt | Actual outcome | Treatment |
| --- | --- | --- |
| [Initial local test build](preliminary/local-resource-owner-preliminary.log) | Cargo 101: missing original consensus-arithmetic compile-time fixture. | Later recovered exact #812 bytes; no synthetic replacement. |
| [Local test build after fixture recovery](preliminary/local-resource-owner-preliminary-02.log) | Cargo 101: `rustc` reached Node test code generation and was terminated by SIGKILL under unchanged optimisation level 3. | Cause remains unconfirmed; not a proved out-of-memory event, a particular test failure or a successful run. |
| [Local metadata check already started before diagnostics stopped](preliminary/local-resource-owner-preliminary-check.log) | Cargo 101: missing original `tests/fuzz/fuzz_targets/support/work_certificate.rs`. | No overall Cargo-check PASS or local native test result. |

The restored consensus fixture is 31,741 bytes, Git blob
`c3a86442e0b2d0b57fbdd5d0954288b5e92e6dc2`, SHA-256
`e1146d6a055790c89a8b66f96bc5a9c36bc1b0bf1102d6bf3b4063cc308ab737`.
Original logs retain the local SQLite loader-directory **UNQUALIFIED** warning.
No local native tests executed in these preparatory attempts. Their failures
are not replaced by later, independent complete-checkout C1 passes.

## Publication and evidence child

Publisher preflight on mac first failed because Python 3.9 lacked `tomllib`.
The retry selected the existing `/opt/homebrew/bin/python3` 3.14.3 through the
explicit `/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin` PATH, without source
changes. The retry exited zero, confirmed `ProfHepta`, verified the exact base
and passed preflight. Both attempts remain in the
[publisher preparation record](preliminary/publisher-preflight-attempts.json).
Publication status, the final branch identity and actual GitHub readback belong
to the resulting pull request, separately from these frozen C1 test outcomes.

An evidence and plan publication child includes the matching documentation
source pin in the corpus manifest. It must retain C1 runtime, proof, test,
dependency and admission-profile bytes and pass its own source and Markdown/link checks.
The pull request records the child's exact commit/tree, actual checks and
GitHub readback. C1 native results remain bound to C1; new runs have their own
source identity. Any actual runtime or test change requires its own subsequent
verification record.

## Acceptance limits

- The new observer uses the original native snapshot and packet observation.
  Successful supervisor completion consumes the entire reserved principal; it
  does not report measured child CPU or complete SQLite I/O.
- Unresolved process/cleanup outcomes retain their full original reservation.
  Recovery assertions require trusted local stop, readback and cleanup evidence.
  Full rollback of the journal, database and local witness still requires an
  independently fresh state anchor; the append hash chain alone does not supply it.
- Only adopted packet-observer entry points enforce this new local account.
  Cookie/PQ, other public and local readers, History, Growth and all host processes
  are not yet jointly qualified by this integration.
- Direct internal workers retain the once-only claim and CPU ceiling, but the
  independent supervisor wall/cleanup contract is not supplied by a worker flag.
- Positive honest service requires actual minimum host supply, bounded admitted
  backlog and bounded nonpreemptible interference. Three accounting allocations
  alone do not establish that supply or implement a cost-fair scheduler.
- Admission and journal overhead, multiple workers, sampling resolution and
  nonpreemptible State/SQLite tails still require an actual physical overshoot
  bound. Declared nonzero overshoot is not a measured or enforced host guarantee.
- The full product/transcript/State/novelty rejection-cost matrix still needs
  same-source cost and honest-service observations under the original envelope.
  Valid computation does not prove the cheapest legal strategy's physical cost.
- A complete statement-equivalent proof backend still needs prover total cost,
  post-win latency, late-failure, verifier CPU/memory, State/commit/cleanup and
  concrete cryptographic/QROM/lifetime-budget qualification. No PQ128 or
  production-admission claim is made here.
- The original 0.25 CPU / 2 GiB / zero swap / 256 PID / 4-second / 16-hostile
  acceptance profile is unchanged and is not replaced by these component tests.
