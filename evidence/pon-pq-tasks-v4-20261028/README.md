# NPQ4 task-authority candidate observations — 2026-10-28

**Native execution on this candidate: NOT_RUN locally. P1 completion: false.**
This package preserves source, compilation metadata, strict Python reader
controls and their failures. Shared disk reached the owner stop line; no new
Cargo target or native test ELF was built to bypass that limit. The required
fresh hosted result remains a separate observation on the published exact head.

The scope and actual remaining permission owners are in
[Native PQ task permissions v4](../../docs/protocol/pon-nakamoto-v1/details/NATIVE_PQ_TASKS_V4_RESEARCH.md).
The publication parent is `29e1f194742e436b44b4c8758777341e62fe2bd8`, whose
tree equals local `ab4a7daf9892035c435608b9a7d9f3b3952b1a39`. The previous
[164-test hosted result](../pon-pq-hosted-a1e407-20261028/README.md) belongs to
its earlier runtime and is not promoted to this candidate.

## Evidence and status

| Boundary | Recorded observation |
| --- | --- |
| Actual new ML-DSA/M06/Node tests | **NOT_RUN locally**; hosted gate required |
| New runtime library metadata | Four actual Rust 1.95.0 library targets typechecked using recorded frozen dependency artifacts |
| New test metadata | M00/M06 unit targets and M06/Node task integration targets typechecked; this does not execute a test |
| Direct Clippy | Warnings denied on the same metadata graph; final Node transaction-membership delta checked separately |
| Locked Cargo graph | Actual offline resolution: 173 packages, 26 workspace members, unchanged manifests and lockfile; no native build |
| Legacy evidence reader | Complete 75-method runs, zero skips; exact source/times and retained input hashes in summary/raw records |
| NPQ4 gate reader | Synthetic positive/negative controls only; full test names, original ignores, proof/command sizes and phase counts are enforced |
| Complete workspace / physical I/O | Not qualified by this package |

The [summary](summary.json) supplies actual result, elapsed time, source
identity and scope per observation. The [raw inventory](raw-inventory.json)
enumerates every retained file and hash in [observations.tar.gz](observations.tar.gz).
The [source identity join](source-identity-join.json) names any final-source
delta relative to earlier immutable observations instead of relabeling them.

## Retained failures and review finding

The initial full formatting attempt lacked the cargo-fmt tool in PATH; the
next attempt exposed a missing unchanged sparse fuzz include. The first
gate-reader import lacked the unchanged bounded-process helper, and the first
M06 unit metadata check lacked the unchanged 14,205-byte growth reference
vector. Exact tracked files were restored and their Git/SHA identities retained;
no dependency source or test expectation was replaced to obtain success.

The first expanded unit-roster parser control incorrectly wrote zero ignored
tests into its synthetic positive summary even though it listed the eight
original ignores. The parser rejected that inconsistent fixture. Its failure
is retained; the correction supplies the actual synthetic ignored count and
retains all negative controls. This fixture failure is not a native execution
failure or an excuse to permit new ignored cases.

Read-only review of the new local withdrawal owner found a detached-block
transaction binding gap. The initial audit used the original packet reader,
which checks header/block identity but does not independently recompute the
transaction root. The final NPQ4 owner adds that check for every activation
event, including detached blocks. The added native SQL control retains the
original header, block ID and complete W1, replaces the old revocation's
transaction list, and deletes the local revocation row. Cold open must refuse;
restoring the exact packet and row must restore the valid path. **This is a
source-identified counterexample and a required native test, not an executed
native RED/PASS observation.**

An attempted release of this task's own old metadata/object cache is also
recorded. Its files reappeared after deletion with different inode identities;
no net-space reclamation or unexplained process ownership is claimed. The
action was not repeated. Other agents' artifacts and source trees were not
modified or signalled.

## Required finite hosted acceptance

The new workflow retains a 60-minute job limit and the original 2,400-second
total command limit, one build worker, exact source checks before/after each
command, locked Cargo, unchanged full W1 and the selected warnings-denied
all-target/all-feature Clippy checks. Its required count is **180 actual
passes**, comprising 47 M00 and 89 M06 unit passes and 44 integration passes.
Exactly the original two M00 and six M06 timing cases remain ignored; every
other name and outcome is pinned to the actual prior hosted roster plus the
new cases. No integration case may be ignored or filtered.

The new Node tests require 26 actual phase records, with six material calls,
full 7,894-byte registration frames, the 32-registration/64-proof cohort and
49,188-byte W1 proofs. Those phase observations include real execution, proof
construction, independent reference verification, admission and SQLite work;
they are not worst-case CPU or energy measurements. A compiled target, a
zero-test command, a partial phase set, or synthetically generated reader
records cannot satisfy the gate.

The legacy evidence reader still returns only the unchanged legacy V2 schema.
New NPQ4 schema IDs, packet headers, statement tables and revocation history
tables are all negative controls. This compatibility work grants no PQ or
public-network qualification to old legacy evidence.
