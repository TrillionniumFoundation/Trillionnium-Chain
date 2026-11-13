# V2 root journal: SQLite connection lifetime continuation

Status: **HOLD / RESEARCH ONLY**. This is a resource-cleanup change to the
research V2 journal. It closes no whole-chain P0 qualification item and grants
no root, recovery, payment, API, M15 or FinalUse authority.

## Exact starting source and scope

This continuation starts from PR #837 delivery commit
`44330b91eb552fd20ef6f2e69bf5e6f1e8f5c0b0`. It does not incorporate the separate
PR #835 integration candidate, and its results must not be presented as
execution or integration on that candidate.

The [V2 journal](../../formal/pon-nakamoto-v1/pq_root_recovery_journal_v2.py)
previously established a SQLite connection and executed its three initialization
PRAGMAs before entering the existing `try/finally`. An initialization exception
could therefore leave that connection outside the explicit cleanup path.

The change moves all three PRAGMAs inside that existing `try/finally`. Exclusive
file creation, read/write mode, timeout, journal mode, full synchronization,
foreign-key checks, SQL order and the transaction context manager remain the
same. Successful transactions still commit; body and commit failures propagate
and retain SQLite rollback semantics. Every connection successfully returned by
`sqlite3.connect` reaches the existing explicit close after setup, transaction
success or failure. No retry, fallback, schema migration or new authorization is
introduced.

## Component validation

The [cleanup suite](../../formal/pon-nakamoto-v1/test_pq_root_journal_cleanup.py)
contains **four tests**, using actual temporary SQLite databases. Connection
instrumentation observes lifetime and injects ordinary initialization errors;
it does not substitute SQL execution or cryptographic verification.

| Test | Observation |
| --- | --- |
| Initialization error | Each of the three PRAGMAs is checked as a subcase; the owner body is not entered, the original exception is preserved and the connection closes once |
| Successful transaction | Reopening the actual database observes the committed row; the original connection is closed |
| Body error | Reopening observes rollback; the original application exception is preserved and the connection is closed |
| Deferred commit error | An actual deferred foreign-key constraint fails at commit, rolls back and closes the connection |

The three initialization subcases are not three additional tests. The local
component invocation passed **4/4** on the derived working tree. This is not a
claim that the old base commit contains the change, or that every mandated gate
ran on a later delivery commit. Exact committed-source verification and its
receipts remain separate from working-tree preparation.

```sh
python3 formal/pon-nakamoto-v1/test_pq_root_journal_cleanup.py -v
```

The direct-file command is mandatory exactly once in the straight-line
`repository-truth` root structure prefix. The
[CI contract](../../scripts/ci/check_ci_contract.py) also requires a regular
suite file. Its [source controls](../../scripts/ci/test_ci_contract.py) reject
removal, duplicate execution, comments/stubs, conditional skipping, early success,
swallowed failures, relocation to another lane and zero-match discovery.
The original native root selectors, their order, the following Host gate and
all original resource/workload requirements are unchanged.

## Reviewed current-source registration

The current [root dependency register](PQ_ROOT_DEPENDENCY_REGISTER_V3.md) is
deliberately re-frozen after review of this small helper change: its journal
SHA-256 and the checker's canonical source-map digest are updated together.
The original review-base context, 37 declared source files, five roles, 16
hash-use groups and all unknown error/query bounds retain their meanings.
There is still no runtime regeneration or accept-current-bytes mode.

The current cross-branch corpus binds the changed source/CI files and the new
test and this document. Source consistency is not a new native execution,
complete transitive-dependency proof or whole-chain security qualification.

## Historical evidence and remaining gates

The [V4 evidence archive](../../evidence/pq-root-continuation-v4-20261109/README.md)
is unchanged. Its executed source `0d99924005b70b1308bf3e62c53e9300fbb4aac4`,
42/42 local commands, component counts and original hosted native campaign
**0/3** remain observations of their recorded source and environments. This
continuation does not relabel them as current-source acceptance or overwrite
their failures, warnings or unknown causes.

The retained V2 native suite's ResourceWarnings were not uniquely attributed.
This fix addresses the explicit initialization-cleanup path; it does not claim
that every historical warning originated there or that the native suite is now
warning-free. The native suites have **not been rerun** for this continuation.

Only the cleanup tests and selected source/register/CI controls are in the
present validation scope. The complete mandatory protocol/native lanes, full
workspace tests, locked Cargo graphs, formatting and strict Clippy, original
three-run campaign, cross-architecture service/History acceptance and ordinary
Hepta integration still require their own exact committed-source observations.
Passing a parser or register check cannot replace any such gate.

Independent custody, sufficiently fresh currentness surviving a common restore,
real external effects, lifetime bounds and whole-chain composition remain open.
Multiple keys, processes or directories still do not authenticate independent
administrators, backups, networks, power or recovery procedures.

```text
status = HOLD
whole_chain_pq_qualified = false
independent_custody_verified = false
actual_external_effects_verified = false
actual_lifetime_failure_bound = null
production_activation = false
```
