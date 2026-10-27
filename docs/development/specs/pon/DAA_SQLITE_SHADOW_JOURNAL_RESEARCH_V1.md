# Research-only M07/M08 durable DAA shadow journal v1

This is an explicitly **non-authoritative** continuation of
[DAA_ANCHOR_PROJECTION_RESEARCH_V1.md](DAA_ANCHOR_PROJECTION_RESEARCH_V1.md)
under the [sole development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It is not a Node database, not a production profile, not a consensus rule or a
separate trusted owner. No existing Q4, Revision12, W1, target, work, signature,
state root, deployment or activation bit changes.

## Experimental implementation

- `formal/pon-nakamoto-v1/daa_shadow_journal.py` implements an isolated
  `daa_shadow_meta_v1` plus `daa_shadow_headers_v1` SQLite namespace.
  Context, genesis and active tip are immutable/CAS-bound metadata.
- Every row binds exact 32-byte block/parent IDs, BE64 height/time, 32-byte
  target, upstream packet SHA256 and **externally supplied** projection SHA256.
  A domain-separated row SHA256 detects accidental/local-byte corruption,
  not adversarial replacement by a hostile database writer.
- `append` and `activate` use `BEGIN IMMEDIATE`, SQLite FULL synchronization,
  exact input checks, create-only row semantics, and readback. A pre-commit
  fault rolls back. A post-commit fault yields `UnknownEffect` and permits only
  same-identity reconciliation; it must never be treated as a failed operation
  granting a new budget.
- Local branches are stored separately; an active-tip CAS is an experimental
  pointer, **not** Nakamoto heaviest-work selection.
- Cold open checks schema, context and a bounded streaming ancestry audit,
  including canonical row fields, hashes, parent existence, increasing height,
  immutable tip membership and a finite record budget.

## Testing and precise limits

Run `cd formal/pon-nakamoto-v1 && python3 -m unittest -v test_daa_shadow_journal.py`.
Thirteen source-derived local Python/SQLite tests on 2026-10-26 passed: atomic replay,
durable branch switch, 3 pre-commit faults, post-commit Unknown, active-tip
CAS restart, duplicate corruption, hot index drift, cold byte tampering,
missing parent, foreign DB/symlink refusal, height and row resource bounds.
This observation is from locally prepared identical source files, **not**
a GitHub runner, native Node transaction or physical power-cut experiment.

The journal intentionally DOES NOT authenticate an actual `Packet`, check
PNW1/W1, derive the ASERT projection hash, verify a qualifying Task/Lease,
enforce native StateRoot, or validate chainwork/fork choice. A malicious caller
can supply a self-consistent but false `projection_hash`. SQLite row hashes do
not attest provider identity, disk integrity against a privileged attacker,
independent storage custody or full-fsync durability under physical power loss.
`max_headers` bounds record count only; SQLite/VFS page/WAL/rollback and global
memory/CPU budgets remain separate obligations. Path checks here do not provide
hostile-filesystem race-safe ownership.

## Required native next step (P1-C still OPEN)

Use existing M07/M08 native authenticated owner for *one* atomic commit:
independently W1-verified native packet + expected branch-local DAA target +
state/root/receipt + derived projection + durable commit/readback. Only a
versioned, reviewed, genesis-bound new consensus profile may consume that target.
Inject detach/attach crash cuts, corrupt early ancestry, cold/audited replay,
deep forks, version/context mismatches, missing history, and live-client
confirmation under measured bounded resources. Do not import this research DB
as authority, alter historical DAA or mark public readiness true.

## Cross-check against original owner facts (advisory, not authority)

`audit_against_upstream(read_packet, derive_projection, max_rows=...)` now
compares each stored row against actual caller-provided upstream packet bytes
and an independently derived projection digest. Missing, mutated, oversized
packets, incorrect projections and bounded audit exhaustion reject. Both
callbacks remain untrusted Python callables in this research experiment;
there is **no** native VerifiedWork/Node capability or proof that a callback
speaks for M02/M07. The audit is read-only and never calls a signer, repairs
external effects, changes active tip, or grants model/consensus final use.

This additional research contract has two focused positive/negative tests;
the exact local Python total is now 13/13. No physical power loss, native W1
packets, Rust compiler or independent operator was exercised.

## Snapshot-fenced original-owner review

The same upstream readback method now obtains one SQLite read transaction
before scanning. A caller's original writer may not reenter through an audit
callback and silently mutate the branch while evidence is assembled; read
transactions are rolled back on every success/error path. The requested
`max_rows` budget is checked before the deeper scan. One source-matched
negative test checks reentrant writer refusal, unchanged tip and resumed
ordinary append after the audit. The local research suite is 13/13; this is
not a replacement for native atomic M07 packet/projection persistence.

## Same-snapshot graph/active-tip audit (2026-10-26)

The read-only `audit()` now pins its complete ordered header scan and the active
branch pointer to **one SQLite read transaction**. An external research writer
cannot commit a newly appended or activated branch between those observations.
The complete read transaction is rolled back on success and failure, and a
reentrant audit inside an original writer transaction refuses with a typed
`AUDIT_REENTRANT` error rather than releasing a caller-owned transaction.

The external-owner comparison `audit_against_upstream()` calls the internal
`_audit_snapshot()` under its existing one read transaction. It refuses
reentrant entry as `OWNER_AUDIT_REENTRANT`; it never performs a second BEGIN,
accepts new authority or rewrites local history. Competing real SQLite writers
are covered by a negative-control interleaving which confirms the original
writer can commit only after the audit releases its snapshot. No native W1
proof, public fork-choice rule or production consensus is affected.

## Immutable meta drift during hot append/activation (2026-10-26)

A cold open originally validated the fresh research context and genesis; the
original hot `append` path checked only header/parent rows, and `activate`
read only the active-tip value. A second local SQLite owner could corrupt or
remove immutable meta rows after open and before a later research mutation.

The corrected read-only context fence checks the **complete** meta keyset and
exact `schema`, `context`, `genesis` values on `active()`. `append()`
calls that same fence **inside its existing `BEGIN IMMEDIATE`** before
writing any row; `activate()` already calls `active()` inside its original
writer transaction. The full read-only audit also reaches the same fence within
its pinned snapshot. Two new tests mutate context, delete schema/genesis after
open, verify every mutation is refused and no partial header/active tip exists,
then restore original bytes and verify a normal branch may be appended/activated.

This is O(1) in meta rows plus the original indexed tip lookup, not a
per-append full graph scan. Earlier-ancestry corruption still needs cold/full
upstream auditing; self-consistent forged metadata, W1 proofs or projection
hashes cannot be authenticated by this research database. SQLite file-path race
and physical power-cut isolation are still unqualified. Native M07/M08 custody,
versioned consensus ASERT acceptance and activation remain **OPEN**.

### Strict-schema readback boundary

The research `ShadowJournal.get` read API now performs the same immutable context and canonical table-DDL check as the native-independent writer/audit boundary before returning a locally hash-matching header. A foreign schema or changed context invalidates even an unchanged row's research readback. This is not independent W1, target or fork-choice authority.

### Committed-but-unreadable effects remain Unknown

After an `append` or research active-tip CAS has COMMITted, any failed row/context/schema readback now produces `UnknownEffect` rather than a precommit `JournalError`. Injection regressions confirm that original header/tip bytes survive cold reopening when the immediate readback failed. The caller must reconcile the original operation identity and cannot assume the write was absent. This change grants no actual native chain, release or execution authority.

## Exact active-tip pin in upstream research audit (2026-10-27)

`ShadowJournal.audit_against_upstream` now requires `expected_active`,
the 32-byte nonzero active branch tip independently pinned by the native owner.
Inside one local SQLite read snapshot it audits the complete graph and local
active selection, rejects a different selected tip **before** invoking packet
callbacks, checks each externally supplied packet/projection, then rechecks
the same local tip. This prevents a stale research CAS after a real reorg from
passing solely because the old branch's stored rows are internally consistent.
The extra verification is diagnostic: it is **not** proof that the upstream
owner was held stable. A production caller must capture the native tip and
complete header/material facts under one externally fenced owner readback;
an attacker-supplied `expected_active` or callback remains untrusted.

The existing cold SQLite and byte-verification tests retain their original
meaning. The additional negative test creates sibling research branches,
switches the local selected tip and rejects a stale external expectation
before invoking callbacks, then cold-reopens the same identity. No existing
legacy DAA, Q4 signature, W1 work or production flag is changed. Exact-source
Python/Rust native tests and WAN acceptance remain separate OPEN gates.

### Early read bounds before SQLite shadow replay (2026-10-27)

The shadow research owner checks metadata TEXT/BLOB lengths against 4096 bytes
before materialization on cold open and hot readback. Auditing first checks
its exact fixed-width header-table schema and configured row count **before**
reading header BLOBs in the existing SQLite read snapshot. An oversized
metadata row must refuse get, activation, audit and cold reopen without new
branch publication. Native Node, W1, old DAA, Q4, Revision12 and activation
flags are unchanged. This does NOT bound DB/WAL/RSS, authenticate external
W1 facts or close P1-C/P2 independent acceptance.
