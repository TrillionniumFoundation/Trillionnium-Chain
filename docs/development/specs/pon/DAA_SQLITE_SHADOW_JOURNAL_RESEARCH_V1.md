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
