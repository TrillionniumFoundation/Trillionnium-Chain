# PQL5 local witness ACK and SQLite TEMP namespace fence

**Research-only / HOLD_NO_GO**, stacked on PR #458 at `192480f0c5e1fa6077c8c3bc2b9e1790a02c0552`.
This does not alter PQL4/PQL5 signed wire bytes, ML-DSA-65 algorithms, installed
PoN W1, Chainwork, main, Hepta FinalUse, or production activation.

## Threat and patch

The original `LocalWitness._audit` compared only `sqlite_master`.
Connection-local TEMP tables/triggers are invisible to that query. A TEMP
AFTER INSERT trigger could erase the new PQL4 witness event while the writer
returned `FIRST_RECORD`. A TEMP `events` table could shadow the persistent
table. Both mutation and signed observation must fail closed.

The new audit also rejects TEMP schema objects and checks the original
SQLite leaf inode (not a cross-process monotonic anchor). After any first
or repeated append COMMIT, a new `BEGIN IMMEDIATE` audits the complete
signed PQL4 witness chain and verifies the exact acknowledged head.
If the file was moved/changed or its content is not present, acknowledgement
is withheld. Crash after original COMMIT but before the recheck remains
indeterminate and must be reconciled.

Three additional threat-derived tests cover a TEMP trigger, TEMP shadow
table (also on signed observation), and a filename rename inside the
original transaction. The previously recorded all-operator keys and
same-process local crypto tests remain separate.

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql5_quorum.py
```

The TEMP SQLite and detached-inode mechanisms were independently reproduced
on SQLite 3.46.1. **The exact GitHub branch's full test suite has not run
in this tool environment.** No source-qualified, independent, hardware or
production verdict is claimed.

## Unresolved blockers

The signed witness is only as trustworthy as its external, operator-owned
freshness anchor. A 2-of-3 compromised witness majority can re-sign an
older valid head without detectable equivocation; ordinary SQLite,
second readback or local content hashes cannot solve this. Sidecar/ancestor
replacement by the same UID, crash during fsync, physical power loss,
WAN operator independence, native Rust M13 integration, authenticated
time, Hepta authority, and PoN quantum-effective work remain open.
