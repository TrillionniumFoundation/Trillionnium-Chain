# W2-C shared durable spend: explicit crash/restart anti-replay boundary

Status: **RESEARCH_ONLY / HOLD_NO_GO**. Frozen parent:
`2787ad3959359bc5377d982a7ab46a2d76d44e0e` (#339).
This is an opt-in Python-only durable store. No W1/PNW1 bytes, V3 signed
Cookie revision, consensus work score, network service, mining target, ledger
authority, model installation or production-activation change.

## Original red-team counterexample

A W2-C `StatelessReceiverAdmission` sends a server-MACed challenge,
then retains *paid-only* token identities in a process-local `spent` map.
If the process restarts with the same receiver secret **and same epoch**
but an empty map, a formerly paid ticket can return `READY_RESOURCE_ONLY`
again. The original regression in
`test_w2c_stateless_receiver.py::test_copying_same_secret_and_epoch_cannot_be_called_safe_restart`
**must remain a passing demonstration of this failure**; rewriting that test
to hide the clone is not a fix.

## New measured owner and security boundary

`formal/pon-nakamoto-v1/w2c_durable_spent.py` implements
`DurableReceiverAdmission` as a subclass of the original stateless
grant issuer, leaving unpaid issuance free of database row allocation.

The caller explicitly selects a trusted, absolute, owner-private
directory (not a remote/client-chosen path). A new store must be
`create=True` and backed by a create-exclusive SQLite file named
`paid-spend.sqlite`. A restart must use `create=False`, require the
**existing** file, reject symlink/hard-link/mode/inode replacement and
verify the already persisted HMAC-bound receiver/secret/epoch fingerprint.
It may **not** silently recreate missing evidence. SQLite rollback
journal mode and EXTRA synchronization are selected. A bounded exact
paid-grant table and persisted signed-64-bit monotonic watermark live
under one SQLite transaction and `BEGIN IMMEDIATE` locks.

A candidate first passes the original canonical grant/MAC/receiver,
authenticated caller, header/proof proposal, expiry, and 8..24-bit
ticket checks. Then under a *single physical database* transaction,
it checks persisted identity and time, prunes expired entries,
atomically rejects replay/capacity, inserts one paid identity and
**commits the spend before any external W1 validation is permitted**.
A valid ticket can only yield `READY_RESOURCE_ONLY`; it cannot mint
`VerifiedWork` or Chainwork. Invalid W1 does not refund the paid row.

Crash outcomes are deliberately conservative: after a durable commit
but before W1, a ticket remains consumed even if zero useful work ran.
This is an **at-most-once admission**, not exactly-once execution.
Missing or corrupt owner data, failed SQLite lock/commit, changed
inode, unexpected field/clock range and untrusted local storage must
fail closed. A successful early ticket or a local `DURABLE_UNAVAILABLE`
is NOT a consensus validity result.

## Explicit bounded tests

```sh
python3 formal/pon-nakamoto-v1/test_w2c_durable_spent.py -v
```

The new selectors include:

- Pay -> close -> reopen original DB -> exact old nonce rejected as REPLAY.
- Real child interpreter pays and uses `os._exit(17)` immediately after
  the durable transaction; parent reopens and rejects the same old ticket.
- Two independent store connections with 32 racing paid replays:
  exactly 1 READY and 31 REPLAY if all lock operations completed.
- Many stateless *unpaid* offers create zero spent rows.
- Shared two-paid-token saturation across processes and expiry recovery.
- Invalid Hashcash and MAC do not write spend rows.
- A paid but fabricated W1 transcript still fails `TRANSCRIPT` and
  the consumed ticket is never refunded.
- Missing database, new-on-existing, wrong secret/epoch, file replacement
  and permission/symlink checks refuse instead of silently resetting
  the original owner state.
- **Deliberate remaining red team:** copy the DB snapshot *before*
  spending it into a separately rooted, same-secret/same-epoch clone:
  both independent stores can return READY. This is a **negative**
  security demonstration, not globally solved replay.

Unrun Rust compilation, standalone Go differential, physical cgroup,
shared-host CPU, real network traffic, independent operator and GPU
measurements are explicitly NULL. Python test pass on one local
host qualifies only its own code/research assumptions, never P0–P6
production readiness.

## Irreducible operational qualifications

SQLite serializes only participants using the **same** original storage
file and its OS-level lock. It cannot prevent a fully compromised
administrator from copying the directory, database snapshot and
HMAC key to another failure domain, nor prove real non-clonable
hardware custody. To qualify production use, bind an externally
enforced unique authority epoch, physically shared durable spend owner
or equivalent monotonic non-clonable key service; test disk loss,
crash cuts, fork/restore, multi-host split brain, secret rotation,
replay from old snapshots and honest availability under a full ledger
workload. Identity aliases and copied credentials are not independent
operators. Even a perfect replay fence does not close the *single
receiver* forged-transcript CPU amplification, anonymous issuance
bandwidth flood or unqualified W1 computational hardness.

P0: original full Rust/Node regression still required.
P1: real Host service/remote loopback/worker accounting still required.
P2: empirical actual native V3 CPU/GPU/hash price still required.
P3: sustained malicious identity and real mixed-service load still required.
P4: original A03 3 modes x 3 runs x 3 timely confirmations still required.
P5: efficient, sound W2 computational proof still missing.
P6: external independent cryptanalysis/real deployment acceptance missing.

Keep #339 and this child PR **DRAFT**, and all production flags off.
