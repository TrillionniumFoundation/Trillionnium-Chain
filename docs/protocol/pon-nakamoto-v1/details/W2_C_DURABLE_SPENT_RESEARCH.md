# W2-C experimental durable paid-spend owner: local cross-process replay

**Status: research only / HOLD_NO_GO.** This child starts from PR #339 source
'2787ad3959359bc5377d982a7ab46a2d76d44e0e'; it does not change
W1 proofs, challenge, target, chainwork, consensus, V3 Cookie, networking,
model authority, FinalUse or production activation.

## Exact problem and threat scope

'W2-C stateless receiver' fixes pre-payment issue-row exhaustion by keeping
zero issuance entries and storing only paid tokens. Its volatile 'spent' table
still resets on crash: cloned receiver secret + identical epoch can accept an
already-paid W2-C claim twice. This package demonstrates a **different**
persistent design for a single trusted physical owner with a shared SQLite
database. It is not a permissionless solution and not a deployment profile.

The new 'w2c_durable_spent_owner.py' accepts the original authenticated
stateless receiver's MACed 'Grant' and the trusted caller, complete proposal,
ticket nonce and monotonic-clock sample. It checks the original HMAC-SHA256
and exact receiver / process epoch / caller+proposal binding, ticket difficulty,
lifetime and expiry. It then starts 'BEGIN IMMEDIATE' against one private
SQLite file. The exact paid-grant identity is unique in the 'spent' table.
The committed insertion happens **before** a future W1 validation request may
be started. Losing the subsequent W1 call never refunds a spent ticket.

The database is *only* a resource-spend record, not a ledger object or
VerifiedWork. Explicit 'create=True' is required to initialize an empty
store; ordinary 'mode=rw' restart fails closed when the file is missing.
One database context binds receiver, epoch, supplied boot identity, lifetime,
capacity, schema and fixed profile. Failed context or monotonic clock
regressions refuse new paid admission. Linux POSIX owner/mode, symlink,
hardlink and observed inode checks are local defensive checks, not an
attestation of a hostile filesystem.

Current research accounting:
- SQLite 'DELETE' journal, 'synchronous=FULL', atomic writer lock;
  paid rows are bounded by 1..1024, and expired entries are removed under
  transaction before attempting a new paid reservation.
- A correct ticket with no free slot returns local 'PAID_CAPACITY_BUSY';
  target misses, old epochs, tampering or duplicates never invoke W1.
- Every individual process uses a fresh SQLite connection to the **same**
  database path. Its 'BEGIN IMMEDIATE' and unique receipt key prevent
  a second READY among simultaneous workers sharing that one file.
- No new per-receiver W1 CPU allowance, signer, Node, PNW1 validator,
  miner entitlement, global Peer priority or model deployment authority
  is constructed.

## Reproduce and preserve the negative controls

    python3 formal/pon-nakamoto-v1/test_w2c_durable_spent_owner.py -v

In an isolated 2026-10-27 local Python environment, a source-equivalent
implementation with the same explicit public grant/HMAC algorithm and
12 independent unit controls completed **12/12 PASS**, including:

1. Identical paid ticket reopens as REPLAY after closing/reopening the DB.
2. Twelve independent OS processes sharing one file yield exactly
   one READY and eleven REPLAY.
3. A subprocess exits with os._exit immediately after a committed spend;
   the next process cannot replay that ticket.
4. Wrong receiver, epoch, boot identity and lifetime refuse file reopening.
5. Missing store does not silently create a new unspent allowance.
6. Caller/proposal/MAC tampering does not spend a row.
7. Paid capacity full returns Busy and creates no new W1 work.
8. An earlier timestamp is refused across reopen.
9. Weak mode and symlink are refused locally.
10. **Unresolved counterexample:** copying the SQLite DB before consuming
    the ticket into two independent files allows one READY **per copy**.
11. Local inode replacement is detected before subsequent expensive work.
12. Target miss is refused before any durable spent record.

The exact GitHub-committed source still requires original-checkout preflight,
dependency-inclusive Python execution, exact tree/blob comparison,
multi-process fault testing on the deployment filesystem, and independent
review. A scratch run does not stand in for these gates. Test run notations
must distinguish expected negative attack outcome from soundness evidence.

## Remaining blockers / why this does not solve W1 DoS

The original low-cost forged W1 transcript still passes a cheap ticket and
forces a complete W1 reject. Durable one-use W2-C work only prevents
duplicate delivery to the **same database owner**. A database clone,
independent host, remote relay, wiped store, reused boot/epoch, administrator
fault, filesystem TOCTOU or untrusted caller authentication can break the
assumption. Host budget, real source CPU/GPU ratio, admission fairness,
storage-crash durability, 3×3×3 original A03, mathematical neural useful
work, sound W2 succinct proof and P6 external cryptographic review remain
separate **OPEN** gates.

The source must not be loaded as a public resource server, a production
consensus proof or an automatic Hashcash fallback. P0–P6 activation stays
**DENY_ALL / HOLD_NO_GO**.
