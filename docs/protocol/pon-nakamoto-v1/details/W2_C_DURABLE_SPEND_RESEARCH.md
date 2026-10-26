# P5 research: durable original paid-spend ownership across cloned W2-C processes

Status: **research only / HOLD_NO_GO**. No native W1 proof bytes, W2
consensus, V3 Cookie, Chainwork, source admission, mining reward, model
authority, final-use or production activation is changed.

## Problem reproduced

The original stateless W2-C admission research uses an in-process dictionary
to mark paid tickets as spent. A second process with a copied 32-byte
receiver secret and identical Epoch starts with an empty dictionary.
It can return READY_RESOURCE_ONLY for a ticket that was already consumed
by the first process. Existing test
'test_w2c_stateless_receiver.py::test_copying_same_secret_and_epoch_cannot_be_called_safe_restart'
retains the counterexample; it must not be deleted.

## Additive candidate

The new research component 'w2c_sqlite_spend_owner.py' stores **only
already-priced ticket-spend identities** in one separately provided,
administrator-owned, local SQLite file. It does not allocate a row
for each free challenge issuance. Each claim uses:

- One owner context bound by
  H('w2c-stored-owner-v1', receiver, epoch, original_secret).
  Different Epoch, key, receiver or finite capacity must not reuse it.
- The already-existing exact paid identity from the unmodified W2-C
  grant MAC, authenticated caller, proposal, nonce and ticket checks.
  Bad tickets are filtered before SQLite's W1-start permission.
- A **BEGIN IMMEDIATE** SQLite transaction, finite positive slots,
  unique 32-byte paid keys and expiry-based deletion. Exactly one
  transaction can insert a given key; the transaction commits with
  SQLite synchronous=FULL and WAL **before any expensive W1 replay**.
  No failed W1 rejection refunds a paid row.
- A durable high-water monotonic millisecond clock that prevents time
  rollback after an old row has expired. SQLite signed-int bounds,
  file owner/mode/link and 0700 parent directory are checked.
- Any poisoned/unavailable DB fails closed and returns no
  READY_RESOURCE_ONLY. A true RPC/DB failure is a local resource failure,
  not an Invalid W1 verdict.

The original 'StatelessReceiverAdmission' constructor now accepts one
optional trusted 'paid_spends' owner. It checks that owner's exact
context and capacity before using it. With no owner supplied the existing
volatile research behavior remains unchanged, including its explicit
clone-epoch counterexample. This is not selected by real public V3.

## Actual isolated tests and exact source

Standalone selectors:

    python3 formal/pon-nakamoto-v1/test_w2c_sqlite_spend_owner.py -v
    python3 formal/pon-nakamoto-v1/test_w2c_stateless_durable_spends.py -v

One local Python 3 isolated test run dated 2026-10-26 completed
**12 / 12 PASS** in ~5 s: exact-once across 32 threads, exact-once
across six real spawned processes, actual child process exit
immediately after a committed claim, new-process reopen, capacity,
expiry/high-water rollback, changed context, unsafe symlink and
out-of-range identity refusal, cloned-instance spend and fake W1
TRANSCRIPT rejection after an actual research cost ticket.

Local source integrity for **three new files** was checked against the
Git Blob SHA of each corresponding published file (Git object SHA,
not a claim of reproducible Rust build). The original W2-C
dependencies for isolated execution were *semantic local mirrors*;
the complete original GitHub repository checkout, project preflight,
native Rust execution, real paid V3 transport and independent WAN
were NOT run in the isolated sandbox. The local raw test-output
receipt and hash are outside GitHub; a report can be supplied
separately for external review. Do not carry the PASS marker into
a different exact source or environment.

## Mandatory adversarial limits still open

1. This is **one local POSIX/SQLite filesystem**, not a replicated or
   independently administered durable consensus owner. A separately
   copied SQLite file can accept the same ticket again; the test
   proves that negative. SQLite's WAL, unique keys and locks are
   not network-wide replay protection. Network FS and disk rollback
   are unqualified. Encryption/key sealing, backup restore and
   writable-directory races are outside this prototype. There is
   also a stated race between file-path checks and sqlite3.connect;
   it cannot be represented as hardened hostile-filesystem I/O.
2. A cloned original secret plus Epoch without the **same original
   database** remains an explicit vulnerable configuration. A
   production design needs enforced resource ownership/epoch
   generation and anti-rollback state across physical failure domains.
3. Because a locally priced 8/12-bit Hashcash may cost dramatically less
   than a complete 64x64 W1 replay, the original **local CPU
   amplification still exists**. This prototype does not solve
   GPU/ASIC differential costs, unpaid HMAC/RNG/connection floods,
   honest-traffic fairness or verified useful-work hardness.
4. The exact Rust P0 regression, source-wide P1 native CPU and Host
   cgroup measurements, P2 hardware calibration, P3 mixed traffic,
   original A03 P4 3×3×3 timely confirmations, P5 succinct work
   soundness, and P6 independent external cryptography are NOT
   established by this study. No readiness flag changes.

All temporary and durable research identifiers are **resource admission
hints only**, never VerifiedWork, valid Block, Chainwork or Hepta FinalUse.
