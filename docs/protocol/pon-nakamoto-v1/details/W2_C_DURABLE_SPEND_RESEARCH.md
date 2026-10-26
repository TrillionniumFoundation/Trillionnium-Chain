# W2-C durable local spend / restart fencing: adversarial research

Status: **research-only, unqualified**. Parent is Chain W2-C PR #339, source
'2787ad3959359bc5377d982a7ab46a2d76d44e0e'. The W1 49,188-byte
PNW1 relation, ticket, chainwork, genesis, current signed Public V3 Cookie,
model acceptance and production activation are **unchanged**. No W2 authority
is granted by this code.

## Attack reproduced and protected boundary

The earlier stateless W2-C issuer spends a valid Hashcash ticket in a bounded
volatile map. If that receiver restarts with a cloned private secret **and the
same Epoch**, the empty map can admit the previously paid ticket again.
A same-host second process or a crash between spending and expensive W1
must not create an additional accepted resource-attempt entitlement.

'formal/pon-nakamoto-v1/w2c_durable_receiver.py' is an isolated Python
reference component testing a stricter local owner:

1. Its SQLite database and lock file reside in a directory owned by the
   current process UID with no group/other access. Open rejects symlink,
   hardlinked, foreign-owner or group-accessible state files.
2. An exclusive Linux flock on a stable lock inode is held through the
   entire owner process. Another same-host process cannot acquire a second
   active spending epoch against those original paths.
3. On each opening, create and commit a fresh 32-byte epoch in SQLite with
   WAL and synchronous FULL. A ticket from a previous process Epoch cannot
   be reused by the newly opened receiver, even with the same old key.
4. The short-lived, receiver-specific, MAC-authenticated offer binds the
   exact proposal, upstream-*authenticated* caller, nonce challenge, token,
   epoch, declared difficulty and original immutable expiration. An unpaid
   offer allocates **no pending DB row**.
5. A valid ticket is checked, then its unique paid identity is inserted
   within 'BEGIN IMMEDIATE', with a matching persisted epoch and a bounded
   outstanding paid-row count. Only a completed SQLite commit may return
   'READY_RESOURCE_ONLY'. Concurrent copies of the same ticket return
   REPLAY; full W1 rejection never grants a ticket refund.
6. Unknown transaction outcome, database error, or monotonic clock
   regression fences this instance from subsequent admission; caller
   cannot treat a local refusal as invalid blockchain work. A post-commit
   crash leaves an on-disk spent record, and the next process also rotates
   epoch before issuing more grants.
7. These keys/epochs/receipts are not accepted by any production Rust
   component. A successful local grant **only** permits a subsequent
   unmodified full W1 check. There is no VerifiedWork, Chainwork, or
   final-use API here.

## Local exact-byte test evidence

Execute from a full repository checkout:

    python3 formal/pon-nakamoto-v1/test_w2c_durable_receiver.py -v

The current-turn local scratch run executed **12/12 tests PASS** on an
actual Linux filesystem and Python SQLite. It covered:

- 32 concurrent same-grant calls: exactly one READY, 31 REPLAY
- paid capacity saturation, two-sided expiry checks, and row reclamation
- 2,000 unpaid offers with zero paid/pending database rows
- original proposal/caller, nonce, MAC tampering, and unknown time refusal
- invalid/symlink/hardlink filesystem inputs
- an actual second subprocess denied by the held lease
- forced exception before SQLite spend commit, then a fenced owner
- restart epoch rotation with the original spent row retained
- monotonic-clock regression followed by denial of all new offers
- an actual child process calling os._exit(0) immediately after durable
  spend commit, then a parent reopening and reading its retained paid row
- real SQLite max-page-count exhaustion under repeated paid requests:
  the first out-of-space insert fails closed, prior committed rows survive
  reopening, no false READY is returned; this is not full-disk or power loss
- an actual 512-tile W1 independent Python oracle replay: forged
  transcript returns TRANSCRIPT **after** paid ticket, repeat returns REPLAY.

The exact committed Git blob ids were checked byte-for-byte against those
locally executed:

| Source | Git blob SHA-1 |
| --- | --- |
| 'w2c_durable_receiver.py' | 'afa20256affa295d1ee085056e5dca2b189b437f' |
| 'test_w2c_durable_receiver.py' | '2990b7f973c8f26857a03da4c254a10ca1b06347' |
| Original 'work_oracle.py' scalar W1 | '9cbfccd2d50af48fc43522b967ffdfb1f45ec098' |

The local scratch test used the unmodified 2,944-byte independent W1 oracle
and a locally copied, equivalent domain-separated 'H' function, not a
full-pinned complete repository checkout or Rust binary. It is a test of
a research mechanism, not source/machine-level production qualification.

## Remaining material blockers

- The persisted epoch fences **process restarts with one shared original
  state path**. It does **not** prevent copying an active VM/container,
  state/secret/epoch into a separate Host or restoring an entire live
  process snapshot. A distributed, non-clonable monotonic lease authority,
  independent key custody or hardware secure counter is required for a
  multi-operator deployment claim.
- The illustrative entropy callback/test uses deterministic vectors;
  deployed secrets, tokens and epochs require real CSPRNG and unshared
  physical key custody. Passing a signed caller key is not authentication;
  the original transport must authenticate it first.
- The local SQLite test observes a process exit, not a storage-device
  power loss, torn sectors, delayed fsync controller behavior or network
  partition. Crash honesty and durability require a real fault lab.
- A grant still costs the receiver HMAC, RNG, SQLite fsync, memory, disk
  and W1 CPU. Hashcash CPU/GPU/ASIC prices and honest latency are not
  economically qualified. SQLite performance may itself harm throughput.
  A finite capacity may deny honest work under paid Sybil saturation.
- No logic is connected to V3 Cookie and no public service/native
  Rust verification path has adopted this schema. Creating a second
  service budget from this prototype would be a security regression.
- All original P0/P1/P2/P3/A03 P4/P5/P6 gates remain independent,
  including physical host fairness, the 3 modes × 3 runs × 3 on-time
  confirmations requirement, a *sound* and low-cost complete W2 proof
  and an external independent cryptographic audit.

Status: SHADOW_ONLY / HOLD_NO_GO; production remains disabled.
