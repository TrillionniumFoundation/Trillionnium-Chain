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

## P2 matched-cost negative experiment on the committed reference code

The separate executable
'formal/pon-nakamoto-v1/w2c_durable_costs.py' records **all**
producer misses until each honest work winner, then uses precisely the
same 318-byte synthetic header, challenge, target, zero A/B and task for
a from-zero bogus W1 trace. It compares W1 success and complete false
rejection with receiver-bound W2-C tickets and real durable SQLite
consumption, including hash attempts and exhaustion. No task substitution,
reused valid proof or fabricated CPU reading pays for a false W1 producer.

Run manually with one new exclusive path:

    python3 formal/pon-nakamoto-v1/w2c_durable_costs.py \
      --samples 3 --bits 8 12 \
      --out /unique/new/w2c-durable-matched-costs.json

An executed current-turn Python-only three-seed cost cohort (same underlying
W1 challenge/target within each seed) reported:

| Arm | Measured process CPU ms / attempts | Scope |
| --- | --- | --- |
| Honest complete W1 search (3 seeds) | 74.58 / 151.75 / 213.23 ms | all attempted genuine W1 candidates, including target misses |
| Honest complete W1 verification | 72.52 / 76.70 / 80.35 ms | raw independent Python verification |
| From-zero fake W1 search | 0.032 / 0.026 / 0.033 ms | public canonical material + hash trial search, no valid W1 generated |
| False W1 complete rejection | 76.03 / 75.89 / 80.45 ms | all cases refused TRANSCRIPT |
| W2-C durable 8-bit search + paid insert | 0.891 / 0.776 / 2.798 ms | trials 275 / 243 / 981, plus one original SQLite commit |
| W2-C durable 12-bit search + paid insert | 11.877 / 57.939 / 0.819 ms | trials 4514 / 14749 / 267, plus one original SQLite commit |

Cold SQLite epoch initialization cost was separately observed as approximately
1.58–2.97 ms; the recorded paid-insert CPU alone was 0.14–0.502 ms.
These are different resource phases; they cannot be silently omitted or
added twice to nested timing intervals. The raw JSON was retained with SHA256
'c4d16de1ed3ef0ad5cb39f6e43968848e104d7d202f2601cbabf98ef3be67cca'
(7,085 bytes). Exact committed benchmark source Git blob SHA-1:
'4a77f02b57d0edf45a4861c76610a9e32268eb0b'.

**Negative result:** on this Python host and small finite cohort, even a
receiver-bound 12-bit ticket often costs less CPU than one full false W1
rejection. Hardware/grinding advantage may be much worse on GPU/ASIC.
Per-receiver cost ownership and durable one-use semantics are not
sufficient to close P2 economic anti-amplification. No preferred production
difficulty, Node throughput or public readiness is inferred from these
synthetic Python costs.

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
