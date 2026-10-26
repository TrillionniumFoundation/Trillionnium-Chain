# W2-C research: durable original-owner paid ticket spend

Status: **research-only / SHADOW_ONLY / HOLD_NO_GO**. This candidate is
incremental to the distinct stateless W2-C work in Chain #339 and the W1 P0
work in #335. No existing PNW1, consensus ticket, target, chainwork, BlockId,
V3 signed Cookie, Genesis, Node authority, model final-use or production mode
is changed.

## Counterexample and exact threat boundary

The original stateless, caller-bound W2-C grant only stored a successful
ticket's spent identity in one process's in-memory map. Two workers or
processes running a *cloned receiver secret and Epoch* but independent maps
can each return READY for the exact same validated paid grant. One attacker
can therefore trigger two full W1 replays after one original Hashcash search.
A genuinely new process Epoch prevents old tokens, but its uniqueness
and trusted boot provision were not otherwise enforced.

The new optional `w2c_durable_spent.py::DurablePaidSpendOwner` stores only
**successfully paid** exact grant identities in one private administrator-
controlled SQLite WAL database. Its key is the original stateless W2-C
SHA-256 grant/MAC identity, computed **after** HMAC, authentic caller,
proposal, receiver, Epoch, exact difficulty, lifetime and target pass.
The store has NO public W1/Chainwork/VerifiedWork API and cannot be called
from a hostile network without an already trusted signed-ticket verifier.

* `BEGIN IMMEDIATE` serializes concurrent process writers and a unique
  primary key prevents a second READY. `synchronous=FULL` and commit
  before READY provide database-level durable spend accounting.
  A crash after spend commit but before W1 can lose the user's chance to
  run that request; it must not silently refund it or claim that W1 ran.
* The same file also freezes the *receiver*, *Epoch*, *capacity*,
  *required ticket difficulty*, *lifetime* and *last observed time*. An
  incompatible process cannot replace the original budget owner by
  opening the same path with a new policy. A real monotonic clock going
  backwards refuses new READY; a concurrent request that sampled time
  before the database lock may be conservatively denied.
* The original stateless issuer now accepts optional `spent_owner` and
  requires the exact shared receiver/Epoch/capacity/difficulty/lifetime.
  Default in-memory mode remains an explicitly unqualified research path.
  A receiver created with 16-bit policy cannot issue or consume an 8-bit
  grant simply because a caller asks to.
* Entries are bounded at 1..1024 and expire only after trusted time
  advances. At capacity, PAID_CAPACITY_BUSY is an *operational* refusal,
  never an invalid W1 verdict or negative cumulative work.
* The database path must be absolute, its immediate/ancestor path
  canonical, its parent a private owned 0700 directory, and its file a
  single-link private owned regular 0600 file. O_NOFOLLOW and
  O_CLOEXEC are mandatory on the supported local OS. SQLite I/O/lock
  failures, corrupt schema, wrong context and unsafe file ownership
  produce OwnerUnavailable, **not READY**. WAL/SHM sidecars remain inside
  the private parent. Same-UID or administrator filesystem compromise
  is outside this prototype's protection.

## Exact source and tests

The following four committed Git blobs were independently copied into the
local Python test harness and checked with `git hash-object` against GitHub:

| Module | Git blob |
| --- | --- |
| `w2c_durable_spent.py` | `ea04a117717956911b7d0667b016670d57dd86c7` |
| `w2c_stateless_receiver.py` | `1db98af8b9a77c47e08d2b588cb0cc4c15dc1330` |
| `test_w2c_durable_spent.py` | `40252ee6847422b026c8354380be2f22e576777b` |
| `test_w2c_durable_integration.py` | `140d7ac97022082aaf8465c17505f0d3af16ff1a` |

Execute from repository root, independently of GitHub CI:

    python3 -W error::ResourceWarning -m unittest discover \
      -s formal/pon-nakamoto-v1 \
      -p 'test_w2c_durable_*.py' -v

The checked local run completed **14/14 tests**. Cases cover 24 actual
independent Python processes competing for one paid-grant identity (exactly
one READY, 23 REPLAY, using a fixed trusted timestamp), clone-restart
replay, persisted clock regression, invalid receiver/Epoch/policy and
capacity, bounded expiry recovery, corrupt database, symlink or unsafe
parent, strict expiry overflow, persistent owner failure before work,
and 8-bit downgrade attempts against a 16-bit issuer. The follow-up
controls also abruptly exit the paid process after COMMIT, reopen the same
journal and require REPLAY; a *separate* database with the same secret/Epoch
is intentionally shown to double-accept the same grant. This last result is
a negative cross-host counterexample, **not** evidence of global uniqueness. The test harness
uses the same canonical H and grant/ticket bytes, but a locally extracted
minimal reference of `contract_wire` / `w2c_receiver_admission`, **not
an exact source checkout or all repository dependencies**. Tests in the
actual repository must also run before any source qualification.

The existing research unit suite and the two durable selectors were added
to the normal repository-truth test *script*, without weakening original
required checks. Their presence is not a claim that a GitHub workflow ran.

## Remaining and newly exposed blockers

- **P0:** New four-transcript W1 Rust Node/independent oracle proof regression
  still needs exact-source native execution and raw preserved evidence.
- **P1:** Shared durable W2-C admission memory is *not* shared V3 CPU
  scheduling or a cgroup physical Host proof. Pinned-peer, direct sync,
  loopback forwarding, multi-process Host CPU, restarted debt, honest
  admission and throughput still need real resource control qualification.
- **P2/P3:** Receiver-local hashcost may still be tiny relative to W1
  replay. GPU/ASIC asymmetry, online random challenges, original signed
  V3 Cookie cost and malicious valid-W1/false-StateRoot pressure remain open.
- **P4:** No new exact-source A03 3 modes × 3 runs × 3/3 timely confirmations.
  All failures, CPU counters, unfair delay and censored windows must remain
  in the preregistered verdict.
- **P5:** Existing W2-A sampled Merkle filter is unsound, W2-B is a full
  replay witness not succinct proof, and W2-C merely shifts extra
  non-neural work. No fully qualified new PoN proof relation.
- **P6:** There is NO external independent cryptography audit, physically
  independent operator, governed protocol activation or valid public WAN
  security receipt.

**Critical adversarial counterexample remains:** independent replicas that
use the same secret and Epoch but different database files, or a cloned
pre-spend snapshot of the same database, can still issue a second READY.
Only a non-copyable single-writer ownership protocol with authenticated
anti-rollback evidence (or truly fresh and independently enforced Epoch
identities) could close the cross-host replay problem. SQLite on one local
filesystem cannot provide that guarantee.

The kernel, transport and mining runtime still use their original signed
profiles and no production W2-C admission is enabled.


## Local admission overhead observation, not native cost acceptance

An additional nonexclusive Python-only trial on 2026-10-26 reused twenty
identical pre-solved, valid 8-bit receiver-local W2-C grants and caller
identities with the two existing research implementations. Each admitted
twenty unique grants and rejected the exact twenty later replays; the original
Hashcash searches, host context, W1 transcript, network, V3 signatures,
storage provisioning and any physical GPU costs are **outside** these
per-spend measurements. The run executed the memory arm first, then the
SQLite arm, so warm caches, process contention and ordering were not
controlled. Its preliminary paired medians were:

| Local research-only arm | Median per-grant wall | Median process CPU |
| --- | ---: | ---: |
| Volatile in-memory spent map | 0.010 ms | 0.010 ms |
| SQLite WAL + synchronous FULL original owner | 2.414 ms | 0.736 ms |

These are exploratory readings from one scratch run, not statistically
qualified Rust or WAN measurements and not the minimum durable transaction
cost. The SQLite configuration is deliberately durability-conservative;
simply changing synchronous mode, removing commit-before-READY, or faking
a zero-cost journal would silently reopen the crash/replay bug. The
per-grant storage latency must be included in any genuine P2 end-to-end
admission price and P4 honest-service SLA. Deployment cannot infer that
persistence is free or that the 8-bit/hashcash attacker economically pays
for the verified W1 CPU.
