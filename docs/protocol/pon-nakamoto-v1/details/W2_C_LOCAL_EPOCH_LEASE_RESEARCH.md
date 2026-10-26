# W2-C single-host process Epoch lease — research-only containment

Source parent: Chain #339 head
`2787ad3959359bc5377d982a7ab46a2d76d44e0e`.
Status: **not activated; no native W1 or public-V3 protocol change**.

## Problem: duplicate paid grants across cloned process epochs

The preceding stateless issuer correctly avoided allocating admission records
to unpaid callers and bound each paid ticket to a receiver, caller, proposal
and Epoch. A direct counterexample remained: two separately running processes
with copied receiver credentials and the **same Epoch** each owned an empty
spent-ticket table and could both return `READY_RESOURCE_ONLY` for the same
paid ticket. Short TTL and a mutex within one process do not repair this
cross-process double-spend.

The optional `w2c_local_epoch_lease.py` research owner requires an
exclusive original *Linux/POSIX kernel flock* over a deterministic per-receiver
lock file inside a verified private directory. It pins the file inode and
the original directory's identity/permissions; it rejects symlinks, aliases,
wrong owners/modes, hard links and replacement. A live process creates a
fresh random **secret AND Epoch** rather than reading/reusing predecessor
bytes. A forked child closes its inherited lock descriptor without
unlocking its parent's live lease, and its copied Python receiver object
rejects every API access based on the owning PID.

The issuer clock is the process's monotonic OS clock, never an attacker-
provided `now_ms`. Its difficulty policy must be selected by the trusted
owner at construction with `policy_bits=8..24`; a remote requester cannot
downgrade the bits when asking for a grant. The underlying stateless
paid-only replay fence, capacity and HMAC constraints remain unchanged.

The lease is held while the in-process resource admission owner is alive;
it does **not** persist an operation ledger, own W1/M06 or final-use,
prove crash/kill safety for already-running external operations, or turn a
local Hashcash success into verified neural work.

## Local exact-source regression

```sh
python3 formal/pon-nakamoto-v1/test_w2c_local_epoch_lease.py -v
```

The new files have exact published Git blob identities:

| New file | Git blob SHA |
| --- | --- |
| `w2c_local_epoch_lease.py` | `352cf5b9400d347d0e4360d5c381cf8eec6ebf86` |
| `test_w2c_local_epoch_lease.py` | `446e211fda58f0de2e32f7a4c5f75ee2d32f351f` |

The 2026-10-26 scratch execution copied the two new source files
byte-for-byte (Git blob identities rechecked) and ran **8/8 passing tests**
using Python 3.13 on Linux, with function-equivalent local mirrors of
the preexisting W2-C `StatelessReceiverAdmission`,
`Grant`/`solve` and domain-separated `H` dependencies.
This is **not an exact full-repository/preflight or native-Rust run**.

Tests cover two actually separate OS processes contending on the same lock;
fork-duplicated object rejection; replacement file/symlink/wrong mode;
reopen with genuinely fresh Epoch and refused old ticket; one-use paid
nonce replay, closed-owner secret lifetime, live parent/file-mode tampering and fixed
difficulty-policy downgrade. One local fork test emits a Python
multithreaded-fork deprecation warning; it is retained as a process-boundary
limitation rather than hidden.

## Security limits and next qualification

- **Single host only.** No kernel file lock covers separate hosts. An
  attacker who controls root, the issuer's same UID and its lock directory,
  memory snapshot/secret, arbitrary virtual machines or copied file namespace
  can create different locks or clone a supposedly unique epoch. A real
  platform needs administrator-owned immutable namespace or a separately
  durable global Epoch owner and independent operator testing.
- Issuance still costs RNG/HMAC/network work; the finite original V3
  connection/queue/CPU budget is still mandatory and this research object
  is **not** connected to that transport.
- Once `READY_RESOURCE_ONLY` is consumed, the expensive W1 validation
  can still reject after complete replay. Per-receiver Hashcash does not
  establish CPU/GPU/ASIC cost parity or a mathematical proof of genuine work.
- The kernel lease must remain owned until all admitted native operations
  settle; merely releasing it after a successful grant is not a durable
  external-operation barrier.
- The unchanged P0 raw four-proof receipt, P1 physical cgroup/remote
  source budget, P2 complete CPU/GPU admission-cost calibration, P3
  mixed-service attack matrix, P4 original A03 3 modes × 3 runs ×
  3 timely honest confirmations, P5 sound and low-cost complete W2
  proof and P6 **independent** external cryptographic review are all
  OPEN. There is no silent consensus profile promotion.

Status remains `SHADOW_ONLY / HOLD_NO_GO`; W1 block validity,
fork weight, version namespaces and production activation are unchanged.

## Preserved at-fork secret-retention counterexample and correction

A separate Python lifetime review observed that registering the bound
`self._after_fork_child` method via `os.register_at_fork` makes the
process-global callback registry **retain the otherwise closed issuer
object**, including the old secret and Epoch. The pre-fix local weakref
counterexample returned `closed_epoch_object_retained_by_atfork_callback=True`.
Closing its file descriptor alone was not a memory-lifetime fix.

The current implementation registers a function holding only a
`weakref.ref(self)`, then checks whether the issuer is still alive
before safely disowning its FD after Fork. A new test
`test_closed_epoch_owner_and_secret_not_retained_by_global_fork_callback`
now demands garbage collection of the closed issuer. The 2026-10-26
isolated Linux/Python 3.13 harness passed **8/8** tests against
byte-identical new source files. This reduces accidental lifetime
retention but **does not guarantee cryptographic zeroization** of
old Python heap allocations, memory snapshots or external process
copies; the independent P6 review remains open.
