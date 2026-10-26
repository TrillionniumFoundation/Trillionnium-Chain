# W2-C durable paid replay experiment — P5 research, NOT consensus

Candidate parent: Chain PR #339 source
'2787ad3959359bc5377d982a7ab46a2d76d44e0e'.
This is an isolated research module. It has NO V3 listener, W1 format,
new Genesis, consensus retarget/fork choice, chainwork or model Final-use
authority. Explicit public-activation status remains FALSE.

## Concrete counterexample being reduced

Earlier 'w2c_stateless_receiver.py' binds a ticket to one signed Epoch but
keeps the spent map only in memory. Restarting with **the same secret and
the same Epoch** recreates empty spent state; a paid ticket can enter W1
again. This is a local crash/restart replay problem, separate from the
globally transferable W2-C original ticket.

'formal/pon-nakamoto-v1/w2c_durable_receiver.py' adds a separate
same-host owner with:

1. An already operator-owned 0700 private directory, 0600 regular SQLite
   database and 0600 lockfile; reject symlinks/hardlinks/insecure
   permissions and zero secrets. One lifetime-held advisory
   flock(LOCK_EX|LOCK_NB) guards concurrent instances on the same OS
   filesystem. This does not provide multi-host exclusion.
2. A SQLite metadata row containing a hash of receiver/credential, a
   monotonically incremented generation and fresh 32-byte process Epoch.
   A new Epoch is synchronously committed with full SQLite DELETE-journal
   durability and parent-directory fsync before issuing any grant.
   Cloned old receiver keys do not make an old Epoch valid on restart
   of the same durable owner. The caller must use secure independent RNG.
3. Stateless MAC grant issuance, bound to receiver, Epoch, authenticated
   caller, exact proposal, token, bits and 100–2000ms lifetime. An
   authenticated caller identity and monotonic trusted now_ms remain
   caller-supplied, NOT established by this research module.
4. One BEGIN IMMEDIATE SQLite transaction per passing-cost ticket,
   atomically deleting expired rows, checking replay and finite capacity,
   writing a grant digest once and COMMITting before returning
   READY_RESOURCE_ONLY. A failed DB transaction cannot return READY;
   the live in-memory RLock also linearizes threads.
5. No refund when actual subsequent W1 work rejects or requester drops.
   PAID_CAPACITY_BUSY is a local resource refusal, not an invalid
   chain proof. Every W1 proof still requires complete independent
   verification and cannot gain VerifiedWork through this module.
6. Old epoch spent entries are pruned when the new epoch is committed.
   There is no permanent monetary/spend historical audit ledger; an
   external durable owner remains required to reconcile actual service
   costs or after-crash unknown operations.

## Exact negative regression to execute locally

    python3 formal/pon-nakamoto-v1/test_w2c_durable_receiver.py -v

Nine cases test the following claims on a trusted Linux owner:

| Case | Required result |
| --- | --- |
| 32 simultaneous identical paid tickets | Exactly one READY, 31 REPLAY |
| Same key and repeated deterministic RNG sequence after restart | Old Epoch rejected, new Epoch payable |
| Second simultaneous same-directory owner | Exclusive lock rejects before issuing grants |
| Wrong key on historical directory | Refuses credential change |
| Insecure directory / stored DB file permissions | Refuses without entering W1 |
| Injected SQLite INSERT failure | No READY, transaction rolls back, retry only after repair |
| Paid capacity/expiry | Capacity cannot be overwritten; expiry can reclaim under same owner |
| Caller/proposal/MAC/clock regression mutation | Strict refusal |
| Real independent Python W1 arithmetic on fabricated transcript | TRANSCRIPT error after paid cost, no VerifiedWork |

Tests exercise a developer-owned temporary SQLite filesystem, not raw
power-cut/cgroup physical host evidence. A new signed transcript is not
made valid by proof of admission cost.

## Remaining limitations that prohibit P0–P6 graduation

- Crash/replay: an owner with copied credentials, a cloned VM/network
  namespace and independent writable replicas can still issue two
  different service lineages. SQLite locking is only same-host. An
  untrusted identical root filesystem snapshot can reset history; epoch
  uniqueness also requires trustworthy entropy, physical host identity,
  secret custody, storage durability and secure time.
- Amplification: even 16/24-bit SHA-256 search may be much cheaper on
  GPU/ASIC than complete W1 matrix transcript replay. Valid paid grants
  may be forwarded as W1 service requests, and legitimate spending cannot
  establish economic hardness or fair resource access.
- Front-door DoS: stateless grants still consume RNG/HMAC/network CPU,
  and a fully paid attacker can saturate the finite pending budget.
  Existing V3 CPU/memory/worker/read-reserve gates are independent.
- Native verification: exact Rust source, full owner cancellation,
  per-scoped-worker CPU, multi-process crash/cgroup, packet and State-root
  accounting, saved raw CPU evidence and three A03 multi-host honest
  confirmation runs have not been produced by this Python-only candidate.
- Proof theory: W2-A is unsound sampled arithmetic; W2-B is a full
  witness, not a succinct sound proof; W2-C is extra separate Hashcash,
  not useful-work hardness. Independent external cryptographic
  cryptanalysis, multi-language validation and consensus-version
  upgrade/reorg authorization are still absent.

This document neither changes the existing signed V3 Cookie nor asserts
a new deployment policy. Status remains SHADOW_ONLY / HOLD_NO_GO.
