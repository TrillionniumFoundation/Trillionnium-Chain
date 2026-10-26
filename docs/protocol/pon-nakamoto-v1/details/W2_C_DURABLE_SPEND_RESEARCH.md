# W2-C durable paid-spend owner: exact shared-DB research

**Status:** isolated research only. No W1/PNW1, Hashcash target, consensus,
chainwork, V3 Cookie, Node ledger, model authority or production activation
has been changed. Parent source: Chain #339
'2787ad3959359bc5377d982a7ab46a2d76d44e0e'.

## Why this exists

The earlier 'w2c_stateless_receiver.py' removes unpaid issuance rows
but retains paid replay decisions in one process's volatile dictionary.
It deliberately shows a clone with the same key and epoch (empty spent
dict) can re-present the same ticket as fresh resource admission.
Authentication, a new peer signing key or a paid SHA-256 ticket **does not**
make such a restart safe.

The research module 'formal/pon-nakamoto-v1/w2c_durable_receiver.py'
uses the *same existing* W2-C grant byte grammar and ticket rules
for a separate proof-of-spend storage experiment. It adds:

1. A single trusted absolute-path SQLite WAL owner, with 'synchronous=FULL'
   and a bounded paid-ticket table. An externally created service process
   must have access to the **identical original DB**, not a fresh DB.
2. Explicit service startup mode. 'rotate' atomically advances the epoch
   and clears old paid entries; trusted same-service workers may 'join'
   the exact existing epoch without minting new paid credit. A stale
   process cannot issue or consume under its old epoch. Epoch equality,
   original receiver and 32-byte secret fingerprint are checked within
   the same DB transaction before a successful paid operation.
3. HMAC-SHA256 bound to exact receiver, process epoch, authenticated
   caller digest, proposal, token, difficulty and expiry. The original
   grant/ticket validation is required before the durable paid operation.
4. 'BEGIN IMMEDIATE' serializes cross-**process** paid-slot reservation;
   committed paid IDs cannot be spent twice. A successful transaction
   is committed to durable storage **before** the return of
   'READY_RESOURCE_ONLY'; error/no DB availability can never
   substitute an accepted cost ticket or create VerifiedWork.
5. A finite 'capacity' (1..1024), no allocation per **unpaid** grant,
   expiry-based recycling under a trusted monotonic millisecond clock,
   explicit rollback rejection, original proposal/caller binding and
   strict typed errors for remaining invalid admissions. Accepted CPU
   work itself is **not** measured or refunded here.

### What the tests actually prove

    python3 formal/pon-nakamoto-v1/test_w2c_durable_receiver.py -v

Nine bounded Python tests cover:

- 32 simultaneous submissions across two independent SQLite connections:
  exactly one paid READY and thirty-one REPLAYs.
- Eight **real spawned OS processes** contending for the same one
  paid grant: one READY, seven REPLAY; exactly one durable paid row.
- A separate process executes the paid commit then forcibly exits
  with 'os._exit(0)' before any ACK; the surviving process sees REPLAY.
- Service restart atomically rotates to a distinct epoch; stale
  issuer cannot offer/consume, old grant fails closed.
- Four hundred unpaid grants do **not** allocate any paid entries.
- Paid-slot exhaustion preserves existing entries; expiry and a later
  paid grant restore finite capacity.
- Tampered caller/HMAC/bits/nonce, clock rollback and wrong
  owner key/receiver cannot create new paid authority.
- **Deliberate RED counterexample**: copy the entire SQLite DB along
  with receiver identity, secret and epoch *before consumption* to
  another independent filesystem. Both copies can then accept the
  same old paid ticket once. Local SQLite does not make independent
  DB replicas globally consistent and is not an anti-Sybil theorem.

On 2026-10-26 a local scratch execution of the frozen research source
produced **9/9 test passes** (approximately four seconds, including real
spawned processes). The local scratch dependency shims implement the
documented 'contract_wire.H' and 'Grant/ticket/solve' byte arithmetic,
but that is **not an exact repository checkout or a native Rust run**.
Both research source files were published and their Git blob SHAs
checked against their local executed copies:

- 'w2c_durable_receiver.py' blob:
  '9052b554b0d77f88e25409cc1bccd4c8178adc1c'
- 'test_w2c_durable_receiver.py' blob:
  '50b3a31c86f993ab2beb6403c7e1b926e77f26bc'

Do not relabel this as real multi-node/cross-host acceptance,
cryptographic hardness, or production restart correctness.

## Critical remaining conditions

**Physical single-owner trust:** file ownership, symlink and directory
replacement, filesystem rollback/snapshot restore, WAL atomic durability,
key custody, process start ownership, real monotonic clock and cgroup
membership are **not** attested by Python's SQLite primitive. A cloned
DB/key/epoch still breaks uniqueness, as preserved by the negative test.
Real deployments need one independently controlled monotonic root,
a per-host nonclonable key / attested generation, or a distributed
single-writer quorum with explicit timing/finality assumptions.

**Cost asymmetry:** this only blocks repeat spending. A *new* ticket
passing a cheap hash target can still force a full expensive invalid W1
transcript replay. No credible CPU/GPU/ASIC economic cost floor or
hostile fairness improvement has been proven. Unpaid grant issuance
still costs HMAC/RNG/bandwidth; the original V3 front-door budget is
mandatory.

**Runtime:** No Rust/Node/CLI or V3 code consumes this new module.
The original existing V3 Cookie and original shared CPU owner remain
authoritative for current development service. No new ledger permission,
fork weight or model use is derived from 'READY_RESOURCE_ONLY'.

P0 original native four-trace test, P1 physical host resource owner and
relay-bound remote-sync proofs, P2 matched GPU/CPU cost, P3 full honest
mixed traffic, P4 original A03 3 modes × 3 runs × 3 confirmed rounds,
P5 complete sound economically qualified proof and P6 independent
external cryptanalysis all remain **OPEN**.

Status: SHADOW_ONLY / HOLD_NO_GO; no new activation or merge permission.
