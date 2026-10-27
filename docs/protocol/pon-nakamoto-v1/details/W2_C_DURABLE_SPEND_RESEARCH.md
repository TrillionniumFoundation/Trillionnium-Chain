# W2-C local durable paid-spend owner (research only)

Status: **experimental / no W1, Cookie, consensus or production activation**.
Developed on the three-parent integration candidate of Chain #444. Do not
identify this as a network upgrade or a replacement for its deployed V3 Cookie.

## Adversarial motivation

The original stateless receiver-side W2-C prototype needs a per-epoch spent
record, otherwise one already paid Hashcash nonce can drive repeated expensive
W1 rejection after a restart. The negative control intentionally re-instantiates
a receiver with the **same key and same epoch, but an empty in-memory spent map**;
it accepts an already spent ticket again.

The additive `formal/pon-nakamoto-v1/w2c_durable_spend.py` implements a
**single-local-store** crash-persistent replay fence. It does not remove W1's
cheap forged-trace / full-replay cost imbalance.

## Exact local authority and timing

- A pre-provisioned, absolute local SQLite file in a private, same-owner
  directory binds the receiver, secret digest, epoch and externally attested
  boot context. Existing files must be private regular single-link files;
  symlinks and writable parent directories are refused.
- SQLite WAL and `synchronous=FULL` retain an original durable authority row,
  schema-version check, monotonic consumed clock and a unique key per MACed
  grant. `BEGIN IMMEDIATE` serializes successful spends from different
  connections and **different local processes**.
- Grants still come from the bounded, stateless W2-C research issuer.
  The caller identity must already be authenticated by a separate upstream
  transport. Only a correctly signed grant, canonical matching context,
  valid nonce, exact TTL and paid Hashcash ticket may reach SQLite's spent
  transaction.
- The spent key commits before `READY_RESOURCE_ONLY`. An erroneous W1
  transcript, application refusal, cancellation or loss of the caller afterward
  does **not** refund or reverse this paid fact.
- A full paid ledger rejects exact retransmissions even if another nonce for
  the same grant passes the target. Expired entries can be collected only
  after the signed grant can no longer be accepted. Bounded full capacity
  produces `PAID_CAPACITY_BUSY` (a local resource refusal, not a consensus
  invalidity claim).
- SQLite open, damaged authority, clock regression, unexpected schema or
  lost storage always fail closed. A lost connection's failed ROLLBACK must
  not hide the typed `DURABLE_RESOURCE_UNAVAILABLE` error.
- Success does not create `VerifiedWork`, block reward, Chainwork,
  model-adoption authorization, runtime authority, or evidence that a
  claim actually contains valid useful work.

## Executable negative controls

    python3 formal/pon-nakamoto-v1/test_w2c_durable_spend.py -v

The original repository-truth entry includes this selector, but a source
commit or test declaration is not proof of an executed test. Checks cover:
reopen with same epoch, multiple independent SQLite connections and actual
separate OS processes racing one spent key; child process hard exit **after**
a committed READY, followed by a fresh owner rejecting the old ticket;
different secret/epoch/boot, target misses and changed caller; cloned
storage **snapshot** counterexample; schema/path/symlink permissions; paid
capacity/expiry, stored-clock regression and an actual independent Python
W1 `TRANSCRIPT` rejection after the research payment.

The hard-exit test is NOT a physical power-loss/fsync/controller experiment.
SQLite's documented durability and actual OS/file-system assumptions still
require a real Host fault campaign.

## Deliberately unresolved cryptographic/system gaps

1. A copy of the database **before** a spend, coupled to a cloned secret
   and epoch on a different host, can accept the same ticket in two worlds.
   Two independent installations are not one shared durable owner.
   Cross-replica authority requires independently unique receiver epochs,
   key custody and/or replicated consensus for the spent frontier.
2. A rollback of the original durable database to an old snapshot remains
   unsafe if the old secret/epoch is still admitted. OS snapshot, backup,
   restore and crash/recovery trust must be tested. A local SQLite WAL
   transaction alone does not prove anti-rollback across hosts or privileged
   administrators.
3. A locally paid ticket still costs the attacker far less than full W1
   replay at measured Python research difficulties; faster GPU/ASIC search
   can further widen the gap. Authentication, paid records and finite
   memory limits cannot establish permissionless honest fairness.
4. This research DB is an **additional test-only storage owner**, not
   automatically the existing Chain Node/SQLite state, V3 account or
   durable owner journal. It must not be wired to production without a
   unified owner, transaction/recovery semantics, signed profile migration,
   bounded kernel resource enforcement and independent review.
5. P0 exact native negative regression, P1 actual Host-owner path sweep,
   P2 hardware-priced admission, P3 mixed honest/hostile loads,
   original P4/A03 three modes × three runs × three confirmations,
   a sound and efficient P5 work relation, and third-party independent
   P6 security acceptance remain **OPEN**.

Status: SHADOW_ONLY / HOLD_NO_GO.
