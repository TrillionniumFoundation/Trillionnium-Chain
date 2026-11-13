# W2-C durable one-use spend gate: research-only

Status: **P5 research prototype, not a deployed admission or a consensus proof**.
The exact parent is Chain #403 at
'3d89f80f3c84123d37b0d81cdc5305a4f1572371'.
This module does not write blocks, VerifiedWork, Chainwork, model weights,
execution authorizations, cookies, genesis or fork-choice.

## Why the local volatile gate is insufficient

A W2-C MAC proves what the issuer signed but cannot attest whether a ticket
has already been spent. If the process restarts with the **same** server
secret/epoch but a fresh empty in-memory spent set, an earlier still-valid
paid ticket may trigger a second expensive W1 replay. This is a real
counterexample to calling a stateless ticket "single use". A new unshared
epoch prevents one form of replay but can be undermined by VM cloning or
snapshot restoration with shared cryptographic credentials.

'formal/pon-nakamoto-v1/w2c_durable_spend.py' is a separate, optional
'DurableSpendGate' research prototype that uses one administrator-owned
local SQLite database as the ONE consumed-ticket owner:

- It authenticates the exact signed receiver/epoch/caller/proposal/token,
  original lifetime and Hashcash ticket. Neither issuer identity nor
  packet bytes create W1 acceptance; 'READY_RESOURCE_ONLY' is only local
  permission to proceed to another independently verified relation.
- A SQLite 'BEGIN IMMEDIATE' transaction validates the **stored** current
  minimum bit-price, monotonic trusted input clock, original capacity and
  original TTL; it writes the exact spent-key under PRIMARY KEY before
  returning READY. Separate processes opening the **same database** serialize
  the spend. The original W1 verifier is not called by this module.
- 'journal_mode=DELETE', 'synchronous=FULL' and synchronous transaction
  completion are configured. Database errors abort rather than returning
  READY. This is a best-effort local filesystem durability property,
  not a guarantee against a lying storage device/power-loss sequence.
- Original 'capacity' and 'lifetime_ms' must match the on-disk policy on
  every reopen, so creating another consumer cannot increase capacity or
  prolong paid admission. 'minimum_bits' may be raised but not lowered;
  the current floor survives process restart and rejects older cheap grants.
- Expired entries are removed only under the same transaction after the
  trusted clock advances. A clock regression raises a local operational
  failure; it is never silently converted to zero elapsed CPU or
  consensus-invalid work.
- A preexisting symlink, hardlink, nonregular database or world/group
  accessible database is refused. The enclosing parent directory must
  already be administrator-controlled: Python's pathname checks are not
  a race-free protection against malicious concurrent filesystem actors.

## Executable controls and actual experiment scope

Run from the repository root:

    python3 formal/pon-nakamoto-v1/test_w2c_durable_spend.py -v

The nine test cases cover: crash/reopen replay, 32 parallel consumes through
two independent SQLite handles (exactly one READY), price rise and downgrade
across reopen, tampered MAC/changed caller, real bounded capacity, trusted
clock regression/expiry, attempted capacity/TTL widening after restart,
secret/epoch mismatch, and symlink/hardlink denial.

A local isolated Python 3.13.5 evaluation ran those exact new module/test
file bytes and passed **9/9** tests. The supporting preexisting H and Grant
interfaces were reconstructed with protocol-matching development stubs in
that isolated work directory; this is not a full checked-out Chain run,
independent native Go/Rust consensus comparison, or externally attested
execution. The Git Blob identities of both added remote files match those
used in the local run.

**Mandatory negative control: copied-state attack.** A test explicitly
duplicates the same SQLite database *before* consuming a ticket. Two
independent copies subsequently both return READY for the same correctly
signed grant. This is a PASSED negative test of an **unresolved security
failure**, not a proof of distributed replay resistance. Protecting against
rollback/cloned hosting requires a separately trusted monotonic owner,
external consensus/attestation, or provider-specific isolation, with
corresponding failure and migration evidence.

## Production and P0–P6 blockers remain OPEN

The new durable gate is NOT wired into V3 (which already has its distinct
one-use Cookie and original CPU domain), and must not silently create a new
signed profile, double charge a caller, or provide final-use authority.
Pricing still requires same-host CPU/GPU/ASIC costs of cheapest fake proof,
honest requests, parallel listeners and real attack ratios.

P1 complete origin/loopback/Host ownership, P2 actual economic cost
calibration, P3 true hostile mixed traffic, P4 original A03 three modes
x three runs x three timely confirmations, P5 sound/efficient full W2
mathematical proof and P6 independent third-party cryptographic acceptance
are all unsatisfied by this source. Production activation stays FALSE /
HOLD_NO_GO. Do not merge this experiment as a hardened admission service.
