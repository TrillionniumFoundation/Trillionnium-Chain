# W2-C receiver-bound admission cost: research-only adversarial prototype

Status: **prototype, not public transport or consensus**. Derived from Chain PR #335
source 'db0dad68f0909460e8b1cf0c248d8bab4b59c129'.
No modification to W1, PNW1 ticket, block format, target/chainwork, V3 Cookie,
Genesis, final-use or production flags.

## Measured problem and distinction

The existing 'w2c_separated_security_pow.py' research method binds a global
Header and full PNW1 proof. Its valid Hashcash nonce is transferable to other
receivers. Two independent validators can each be driven into a full W1
TRANSCRIPT rejection after the attacker solved only **one** ticket.

The local alternative in 'formal/pon-nakamoto-v1/w2c_receiver_admission.py'
requires one **separate** cost ticket per independent receiver:

- An issuer-local 32-byte secret and 32-byte process epoch authenticate a
  bounded grant with HMAC-SHA256. The grant binds a receiver id, complete
  W2-C proposal digest (which includes 318-byte header and entire original
  49,188-byte PNW1), unique 32-byte server token, bits and 100–2000ms
  validity. Its verifier requires an actual issue record.
- Search uses 'H(w2c-local-admission-v1, canonical grant, MAC, LE64 nonce)';
  a successful research ticket has 8..24 leading zero bits.
  No W1 valid-work capability is created by that search.
- The token table is bounded 1..1024 and guarded by a single lock.
  A grant is atomically spent **before** passing control to W1; an invalid
  W1 relation never refunds its ticket. The live token cannot be evicted
  to manufacture a fresh admission entitlement. At capacity, new issuance
  returns local BUSY, never a consensus-invalid decision.
- Receiver mismatch, old process epoch, proposal/body mismatch, bad MAC,
  expiry, clock regression, target miss, token reuse and exact replay are
  refused before any invocation of W1. The research caller supplies a
  **trusted monotonic millisecond clock** and an unpredictable secret/epoch.
  Replacing these with client-controlled time or cloned host credentials
  invalidates this claim.
- This is a standalone, research-only mechanism **separate from** the
  already deployed development V3 Cookie. It is NOT another production
  listener, consensus fallback, protected identity or a reason to double-charge
  current V3 requests.

## Exact negative selectors and local evaluation

    python3 formal/pon-nakamoto-v1/test_w2c_receiver_admission.py -v
    python3 formal/pon-nakamoto-v1/w2c_receiver_admission_cost.py \
      --bits 8 12 --cap 65536 --out /new/unique/w2c-receiver-cost.json

The first selector includes eight cases: independent receivers,
same-grant 32-way concurrency (exactly 1 READY, 31 REPLAY), tampering,
epoch/restart, expiration and monotonic clock, bad ticket, capacity, strict
inputs and an actual independent Python W1 false-TRANSCRIPT rejection.
The second runs an identical Header/Challenge/Task/false-PNW1 claim against two
synthetic receiver identities and records all ticket attempts, actual
Python process CPU, W1 full rejection CPU and zero chainwork.

One local scratch sample on 2026-10-25 gave:

| Research bits | Receiver | Hash attempts | Ticket-search CPU ms | Full false W1 reject CPU ms |
| --- | --- | ---: | ---: | ---: |
| 8 | A | 495 | 1.273 | 83.292 |
| 8 | B | 70 | 0.382 | 88.273 |
| 12 | A | 671 | 1.761 | 84.928 |
| 12 | B | 3663 | 10.201 | 86.569 |

These numbers are **single synthetic Python-run samples**, not source-attested
Rust V3 costs, hardware-wide attacker budgets, GPU/ASIC prices or evidence of
new W1 difficulty. The attacker still buys a cheap locally valid ticket which
triggers expensive W1 verification at its selected receiver. Receiver binding
removes cost *transfer* between honest independent hosts under the declared
secret/epoch assumption; **it does not eliminate local cost amplification or
the finite-listener/issuance DoS problem**. The bounded pending grant table
can itself be exhausted by unpaid senders without an earlier front-door limit.

## Remaining mandatory P0–P6 blockers

- P0: actual Rust Node and wire-format four-forgery regression and original
  historical evidence are independently preserved on PR #335, not closed by
  this research.
- P1: all externally reachable V2/V3/authenticated/p2p/sync paths must
  demonstrate one genuine host-wide resource owner under actual attack and
  process restart, with no loopback forwarding bypass.
- P2: signed V3 Cookie costs, attack CPU/GPU hash rates, honest admission
  burden, real W1 replay CPU and full network traffic require fresh, matched
  measurements. No fixed 8/12/16/20-bit recommendation follows here.
- P3: repeated identities, copied/synthetic tickets, authentic signed valid-W1
  bad-StateRoot traffic, fair read/submit concurrency, and restart must be
  tested against the original native Node owner.
- P4: original A03 three modes × three runs × three timely confirmations,
  including failed/Busy/timeouts and real aggregate CPU ownership; no mock
  report can close this requirement.
- P5: W2-A remains unsound sampling, W2-B has no succinct proof, W2-C's
  receiver-localized ticket still lacks acceptable matched GPU, latency,
  cryptographic security and honest-cost evidence; W1's *valid* mining
  difficulty is a separate unproven requirement.
- P6: independent third-party cryptanalysis and independent verification,
  real deployment/upgrade/fork-choice rules and explicit authorization are
  missing. Internal Python/Go/Rust agreement is not external acceptance.

W2-C admission research must NOT be advertised as a decentralized consensus
safety theorem. Until these gates close, continue to deny production PoN
activation.


## W2-C stateless issuance and paid-only replay ownership (2026-10-26)

The earlier `ReceiverAdmission.offer` reserves a finite server-side row
**before** a client pays any Hashcash cost. An unsigned request flood could
fill all pending issuance slots without earning even an admission ticket.
The new **separate** research-only candidate
`formal/pon-nakamoto-v1/w2c_stateless_receiver.py` does not allocate any
issue record. Every offer returns a short-lived HMAC-authenticated grant
bound to receiver, unique process epoch, original proposal bytes **and
authenticated caller identity**, and a server-generated token. Upstream
authentication of the caller is an explicit assumption; caller-provided keys
alone are not identities.

Only a ticket that passes its declared 8..24-bit target consumes a row
in the bounded original receiver's local `spent` map, under one mutex,
before it could request full W1 verification. Failed W1 never refunds that
row. Spent-capacity exhaustion returns a *local* `PAID_CAPACITY_BUSY`
without entering W1 and is not consensus-invalid work. Expiration frees
old rows. No valid ticket can construct VerifiedWork, Chainwork or Model
authority. This is NOT wired into V3, and cannot replace the existing
signed original Cookie without its own versioned network/profile review.

Run exact existing-Python-oracle controls:

    python3 formal/pon-nakamoto-v1/test_w2c_stateless_receiver.py -v

The ten tests cover 4,096 independent UNPAID grants with zero stored
spent entries, thirty-two simultaneous identical paid submissions
(exactly one READY and thirty-one REPLAY), full paid-slot refusal and
expiry recovery, caller and proposal binding, cross-receiver and new
epoch failure, HMAC/nonce/field tampering, clock regression, and actual
W1 fake transcript rejected after paid resource admission.

In the 2026-10-26 scratch environment, the exact committed Python
source blobs `8a800f526bbcfddb3308a1966fc4c406ee29c5d0` and
`55c0e8a3dee0d25999f9ea259545e1d6b8c332d3` were independently
copied, checked against Git object blob identity and executed with the
original 2,944-byte Python W1 oracle blob
`9cbfccd2d50af48fc43522b967ffdfb1f45ec098`.
Result: **10/10 tests PASS**, approximately 0.12 seconds of local
Python wall time. The stateless candidate's `Grant` and `ticket`
dependencies used the corresponding original W2-C semantics (not a
production V3 transport replay). This is local testing only, not physical
operator evidence, Rust native verification, Hashcash economic hardness,
A03, P5 soundness or P6 third-party review.

**Deliberately retained red-team failure**: restarting with a cloned
receiver key AND the same Epoch silently recreates an empty spent map,
and an old ticket can once again return READY. The test explicitly
demonstrates this double-admission; **there is no safe-restart claim**.
An independently fresh unshared epoch, or a durable shared spent owner
with enforced uniqueness across all replicas, is a mandatory deployment
property. Even secure epoch rotation does not prove crash debt settlement,
CPU cost equivalence or fair service.

**Residual anonymous DoS**: Offer is now O(1) memory, but many unpaid
offers still cost RNG, HMAC, serialization and network bandwidth. Existing
V3 global connection, issuance and CPU resource owners remain required;
this experiment does not replace them. An attacker with a faster SHA-256
device can still earn a cheap locally accepted Hashcash ticket and force
costly full W1 replay. Thus **P2–P6 remain OPEN**, and production
activation stays disabled.


## 2026-10-26: receiver-enforced research cost floor

The research prototype previously accepted any caller-selected 8..24-bit
cost in 'StatelessReceiverAdmission.offer'. A valid grant authenticated its
own bit count, but the receiver had no separately pinned minimum service cost:
a sender could always choose 8-bit work even when an operator intended a
more expensive protection policy. The MAC on a weak grant does not prove
the receiver's current pricing rule.

The new optional, typed 'minimum_bits' constructor setting defaults to
the old 8-bit research behavior for existing vectors, with a monotonic
'raise_minimum_bits(bits)' API. Under the existing single internal lock:

- Signing a grant below the current floor raises 'PRICE_POLICY' without
  consuming a paid slot.
- A previously MAC-valid low-bit grant remains subject to the *current*
  server floor at consume time and receives 'PRICE_POLICY' before any full
  W1 validation or paid replay slot.
- A simultaneous price decrease in the same receiver epoch is refused
  ('PRICE_ROLLBACK'), so clients cannot revive cheaply issued grants by
  toggling service configuration during that epoch.
- Invalid or tampered grant MACs must still fail 'GRANT_MAC' before the
  pricing verdict. The original exact caller/body/receiver/epoch context,
  expiry, target and one-use behavior remain unchanged.
- New test selectors cover caller key rotation, old grants after raising
  the floor, monotone rules, bit bounds, unpaid-capacity invariants and
  forged MACs. They do NOT claim native/Host CPU qualification.

This **does not** determine the correct numeric floor. Hashcash has huge
CPU/GPU/ASIC performance variability, and even high difficulty can cost
much less than full W1 verification, especially when a bogus proof reaches
multiple processes, aliases or compatible receivers. Selecting a production
price requires actual per-hardware adversarial measurement and independent
review under the original P2/P4 gates.

A restart with copied secret+epoch and lost paid-grant history can still
replay a paid ticket; the existing negative regression retains that
failure. The floor is not a durable ledger or a consensus fork-choice rule.
Production remains HOLD_NO_GO.
