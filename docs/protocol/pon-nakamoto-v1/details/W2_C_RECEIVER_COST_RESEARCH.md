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


## Bounded total issue count across the receiver epoch (new child research)

The receiver-scoped prototype also enforces a strict
'epoch_issue_limit' (default 4096; constructor bounds 1..65536), in addition
to 'capacity' (1..1024) for currently retained unexpired grants.
'issued_total' is monotonically incremented only for actually issued grants
and is **never** refunded by token use, rejection, caller identity rotation,
expiry or in-process reopening of issuance. After the finite count is reached
new requests receive local BUSY even if there are zero live grants.
Two additional unit tests exercise consumption + expiry + identity rotation
and invalid constructor values.

This is **not** a solution to an adversarial issuance flood: exhausting
the lifetime issue allowance can deny every subsequent honest requester.
An attacker can also restart/clone its own research issuer if it holds the
same authority, and upstream acceptance of a remote issuer must not treat a
fresh epoch as a legitimate refund. A true public issuer needs externally
controlled process epochs, actual Host CPU/connection guards, bounded issuance
work and measured honest-service fairness. No proof/ledger/production
authority is created or activated by this monotonically bounded counter.
