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

## Receiver-owned difficulty policy (incremental research child)

This change closes an additional research-only downgrade hazard in the
first receiver-bound prototype: issuer method `offer(proposal, bits, now)`
originally allowed different difficulties to be issued by the **same**
receiver, and `consume` checked only the signed grant's own bits. If a
remote request could select this field on a later transport adapter,
8-bit grants could bypass an intended 12-bit server cost price while
retaining valid MACs and one-use semantics.

The trusted issuer now pins `bits` on `ReceiverAdmission` construction,
requires exact equality before issuance, and independently checks
`grant.bits == issuer.bits` **after validating its MAC** and before the
Hashcash acceptance check. Research price comparisons instantiate a
separate issuer with the exact requested 8/12-bit policy instead of
changing the same issuer per incoming proposal. A new negative test
builds an otherwise MAC-valid weak grant under the same receiver secret
and epoch, finds a genuine 8-bit ticket, and expects `BITS_POLICY`
with the original unspent record unchanged. The deterministic test
ticket finds its first winning nonce at 485.

This is NOT a cryptographic defense against compromised issuer policy
code or an approved V3 policy change. The original V3 signed profile,
W1 and all consensus state stay unchanged. CPU/GPU economic adequacy,
unpaid issuance capacity, physically independent hosts, native
integration, and third-party crypto review remain open.


## P5 independent stateless-offer alternative (2026-10-26)

The original receiver research prototype stores a pending entry *at offer*,
even if the requester does no Hashcash work. Consequently a burst of at most
\`capacity\` unpaid offers can fill it. The separate research-only
\`formal/pon-nakamoto-v1/w2c_stateless_receiver.py\` tests a stricter
resource-accounting boundary:

- An issuer-owned, fixed difficulty is MACed into a short-lived grant,
  bound to receiver, process epoch, exact original proposal and fresh token.
  Issuance changes **no retained grant table**. It is a research API, not a
  replacement V3 Cookie or a production listener.
- Only an authenticated, unexpired *valid cost solution* can claim one
  bounded spent-record slot. A lock linearizes the first claim. Subsequent
  exact replays refuse before W1. Failure of the later W1 does not refund.
  The spent key binds the complete signed grant, not a caller-generated
  identity or unverified packet's claimed chainwork.
- When spent records reach the finite original study cap, another actually
  paid solution gets \`PAID_CAPACITY_BUSY\` (local resource refusal, **never**
  consensus-invalid work). Expired paid claims can be reclaimed on the next
  valid, paid submission; untrusted junk cannot force a full-table scan on
  every rejected input.
- A fixed 8–24 bit receiver policy, HMAC, issuer epoch, trusted monotonic
  clock and expiry are rechecked. A signed lower-bits grant cannot downgrade
  the receiver's selected difficulty.
- \`test_w2c_stateless_receiver.py\` defines eight cases including 256 unpaid
  grants without a stored reservation, 32 concurrent uses of one valid
  grant (only one resource READY), two independent receiving nodes,
  paid-capacity busy, full-W1 TRANSCRIPT rejection after a paid ticket,
  issuer-policy downgrade, malformed context/MAC/nonce and expiry/clock
  rollback.

**Important:** this experiment has not created a cryptographically
independent useful-work proof, eliminated the cheap paid-ticket versus
expensive-W1 rejection cost gap, or established globally fair front-door
issuance. An unbounded stream of issue requests can still consume HMAC,
connection, bandwidth and signature resources; real deployment must
reuse the original V3 global protected admission infrastructure.
A paid Sybil coalition can also fill the finite spent table; that
remains a bounded service-degradation counterexample, not an accepted
admission-economics theorem.

No native Rust/W1 byte, original V3 signed cookie, activated W2, consensus,
Chainwork or production flag changes. P1 host and restart evidence,
P2 native/GPU calibration, P3 actual malicious/honest mix,
P4 original A03 3 modes x 3 runs x 3 confirmations, W2 cryptographic
soundness and P6 external independent review remain OPEN.
