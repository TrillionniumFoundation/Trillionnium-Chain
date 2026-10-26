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


## Next revision: stateless issuance, paid-only replay state

The earlier receiver-local research issuer allocated one pending row **on
every HMAC grant issuance**. A sender who did not solve any proof-of-cost could
obtain a finite batch of pending grants and fill the admission table. This
is an independent cheap state-exhaustion path.

The additive, separate module
'formal/pon-nakamoto-v1/w2c_stateless_receiver_admission.py' now supports a
**stateless grant issue** mode: every signed grant binds exactly receiver,
process epoch, proposal, random token, bits and fixed expiry, but issuing
it creates NO pending state. The only mutating table contains hashes of
grants that have **actually passed** an authenticated, receiver-local Hashcash
check; the insertion is atomic and bounded. Existing live spent facts are
never evicted to allow replay. The issuer's untrusted-grant method does not
scan the spent table on issuance, so with respect to memory and table size,
grant issuance is O(1).

The separate negative selector
'python3 formal/pon-nakamoto-v1/test_w2c_stateless_receiver_admission.py'
tests 5000 unpaid grants consuming zero pending rows, exact 32-way
single-grant contention, receiver copy, old process epoch, credential
tampering, invalid ticket, expired/clock-regressed grant, bounded paid-table
full with fail-closed Busy, and exact paid-row expiry. The suite passed
8/8 in a local standalone Python execution; published source/test blob SHA
must match the tested bytes. No Rust native verification or WAN request was
part of this run.

This is NOT free anti-DoS: 5000 grant issuances still consume HMAC, socket,
entropy, framing and wall-clock resources. Those must be bounded by the
already selected V3 front-end and one physical Host owner before this
research could be considered for integration. Paid requests can still
fill the bounded spent table until expiry; anonymous honest fairness and
GPU/ASIC economics remain open. A real restart MUST select a fresh
cryptographically independent epoch or persist the spent table; reusing
an old epoch with lost replay state is forbidden. The original V3 Cookie
and W1 remain unchanged and unqualified for public launch.

The stateful and stateless examples deliberately live side by side for
paired counterexamples; selecting the stateless one at runtime would
require a new signed policy namespace, negative compatibility tests and
explicit governed adoption rather than silent replacement.


### Server-pinned cost policy: no caller-selected difficulty

A further counterexample showed that signed HMAC grants alone do NOT stop
an authenticated requester choosing the cheapest allowed search difficulty.
The stateless research variant now freezes 'bits' in its receiving issuer
configuration and refuses 'offer' calls requesting any other number of
leading-zero bits, even if the value is syntactically valid. After verifying
the MAC, 'consume' also refuses old, correctly signed grants whose bits differ
from this current receiver policy. This prevents a policy downgrade when an
operator raises the local research cost floor; the old grant receives
'BITS_POLICY', not VerifiedWork, chainwork or a free workload.

An additional ninth Python negative regression exercises a fixed 12-bit
receiver rejecting an 8-bit request and a historically valid 8-bit grant.
All nine research tests passed locally; this does not establish the correct
production bits, GPU/ASIC fairness or resistance to issuance CPU floods.
A real deployer must pin difficulty to a versioned signed transport policy
and enforce an authentic server clock; the caller-supplied research time and
difficulty values are **not** a production-safe remote API.


## Matched-reference CPU experiment: the original amplification persists

The executable 'formal/pon-nakamoto-v1/w2c_stateless_paired_cost.py'
compares the original independently coded W1 Python oracle against its
own fixed 64x64 zero task, the unchanged half-target
'7f' followed by 31 'ff' bytes and a deterministic fresh challenge stream.
It requires the **exact Git blob SHA**
'9cbfccd2d50af48fc43522b967ffdfb1f45ec098' for 'work_oracle.py'
before accepting the report. Every failed legal challenge, winner,
independently searched fabricated trace, early precheck and full verifier
outcome is retained, including bounded exhaustion cases. A third test
selector 'test_w2c_stateless_paired_cost.py' refuses bad bounds, impossible
ticket payments and omitted valid-work attempt denominators.

A local exploratory Python process-CPU run used
'--seed 1 --samples 2 --bits 8 12 --w1-attempts 8
--ticket-attempts 8192' and retained JSON SHA256
'b681deddd4bc953a840799b17d953c8effbaef67a305190448323b39cea05a0a'.
This was one executable process and two deterministic samples, with *both
difficulty arms reusing each sample's same task/challenge stream*: four
observations are **not** four independently sourced tasks.

| Sample / local receiver bits | W1 legal attempts | Full legal producer CPU ms | False producer CPU ms | Full false rejection CPU ms | Receiver / false producer CPU | Extra stateless ticket CPU ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 / 8 | 2 | 150.80 | 0.0888 | 74.42 | 838.3x | 0.47 |
| 0 / 12 | 2 | 152.71 | 0.1074 | 76.15 | 709.0x | 0.66 |
| 1 / 8 | 2 | 149.83 | 0.0609 | 77.17 | 1267.1x | 0.53 |
| 1 / 12 | 2 | 156.87 | 0.0888 | 79.11 | 890.7x | 12.94 |

Each paid local ticket remained **non-authoritative**; every forged W1
proof was rejected as TRANSCRIPT. These are *Python-only CPU* observations:
no actual native Rust W1 path, V3 signed Cookie/body handling, WAN/cgroup
contention, GPU/ASIC hashes, honest pending work or independent operator.
Neither the raw CPU ratios nor the synthetic bits determine an acceptable
public security price. The exact-source-native security qualification,
A03 3x3x3, GPU calibration, W2 soundness, and third-party cryptanalysis are
still OPEN.
