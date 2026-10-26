# W2-C no-unpaid-occupancy admission experiment

**Research only / HOLD_NO_GO.** This additive child of Chain #339 changes
neither PNW1 consensus nor the selected public V3 Cookie. No claim of
production-safe admission, publicly qualified PoN, or new W1 VerifiedWork.

## Original counterexample and addressed subproblem

The original W2-C receiver-local prototype in
'formal/pon-nakamoto-v1/w2c_receiver_admission.py' allocates a bounded,
per-grant pending row at **offer** time. An unauthenticated attacker may ask
for many signed offers without solving any of them; even before complete
W1 verification, the service's pending-grant table can fill.

'formal/pon-nakamoto-v1/w2c_stateless_admission.py' explores the narrower
anti-occupancy property:

* **Issuance is stateless per offer:** an immutable offer carries receiver,
  random 32-byte epoch, network, exact 32-byte body/proposal identity,
  fresh salt, issuer-fixed difficulty, original issue/expiry and a
  domain-separated HMAC-SHA256 over all those fields. No per-offer row is
  inserted into the paid replay owner. Issuing 16 unsolved offers does not
  consume a single paid replay slot.
* **The HMAC generator has one bounded shared issue-rate bucket:** its
  whole-issuer token count (not per identity) limits creation of unearned
  challenge envelopes. A BUSY local reply is not an invalid W1 proof.
  A new Issuer instance could mint another bucket, so all real listeners
  must bind one original host owner rather than construct new instances.
* **Only successfully solved tickets consume paid replay memory:** verify
  strict version/receiver/epoch/network/body/difficulty, original MAC,
  fixed expiry and ticket; then insert one exact domain-separated replay
  identity into a bounded paid-only owner under a single lock. A late W1
  TRANSCRIPT/PRODUCT rejection never refunds or awards Chainwork.
  Expired entries are pruned only at trusted monotonic time. The replay
  table refuses new *paid* admissions when full; no live eviction.
* **Difficulty cannot be chosen by the guest:** an Issuer fixes bits
  (8..24 in this research only) at construction, and consuming a modified
  or downgraded challenge returns CONTEXT or MAC. This research range is
  not a V3 policy revision or a cost-optimal production difficulty.
* **The host owner must be shared across Listener instances:** independent
  Issuer objects can share the one PaidReplayOwner (and same keys/epoch)
  without replay. Conversely, a deliberately tested *unsafe clone*
  with the same secret and epoch but **different** replay owners accepts
  the same paid offer twice. The remedy requires verified unique epochs
  and/or an independent durable host-global spent authority, not code
  comments or a MAC alone.

## Exact local test evidence

Additive Python test selector:

    python3 formal/pon-nakamoto-v1/test_w2c_stateless_admission.py -v

A local scratch run on 2026-10-25 executed **10/10 passing tests** using
the source byte-identical to the submitted Git blobs (SHA1
'c7b5104f44074c91e59b51d3d434c6d617ef452a' and
'ff540eb98670af04458e9a05b8744f23e7ad27e9').
The scratch 'contract_wire.H' shim contained only the exact SHA-256
domain/length framing from the official Python oracle. Running in the
full checkout with the official 'contract_wire' is a distinct, pending
qualification; the same source was not compiled into Rust or used on WAN.

The tested cases include:
1. sixteen unsolved offers produce zero paid replay rows;
2. 64 concurrent copies of one paid offer yield exactly one resource READY;
3. two Issuer objects sharing one PaidReplayOwner cannot mint a replay;
4. receiver/network/epoch/body context and HMAC/bit downgrade failures;
5. a failed ticket does not reserve CPU or take a paid slot;
6. a bounded full paid-store refuses instead of evicting active tickets;
7. time expiry, clock rollback and arithmetic overflow;
8. explicit **FAILURE** counterexample for two cloned issuers with
   separate paid stores and identical secret/epoch.

The fact that the negative counterexample is *observed* is not a security
pass. The model is single-process in-memory research, not a real distributed
durable CAS, certified randomness or OS CPU owner.

## Remaining P0–P6 blockers

- P0: four real fake transcript vectors + native state unchanged verification
  on the parent PR #335 must be independently reproduced on exact source.
- P1: remote peer polling, remote native/CLI History, loopback proxies and
  addressless embedding routes still require root resource ownership and
  real multi-process crash tests; source patches #340/#342 are drafts.
- P2: real CPU/GPU/ASIC and signed V3 Cookie costs, honest admission burden
  and W1 full receiver CPU must be measured under equal host budgets.
- P3: paid and unpaid identity churn, diverse false traces, valid W1 with
  invalid StateRoot, adversarial scheduling and honest confirmations.
- P4: original A03 three attack modes times three complete runs each with
  three out of three timely independently confirmed honest rounds.
- P5: this scheme does not change the fundamental low-cost forged trace
  relation; it merely eliminates **unpaid replay-memory occupancy**.
  A ticket paid to one receiver can still cost that receiver more CPU
  than the attacker spent, particularly on GPU.
- P6: independent external cryptographic review, physical WAN operators,
  mixed peer failures and proper W2 consensus/upgrade authorization.

No code in this experiment may set an activation, usefulness, chainwork,
trust-root or FinalUse flag.


## Deterministic bounded same-task CPU diagnostic (new P2 observation)

Source: 'formal/pon-nakamoto-v1/w2c_stateless_cost.py', exact published
Git blob 'ebd9814d87edb4bb2f017ff2160e4b322f48fc20'.
It reconstructs the same 64×64 W1 scalar relation in the independent
'work_oracle.py', validates a genuine proof, then records eight actual
TRANSCRIPT-only replays for a fixed false W1 statement. The cost arms
use deterministic offer salt derived from the frozen seed and context;
all failed hash attempts are counted, not silently excluded.

    python3 formal/pon-nakamoto-v1/w2c_stateless_cost.py \
      --seed 7 --bits 8 12 --samples 4 --cap 65536 \
      --unpaid 1000 --out /new/unique/w2c-stateless-cost.json

One actual *local Python process-CPU* run on 2026-10-25 recorded median
false W1 rejection 78.92 ms. The synthetic trusted clock did not advance
with solver execution, so neither live Cookie expiry nor network latency
was measured. Four independent fixed challenges per research cost class:

| Bits | Full-ticket search attempts | Observed CPU ms |
| --- | --- | --- |
| 8 | 145, 548, 686, 390 | 0.368, 1.545, 1.777, 0.986 |
| 12 | 10,967, 1,590, 1,460, 15,699 | 29.425, 4.563, 4.054, 44.376 |

Separately, 1,000 unpaid calls in the same fixed-clock burst issued 32
offers (the original bounded global issue-credit ceiling) and took zero
paid replay rows. It does not prove any upper bound on authentic network
socket occupancy or HMAC CPU under unlimited client requests.

The data **refutes** calling 8/12-bit ticket payment equivalent to the
complete W1 replay cost. Even at 12 bits, favorable hash outcomes can
arrive after very few attempts; no finite ticket target sets a hard
attacker cost floor per accepted request. GPU hashing may further reduce
the attacker price. Legitimate users still bear the extra ticket burden.

All CPU times are conditional on this particular Python interpreter,
one host and one source version. Real native V3 receipt/signed Cookie,
GPU/ASIC, whole-host costs, fair honest completion and full A03 runs
remain **unmeasured / NOT PASSED**. Do not retrofit these numbers into
any production policy or claim a closed P2/P5 gate.
