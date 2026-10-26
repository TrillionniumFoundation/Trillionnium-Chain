# P2 independent admission economics: conservative analysis contract

Research-only; frozen parent `2787ad3959359bc5377d982a7ab46a2d76d44e0e`.
This reader changes **no** W1 work, signed V3 Cookie, W2-C prototype, canonical
ledger, authority, cumulative work or active network profile.

## Input contract

`formal/pon-nakamoto-v1/w2c_cost_verdict.py` takes a caller-supplied JSON
with schema `trnm-w2c-empirical-cost-verdict-v1`, receiver count (1–256),
scope `receiver-bound` or `globally-replayable`, 1–128 same-condition trials,
and *actual complete* ticket search, false proof construction, transport
sending and receiver full rejection CPU nanoseconds for every case.
It also requires **measured, externally justified** upper bounds on attacker
GPU and ASIC CPU-speedup factors. Zero trials, negative costs, bad units,
overflows, unsupported bounds and malformed JSON fail closed.
Unknown acceleration or missing transport cost produces `UNKNOWN` — never
an estimated safe difficulty.

For a declared finite sample, compare the most expensive observed rejection
against the least expensive **complete** declared producer. Receiver fanout
multiplies rejection cost, while an independently bound ticket is charged
separately per receiver. Crucially, the SAME forged W1 proof construction is
charged only **once** for the same fixed challenge/task/target across nodes;
only receiver-bound security-ticket search and per-receiver sends repeat.
For N receivers, denote T = one ticket search, F = one fixed-W1 false
construction, S = one first-hop send, and V = one complete receiver reject:

- Receiver-bound MACs: attacker = N*(T + S) + F, receiver = N*V.
- Globally replayable ticket: attacker = T + S + F (one initial send can
  propagate via other peers), receiver = N*V.

The old formula N*(T + F + S) for receiver-bound mode incorrectly
assumed the same false W1 proof must be reconstructed per receiver. It
could mask observable cost amplification; the new negative regression
demonstrates that 10,200 guessed attacker units become only 5,200 against
6,000 receiver units for two receivers. Distinct challenge/task statements
require separately accounted F; the reader's declared cohort must enforce
identical frozen source and context before using this sharing assumption.
The formula is a conservative cost envelope, not a lower bound on attacker
hash or hardware economics. Hardware advantage conservatively scales the
attacker's effective hash capacity. The reader never averages away failures,
never omits ticket misses, and never promotes `NO_OBSERVED_AMPLIFICATION`
to a public-security qualification.

Run on exact source (not a CI substitute):

```
python3 formal/pon-nakamoto-v1/test_w2c_cost_verdict.py -v
python3 formal/pon-nakamoto-v1/w2c_cost_verdict.py /retained/exact-costs.json \
  --out /new/unique/verdict.json
```

## Strict interpretation

- `OBSERVED_AMPLIFICATION`: even the supplied conditional economics show a
  receiver-cost advantage for the adversary.
- `NO_OBSERVED_AMPLIFICATION`: no such advantage under these **particular
  supplied measurements and assumptions**. It is NOT a hardness lower bound,
  future public-DOS immunity or permission to change the W1 consensus.
- `UNKNOWN`: missing hardware or transport evidence; it is not a passing gate.

Input labels are not authenticated evidence. True closure requires source,
binary, device/OS/CPU/GPU/ASIC identity, clock, memory, wall-time, all attempts
and cancellations, per-host received bytes, request concurrency, own cgroup
readback, remote operator identities and signature/retained immutable hashes.
A bounded collection cannot prove global cheapest producer, uniform mining,
worst-case asynchronous replay or Sybil-neutral availability. A receiver-bound
ticket also depends on distinct uncompromised server epochs/secrets.

The repository A03 P4 campaign, independent security audit P6, W2-A soundness
counterexample, W2-B missing succinct cryptographic proof and W2-C unfair
single-receiver CPU cost remain **OPEN**. Production remains HOLD_NO_GO.
