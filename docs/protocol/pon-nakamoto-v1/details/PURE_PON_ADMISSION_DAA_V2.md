# Pure PoN admission and conditional confirmation research

This is a technical attachment to the existing
[development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
continuing its PN1 / I01-I02 owners. The input is Chain
`0d02a946c9126c5dbdad41edd770c81eda07a96e` (#539). It introduces no new
consensus selection, auxiliary Hashcash, stake, voting, deployment or activation.
The actual final source, tree, binaries and failures belong to their own CI
receipts; the input pin is not acceptance of this increment.

## Three verdicts remain separate

1. **Validity:** a winning hash of a fabricated trace does not create a valid
   W1 block. The complete native relation still rejects it. A computational
   certificate has a separate soundness obligation.
2. **Bounded resource loss:** original shared admission, worker, grant,
   byte, mutation CPU and deadline limits bound particular owners. A cooperative CPU
   checkpoint is not preemption of an arbitrary SQLite or kernel operation.
3. **Honest service:** a finite pass under a specified arrival schedule does not
   prove service against unrestricted Sybil traffic. Cold zero-credit progress,
   receiver attack work, actual depleted credit and honest completion must be
   observed together, without extending a failed phase.

## Explicit pure-v2 transport

Select `public-pure-pon-development-v2` on both endpoints. The native CLI exposes
the same `serve`, `public-task-fetch`, `push`, `head`, `history` and public pool
operations. It uses a canonical zero acknowledgement nonce and zero transport
hash-search trials. Nonzero admission bits reject. Its signed resource identity
is distinct from pure-v1, protected-v3 and growth; a foreign signed cookie or
response rejects and never triggers a protocol fallback. Existing pinned peer
polling and reliable-submit recovery have v1-specific contracts, so selecting
those with v2 is explicitly unavailable rather than silently using another
namespace.

The original limits remain: 64 connections, four listeners, eight mutation
grants, two active mutation CPU owners, 100 ms start reservation, 250 ms CPU
refill per second, 2 s maximum stored burst, the original byte/queue limits and
absolute deadlines. A new process still starts with zero CPU/challenge credit.

After each listener's original dequeue-order lock, v2 registers at most one
scalar FIFO position per listener in the **same** CPU account. Registration
does not reserve credit. The oldest live v2 position acquires the original
start reserve atomically under the original account mutex; later v2 requests
cannot repeatedly win a refill race. Cancellation, expiry and errors remove
the scalar position. The original verified-completion priority and measured
debit/settlement remain authoritative. `observe_pure_admission` only reads
counts and cannot create an epoch or refill it.

This ordering covers already-admitted v2 requests. It does not entitle a public
identity to a socket, defeat unlimited queue-filling identities, coordinate
unrelated processes without the existing host-kernel owner, or guarantee a
deadline when preceding work or competing local owners exhaust the account.
Those are explicit limits, not an implicit fairness certificate.

The mutation account does **not** include all read/reactor/network CPU or the
existing trusted local producer selected by `serve --mine`. That producer keeps
its original mining path and has no new scalar-account fairness entitlement.
It remains inside the fixed host parent's aggregate resource limit when the
non-loopback service is used. The
existing library and CLI require the same administrator-provisioned
`/sys/fs/cgroup/trnmponpublic.slice` for non-loopback service and continuously
recheck its immutable identity and original limits. V2 adds bound kernel samples
carrying boot ID, device/inode, fixed parent, CPU quota/period/zero burst,
memory/swap/task ceilings and actual cumulative usage/throttling counters.
The endpoint delta refuses a changed binding or counter rewind; it is not a
second balance. This covers that parent's descendants, not unrelated host
cgroups or outside network infrastructure. Loopback without the real handle
reports no kernel sample, and the experimental campaign's outer 4-CPU/16-GiB
unit cannot substitute for the 25%-CPU receiver parent. Actual administrator
controlled-parent evidence and whole-node adversarial qualification remain due.

The same CPU epoch owns one existing 64-slot `ArithmeticFactCache`, shared by
its v2 listeners. Each fact binds the complete header challenge and whole A/B.
Every request still checks current encoding, fields, task, target, trace and
product claims, then rebinds native parent/state authority. There is no cache of
an accepted block or caller entitlement. The fixed object accounting is not
an RSS measurement. Different fake traces of the same statement can reuse a
computed fact; a fresh-challenge flood or capacity churn still incurs real work.
Contention uses the original accounted arithmetic path and cannot bypass W1.

## Complete statement-bound transparent certificate API

M01's optional `transparent-w1-admission-research` feature exposes
`pon_work::transparent_admission::verify_bound`. Its fresh `PWAI0001` envelope
contains the complete 49,640-byte PWG1/PNW1 input and an actual Succinct receipt.
The whole envelope is at most the existing 1 MiB packet comparison ceiling.
The native PNW1 codec and live public request grammar are unchanged.

Before proof verification the API compares every byte of the supplied complete
expected statement: all 318 header bytes, external task, external target and
the canonical PNW1 commitment. The caller, not the received certificate,
supplies this expected context. It reconstructs the complete claimed PWJ1
journal without executing matrix work, checks canonical PNW1/ticket encoding,
and scans the entire bounded receipt grammar without allocation. Lengths,
variants, journal size, inclusion depth, trailing data and recursion po2=18
are checked before bincode creates vectors.

The actual RISC Zero 3.0.6 verifier checks the pinned guest image, ordinary join
control ID, Poseidon2 verifier parameters/control root, successful exit,
empty assumptions and exact journal. Fake, Composite and Groth16 envelopes
and ambient development mode are refused. The registry graph includes SDK
dependencies also used for other receipt types; their presence does not enable
those receipt types at this entry. The final lockfile identifies the actual
dependency graph. This API never calls full W1 replay and has no conversion to
native `VerifiedWork`, chainwork or installation authority.

The retained positive fixture is the real certificate from
[run 40659377917](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40659377917),
artifact 12804405518. Its full ZIP SHA-256 is
`fd681537c4040b2884e3a99982aa750c2cdca8374e366726c8a688e0ad20100c`;
the original 273,338-byte certificate SHA-256 is
`9c370089ba5203b9a8559b900c975778425839f4ccfa171387bdfb0853a3e5c9`.
Tests adapt only its eight framing bytes and preserve all input/proof bytes.
The full relation source blob equals #534's
`5d0f1727f59bf794700d01719560bf695dfb1ea9`. Tests mutate every header byte,
external context, witness, journal, actual seal, proof parameters and allocation
prefixes. A forged journal with a recomputed witness commitment still requires
the real unchanged cryptographic proof and must fail.

This is a real verifier API, **not live public certificate intake**. One retained
proof does not measure new arbitrary-input production, from-zero generation,
worst invalid-proof CPU/RSS, cancellation or node-wide proof CPU ownership.
These, backend/guest independent review and parameter soundness must precede
a network certificate profile. In particular this increment does not assert
PQ-128, independent security acceptance, superior receiver cost or work hardness.
The research API cannot silently replace the current full native verifier.

## Fixed pure-v2 pressure campaign

The new `pure_pon_pressure_v2` test and independent
`check_pure_pon_pressure_v2.py` reader leave the old r13 and pure-v1 campaigns
intact. Each phase uses a new zero-credit receiver epoch with two actual TCP
listeners sharing one account. The phases are the original 30 s baseline,
30 s from-zero attack and 30 s correct-product/false-trace attack. Attack
phases have 24 separate actors and at most 480 calls each; honest calls retain
their 2 s deadline. The native fixture contains four 256-transfer seed blocks
and 21 business blocks, with three signed business transactions, History
replay and three depth-six confirmation rounds per phase.

From-zero traffic changes its claimed trace under each actor's fixed context.
The correct-product phase changes the header nonce/challenge on each request
and charges the one-time valid product acquisition separately. The reader
reconstructs packet/body hashes, trial targets and distinct statements. Its
churn condition requires at least 65 distinct **receiver-completed and newly
published** arithmetic facts in a 64-slot epoch; merely sending 65 packets is
insufficient. Failure to obtain coverage stays unqualified.

Actual elapsed timestamps, receiver work observations and the shared CPU flow
must establish attack/depletion overlap within honest rounds. Initial cold
zero credit or booked reservations alone do not establish attack depletion.
Client calls alone do not establish receiver CPU work. Confirmation after the
fixed phase end does not qualify. The reader separates structurally consistent
failure evidence from finite service qualification; `--require-qualified`
fails unless the frozen conditions hold. Native failure, timeout and incomplete
coverage are retained; there is no automatic retry for green.

Stored credit can be stale while unbooked time-based refill would already let a
new request start. The sampler therefore also records the existing read-only
`observe_credit_freshness()` snapshot: its actual flow and original refill
watermark age are captured under the same account lock. The reader independently
recomputes full-age refill, the reservation-adjusted ceiling and signed debt.
It adds a conservative, upward-rounded refill allowance for the entire sampling
interval. Only an end-of-sample paid-credit upper bound strictly below 100 ms,
with more than 1.9 s of actual paid CPU and the original clock/account checks,
can count as depletion. Neither worker saturation nor a stale low balance is
enough. This observes an instant inside the honest round, not continuous
exhaustion for the whole round; the observation never calls actual refill or
changes the resource supply.

The [retained local observations](../../../../evidence/pon-pure-admission-daa-v2-local/README.md)
include the initial failed workload and its telemetry defects. A subsequent
measurement of corrected telemetry cannot replace the original failure or turn
shared local hardware into the declared CI or receiver-kernel envelope.

## PoN-specific DAA and confirmation experiment

The [conditional risk model](../../../../formal/pon-nakamoto-v1/pon_risk_model_v1.py)
loads the installed development parameters and computes 256-bit targets and
512-bit cumulative required work with integer arithmetic. Shared JSON vectors
are checked independently by the native Rust consensus functions and the
Python model. MTP, future skew, 16-block endpoint retargeting, clamp/rounding,
chainwork and tie behavior remain the current rules. No ASERT or other DAA is
activated and no fourfold legal target excursion is relabeled a profitable
time-warp attack.

The finite suite varies legal complete-attempt cost, context setup, winning
witness and publication delay, producer entry/exit, legal timestamp policy,
hidden branch release and a conditional quantum producer. The quantum arm
charges a complete clean oracle plus diffusion and measurement/check/restart,
uses a fixed stopping schedule without selecting it from the marked count,
and makes the marked fraction an explicit hypothesis. It does not replace
the full PoN oracle with a hash-only cost or infer physical quantum hardware.

Each scenario runs the current DAA and a fixed-target counterfactual. Costs,
workers and marked fractions are assumptions, not measured adversarial share.
The model allows at most one winner per producer group per slot, discards
unfinished phase work, and uses a specified withholding/release policy.
Unconfirmed trials, work still in flight and finite-horizon survival remain
separate denominators. Reported intervals describe simulation sampling only.
They do not give a real-chain probability, revenue, chain-quality theorem or
universal safe confirmation depth.

`pon_confirmation_risk_v1` separately constructs real valid PNW1 blocks and
native application states, observes the original depth/work confirmation, then
publishes a strictly heavier hidden branch and checks the reorganization,
equal-work nonreplacement and durable reopen. It demonstrates reversibility
of a confirmation observation under the existing rules; it does not show that
an attacker can economically produce that branch faster than honest miners.

## Remaining PN1 vetoes

Public admission still needs a sound complete-proof network binding with
measured worst rejection cost and the original whole-owner resource account,
plus sustained cold honest service under declared adversarial arrival bounds.
Permissionless fairness cannot follow from per-key quotas in a free-identity
network. A concrete finite pass and any failures must be reported separately.

DAA/confirmation qualification still needs measured complete legal solver and
task distributions, calibrated rate/latency variation, more general withholding
and network schedules, energy/economic costs, and an independent security
argument including the quantum assumptions. No source check, one fixture,
model counterfactual or green CI can turn these open obligations into activation.
