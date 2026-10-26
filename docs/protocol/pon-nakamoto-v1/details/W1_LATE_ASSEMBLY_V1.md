# W1 late assembly and publication, research v1

## Exact question

The existing prepared integer-paired producer already pays for `AB` and the
fixed `PNW1 || A || B || AB` prefix once during preparation. This experiment
does not claim a new saving of matrix multiplication or a cheaper transcript.
It separates the remaining legal scheduling choice: compute the canonical trace
and ticket first, then assemble and flush the full 49,188-byte proof only when
the ticket meets the original target. The eager comparison assembles and emits
the complete proof on every attempt.

In this executable both modes evaluate the ticket before the assembly decision.
Eager means unconditional per-attempt assembly/delivery; it is not an empirical
example of protocol-enforced proof-before-lottery execution.

Both modes use the same copied integer-paired arithmetic and SHA-256 trace
kernel. All four challenge-derived noise arrays, every canonical transcript
partial, and the original ticket construction remain unchanged. The original
Node template fixes the target before any research attempt. There is no ZK
compression, additional lottery, hybrid work, or production protocol change.

## Cost implication

For a fixed target with conditional success probability `p`, let `c` denote the
trace and ticket cost, and `s` the subsequent full-proof assembly/publication
cost. Ignoring separately itemized observation overhead, eager execution costs
`c + s` per trial, whereas deferred execution costs `c + p*s` in expectation.
These are scheduling identities under the stated probability model, not lower
bounds on either quantity. The mandatory cost of producing a valid winning
ticket cannot be inferred by charging every failed attempt the honest logger's
full encoding and output cost.

This test includes the original stdout encoding and flush in miner process CPU.
It does not measure WAN transfer, physical bandwidth, energy, independent
operators, or a universal attacker advantage. Its compact loser records also
have observation costs. They are not a proposed production wire format.

## Four strictly ordered phases

1. **Setup P:** open the original development Node, acquire its real maintenance
   task and a native admitted template, then prepare `AB` and the fixed prefix.
   The original make path uses at most 64 attempts. Its winner and paid internal
   misses belong to setup, not the miner's online numerator.
2. **Miner B:** the mining function receives only the prepared material and
   fixed header. It has no Node, verifier or receiver feedback. Both modes use
   the same disjoint high-nonce schedule. Original records must finish flushing
   by B to count. Atomic overruns remain recorded and receive no B credit.
3. **Receiver:** the original Node admits every actual winning research proof,
   including late proofs. Research blocks are never activated. These costs are
   retained separately, and acceptance is not backdated into B.
4. **Audit:** all original full proofs and every deferred loser are checked by
   the original and scalar reference relations. For a deferred loser, its
   original trace is appended to the already prepared prefix after mining has
   ended. These reconstructed bytes earn zero new opportunity or reward credit.
   Original setup misses are also reconstructed and distinguished from bytes
   actually observed during acquisition.

Phase boundaries, complete proof availability, original trace availability,
original Node admission and posthoc reconstruction are different events.
The independent Python reader replays every retained full proof, checks exact
field types and ordering, binds the original nonce schedule, reconciles all
counts, and rejects credit or provenance mutations. These checks do not attest
the host's clock or the Node's execution. Final summary encoding and
remaining in-memory drops after the recorded native endpoint are retained in
the external whole-command CPU observation and its signed residual; phase totals
do not claim to contain that final tail.

## Frozen finite campaign

The committed plan contains 14 jobs: two seeds, two online CPU budgets
(128 ms and 512 ms), and the eager/deferred pair, plus six controls covering
zero/tight setup, zero/tight miner budget, and both attempt caps. Normal setup
budget is one second and the normal attempt cap is 4,096. Cap-only functional
fixtures precede freezing and are not used to select performance outcomes.

The collector requires a clean committed source, a fresh release build, exact
Cargo graph and toolchain identities, pinned CPU affinity, and the real GNU time
observer. After each command has exited, lossless gzip compression is round-trip
verified against the original stdout byte count and SHA-256 before deleting the
redundant uncompressed copy. Original step receipts do not change. Compression
is never attributed to the miner's measured work.

Comparisons require identical paid setup bytes and identical identities and
hit results on the common challenge prefix. Incomplete setup or an attempt cap
prevents an uncensored ratio. Regressions are retained. Two seeds are not a
population confidence interval or a production kappa calibration.

## Source and evidence entry points

- Native example: `pon_w1_late_assembly_research.rs` in the `trnm-pon-node`
  examples directory; helper `support/w1_deferred_producer.rs`.
- Frozen plan: `formal/pon-nakamoto-v1/experiments/w1_late_assembly_plan_v1.json`.
- Collector: `scripts/run_w1_late_assembly_research.py`.
- Raw replay: `scripts/w1_late_assembly_reader.py`.
- Source-bound bundle reader: `scripts/read_w1_late_assembly_research.py`.
- Fixed analysis: `scripts/analyze_w1_late_assembly_research.py`.

The sole development plan remains
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
This document supplies a bounded research specification, not a replacement plan.
