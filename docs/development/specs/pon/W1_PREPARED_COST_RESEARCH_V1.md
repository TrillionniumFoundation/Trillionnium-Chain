# W1 prepared-product legal-miner cost research

Status: **research only; no PoN production acceptance or protocol activation**. This document is subordinate to the sole development plan, PN1/P0-C. Its artifacts never replace the existing W1 proof format, Q4 signature rules, Revision 12 genesis maintenance or old DAA.

## Legal optimization under investigation

The challenge-bound W1 transcript varies with the complete canonical header. However, for an already admitted task with fixed finite-field matrices A and B, its useful product C=AB does not change between attempts. The original generic Go verifier/producer computes C from the challenge-augmented matrices on every attempt. An independent legal miner can instead compute C once, retain it, and generate every nonce-dependent noise matrix, modified-matrix transcript and digest from scratch for each challenge. The new research helper `PreparedW1Task` deliberately snapshots and validates A/B, computes C at preparation time and never accepts a supplied transcript.

This is an example of **adversarially admissible amortization**, not a new validity relation. The goal is to falsify an assumption that the unoptimized reference producer approximates the minimum work cost.

## Executable references

The existing `formal/pon-nakamoto-v1/work_go_probe.go` remains unchanged. Run the original reference and the new helper *together*:

```bash
cd formal/pon-nakamoto-v1
GO111MODULE=off go test -count=1 -v \
  work_go_probe.go work_go_prepared.go work_go_prepared_test.go work_go_prepared_long_test.go
GO111MODULE=off go test -run '^$' -bench 'BenchmarkPrepared' -benchmem \
  -benchtime=5x -count=3 \
  work_go_probe.go work_go_prepared.go work_go_prepared_test.go work_go_prepared_long_test.go
```

The parity test covers maintenance, dense, zero, rank-one and sparse input classes, three independent deterministic material seeds and four challenge IDs (60 complete proof byte comparisons). It calls the existing full verifier and exercises input aliasing, changed Challenge, false transcript/product, noncanonical fields and short inputs. A separate 15-case half-range Ticket search compares the same full legal generic and prepared nonce stream, winning challenge, losing-attempt count, complete PNW1 certificate and full verifier; a zero-attempt search remains an explicit failure. The benchmark compares setup **plus all attempted proofs** at horizons 1, 4, 16, 64 and 256. The longer 64/256 runs require explicit invocation; none of these tests creates a signed native packet or a public W1 ticket in a production chain.

## Local reconnaissance / scope

A separate local Go experiment on AMD EPYC 9V74 used a **locally reconstructed Go generic helper**, not the exact GitHub `work_go_probe.go` file; all 60 proof comparisons and negative controls passed in that local fixture. Four-benchmark-iteration samples for 16 maintenance attempts were 23.576 ms generic and 18.239 ms prepared; one-shot 256-attempt samples were 368.560 ms generic and 287.185 ms prepared. These values are illustrative, compiler/host dependent, low sample count, and **not** exact-source GitHub production or independent security evidence. They are not merged into the historical W1 cost corpus.

The exact-source test commands above must run and preserve SHA256 of source/binary, actual whole-process CPU and wall time, full batch denominators, compiler/hardware settings, all errors and losing attempts before numerical cost inferences are accepted.

## Blockers retained

A faster legal method on one public task is not a cheapest legal method over all input classes, selection algorithms, reuse horizons, GPU/FPGA/ASIC designs, multi-instance preprocessing, shared production facilities and task-mix advantages. True difficulty safety requires independent review of cost-lottery assumptions, not just byte-parity of two producers. Cheap false-ticket/full-verification asymmetry, Sybil-service exhaustion, attack-time honest admission, independent hardware and WAN operation remain unqualified. P0-C/PN1 and all production activation flags must remain **false**.
