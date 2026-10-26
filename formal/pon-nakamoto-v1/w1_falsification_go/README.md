# W1 independent scalar falsification profile — HOLD_NO_GO

This is a **research-only, independent Go verifier** of the unchanged
`pon-matmul-transcript-64-v1` arithmetic relation and witness bytes. It does
not replace native `trnm-crypto-primitives`, define a new proof version,
select the parent task, sign a requester/source lease, issue `VerifiedWork`,
measure minimal mining cost or activate production.

Use Go 1.22+ and Python 3.11+; no non-standard Go dependencies:

```sh
cd formal/pon-nakamoto-v1/w1_falsification_go
GOWORK=off GOPROXY=off go test ./... -count=1 -v
GOWORK=off GOPROXY=off go vet ./...
GOWORK=off GOPROXY=off go build -o /tmp/pon-w1oracle ./cmd/w1oracle
cd ..
python3 w1_go_diff.py --go-binary /tmp/pon-w1oracle
```

Go uses independent row-major, per-product modular reduction rather than
Rust's 128-bit accumulation, and independently reconstructs EL/ER/FL/FR,
challenge-dependent perturbed matrices, every intermediate tile transcript,
the corrected AB product and PNW1. The original Python `work_oracle.py`
serves as the second independent scalar producer in `w1_go_diff.py`.

## Actual local observation — 2026-10-26

On one Go 1.23.2 linux/amd64 / Python 3.13.5 container (no Rust compiler):

- Go `TestW1FullRelationAndMutants`: PASS (full proof, task/product/trace
  mutants, zero target; a ticket-valid forged transcript is still rejected).
- Go `TestMaintenanceFixedMaterialProducesDeterministicTranscript`: PASS.
- Go `TestCheapTicketForgeryVsFullReplayCost`: PASS; **32** full rejects versus
  **32** syntax/task/ticket prechecks on a test-only all-FF target:
  precheck **2.595929 ms** wall, full verification **43.715861 ms** wall;
  ratio **16.84×** on that one finite local run. This is NOT actual paid CPU,
  native production admission, attacker cheapest cost or proof hardness.
- Same fixed public non-zero maintenance matrices were reconstructed in a
  separate Python scalar reference and yielded identical 49,188-byte PNW1
  proof ID/trace to the Go implementation.
- Challenge (test-only, NOT a 318-byte admitted header):
  `98f218028378105b955ce48482ef56e4ea63c26235b8f1e3729d51071a6a6e07`
- Task ID:
  `c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496`
- Transcript:
  `eb3e1740a7054eea29374a993c59eb3d3c74ae0aacd3d58b0178975a84e968f0`
- SHA256 of full PNW1 bytes:
  `a04567bf099baaae13232d1913e872c1165effad3479601c2e5d9f27c1848746`
- Go output binary sha256:
  `b3c39b9e33ec54d257a0eb4005e3770798d9eab979e5a1f9288437b39122f433`

The Go/Python comparison was first executed using a faithful local copy of
the repository's scalar Python `work_oracle` function and hash domain, then
the `w1_go_diff.py` entrypoint was committed to import the **existing**
`contract_wire.py` and `work_oracle.py` on a complete repository checkout.
The full original-tree integration of that entrypoint is not claimed executed.

The all-FF ticket threshold is not necessarily an allowed chain `pow_limit`
in any production context. No new actual W1-winning block, 32-slot Q4
lifecycle, authenticated M07 cold-reopen, independent attack hardware, or
real network service measurement is claimed. This tests a *known*
cheap-false-transcript property; no local wall-clock ratio can close P0-C.
The original P0-A/B/P0-C, P1-C and P2 blockers stay OPEN.

## Follow-up half-target from-zero falsification (same local host)

The new `TestHalfRangeFromZeroForgedTicketVsFullVerification` constructs
candidate witnesses using only the published 64x64 A/B, a zero product and
freshly hashed invented transcript digests. It **does not** first compute
a valid W1 proof. For each synthetic challenge it searches until the
*same half-range dev target shape* passes the actual cheap Ticket predicate,
and then requires the complete independent verifier to return
`TRANSCRIPT`, never `VerifiedWork`.

Actual run on the Go 1.23.2 container: **64/64** fabricated tickets from
**112** total hash trials; generation including all public A/B witness assembly
and precheck took **12.117174 ms wall**, and 64 complete late rejections
took **82.846352 ms wall**, ratio **6.84x** in that finite sample.
This is stronger than the earlier all-FF diagnostic because all 64 claimed
tickets satisfy the development half-range target, but all have zero valid
chainwork. The challenges are still synthetic, not genuine native signed
headers; wall clock is not the original paid native service CPU clock.
This observation cannot qualify honest public-miner service, Sybil costs,
hardware advantage or minimum valid producer difficulty. These blockers
remain OPEN.
