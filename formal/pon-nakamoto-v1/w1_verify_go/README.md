# P0-C — Independent W1 full-transcript verification research

**Scope:** Experimental `pon-matmul-transcript-64-v1` / `PNW1` only. This Go
command is a **research verifier**, not a PoN node, miner, a wire endpoint, a
trusted source/evaluator, a Hepta task owner, or a consensus-validity authority.
Its output does not grant `VerifiedWork`, chainwork, admission, payment,
model-use authority, or activation. Never wire it to `M02::expected_target`.

Unlike the existing bounded Python work oracle and Rust W1 implementation, Go
replays the complete challenge-dependent 8×8 tiled transcript but checks the
claimed output C by **independently recomputing A×B** rather than using the
Rust decoder's low-rank cancellation identity. All products are reduced modulo
4,294,967,291 at every scalar accumulation, avoiding an overflowing `uint64`
8- or 64-term sum. Encoding is the exact 49,188-byte `PNW1` contract: A, B,
C as little-endian canonical `u32` field elements plus a 32-byte trace.

Local commands from repository root (Go 1.23+ and Python 3):

```sh
GO111MODULE=off go test -v ./formal/pon-nakamoto-v1/w1_verify_go
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_w1_go_differential.py' -v
python3 formal/pon-nakamoto-v1/w1_go_cost_campaign.py --output /tmp/new-w1-go-cost.json
```

The Go command accepts `--challenge`, `--task`, `--target` as exact 32-byte
hexadecimal inputs and `--proof-file` as a **regular, exactly 49,188-byte** local
file. It reads at most 49,189 bytes, does not expose submitted material in its
JSON result, and exits 0 only after full verification. A locally supplied
`target` is checked as a nonzero comparator; the **native Node** remains owner
of branch-derived expected targets, admission and fork choice. Do not expose
this experimental tool as a public verification service.

## Local observation — 2026-10-26

On one Linux AMD64 host running Go 1.23.2 and Python 3.13.5:

- The standalone Go tests passed 4/4.
- The Python/Go interop suite passed 5/5 methods, including **six** genuine
  matrix input classes (zero, rank-one, sparse, dense, committed Revision 12
  Maintenance, near-field-boundary) and **96** deterministic altered proofs.
  It compared exact `ticket`, direct C output hash and typed negative verdicts
  with the existing `work_oracle.py` logic; every alteration agreed.
- The finite cost-screen regenerated complete honest Python proofs for each
  of the six classes and constructed six from-zero invalid transcripts by
  searching hash tickets over zero-claimed C. Go's complete verifier refused
  all six with `TRANSCRIPT`; **zero fake ticket hits were accepted as work**.
  The actual finite report is a conversation artifact, not source evidence
  checked into this repository. It records the full attempts, Python process
  CPU and Go per-relation verification *wall* clocks as distinct units.

The local Go and Python source blobs are identical to the submitted Git blobs
only when `git hash-object` confirms them; the formal/current-source CI, native
Rust build and third-party qualification are separate observations. No
independently administered verifier or cheapest-producer proof has been run.

## Missing security qualifications

- **W1 hardness**: Compare the cheapest fully valid adaptive CPU/GPU/FPGA/ASIC
  producer, preparation reuse, structured tasks and committed Maintenance
  against the *total* failed + successful attempt denominator at the same
  challenge/target. Equal code paths do not imply equal marginal work.
- **Public ingress**: The cheap hash-search false transcript still costs full
  replay at the receiver. Only real fully-accounted hostile transport plus
  honest-service workloads can show whether admission remains usable under
  Sybil, packet and connection pressure. Local Go wall times are not an
  attacker energy/CPU lower bound or public DoS safety proof.
- **Native correctness**: Run exact-head Rust W1 packet/negative regressions and
  actual independent Node confirmations on the native source; compare hidden
  third-party vectors, different CPUs and fully loaded chain/business costs.
- **No activation**: No Q4, Revision 12, DAA, coinbase, consensus target,
  chainwork, P2P security, model-training or production flags are changed.

The authoritative plan remains
`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`;
this document is a subordinate non-activated P0-C technical test note.
