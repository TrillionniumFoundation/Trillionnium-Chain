# Non-activated ASERT batch differential harness (research only)

This additional standard-library-only Go implementation exists **only to falsify and
stress-check** the ASERT candidate at high volume. The already present
[`daa_reference_go`](../daa_reference_go/README.md) remains the original Go
oracle. This batch-oriented executable is deliberately independent, but neither
Go implementation is an authority over the original Rust consensus core, and
there is **no fourth consensus rule, activation or replacement of Q4 / W1 / DAA**.

The production implementation, if ever reviewed, must have **one normative,
versioned consensus rule**, independently implemented reference verifiers and
an authenticated parent/anchor selection. Go/Python parity does not qualify
a new consensus profile, W1 security, independent operators or real WAN tests.

## Reproduce the source-bound local campaign

From `formal/pon-nakamoto-v1`:

```sh
cd daa_oracle_go
GOWORK=off GOPROXY=off go test ./... -count=1
GOWORK=off GOPROXY=off go vet ./...
GOWORK=off GOPROXY=off go build -o /tmp/trnm-daaoracle ./cmd/daaoracle
cd ..
python3 daa_go_batch_differential.py --go-binary /tmp/trnm-daaoracle \
  --seed 20261026 --count 10000 --output /tmp/trnm-daa-go-report.json
```

The Go oracle uses `math/big` independent of the native Rust eight-limb type.
It enforces exact 256-bit targets, i128 intermediate bounds, truncation-towards-
zero division, Euclidean exponent fraction, checked shift saturation and
the aserti3-2d polynomial. It does **not** load state or choose an anchor:
the input is caller-supplied and therefore research-only.

The Go tests compare eight hard-coded Rust research targets and the independent
512-case frozen digest `6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97`.
The Python differential uses 10,000 seeded accepted-input attempts, then 1,024
deliberate failures (invalid targets, heights, spacing, half-life, i128 overflow).
Both accepted and rejected cases must agree. The input/response hashes are bound
to the exact scripted seed; a future changed source must generate a new report.

## One observed local execution (not native Rust acceptance)

- Date: 2026-10-26
- Go: `go1.23.2 linux/amd64`, Python: `3.13.5`
- Command: `go test ./... -count=1`: 3 Go test functions PASSED
- `go vet ./...`: PASSED
- Python/Go accepted-target matches: 10,000 / 10,000
- Python/Go invalid-input rejections: 1,024 / 1,024
- Input SHA-256: `ef9547e842ed6d4227581fb550e4ec809f688d13e60273fbf914f689634c3ee3`
- Accepted result SHA-256: `d6c2a8925241d366c45d9d63f597fe7fc4e1718b8c834cb7e58b8ed43755eafb`
- Rejected result SHA-256: `2131c52924cd8fd0b21186fda2a0d36ccb2d1da05e11fe3f7460d16966ad4e7c`
- Go binary SHA-256: `3e20b83d0adbe3a5e7b175c289bde1d30573e4137554a88f6397493b23b99cc6`
- Exact Go blob identities: `asert.go a3ff961100baed9f96b00ed8ed6ef7d073bd8777`,
  `asert_test.go da5005220772526dc9449608047df41a2b6c9cb9`,
  `cmd/daaoracle/main.go 2db0a056f3cb4bd007680c3422092890c3e2219a`.

The comparison used the previously prepared local Python oracle with the same
i128 and bounded-shift semantics present in the current research oracle. These
measurements were obtained in a container without a full Rust checkout.
The original Rust source at the branch tip has **not** been compiled or run in
this environment; the comparison is independent Go/Python mathematics, not an
exact-head native result. No simulated economic or service score was promoted.

## Release blockers retained

P0-A/B still require ordinary native W1, authenticated Q4 entry / 32-slot
lifecycle and independently verified client readbacks. P0-C requires cheapest
effective-work assessment, hostile proof admission and diverse hardware. P1-C
requires a separate versioned *native* DAA context with real fork/reorg and
cold-reopen. P2 requires independently administered sustained WAN, storage and
failure testing. Do not mark these as closed from this oracle.
