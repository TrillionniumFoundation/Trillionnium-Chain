# Standalone Go W1 conformance oracle

Status: **RESEARCH_ONLY / HOLD_NO_GO**. This independent arithmetic source
creates no native Chain, VerifiedWork, Chainwork, ledger or public-service
authority. It is standard-library Go, separate from the Python implementation.

## Selected source and ordinary controls

The original source is retained from
`658b61cacc539f0c4faf1216f7ff10a77a0bd4d7`. The selected implementation
and bounded `cmd/pon_w1_io` bridge preserve complete W1 proof arithmetic,
canonical fields, task/target checks, full transcript replay and product checks.
The bridge caps each input before decoding. Go source is formatted with gofmt.

`go_oracle/w1_conformance_test.go` retains the original known reference vector
and ordinary malformed-field/length/context/data rejection controls. It has
**two** test functions. Historical cost/falsification drivers in the original
`w1_test.go` remain at their original source; their old four-test count is not
the selected conformance count.

`test_go_w1_cross_language.py` runs ten bounded cases. Each compares all
49,188 proof bytes and calls both the Go verifier and the original Python
full W1 verifier on the same valid proof. Ordinary data corruption and
packet-shape controls remain part of that local conformance scope.

## Observed consolidation result

On source `36ac2df36c3f213c6624d525bd3d09fb743d9e9a`, actual
`go1.27.4 linux/amd64` completed two Go tests and two Python test methods,
including ten full-byte parity cases. The build used the installed Go
toolchain with `GOTOOLCHAIN=local`, `GOWORK=off`, `GOPROXY=off` and
`GOSUMDB=off`. No package download was needed. The exact command, source
bracket, full log and per-case hashes are retained in
`evidence/branch-consolidation-20261113/w2/validation/`.

The original October Go1.23.2 observation and its broader historical suite
remain source-bound in the original branch documentation. These observations
do not establish an independent operator review, global attack-cost bound,
native Rust integration, physical deployment acceptance or production safety.
