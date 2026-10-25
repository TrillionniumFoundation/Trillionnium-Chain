# P6 Go reference verifier for canonical W1 and W2-C research vectors

Status: **standalone research; NO production or consensus authority**.
Source: 'formal/pon-nakamoto-v1/go_oracle/w1.go'.
Tests: 'formal/pon-nakamoto-v1/go_oracle/w1_test.go'.
Go 1.23 standard library only; no Rust, Python, remote packages, or
third-party cryptographic backend is imported.

## Independent arithmetic implementation and scope

The Go verifier uses SHA-256 with the original length-tagged
'TRNM-PON1\0' wire domain and exact little-endian width checks. It
independently recomputes four challenge-generated noise arrays,
64x64 low-rank-encoded operands, every one of the 512 transcript tiles
in the unchanged (bi,bj,bk,i,j) order, exact SHA-256 streaming digest,
useful product C=AB via the existing decoding identity, canonical
TaskId and ticket<=target.

Go deliberately computes each product modulo q using uint64 and
modularizes each addition; this differs from Rust's u128 schedule
and Python arbitrary integers. Its 64x64 field operands fit uint32
and each scalar product fits unsigned uint64 before modulus.
This verifies arithmetic/byte agreement over supplied finite vectors,
not optimal miner hardness or hostile public-service scheduling.

Four registered research tests check:
1. A genuine deterministic dense W1 proof's TaskId, full 49,188-byte
   SHA256 commitment, transcript SHA256 digest and acceptance, against
   independently frozen Python/Rust-compatible literal expected hashes.
2. Four from-zero fake traces all pass the cheap ticket precheck on
   one challenge/target and all fail on full 'Transcript'.
3. The W2-C synthetic Header, forged proof commitment and two
   security-ticket nonces have exactly the same output as the frozen
   Python vector, yet that forged W1 still fails full verification.
4. Malformed length/magic/noncanonical field/wrong task/zero target
   reject before full replay, while altered transcript and C fail at
   their proper late mathematical boundaries.

## Executed local Go reference result

The research module was compiled and run with actual Go 1.23.2 on
October 25, 2026 in a local Linux container using:

    cd formal/pon-nakamoto-v1/go_oracle
    GOWORK=off GOPROXY=off go test ./... -v

The separately staged source-equivalent module completed all four
Go tests successfully in approximately 20 ms total. This is NOT a
frozen current Git SHA native Rust test or an independently operated
reviewer. Go module tests are deliberately outside production
Cargo/workspace and are not delegated permission to construct
'VerifiedWork', adjust DAA or mutate Chain State.

## P6 acceptance still open

A third source implementation in another language adds valuable
differential arithmetic evidence but **does not** constitute
cryptographic peer review, professional assessment of W1 hardness,
a sound STARK/SNARK implementation, a review of invalid-input
resource behavior or independent-operator WAN acceptance.

External reviewers need full code and golden vectors; independently
chosen hidden valid and malformed work/circuit witnesses; an exact
protocol/version/genesis commitment; independent hardware and operator
custody; concrete security assumptions; and signed retained artifacts.
Until then P6 remains OPEN and all public/model authority stays off.
