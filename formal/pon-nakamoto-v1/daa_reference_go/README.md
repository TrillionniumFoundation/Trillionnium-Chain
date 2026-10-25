# PoN ASERT third-language arithmetic oracle (research only)

This standalone Go program is a **third, independently implemented** fixed-width
numeric oracle for the non-activated ASERT research candidate. It does not load
the Node, mine W1 proofs, validate signed tasks or change chain fork choice.

From the repository root, with Go installed:

    GO111MODULE=off go test -v ./formal/pon-nakamoto-v1/daa_reference_go
    go run formal/pon-nakamoto-v1/daa_reference_go/main.go --fixtures
    go run formal/pon-nakamoto-v1/daa_reference_go/main.go --parent-time=2000 --height=80

The first command includes five scalar vectors, bad context, i128 overflow,
full-width positive/negative saturation and a **512-case SHA-256** output
commitment. The second command emits:

    6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97

That digest is over **512 consecutive big-endian 32-byte full PoN targets**
from the exact xorshift64 case stream also implemented in Rust and Python;
it is not a digest of source or of mining probabilities. The interpreter uses
Go standard-library math/big, signed big-integer deviation and Euclidean
fraction extraction. The test guards i128 boundaries before exponentiation.

The single-case CLI accepts 64-character target/limit hex, uint64 timestamps,
anchor/candidate heights, spacing and half-life. It uses PoN's exact 256-bit
target rather than BCH's compact nBits encoding, so it is not a Bitcoin Cash
consensus implementation. It does not authenticate its caller-supplied anchor.
Any future consensus implementation must independently bind anchors to a
fully validated candidate-branch ancestry and a distinct genesis context.

Observed in the research workspace on 2026-10-25: Go's local test run passed
both tests and produced the declared 512-case digest. No Rust compiler is
installed in that local container; Rust's corresponding source-level test has
not been executed in that environment. Agreement between three implementations
written within one development effort is **not independent institutional
security review**. Work hardness, ASERT attack resistance, WAN liveness,
timestamp incentives and production eligibility remain unaccepted.
