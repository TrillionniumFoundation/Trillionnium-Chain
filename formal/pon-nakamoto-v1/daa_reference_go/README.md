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

## Dynamic Go ↔ Python differential execution

From the repository root (requires a local Go compiler and Python 3):

    python3 formal/pon-nakamoto-v1/daa_go_differential.py --output NEW_NONEXISTENT_REPORT.json

The driver compiles Go into a disposable temporary directory, executes the
actual Go binary for 128 seeded inputs and compares each response with the
separate Python exact-integer research oracle. It includes very large u64
timestamps, varied valid targets, seven half-lives and i128 overflow cases.
Go and Python must agree on all exact accepted values and typed range
refusals. The case stream is deterministic and cannot pass by comparing
two hardcoded report files.

Locally observed on 2026-10-25: 111 targets, 17 range refusals, zero mismatches.
The SHA-256 over canonical per-case result rows is
`46c785d0954adf4ebc11b446768b4ab724b1e6892ffde9b2525121f21a62e132`.
These are numeric differential results, **not** actual native Rust execution
or consensus/PoW qualification.

