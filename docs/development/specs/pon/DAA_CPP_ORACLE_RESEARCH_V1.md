# PoN ASERT independent C++ arithmetic oracle (research-only)

This is a subordinate P1-A/M02/M17 experiment under the sole development plan
[TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and existing [Lease × DAA study](LEASE_DAA_RESEARCH_V1.md).

It adds no consensus profile, signing authority, W1 verifier, ledger operation,
production activation, CI gate, or competing database. Revision9 Q4, Revision12
Genesis Maintenance, existing 16-block retarget and Rust target selection remain
byte-for-byte untouched.

## Independent executable

- \`formal/pon-nakamoto-v1/daa_cpp_oracle.cpp\`: C++17 + Boost.Multiprecision
  target evaluator, with signed i128 range checks, mathematical floor
  exponent split, aserti3-2d polynomial and saturating target bounds.
- \`formal/pon-nakamoto-v1/daa_cpp_differential.py\`: source-bound Python/C++
  campaign, 512 Rust-test-derived deterministic cases plus 2048 seeded
  adversarial cases, exact output and negative-case comparison.
- \`formal/pon-nakamoto-v1/test_daa_cpp_differential.py\`: six runnable
  test methods for malformed/oversized input, rejection, saturation,
  frozen digest, repeatability and differential correctness.

Run from \`formal/pon-nakamoto-v1\` using Python 3.13+ and a C++17 compiler
with the Boost multiprecision header installed:

\`\`\`sh
python3 -m unittest -v test_daa_cpp_differential.py
python3 daa_cpp_differential.py --compiler g++ --output /absolute/new/gcc-report.json
python3 daa_cpp_differential.py --compiler clang++ --output /absolute/new/clang-report.json
\`\`\`

The C++ oracle's input is eight whitespace-separated fields in fixed order:
64-character lowercase anchor target, 64-character lowercase pow limit, then
unsigned 64-bit anchor predecessor time, parent time, anchor height, candidate
height, target spacing and half-life. Each line returns one exact unsigned
256-bit target or a typed error. The C++ process caps each invocation at
4096 records and does not accept network inputs or model code.

## Local measured scope

A single local Linux x86_64 environment compiled the source with GCC 14.2
(\`-std=c++17 -O2 -Wall -Wextra -Werror -pedantic\`) and separately with
Clang 17. GCC ran the six test methods and both GCC and Clang independently
ran the complete 2560-case differential with zero mismatches and the same
complete output digests. The C++ source is identical between compilers.

The fixed 512-case concatenated 32-byte target digest equals
\`6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97\`,
the digest embedded in the Rust research test. The 2048 further seeded
cases include 1200 target outputs, 663 parameter refusals and 185
i128-range refusals, all matching the exact Python oracle from the
stacked base at Git blob \`5cce6222769f1ab2f968516f15fcdf330fb695bd\`.
The original source SHA256 and outcome digests are preserved in
[initial evidence](../../../../evidence/pon-daa-cpp-oracle-local-20261026/report.json),
[GCC report](../../../../evidence/pon-daa-cpp-oracle-local-20261026/report-gcc.json)
and [Clang report](../../../../evidence/pon-daa-cpp-oracle-local-20261026/report-clang.json).

No Rust compiler, native W1 block, independent mining operator, source-signing
key, public network, hardware cost-hardness evidence, physical restart,
or consensus-activation test was run. Three languages authored within
one development effort are **not** independent institutional review.

## Strict non-closure

P1-A still requires Rust current-source native execution, independent hidden
vectors and external review. P0-A/P0-B need real signed, W1-verified
long-retention and receipt tests; P0-C needs legal cheapest-producer economics
and hostile network verification; P1-B/P1-C need real native fork-aware
activated-context tests and DAA/withholding analysis; P2 requires independently
operated WAN acceptance. Do not promote readiness flags or reinterpret history.
