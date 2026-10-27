# ASERT C11 fixed-width independent research oracle

Scope: P1-A/M02/M17 research under the [one existing PoN development plan](../../TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md) and [Lease × DAA research](LEASE_DAA_RESEARCH_V1.md).
No existing PoN target, Q4, W1, Revision12, chainwork, genesis, storage, production eligibility or activation flag is changed.

## Deliverable and tested scope

- \`formal/pon-nakamoto-v1/daa_asert_c_oracle_v1.c\` is a standalone C11 verifier for the existing research ASERT arithmetic. It uses unsigned \`__int128\` for checked time-span and exponent arithmetic, nine explicit little-endian 64-bit limbs for target operations, checked canonical input parsing, and fixed small/large target saturation. It shares neither Python's bignum implementation nor Rust's \`Work\` implementation.
- \`formal/pon-nakamoto-v1/test_daa_asert_c_oracle_v1.py\` builds the C implementation using a real C compiler (\`-Wall -Wextra -Werror\`) and compares actual process outputs with the independent Python \`daa_research_oracle.asert_target\` on 4,096 multiwidth randomized-but-frozen cases, 300 explicit extreme cases, malformed/range failures and a relative-time translation property. No synthetic success stub or skipped missing compiler is accepted.
- Fixed SHA-256 digests of complete newline-terminated C outputs: 300-case grid = \`2f2eee7b3540d91aa7857718975dfd04dbbcdbf5ecb49c265a85d680dd18d0fa\`; 4096-case grid = \`01db959e9b902100257d873f6ee467bcad937a53a0738f2ad79650fdb45d636b\`.
- The local Python 3.13 + GCC x86-64 research run on 2026-10-26 executed all four C oracle test selectors with PASS, and the separate pre-existing local eleven-test Lease/DAA research subset passed. Exact local C source Git blob = \`98efbbd0efae56710da9f5d7a5020e36a7dcf5af\`; exact test source Git blob = \`1d37e09486c3e66240cb45d9521a80a40ab92bfe\`. The full GitHub research branch's current Python oracle and new Rust selectors were not executed on that host.

Reproduce from the repository checkout:

\`\`\`sh
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_daa_asert_c_oracle_v1.py
\`\`\`

## Authority and limitations

This C verifier accepts only caller-supplied integer material; it does not examine W1 or Node headers, independently validate a branch anchor, verify consensus task eligibility, or possess block/adoption/reward/FinalUse authority. C/Python agreement is a cross-implementation arithmetic observation, not a proof of network time validity or adversarial cost hardness. The \`__int128\` dependency means this build is a GCC/Clang-capable native research target, **not** MSVC portability acceptance. Test source presence does not close P1-A native Rust exact-head execution, P1-B real fork/clock simulation, P1-C native versioned consensus acceptance, or P2 independent WAN/hardware operation.

Existing old 16-block DAA and all existing source namespaces are unchanged. Production remains disabled.
