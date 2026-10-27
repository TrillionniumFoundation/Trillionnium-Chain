# ASERT full-width extreme-differential local execution (2026-10-27)

Status: **research only**. This is NOT a qualified PoN consensus version or
a deployed DAA. No old Q4, Revision12, current target rule or W1 proof changes.

Executed on one local Linux x86_64 CPU host with GCC 14.2 / GMP and Python.
The exact source bytes were checked using Git blob identities before execution:

- C/GMP `formal/pon-nakamoto-v1/daa_reference_c/target.c`: `1beb15faaba7d82757d426ab9e08fdce1e0e4b28`
- Python `formal/pon-nakamoto-v1/daa_research_oracle.py`: `5cce6222769f1ab2f968516f15fcdf330fb695bd`

```sh
python3 formal/pon-nakamoto-v1/daa_reference_c/test_extreme_differential.py
```

The runner compiles the existing C source locally and compares **4,096**
seeded extreme-boundary inputs with the separately implemented Python oracle.
It covers random 256-bit target magnitudes, u64 timestamp extremes, half-lives,
activation-height gaps, large spacing values and i128 overflow refusal.

Recorded local outcome: **3,055 matching valid targets, 1,041 matching
refusals, zero differing validity/output outcomes**. The complete deterministic
input/outcome digest is
`694d68fc84e7dce207336870eebf9a76c2440d0b7cfb586a752d153e2655191d`.

The observed output is frozen in `report.json` and tied to source and compiled
binary SHA-256 values. It is a sampled arithmetic comparison, NOT proof of
universal ASERT correctness, Rust native execution, time-warp resistance,
W1 marginal cost, economic incentive security or independent operator acceptance.
Production flags remain disabled. Full exact-head repository gates are NOT_RUN
in this local tool environment; do not repin earlier results to later source.
