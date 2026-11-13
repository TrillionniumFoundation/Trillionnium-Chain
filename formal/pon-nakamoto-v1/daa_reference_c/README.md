# ASERT third-language C/GMP oracle — research only

The independent C source evaluates fixed-point ASERT targets with GCC signed
128-bit overflow checks and GMP exact 256-bit arithmetic. It is not a native
PoN verifier, an independently administered scientific audit, or a production
DAA profile. It makes no consensus or activation changes.

To run explicitly on a machine with gcc, GMP headers/libs and Python:
cd formal/pon-nakamoto-v1/daa_reference_c
python3 test_reference.py

On 2026-10-27 the original local GCC 14.2.0 / Python 3.13.5 run passed
three unittest methods: 512 frozen comparisons comprised 472 exact C/Python
target matches plus 40 matching refusals. Strict -Wall -Wextra -Werror
compilation passed. All observations are same-admin local arithmetic only.
Rust exact-source build, W1 native work, WAN, external actor independence,
cheapest cost security and production admission remain unqualified.
