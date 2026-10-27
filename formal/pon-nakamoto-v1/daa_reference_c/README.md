# Independent C ASERT integer oracle (research only)

This module independently evaluates the existing candidate ASERT formula using
four 64-bit target limbs, nine bounded scratch limbs and GCC/Clang unsigned
128-bit arithmetic. It does not import or call the Rust, Go or Python
implementations. It is NOT a mining primitive, native M02/M07 owner, signed
task/evidence verifier, or PoN consensus activation.

The adjacent `../test_asert_c_oracle.py` builds the exact C source and
compares all 512 fixed Go-generated target vectors with the Python exact-integer
oracle and the independently frozen digest:

`6be87e237c37aec8c50af8d4eaf9e14a0ca60e7dc69f18143ede1ef70c420c97`.

A separate seeded 1,500-case campaign covers 256-bit target bounds, u64 time
extremes, i128 multiplication/shift overflow refusals, zero targets and
saturation; seven malformed numeric contexts must fail closed. The Python
reference used is the existing `../daa_research_oracle.py` on this exact PR
base. No signed Q4/PNW1 bytes, old DAA or production activation are changed.

Run from `formal/pon-nakamoto-v1` on a GCC/Clang host:

```sh
python3 -m unittest -v test_asert_c_oracle
CC=clang python3 -m unittest -v test_asert_c_oracle
clang -std=gnu11 -O1 -g -fsanitize=address,undefined \
  -fno-omit-frame-pointer -Wall -Wextra -Wconversion -Werror \
  -o /tmp/asert-oracle-c-san daa_reference_c/main.c
```

A local source-matched execution using Clang passed all three named Python
test methods (512 frozen cases + 1500 seeded random cases + seven negative
contexts), then reran them under ASan+UBSan. C source blob:
`d082e6d4a15002d496fbf13de7a66d61732f32fb`;
Python test blob: `b5b67d50af854ac930db265aec387cf5fc87f10d`.
The exact C and Python blobs executed locally were byte-for-byte matched with
these published Git blobs. The local Python oracle was a copy of the previous
research oracle with its explicit extreme-exponent saturation fix; the complete
GitHub PR Python runtime was not recreated on this host, so no full-PR exact
source qualification is claimed.

Remaining obligations: actual candidate Rust compilation/execution, hidden
external independent vectors and operators, authenticated versioned ASERT
consensus context, native W1 real mined forks/recovery/client confirmation,
plus work-cost/Sybil and sustained independent WAN acceptance.
