# PQL9 executed native TPQ1 cryptographic oracle

**Research only / HOLD_NO_GO**. Parent PQL8 #486:
8d29130ecf5124d21449f0f1d549aacc27de99ad.
Selected research branch:
research/pq-pql9-general-tpq1-verifier-20261027.

The actual local Linux x86_64 environment has Python 3.13.5,
GCC 14.2.0, Clang 17.0.0 and OpenSSL 3.5.5. No Rust/Cargo toolchain.

Actual source and matching published GitHub blobs:

| Item | SHA-256 | Git blob SHA |
|---|---|---|
| native C verifier | a14ef90b94642e3fdbe5b85dd8ed74266a432dda36c687325bc938772881b57a | f3aeade9774b1df116fd10c2449404b07ec36afb |
| native Python tests | 64885bc220ff2530e56fb5993afa85889b4a7999e5c0e79a1e9b84861c3c80b5 | 1d4fe6a89a44faafadbb5cab1343d5849b66ab2e |

Compiler commands performed on the above exact source:

    cc -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
       pq_tpq1_native_verify.c -lcrypto -o pq_tpq1_native_verify

    clang -std=c11 -O2 -Wall -Wextra -Werror -Wpedantic \
       pq_tpq1_native_verify.c -lcrypto -o pq_tpq1_clang_verify

    cc -std=c11 -O1 -g -fsanitize=address,undefined \
       -fno-omit-frame-pointer -Wall -Wextra -Werror -Wpedantic \
       pq_tpq1_native_verify.c -lcrypto -o pq_tpq1_asan_verify

Execution:

    cd formal/pon-nakamoto-v1
    python3 -m unittest -v test_pq_tpq1_native_verify.py

Normal executable: **5 PASS / 0 FAIL**. The same test suite was rerun
using a compiler wrapper that adds GCC ASan+UBSan flags: **5 PASS /
0 FAIL**; no sanitizer errors in observed output.
Raw captured logs: native-test.log and native-sanitizer-test.log.

These tests generated real ephemeral ML-DSA-65 public/private keys
and signatures, and checked all six purpose domains; fake signatures
and classical Ed25519 keys failed as required. Python's byte
construction and the native OpenSSL verifier independently agree on
the prescribed SHA-384 commitment for the frozen public payload.

This is **not** complete PQ native Rust Chain verification. Independent
cryptographic audit, real signer custody, durable replay/fork ownership,
Hepta FinalUse, public WAN, W1 mining quantum safety and physical
power-loss tests remain **NOT_RUN / OPEN**. No production capability
is granted by a local 0 exit status, and all activation flags are false.
