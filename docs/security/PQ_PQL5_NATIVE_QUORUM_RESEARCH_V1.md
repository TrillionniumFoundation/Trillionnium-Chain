# PQL5N — independent native ML-DSA-65 quorum verifier (HOLD_NO_GO)

This is a read-only native C11/OpenSSL 3.5+ research oracle for the PQL5 challenge-fresh witness responses in pq_pql5_quorum.py. It is stacked on Chain PR #458 at 192480f0c5e1fa6077c8c3bc2b9e1790a02c0552.

It is NOT a non-rewindable checkpoint authority, trusted source auditor, on-chain PQ account owner, Node consensus rule, Chainwork evidence, Hepta FinalUse or deployed service. Do not merge or activate it as whole-chain post-quantum security.

## Fixed inputs and native verification

The binary requires exactly three caller-pinned ML-DSA-65 public keys, two or three signed PQL5 responses and exact independently pinned network/import/genesis, fresh 32-byte caller challenge, latest 64-bit sequence and 48-byte frontier ID. Pins and trusted key roster are not issued or verified by this utility.

Keys must be canonical OpenSSL public PEMs: ML-DSA-65 SPKI OID 2.16.840.1.101.3.4.3.18, no algorithm parameters, raw public key length 1952, distinct domain-separated SHA-256 key IDs, regular bounded no-symlink leaf files and no appended PEM data. It refuses Ed25519 downgrade.

PQL5 reply size is 269 unsigned bytes + big-endian signature length 3309 + exactly 3309 real ML-DSA-65 signature bytes (3580 total). The signature covers the bytes of the domain TRNM/PQ/PQL5Witness/v1 followed by a NUL byte and the exact 269-byte response header. Enforce PQL5 version, signer identity, network, import root, genesis, challenge and an observation time not later than caller time, a 30-second expiration interval and no arithmetic wrap. Empty heads cannot authorize a quorum.

The highest observed signed sequence is selected. At least two distinct pinned keys must agree on one frontier ID at that same highest sequence; it must match the externally supplied latest sequence and hash. A lone higher sequence is not discarded in favor of an older majority. Invalid, missing, duplicated and contradictory evidence fails closed.

The tool returns 0 only for PQL5N_VALID_RESEARCH_OBSERVATION_ONLY; rejected input returns 2, PQL5N_REJECT. It performs no database or network mutation and cannot sign or issue model, ledger or final-use authority.

## Reproduction

In formal/pon-nakamoto-v1:

    cc -std=c11 -Wall -Wextra -Werror -O2 pq_pql5_native_verify.c -lcrypto -o /tmp/pql5-native-verify
    /tmp/pql5-native-verify NETWORK64 IMPORTROOT96 GENESIS96 CHALLENGE64 NOW_UINT64 EXPECTED_SEQUENCE EXPECTED_FRONTIER96 WITNESS0_PUB.pem WITNESS1_PUB.pem WITNESS2_PUB.pem RESPONSE_0.bin RESPONSE_1.bin [RESPONSE_2.bin]

    PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql5_native_verify.py
    PQL5N_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql5_native_verify.py

The isolated exact source tests completed 14 PASS, 1 SKIP, 0 FAIL in each normal and sanitizer run. The one skipped case imports upstream pq_pql5_quorum.verify_quorum, unavailable on the isolated code host; in a complete PR #458 stacked checkout it must be re-executed. Native/Python exact-parent parity is NOT qualified by this run.

Tests use actual fresh ML-DSA-65 keypairs and signatures, every one of 269 signed header byte mutations, malformed signatures, Ed25519 downgrade, signer duplication, wrong network/genesis/import/challenge, expired/future response, caller numerical errors, split/higher heads, symlink/noncanonical keys, and oversized inputs.

## Security limitation preserved as a real negative

An attacker who rewinds two witness stores while censoring the third can make a genuine fresh 2/3 signature over an older checkpoint. This C verifier detects that rollback only if the caller independently retains the newer exact sequence and frontier ID. If the caller's trust pin is also rewound, the old quorum still verifies. This is deliberately a passing *counterexample* test, not an antirollback success.

A real independent non-rewindable anchor, separately administered signer keys/HSM, rotation and revocation, hostile cross-operator WAN and power-failure trials are still missing. Production activation and independent acceptance remain false. So do native Rust consensus M00-M17 integration, PQ migration of all historical liability/nonce state, authenticated PQ peer deployment, Hepta final-use and independently qualified quantum-effective PoN work hardness.
