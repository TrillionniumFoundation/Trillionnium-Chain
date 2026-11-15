# PQL10: canonical PEM source binding for the offline ML-DSA TPQ1 oracle

Status: **RESEARCH ONLY / HOLD_NO_GO / DO NOT ACTIVATE**.

Exact frozen parent: PR #489 at `8679d86a75b4d5822d89180888bc8c2db4dc64d2`, inheriting #486 at `8d29130ecf5124d21449f0f1d549aacc27de99ad`. Installed Chain consensus, W1/PNW1, legacy Ed25519, Chainwork, model release/Final-use, 2,048-byte transaction ceiling and all deployment/activation controls remain unchanged.

## Reproduced acceptance alias

The previously committed native `pq_tpq1_native_verify.c` (Git blob `f3aeade9774b1df116fd10c2449404b07ec36afb`) used `PEM_read_bio_PUBKEY` followed by `i2d_PUBKEY`. The underlying OpenSSL decoder can silently skip a leading, unsigned PEM preamble and can ignore **extra DER bytes within an otherwise valid PEM base64 block**; the later canonical reserialization erased evidence of that alternate source representation before deriving the SPKI key ID.

An independent regression with a genuine ML-DSA-65 key, 176-byte TPQ1 statement and real 3,309-byte signature demonstrated all three noncanonical inputs being **accepted as signature-valid** by the exact original native C source: prefixed extra prose, a PEM-wrapped DER value with appended unparsed bytes, and noncanonical trailing whitespace. This is an input-representation ambiguity, **not** an ML-DSA signature forgery or proven Chain consensus exploit. The original C source's existing 5-test suite did not cover these three aliases.

## Minimal fix and exact contract

After decoding and algorithm checking, the existing offline C verifier now writes the candidate `EVP_PKEY` into a canonical, single OpenSSL SubjectPublicKeyInfo PEM via `PEM_write_bio_PUBKEY`, then requires a length- and byte-exact comparison to **the original supplied PEM file** before deriving the SHA-256 domain-separated SPKI identity or verifying the real signature. It retains the existing exact 1,974-byte DER prefix/algorithm test, purpose/network/context/key/generation/sequence/expiry bindings, 64 MiB payload cap, symlink/single-link checks and real `EVP_DigestVerify` path. No private-key I/O or production authority is added.

This deliberately rejects alternate but otherwise parseable PEM encodings, including CRLF/preamble/trailing formatting, until a separately reviewed versioned input-format negotiation exists. An independent caller must still authenticate the expected key ID and may not promote the diagnostic result to any Chain capability. The added test file is `formal/pon-nakamoto-v1/test_pq_tpq1_canonical_pem.py`.

## Actual executed local evidence

On Linux 6.18.55 x86_64, Python 3.13.5, Debian GCC 14.2.0 and OpenSSL 3.5.5:

- Prepatch test against **exact original** `f3aeade9...`: 7 tests, **3 expected failures**, specifically leading PEM preamble, hidden DER trailer and trailing spaces. This is a reproduced negative, not a passing original security test.
- Patched source `9f4aec3b83176709fd4e09ef5d150c087df7268c` plus new test `cbcf1766c0115f792f59d643e71df4d385e76310`: **7 PASS, 0 FAIL**.
- Same new tests with native `-fsanitize=address,undefined`, leak detection and halt-on-error: **7 PASS, 0 FAIL**.
- Reconstructed **byte-for-byte exact upstream inherited** PQL9 test (`1d4fe6a89a44faafadbb5cab1343d5849b66ab2e`): with patched source and new tests **12 PASS, 0 FAIL**, including genuine signatures for all 6 TPQ1 purposes and all 176 signed-statement byte flips.
- Executed source/test Git blob identities match the pushed branch files. The three actual passing raw logs are under `evidence/pon-pq-pql10-pem-source-v1/`.

Commands:

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_tpq1_native_verify.py test_pq_tpq1_canonical_pem.py
PQL10_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_tpq1_canonical_pem.py
```

## Still OPEN — no production security claim

- Rust/Cargo and full exact-stack multi-branch integrated test: **NOT_RUN** (no Rust toolchain/full checkout). No remote CI status is used as passing evidence.
- True signer authorization, HSM custody, rotation/revocation, independent ML-DSA verifier audit, M00–M17 native transaction/account/nonce/fee/reorg/legacy liabilities and durable final use.
- ML-KEM hybrid authenticated public P2P, independent multi-operator WAN storage, external monotonic antirollback and quorum under compromised witnesses.
- W1 quantum-effective work hardness, hostile false-work admission cost, physical power loss, Sybil/economic bounds and independent third-party production acceptance.

**Do not merge to main, auto-approve or activate the Chain from this local research hardening.**
