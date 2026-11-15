# PQN2 native PQG1 dual-possession verifier (RESEARCH / HOLD_NO_GO)

Exact parent is Chain PR #431: commit `c62339bc255b8ba59f1081552c1351109cded287`. This is an **offline C11/OpenSSL conformance oracle**, not the installed Rust M01 signer, M13 importer, M02 consensus, HSM custodian, Node/Hepta authority, or a launch configuration. W1/PNW1, Ed25519 ledger, QTX1, Chainwork, fee policy, and activation flags are unchanged.

## Proof contract

The binary takes four regular files and refuses a symlink leaf or oversized input:

- **PQG1 source snapshot**, <=65,536 bytes, 1..128 sorted unique Ed25519 accounts, <=256 sorted unique liabilities. Fields include distinct old/new networks, old head, withdrawal frontier, new protocol hash, issuer supply, account balances, retained next-nonce/generation and task/escrow/quota/reward liabilities. Account balances plus liabilities must equal supply without overflow.
- **PQA1 expected anchor**, exactly 292 bytes: magic(4), externally verified SHA384 source digest(48), old network(32), new network(32), old head(32), withdrawal head(32), profile(32), issued units(8), expected old key(32), expected ML-DSA-65 key ID(32), observation time(8).
- **PQM1 single-owner claim**, exactly 3449 bytes: magic(4), old Ed25519 public(32), new key ID(32), expiry(8), Ed25519 signature(64), ML-DSA-65 signature(3309).
- **ML-DSA-65 SPKI PEM**, <=8192 bytes. OpenSSL EVP verifies pure ML-DSA-65 and requires the exact canonical DER SPKI OID, 1952-key-byte structure, domain-separated SHA256 key ID and no trailing non-whitespace PEM payload.

Both signatures cover the *same exact* upstream PR #431 migration statement:

```text
TRNM/PQ/GenesisMigration/v1\0 ||
SHA384(TRNM/PQ/GenesisSource/v1\0 || BE64(len(PQG1)) || PQG1) ||
old_network || new_network || old_head || withdrawal_head || profile ||
LegacyAccount56 || new_MLDSA_key_id32 || BE64(old_generation+1) || BE64(expiry)
```

Old Ed25519 uses strict RFC 8032 compressed curve-point and signature-R checks, low-order point rejection and canonical S below group order, followed by genuine OpenSSL Ed25519 signature verification. Boolean attestations and classical-only fallback are never accepted. A passing result prints only `PQN2_VALID_RESEARCH_OBSERVATION_ONLY`: **no account, ledger, reward, consensus work, model release or Final-use can be issued**.

## Executed local conformance

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pqg_native_verify.py
PQN2_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pqg_native_verify.py
```

Measured on local Linux x86_64, Python 3.13.5, OpenSSL 3.5.5 and Debian cc 14.2.0: **17/17 normal and 17/17 ASan+UBSan passed**, 0 failures. The test source and native source Git blobs match the executed local files. Cases include real two-key signatures, two conserved liabilities, changed anchor/source, wrong key/network/profile, tampered old/PQ signature, expiry, low-order Ed25519 points, noncanonical R/S, supply overflow, foreign liability owner and symlink refusal.

## Still OPEN — do not activate

1. A self-consistent anchor created by an attacker is not trusted. Production requires independent old-chain source-tip, revocation/effect-frontier, liability, issuance and migration-governance evidence. Dual signatures cannot protect an old Ed25519 identity already forged by a quantum-capable adversary.
2. This verifies **one** migrated owner only. A complete import must preserve all accounts, quarantines, outstanding liabilities and same-key uniqueness across the whole network with independently pinned checkpoint and durable recovery.
3. PQL1 currently initializes every account `next_nonce=1`, does not carry PQG1 liabilities or quarantined identities, and computes a different genesis ID. **It cannot safely ingest these records.** New versioned native state/import protocol is mandatory.
4. Product Rust M01 implementation, HSM/key lifecycle, PQ TLS/RPC node, independent adversarial WAN/power failure, quantum PoN work-hardness and full Hepta/Cell authority are unimplemented/unqualified.

All consensus-production and post-quantum activation flags must remain **false**.
