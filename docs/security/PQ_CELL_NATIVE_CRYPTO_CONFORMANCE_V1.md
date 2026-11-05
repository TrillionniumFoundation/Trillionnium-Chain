# PQN4 — Native PQ Cell chunk verification (RESEARCH / HOLD_NO_GO)

Parent: Chain PR #434 (`f4050776006ee67de1075fb247df7a848fb12447`), itself stacked on #431 / #427 / #424 / #419 / #417 / #413 / #408 / #406 / #405 / #399. This adds an independent native M09/M01 **read-only verification candidate**. It does **not** change installed PoN W1, PNW1, historical Ed25519 transactions, QTX1, Chainwork, fork choice, consensus parameters, Hepta Final-use, main, or any activation flag.

## Contract

- Source: `formal/pon-nakamoto-v1/pq_cell_native_verify.c`; executable `PQN4` compiled from C11 and OpenSSL EVP. It accepts **only** canonical PCC1 157-byte catalog, PCQ1 217-byte challenge, and PCR1 proof with an exact 3,487-byte TPQ1 purpose=5 genuine ML-DSA-65 signature.
- External caller **MUST independently pin** exact 48-byte expected catalog hash, 48-byte release manifest ID, 32-byte requester and nonce, and 32-byte provider key identity. Trust cannot be obtained by hashing bytes returned by the same untrusted peer. The tool never reads or authenticates on-chain state or signed PCB1/PCA1 release authority by itself.
- Catalog binds 32-byte network, 48-byte release ID, nonzero generation, total bytes 1..64 MiB, nominal chunk width 1..1 MiB, count 1..4096, and SHA-384 Merkle root. The final chunk must be exact declared remaining length. Merkle leaves bind index, count, exact chunk bytes/length. Tree levels use duplicate-last; sibling path count and odd-width duplicate are canonical.
- Challenge binds catalog hash, nonce, requester, provider key ID, generation/sequence/index, issued and expiry. Validity interval is at most 300 seconds; an interval mismatch, expired/too-early request, or caller identity mismatch fails closed.
- TPQ1 statement is reconstructed **independently**: domain-separated SHA-384 payload commitment over PCC1 catalog ID, challenge digest, chunk leaf and Merkle siblings, SHA-256 channel/context commitment, network, signer key ID, generation, sequence and expiry. The unsigned 176 bytes must exactly match the signed frame. Signature size must be 3309 bytes, public key exact ML-DSA-65 FIPS 204 DER SPKI (1952 public-key bytes, no parameter OID or alternate algorithm). EVP verifies actual signature bytes. Ed25519 is not an alternative.
- Opens only bounded regular files with `O_NOFOLLOW` on the final pathname; rejects symlink leaf, oversized/noncanonical frames and PEM key concatenation. It does **not** authenticate path ancestors or provide private key custody.

## Invocation

```sh
cd formal/pon-nakamoto-v1
cc -std=c11 -Wall -Wextra -Werror -O2 pq_cell_native_verify.c -lcrypto -o /tmp/pq_cell_native_verify
/tmp/pq_cell_native_verify catalog.bin challenge.bin response.bin provider_public.pem \
  EXPECTED_RELEASE_96_LOWER_HEX EXPECTED_CATALOG_96_LOWER_HEX \
  EXPECTED_REQUESTER_64_LOWER_HEX EXPECTED_NONCE_64_LOWER_HEX \
  NOW_U64 EXPECTED_PROVIDER_KEY_ID_64_LOWER_HEX
```

Success prints **only** `PQN4_VALID_RESEARCH_OBSERVATION_ONLY`. This is not `VerifiedWork`, model adoption, durable anti-replay, provider membership, storage-time proof, custody reward, Chain balance, Hepta authorization or independent evidence of release consent.

## Actual executed regression scope

`test_pq_cell_native_verify.py` generates real OpenSSL ML-DSA-65 keypairs and produces genuine signed TPQ1 frame bytes using an independent, bounded Python hash/encoding implementation. It cross-checks signatures using `openssl pkeyutl -verify`, then runs the C program in a separate process. It tests all 176 unsigned signature-header bytes and all 217 challenge bytes mutated one at a time, altered chunk and Merkle path, a legitimate provider-signed alternate self-consistent catalog rejected against the **original external pin**, signature replay across nonce/sequence, wrong signer, swapped purpose, expiry, frame truncation/extension, noncanonical catalog/chain context, symlink input and a full 1 MiB chunk.

Normal and `-fsanitize=address,undefined` test runs both passed 12/12 named tests on the recorded single host. Raw exact stdout/stderr and source Git blob SHAs are in `evidence/pon-pq-cell-native-v1/`. This is a local executable regression, **not independent cryptographic verification**; the independently implemented Python fixture generator is not an independent administrative operator.

## Unclosed blockers / HOLD_NO_GO

1. **Product-native Rust M09 and M01 integration missing.** This C binary is a research verifier only; its success string must never become a production authority flag.
2. **Caller authentication not provided.** Must obtain trusted release/current-generation/withdrawal context from the actual Chain + Hepta source owners and verify PCB1/PCA1, independent evaluation and public export permissions. The caller-supplied expected identity could itself be forged.
3. **No distributed availability proof.** One response only proves verified bytes at an instant; continuous retention, erasure repair, independent custodians, Sybil/eclipse resistance, channel replay, WAN DoS, network CPU cost and geographic diversity remain outstanding.
4. **Whole Chain not quantum safe.** Ed25519 production ledger/signers, native account and liability migration, M02 PoN quantum effective-work/Sybil security, M05-M08 reorg/anti-rollback, HSM/PKI, native public TLS/peer deployment, historical/physical failure and independent crypto/security acceptance are still open.
5. **No production promotion.** Neither `main` nor genesis/consensus/production flags should be modified by this research. Upstream #434/earlier are draft; new work remains Draft.
