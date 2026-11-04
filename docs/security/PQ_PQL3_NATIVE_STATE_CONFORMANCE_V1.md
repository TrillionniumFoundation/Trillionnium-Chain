# PQL3 — independent native PQ genesis/liability projection verifier (HOLD_NO_GO)

Parent: the existing PQ research stack through PQL2, Chain PR #442 at `6c63f18795e8937e7e8ea11b757fcdbd2ff1e59c`. This is an **additive read-only C11/OpenSSL implementation**, not an installed native Rust M05/M07/M08/M13 source-state owner. No consensus rule, installed transaction, historical Chainwork, W1/PNW1, account, signed key, HSM, FinalUse, storage namespace, deployment, or activation flag is changed.

## The concrete invariant

PQL1's clean-fixture genesis sets `next_nonce=1` and has no imported task/reward/quota/escrow liabilities. It MUST NOT be handed actual PQG1 state. PQL2's existing Python projection preserves the inherited nonce floors, tracks quarantined balances, and carries all four liability kinds. `pql3_native_verify.c` independently parses and reconstructs **the same bytes**, checks the exact externally pinned source, projected root and genesis, and rejects any mismatch. A code comment, digest or `PQL3_VALID_RESEARCH_OBSERVATION_ONLY` output is not a trusted-account capability.

The checker does NOT verify signatures: before any meaningful use, the independent M13/source and revocation owners must authenticate the old-chain historical state, liability completeness and freeze cutoff, then the upstream PQG1 `verify_handoff` must verify real strict Ed25519+ML-DSA-65 possession on every migration. Even dual possession cannot retroactively secure an already-compromised Ed25519 signer. The checker itself never issues that admission or checks an external reviewer identity.

## Four bounded regular-file inputs

```text
pql3_native_verify PQG1.bin PQS1.bin PQL2.bin PQLP.bin
```

A successful check prints exactly `PQL3_VALID_RESEARCH_OBSERVATION_ONLY` and exits 0. Any failure exits 2 with `PQL3_REJECT`. No mutations, network calls, private keys or issuer operations occur. Input files must be regular, non-symlink leaves (O_NOFOLLOW), and must not exceed 64KiB; the PQLP anchor is exactly 365 bytes. This does not protect hostile ancestor directories, rollback of an external anchor, or a concurrent writer who controls all files and independently accepted pins.

**PQLP anchor grammar (big endian)**: `PQLP` 4-byte magic, version 1 byte; independently fixed PQG1 SHA-384 digest 48; PQS1 SHA-384 state root 48; target genesis ID 48; PQL2 projected state SHA-384 root 48; old network32, new network32, old head32, withdrawal head32, protocol identity32, issued supply u64 (8). All expected roots and contexts must come from an independently authenticated caller, **not** from the source file being verified. PQLP is an input format, not a signed checkpoint format or a source-authority certificate.

Source digest uses `SHA384("TRNM/PQ/GenesisSource/v1\\0" || BE64(len) || PQG1)`. Target state uses `TRNM/PQ/GenesisState/v1\\0` and PQL2 output uses `TRNM/PQ/PQL2State/v1\\0`. The genesis ID hashes `(new network || protocol || expected source digest || expected PQS1 root)` under `TRNM/PQ/GenesisID/v1\\0` with the same framing. Target account identity is `SHA256("TRNM/PQ/Account/v1\\0" || new network || old Ed25519 key || new PQ key ID)` or `SHA256("TRNM/PQ/Quarantine/v1\\0" || new network || old key)`.

The verifier enforces exact PQG1 account and liability ordering, identities and lengths, matching PQS1 129-byte account records, target generation = old generation+1 (no wrap), retained original next nonce, unique destination account/PQ signer IDs, no PQ signer for quarantined accounts, exact liabilities and issued supply. It reconstructs every PQL2 byte and both quarantine and locked-liability totals, then compares independently supplied PQL2 root. Changing the value but rehashing the payload **cannot** satisfy unchanged outside pins. Overflow, absent liabilities, removed account, switched signer status, invalid kind, new network = old network, symlink files, extra fields and underflow all reject.

## Reproducible checks

From a **full stacked checkout** where the independent Python PQL2 parent exists:

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pql3_native_verify.py
PQL3_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  UBSAN_OPTIONS=halt_on_error=1 PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest -v test_pql3_native_verify.py
```

The tests compile from source with `cc -std=c11 -Wall -Wextra -Werror -pedantic -lcrypto`; sanitizer mode enables both ASan and UBSan. Ordinary mode mutates every byte of the source header, target state, PQL2 output and externally expected anchor; sanitizer mode samples field boundaries to bound instrumented process-start overhead. A specific integration regression compares the C-compatible fixture with the parent Python `project` exactly; in an isolated environment without the full parent source this test is explicitly SKIPPED. No Python test success is described as a Rust Node or independent operator acceptance.

A deliberate negative-control test constructs an entirely rehashed forged source, state, PQL2 and pin file, which this *structural checker* accepts when the caller improperly trusts the attacker's pins. That is a documented **unclosed source-authenticity blocker**, not a false-positive security claim or a property a local hash algorithm can repair.

## Production blockers remaining

1. Independently authenticated source-chain history, issued supply, tasks, rewards, quota, escrow, original withdrawal and historical key compromise cutoff; PQG1 signatures and source pins must be checked by real owners.
2. Audited Rust M01 PQ provider, provisioned HSM/rotation, M00 versioned activation, and native M05/M06/M07/M08/M13 import, deterministic transaction execution, fork choice, reorg, crash and power-loss anti-rollback.
3. M04 authenticated public PQ peers/WAN/DoS, M09 distributed retention and source/Hepta export consent, independent evaluators, light clients and model end-to-end availability.
4. PoN W1 quantum-effective work, hardware advantage, cheapest attacker cost and receiver-amplification security, independent cryptographic review and deployment acceptance. **All production and independent-accepted flags remain false.**
