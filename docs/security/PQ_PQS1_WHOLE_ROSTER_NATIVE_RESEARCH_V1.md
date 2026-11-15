# PQN5 — Native whole-roster PQG1 → PQS1 structural projection (research-only)

Status: **HOLD_NO_GO**. This is **not** a production M13 importer, an authenticated legacy-chain snapshot, a transaction validator, a complete migration, a PQ work-security proof or any kind of Final-use / consensus authority. No activation or protocol flag may be inferred from a `PQN5_VALID_STRUCTURAL_PROJECTION_ONLY` result.

## Why this increment exists

The existing PQG1 oracle retains *all* legacy balances, nonce floors, owner generations and signed outstanding Task/Reward/Quota/Escrow obligations in a projected PQS1 genesis. The separate QTX1/PQL1 research ledger instead constructs a fresh genesis using `next_nonce=1`, and does not represent these liabilities. Passing migrated balances into that constructor would silently erase replay floors and liabilities. **Do not use PQL1 to import PQG1 state.** This increment adds an independently implemented **native C11/OpenSSL** validator of the complete source-to-projection transformation before any future M13/Rust import code is considered.

## Exact accepted bytes

All values are canonical fixed-length bytes; numeric values are big-endian. The utility accepts three paths: the canonical PQG1 source, the PQS1 projection and a separately supplied **PQA3 pinned research anchor**. Each input must be a regular file, no symlink leaf, <=65,536 bytes for source and target and exactly 317 bytes for anchor. No private key, network address, shell, DB or mutable state is processed.

`PQA3` is a new *research pin grammar*, not an activated protocol, certificate or signed trust root:

| Offset | Field | Bytes |
|---|---|---:|
| 0 | `PQA3` + version `0x01` | 5 |
| 5 | independently expected `SHA384(SOURCE_DOMAIN || BE64(source bytes) || source)` | 48 |
| 53 | independently expected `SHA384(STATE_DOMAIN || BE64(PQS1 bytes) || PQS1)` | 48 |
| 101 | independently expected `SHA384(GENESIS_ID_DOMAIN || BE64(context bytes) || context)` | 48 |
| 149 | legacy network | 32 |
| 181 | new network | 32 |
| 213 | independently expected old-chain head | 32 |
| 245 | independently expected withdrawal/revocation head | 32 |
| 277 | new protocol digest | 32 |
| 309 | issued supply | 8 |

`context = new_network32 || new_profile32 || source_digest48 || target_state_root48`. The SHA384 domains and PQG1/PQS1 formats are **unchanged** from `pq_genesis_handoff.py` at upstream PR #431. Do not reuse this unsigned research-only PQA3 as a native trusted M13 import certificate: it has no issuer, signature, scope-owner or independently accepted current-head rule.

## Safety properties checked

- Complete exact PQG1 frame, counts 1–128 sorted unique old Ed25519 identities and 0–256 sorted unique liabilities; every liability references a known source owner and carries valid Task/Reward/Quota/Escrow type with positive reserved amount.
- Nonzero original nonce/generation and no generation overflow; the projected account embeds **exactly the original 56 bytes** (including original balance and next nonce) and `new_generation=old_generation+1`. A reset `next_nonce=1` when the source nonce is 17 is rejected even when the attacker rehashes the target and PQA3.
- One projected 129-byte record per original identity, preserving order and count. Migrated account IDs are exactly SHA256 of the declared network, original signer and nonzero PQ key ID. Quarantined accounts must have a zero PQ key ID and derived quarantine identity. No duplicate PQ key or derived account ID.
- Exact identity and byte-for-byte preservation of **all** liability records and their ordering, not merely a sum of liabilities. Source funds are conserved with checked 64-bit arithmetic, including all locked obligations. No overflow can be mistaken for a valid issuance.
- SHA384 exact source, target state and target genesis derivation, plus nonzero network/profile/tip/frontier pins. A changed source, different target, reordered account or stale external pin is not permitted.

## Explicitly NOT checked — independently blocking production

- **No Ed25519 or ML-DSA signature verification in PQN5.** Existing PQG1 dual-possession crypto and the native one-owner PQG1 verifier remain separate. The true native owner must prove all migrating identities, key custody, source chain history and authorized signer rosters before it may consume this structural observation.
- The caller can forge a new *self-consistent* snapshot, projection and PQA3 together; a deliberate regression demonstrates successful structural acceptance of such a counterfeit. Only a trusted independent original-chain source head, complete liability export, withdrawal frontier, independently retained anti-rollback and operator authorization can make the expected inputs authoritative.
- No account changes are applied. It cannot spend, unlock escrow, release reward, migrate state, issue an RPC grant, report confirmation, provide chainwork, select a fork or activate a Node. PQS1 is not a transaction ledger.
- Existing PQL1/QTX1 is **not** an importer for this state. An actual versioned M00/M05/M06/M07/M08/M13 PQL2/Rust importer must preserve every nonce, generation, liability and quarantine through native fork/undo, restart, deep reorg and independently anchored revocations. Prior classical-key compromise remains unsolved.
- This is an isolated native C/OpenSSL utility, not the missing audited Rust M01/HSM provider, real PQ-authenticated M04/M15 WAN, Hepta authority, PoN quantum effective-work proof, or independent cryptographic acceptance.

## Exact local test

```
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_import_projection_verify.py
PQN5_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
 UBSAN_OPTIONS=halt_on_error=1 PYTHONWARNINGS=error::ResourceWarning \
 python3 -m unittest -v test_pq_import_projection_verify.py
```

Both configurations require OpenSSL libcrypto and a C11 compiler. The 21 test methods include byte-by-byte mutations of the complete source/target/anchor, valid full 128-account/256-liability bound, checked overflows, forged re-anchored IDs/keys/nonce/generation, incorrect liability owners, missing/quarantined accounts, file and symlink negatives. `PQN5_SANITIZE=1` compiles with AddressSanitizer and UndefinedBehaviorSanitizer. Each case compiles one native binary per process then executes it as a real OS process (no mock validator).

**No Rust/full Chain CI, deployed P2P, physical disk loss, independent multi-host review, historic full-state import, real signature-owner conformance, quantum mining security or production activation was run by this isolated research increment.**
