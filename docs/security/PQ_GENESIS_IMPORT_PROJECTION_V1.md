# PQI1: exact native/Python PQG1 preserved-liability projection (RESEARCH / HOLD_NO_GO)

**Incremental parent:** Trillionnium-Chain PR #434, `f4050776006ee67de1075fb247df7a848fb12447`; inherits the existing research-only chain #399 → #405 → #406 → #408 → #413 → #417 → #419 → #424 → #427 → #431 → #434. **No production consensus, keys, M05/M07/M08/M13 state, legacy signatures, W1 or protocol activation changed.**

## The concrete unsafe seam

The existing `pq_genesis_handoff.verify_handoff` signs/validates every consenting old Ed25519 owner against the *same* complete PQG1 snapshot, returns a **PQS1** byte projection, and quarantines old-only or independently revoked owners. However `pq_branch_execution.PQL1` does not consume PQS1: it resets each imported account `next_nonce=1`, does not preserve liabilities or quarantined identities, and uses a separately defined genesis domain. Treating PQL1 as an importer is a replay and financial-conservation error. The original PQG1 source includes balances, old next nonce/generation, four separate liability kinds, and the independent withdrawal frontier (indirectly through the externally authenticated PQG1 source digest).

`pq_import_projection.py` implements a **read-only** PQI1 serialization with exact PQS1 structural verification and independently supplied pins. `pqi1_native.c` is a separately implemented bounded C11/OpenSSL 3.5+ verification/projection oracle. Neither calls PQL1 or invents an import authority. These are two implementations of this byte boundary, *not* native Rust M13.

## Required external pins and trust limitation

Caller MUST obtain these five values from a separate authoritative verifier with actual old-chain state/history, migration permission, liability issuance/revocation and rollback anchoring:

- `expected_network`: 32 bytes, exact distinct new chain ID
- `expected_profile`: 32 bytes, frozen new protocol hash
- `expected_source_digest`: 48 bytes, previously admitted `SHA384(TRNM/PQ/GenesisSource/v1\0 || BE64(len(PQG1)) || PQG1)`
- `expected_state_root`: 48 bytes, independently recorded `SHA384(TRNM/PQ/GenesisState/v1\0 || BE64(len(PQS1)) || PQS1)`
- `expected_genesis_id`: 48 bytes, independently admitted `SHA384(TRNM/PQ/GenesisID/v1\0 || BE64(len(new_net || profile || source_digest || state_root)) || those bytes)`

The module checks equality to pins, but **cannot authenticate who supplied them**. A colluding attacker can replace source, state and all pins consistently. This module cannot certify real historical liabilities, old heads or quantum-safe old Ed25519 possession. The existing PQG1 owner/signature verification and independent source proof must run *before* this step; no flag or local checksum substitutes for it.

## Exact upstream PQS1 bytes (1–128 accounts, 0–256 liabilities, <=65536 bytes)

```
PQS1[4] | version=1[1] | new_network[32] | new_profile[32] |
account_count[2, BE] | account_record[129]*N |
liability_count[2,BE] | liability_record[81]*M | issued_units[8,BE]
```

Each 129-byte account record is copied without alteration:

```
mode[1]: 0=quarantined, 1=PQ-active
account_id[32] | new_pq_key_id[32] | old_ed25519_key[32] |
balance[8,BE] | OLD next_nonce[8,BE] |
OLD generation[8,BE] | new_generation[8,BE]
```

Require strict sorted unique old keys, strict positive nonce/old generation, new generation = old+1 (no overflow), unique nonzero PQ key IDs, zero PQ key in quarantine, and exact identity hashes:

```
active:     SHA256("TRNM/PQ/Account/v1\0" || new_net || old_key || pq_key_id)
quarantine: SHA256("TRNM/PQ/Quarantine/v1\0" || new_net || old_key)
```

Each 81-byte liability is preserved unchanged:

```
liability_id[32] | owner_OLD_key[32] | amount[8,BE] |
due_height[8,BE] | kind[1] (1=task,2=reward,3=quota,4=escrow)
```

Reject duplicates/unsorted identities, unrecognized owners, zero amounts, unknown kind, surplus/truncated bytes and 64-bit accumulation overflow; **all balances + all liabilities must equal issued_units**. An expired-looking due height is never silently discharged, and a quarantined owner does not erase their outstanding claims.

## PQI1 read-only projection (exact output)

```
PQI1[4] | version=1[1] | network[32] | profile[32] |
source_digest[48] | state_root[48] | genesis_id[48] |
issued_units[8,BE] | N[2,BE] | M[2,BE] |
original_account_record[129]*N | original_liability_record[81]*M
```

`ImportObservation.projection_digest = SHA384("TRNM/PQ/ImportProjection/v1\0" || BE64(len(PQI1)) || PQI1)`. It has **no** `VerifiedWork`, `FinalUse`, `activation`, `grant`, `imported_account` or `chainwork` authority. `decode_import_exact()` recomputes the embedded PQS1 and all commitments, and refuses noncanonical output. The native C tool emits only binary PQI1 on success, emits no bytes on rejection, refuses symlink leaf/foreign file type and bounded reads, and verifies exact lowercase hex pins.

## Observed execution and adversarial scope

```
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_import_projection.py test_pq_native_import.py
PQI1_SANITIZE=1 ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_native_import.py
```

Tests use generated byte-faithful PQG1/PQS1 fixtures, not invented signed PQG1 authority. They verify preservation of nonce greater than 2^40, active/quarantined accounts and all four liability kinds, 128-account/256-liability boundary, complete source and projected output single-byte-mutation rejection under original pins, wrong/noncanonical pins, duplicate PQ keys, invalid identities, missing/rebalanced claims, issuance overflow, no PQL1 fallback, symlink and C/Python exact byte parity. A controlled test explicitly demonstrates that *coherently forged new pins can conceal an omitted liability*: the missing old-chain independent trust anchor remains open.

## OPEN / NOT REPLACED

1. **Critical**: M13 source provenance, independently authenticated old PoN history, real value/escrow/withdrawal/revocation frontier, and signer migration cutoff; a sufficiently capable quantum attacker can forge old Ed25519 before cutoff.
2. **Critical**: native Rust M00/M01/M05/M06/M07/M08/M13 verified signed migration import, durable account/nonce/liability state and fork/reorg rollback, duplicate-signer prevention across all accounts, real checkpoint retirement and process/power cuts.
3. Native authenticated M04 P2P and PQ key custody/HSM, M09 DA, independent evaluators/Hepta export/Final-use and public network testing.
4. PoN/W1 quantum effective-work/security proof and independent cryptography/host audit.
5. Existing installed `max_transaction_bytes=2048` cannot accept pure ML-DSA-65 QTX1. **No update to consensus or production activation.**

**HOLD_NO_GO** until external security owners and native products independently qualify. Test count is not consensus authority.
