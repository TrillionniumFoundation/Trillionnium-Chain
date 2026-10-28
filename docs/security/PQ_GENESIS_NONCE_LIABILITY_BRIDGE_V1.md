# PQL2 — Preserve PQG1 account nonce and liabilities (RESEARCH / HOLD_NO_GO)

Dependency: existing PQ research stack through Chain PR #440 (PQN4), including upstream #431 (PQG1) and #427 (PQL1). This **adds** a read-only conformance projection and does not patch legacy `PQL1` or change installed PoN, W1, transaction framing, mining, consensus, balances, source authorities, or activation flags. It is not a mainnet code path.

## Why this exists

The PQL1 `ResearchBranchState` constructor sets `next_nonce=1` for its clean ephemeral genesis and has no imported task/reward/quota/escrow liability representation. PQG1 migration **must not** simply pass its output to PQL1: doing so can reset nonces and omit locked funds. The new `pq_genesis_state_bridge.py` strictly parses existing PQG1 source bytes and existing PQS1 projected bytes, binds both to independently supplied SHA-384 roots/chain identities, and constructs an **isolated** PQL2 research projection that explicitly preserves source nonce floors, new owner generations, and all four liability classes.

## Input byte grammar, unchanged from upstream

PQG1 source header (all integers unsigned big-endian):

| Range | Field |
|---|---|
| 0..4 | `PQG1`, version 1 |
| 5..36 | old network (32) |
| 37..68 | new network (32), different from old |
| 69..100 | externally authenticated old head (32) |
| 101..132 | externally authenticated withdrawal head (32) |
| 133..164 | proposed new profile (32) |
| 165..172 | issued units (u64) |
| 173..174 | account count (u16) |
| 175..176 | liability count (u16) |

Then 1..128 sorted unique `LegacyAccount` entries (56 bytes each: old Ed25519 public key32, balance8, `next_nonce`8, old generation8); then 0..256 sorted unique `Liability` entries (81 bytes each: ID32, old owner32, amount8, due height8, kind1). Kinds: task=1, reward=2, quota=3, escrow=4. Issued amount must exactly equal balances + liabilities. No unknown owner, duplicate, zero nonce, invalid kind, unsigned wrap or trailing bytes.

PQS1 existing target projection: `PQS1`/version1, new-network32, profile32, account-count u16, followed by exactly one **129-byte** projected record per old source account in old-key order. Each record: `status:u8` (0 quarantined or 1 migrated), `account_id32`, `pq_key_id32`, exact old account56, `new_generation:u64` (old+1). Status 0 requires a zero PQ signer and the quarantine address domain; status 1 requires a nonzero ML-DSA key ID and the PQ account address domain, unique network-wide. Follow with liability-count:u16, exact original 81-byte liability records, and issued supply:u64. A different record order, nonce, generation, liability, or balance rejects even if an attacker rehashes PQS1.

## PQL2 output, non-authoritative

`PQL2` version1, network32, protocol32, old source head32, withdrawal head32, pinned source digest48, pinned target genesis48, account-count u16, identical validated 129-byte account records, liability-count u16, identical 81-byte liabilities, issued supply8, quarantine balance8, locked liability total8. The output is itself hashed under a **different** `TRNM/PQ/PQL2State/v1\0` SHA-384 length-prefixed domain.

`Projection` exposes read-only diagnostic counters, inherited `(account_id,next_nonce)` floors and the exact bytes/root; it does **not** contain any signer, `VerifiedWork`, `FinalUse`, chainwork, release grant, migration permit, finality claim, or execution callback. QUARANTINED accounts carry liabilities and balances for conservation only and cannot receive an implicitly re-created old-key spend path. Locked liabilities are never silently credited into spendable balances.

### Required externally pinned values

The caller MUST separately authenticate the original `PQG1` source digest, source head, withdrawal head, old/new chain IDs, new profile, issued supply, **PQS1 target state root** and **projected new genesis ID**. All expected values are passed explicitly; none are derived from untrusted input in the implementation. The source and state digests use upstream length-prefixed SHA-384 domains `TRNM/PQ/GenesisSource/v1\0`, `TRNM/PQ/GenesisState/v1\0`; the genesis ID is `TRNM/PQ/GenesisID/v1\0` over `(new_network || profile || expected_source_digest || PQS1_root)`.

**This program DOES NOT authenticate those external pins.** Before using any projection, a separate authorized M13 source owner must verify complete old-chain history/liabilities, independent withdrawal frontier and appropriate migration cutoff. The inherited upstream PQG1 `verify_handoff` must independently verify actual strict Ed25519 + ML-DSA-65 possession on each migrated account (and independently recognize reviewed revocations). A value hash, data shape, or a user-constructed `GenesisObservation` is never itself an authorization. A quantum adversary who can forge the old exposed Ed25519 key cannot be cured by a co-signed new key alone.

## Executable negative regression

From the repository's full stacked research checkout:

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_genesis_state_bridge.py
```

The added suite exercises two original owners with nonces 23 and 91, one migrated, one quarantined; 4 outstanding liabilities totaling 1100, 700 balance units, exact 1800 total units; 177 individual source-header mutations and all PQS1-byte mutations; rehashed account status/PQ identity/nonce mismatches; duplicate ML-DSA identity, omission, reordering, amount substitution and attempted re-credit of escrow; wrong external pins, generation exhaustion, type confusion, unknown/liability owner and invalid signed-integer bounds. Tests are **reference projection tests**, **not** a second signature-verifier qualification or an existing native PoN node test.

## Still blocking native Chain post-quantum eligibility

1. **Source authority**: independenty accepted M13 old-network export and complete debt/escrow/fee/replay revocation frontier, pre-quantum-compromise cutoff and governance.
2. **Actual native import**: M00 versioned protocol and M05/M06/M07/M08 Rust state ownership; preserve nonce floors and liabilities in production, durable branch replay/reorg/anti-rollback, crash/power-loss.
3. **Cryptography**: audited Rust M01 HSM-backed ML-DSA signer/verification and PQ identity revocation; all real transaction/reward/evaluator/Cell/Hepta authorities migrated.
4. **Network/consensus**: real native authenticated M04/M09 WAN and DA, production PQ transaction budgets, W1 quantum effective-work/Sybil/admission security qualification, independent operators and external security audit.
5. **Release gate**: no product `VerifiedWork`, no new consensus rule, no irreversible effect, no write to live Chain. All production activation and independent-accepted flags remain false. No automated merge to main.
