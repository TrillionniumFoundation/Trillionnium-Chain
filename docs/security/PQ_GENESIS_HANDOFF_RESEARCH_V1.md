# PQG1 — fork-independent legacy liabilities to post-quantum genesis (RESEARCH ONLY)

**Status: HOLD_NO_GO.** This is a bounded, independently pinned, *non-authoritative*
new-network genesis projection. It is not a native M13 import, M02 fork-choice engine,
product transaction validator, new-node activation command, chain/Hepta authority, or
permission to bridge live assets. No existing PoN W1/PNW1, Ed25519 transaction,
Chainwork, QTX1, selected target, network parameters or release flag changes.

It extends the PR #399 → #405 → #406 → #408 → #413 → #417 → #419 → #424 → #427
research chain without changing the earlier signed bytes. A complete Chain migration
must be a deliberately activated new chain context, with an accepted and independently
reconciled legacy export, not a database edit or silent signature substitution.

## Concrete threat this increments

Moving `balance` and an Ed25519 address into a PQ account without its original
`next_nonce`, owner generation, source-head identity, withdrawal state and outstanding
task/reward/quota/escrow liabilities can double-credit supply, drop obligations,
reintroduce revoked authority, replay on a second target chain or make a fake quantum
migration look cryptographically complete. A private-key signature over a self-supplied
snapshot does not prove that snapshot matches the old chain.

## PQG1 canonical source snapshot

`pq_genesis_handoff.py` uses a strict, bounded, big-endian byte grammar. All numbers are
unsigned; bool is not an integer. No JSON objects, paths, floating-point values,
scripted descriptors, keys or certificates appear in the snapshot.

| Offset | Field | Width |
|---|---|---:|
| 0 | `PQG1` | 4 |
| 4 | exact version `1` | 1 |
| 5 | legacy chain/network ID | 32 |
| 37 | distinct new chain/network ID | 32 |
| 69 | *externally verified* legacy head | 32 |
| 101 | *externally verified* revocation/withdrawal head | 32 |
| 133 | new consensus/protocol profile digest | 32 |
| 165 | old total issued units | u64 (8) |
| 173 | sorted unique account count | u16 (2) |
| 175 | sorted unique liability count | u16 (2) |
| 177 | each old account: public32/balance8/next_nonce8/generation8 | 56 |
| remainder | each liability: ID32/old-owner32/amount8/due-height8/kind1 | 81 |

Bounds: `1..128` accounts, `0..256` liabilities, <=64 KiB total snapshot, unsigned
`u64` conserved amount and ordered unique old identities/liability IDs. The liability
kinds are `1 task`, `2 reward`, `3 quota`, `4 escrow`. No liability may refer to an
unknown account. The exact sum of account balances plus all locked liabilities must
match `issued_units` without overflow. This does **not** itself prove that all source
liabilities were exported: an independently admitted old-chain source digest and supply
are mandatory.

The snapshot identity is
`SHA384("TRNM/PQ/GenesisSource/v1\\0" || BE64(len(snapshot)) || snapshot)`.
The caller MUST independently supply and match this **exact 48-byte** hash, old and new
network identities, legacy tip, revocation head, target protocol profile and issued
supply. Obtaining them only from the attacker-supplied snapshot proves nothing.

## Actual two-key migration challenge

For each migrated account a fixed `MIGRATION_DOMAIN` statement binds the *exact*
source digest, old/new network IDs, source/withdrawal heads, target protocol hash,
old Ed25519 identity, source balance, old nonce/generation, destination ML-DSA-65
public-key ID, new generation and expiry. It is signed **independently** with real
strict Ed25519 and real ML-DSA-65. Both signatures MUST verify. ML-DSA-65 public keys
have exact SPKI OID `2.16.840.1.101.3.4.3.18`, no parameters, 1952-byte key data and
3309-byte signatures; other algorithms are hard rejected. There is no Ed25519-only,
unsigned, signature-valid-boolean, copied-payload or hash-only acceptance path.

- Duplicate old account migrations, a PQ key reused for two old identities, unknown
  or explicitly revoked old signers, stale old signatures, changed profiles/amounts,
  wrong target chain, changed withdrawal head and expired attestations reject.
- Only a verified PQ key becomes a *research-projected* active account ID. Unmigrated,
  unrecoverable or revoked old accounts have a separate quarantine identity, **not** an
  old-key signature fallback. Balance and liabilities remain accounted for even when
  not spendable.
- Source old nonce floor and generation are retained in new state bytes. The new owner
  generation is checked to be old+1; an expired/maximal generation does not wrap.
- Canonical projected state is a distinct `PQS1` byte domain. Root and resulting target
  genesis ID use separate SHA-384 contexts; neither is a PoN work certificate or block.

## Mandatory trust boundaries

1. **Old ledger is NOT verified here.** External *independent* old-chain authority must
   supply the exact tip, source digest, liabilities, historical payments, issuer supply,
   effect/revocation frontiers and import governance. This oracle cannot independently
   detect a deliberately omitted obligation in a newly forged but self-consistent export.
2. **A post-quantum key does not cure an already-compromised old Ed25519 signature.**
   Source possession proofs are safe only under their migration threat/timing policy;
   post-break dispute/recovery governance cannot be made safe by adding ML-DSA later.
3. **No native product integration.** PQL1 at PR #427 is a signed PQ transfer research
   ledger, not a production-import API. PQG1 does not write to it, open a listener,
   issue a Final-use capability, sign a model release or cross a real asset boundary.
4. **No trusted signer HSM.** The `sign_*_fixture` path is only for ephemeral local keys;
   the verification path uses OpenSSL CLI solely as an offline conformance oracle.
5. **No physical or independent review.** Controlled single-host tests, source hashes,
   cold checks and real signatures do not establish external acceptance, sustained WAN,
   quantum PoN work security, physical durability or migration settlement finality.

## Reproducible adversarial controls

On an isolated checkout of the exact stacked research branch:

```sh
cd formal/pon-nakamoto-v1
PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_genesis_handoff.py
```

Tests create real ML-DSA-65 / Ed25519 keys at runtime and exercise canonical 177-byte
header mutations, omitted/rebalanced escrow, duplicated old/PQ identity, all two-key
signature failures, wrong target context, stale generations/nonces, revocation,
insufficient source anchor, quarantine and amount conservation. The original
`strict_signature.py` is reused unchanged (not an invented substitute).

## Production closure gates (all remain OPEN)

- Exact independently signed and accepted source snapshot with complete branch/reward/
  task/effect/withdrawal liabilities; archive and replay proof verified by M13.
- Audited native Rust M01 ML-DSA-65 signer/verifier and protected custody/HSM.
- M00 canonical genesis/transaction upgrade spec with activation governance and real
  2,048-byte-to-PQ fee, block, mempool and network limits; no implicit fallback.
- Native M02/M05/M06/M07/M08 fork, work, account import, settlement, revocation and
  anti-rollback, with multiple independent owners and physical power-cut recovery.
- M04/M09/M11/M15 authenticated public PQ P2P, long-term Cell DA, independent model
  evaluation, and actual Hepta export/current-head/Final-use binding.
- Formal and adversarial proof of PoN W1 quantum-effective work, Sybil cost and verifier
  amplification, independently reviewed across hardware and public network operators.

**`production_activation=false`; `independent_accepted=false` remains mandatory.**
