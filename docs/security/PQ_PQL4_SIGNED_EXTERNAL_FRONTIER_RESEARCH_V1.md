# PQL4 — signed, independently pinned fork-state witness (RESEARCH / HOLD_NO_GO)

Parent branch: Chain #451 `research/pq-pql3-fork-recovery-20261026`, pinned at commit `06e689c183d69990e61d26dd61aa96af85eeb233`. The PQL3 reference already protects internally consistent nonce/fork history and crash-atomic local tip updates, but a **complete consistent rollback of its SQLite database succeeds** when nobody retains an independent newer head. This additive research artifact supplies an exact bounded observer/witness and demonstrates how a *truly independent latest-head pin* prevents that specific rollback. **No production anti-rollback guarantee follows from this local fixture.**

## Boundaries / non-claims

- `observe_pql3_store` opens a PQL3 SQLite database in read-only mode and uses one explicit read transaction. It demands the **exact four original table definitions**, with no triggers/views/extra indexes/tables, exact externally expected import root and genesis, 1–128 externally supplied imported nonce floors, and a typed migrated/quarantined mask. It recomputes all deterministic PQL3 node IDs (SHA-384), every parent link/height/nonce +1 transition, quarantine rejection, current tip, and retained effect references; it then hashes the entire ordered read view into a SHA-384 snapshot commitment. It does **not** verify old-chain signatures, quantum-safe key possession, Chainwork or model authority.
- `PQL4` is an **isolated witness format**, not a revision to installed Chain QTX1, TPQ1, genesis, mining or consensus. A real OpenSSL 3.5+ ML-DSA-65 signature covers the domain-separated exact witness bytes. It authenticates possession of one witness key, **not** that the key belongs to an independent custodian or that the content has been authorized by M07/M08/M13.
- A caller MUST obtain the current trusted witness key ID, latest monotonically advancing sequence, previous witness ID, expected import/network context, and accepted storage snapshot **outside** the rewindable SQLite state and the untrusted supplied witness. Those values cannot be read from `PQL4` or from the database being checked. If the trusted head can be rolled back together with SQLite, an older genuine signed witness is still accepted. The regression explicitly demonstrates this failure.
- Neither the code nor tests mint `VerifiedWork`, spend/migration authority, model-release permission, Hepta `FinalUse`, custody reward, confirmation or Chainwork. No private production key is loaded and no service is installed.

## Exact PQL4 witness bytes

All integers are canonical big-endian. The 336-byte unsigned grammar is:

| Offsets | Field | Bytes |
|---|---|---:|
| 0–3 | `PQL4` | 4 |
| 4–7 | version `01`, algorithm `65`, two zero reserved bytes | 4 |
| 8–39 | exact network ID | 32 |
| 40–87 | externally pinned PQL2 import root | 48 |
| 88–135 | exact PQL3 genesis node ID | 48 |
| 136–183 | active fork tip ID | 48 |
| 184–191 | active local generation, nonzero | 8 |
| 192–199 | observer sequence, nonzero | 8 |
| 200–247 | predecessor witness ID, all zero only for explicitly anchored initial record | 48 |
| 248–295 | complete snapshot SHA-384 | 48 |
| 296–303 | expiry, nonzero | 8 |
| 304–335 | observer key ID, TPQ1-compatible SHA-256 of canonical ML-DSA-65 DER SPKI | 32 |
| 336–337 | signature length `3309` | 2 |
| 338–3646 | **real** ML-DSA-65 signature | 3309 |

ML-DSA-65 signs `b"TRNM/PQ/PQL4SignedFrontier/v1\\0" + unsigned336`. Witness identity, **independent of randomized signature bytes**, is `SHA384(b"TRNM/PQ/PQL4FrontierId/v1\\0" + unsigned336)`. The verifier accepts only exact 3,647-byte framing, strict SPKI ML-DSA-65 OID and public key size, matching externally expected signer/network/import/genesis/tip/generation/sequence/predecessor/snapshot and unexpired time; bad signatures and Ed25519 algorithm downgrade reject. This format grants no authority to unrelated TPQ1 purposes. It is research-only until protocol versioning and independent validation.

The snapshot SHA-384 domain includes exact PQL3 source/import/genesis, every imported original nonce and migrated/quarantined status, node/effect row counts, the canonical full ordered node graph, active tip/generation, and ordered irreversible-effect observations. Storage node hashes use the original PQL3 `TRNM/PQ/PQL3NonceSnapshot/v1\\0` framing, not invented PQL4 chainwork. Every SQL row is read in one snapshot, not between unrelated tables with mutable head. This is bounded to 32,768 nodes and 32,768 effect records; the reference may refuse a larger legitimate historical store. It has no storage compaction or production liveness claim.

## Observed experiments and honest failing case

From this directory:

```sh
PYTHONWARNINGS=error python3 -m unittest -v test_pq_pql4_signed_frontier.py
```

Genuine OpenSSL 3.5.5 ML-DSA-65 tests cover canonical signing and verification, full signed-header byte mutation, wrong/Ed25519 key, wrong purpose-domain framing, old/wrong external sequence and predecessor, expiry, nonces/generation/quarantine, unknown effects, foreign SQLite DDL, symlink, and a complete old SQLite backup/restore after a newer witness is signed. **The restored old store fails with the independently pinned newer witness; deliberately rewinding BOTH store and trusted witness sequence allows the old valid signature.** This proves why separately provisioned monotone external storage/HSM/ledger quorum (with independent administration) remains an essential unresolved product dependency.

## Remaining whole-chain blockers

1. M13 independent source-chain export with complete balances and liabilities, source/withdrawal authenticity, strict old+PQ ownership proofs, and compromise cutoff policy.
2. **A real non-rewindable independently administered latest-frontier service** with key/HSM custody, crash/partition recovery, equivocation challenge, durable quorum or anchored monotonic counter, revocation and anti-split-brain governance. This local function does not implement it.
3. Native Rust M00/M01/M05–M08/M13 integration, QTX1 final admission and gas/fee, exact reorg of real balances and effects, target-host power cut, key/nonce/escrow migration and multi-operator WAN acceptance.
4. Public PQ-authenticated M04/M09 P2P/Cell availability and Hepta export/FinalUse, historical trust compatibility, PoN effective-work hardness against quantum and classical adversaries, and external cryptographic review.

Do not merge a research witness directly as an installed authority path, mark `independent_accepted`, change activation flags or claim the Chain is quantum safe. Existing main remains unchanged.
