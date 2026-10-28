# PQL5 — Signed, challenge-fresh PQL4 checkpoint quorum (research / HOLD_NO_GO)

**Status:** isolated, add-only experimental extension of Chain PR #457 at `ceb00ad90c034043ce088972db141a5d5b4c9b7c` (PR #451 → #457). **No production activation, mainline consensus, installed Ed25519 transaction, W1/PNW1, difficulty, Chainwork, mining, Hepta authority or Final-use changed.** The witness interface returns a read-only `QuorumObservation`, never a Chain/state/adoption/rollback grant.

## Security question and strict assumption

A PQL4 ML-DSA signature binds one full PQL3 SQLite state digest, but restoring *both* the SQL database and its client's latest local witness pointer defeats a local antirollback check. PQL5 has **three separately keyed witness journals**, with challenge-fresh ML-DSA-65 signed state observations. A client accepts only **two of three** distinct, independently pinned witness keys naming the same latest-sequence, identical PQL4 frontier identity. A single stale/rolled-back witness does not suffice, provided two honest and currently reachable witnesses retain newer heads. This is **conditional**; paths on one machine are not independently governed HSM/monotonic owners.

An attacker who rewinds two witness journals (or controls their keys) and censors the third can obtain fresh signatures over an old, valid head. An isolated regression **demonstrates** this failure. PQL5 does not establish chain finality or a global non-rewindable checkpoint. Neither the PQL4 observer key nor its declared state digest is source authority without independent import/withdrawal/effect owner verification.

## Wire and exact algorithms

Input: exact 3,647-byte PQL4 signed frame from PR #457. Validate its 336-byte `PQL4 01 65 00 00` header, 3,309-byte signature, exact ML-DSA-65 SPKI OID and key ID, signature `ML-DSA-65(DOMAIN_PQL4 || unsigned336)`, network, import, genesis, generation, sequence, predecessor frontier identity and expiry. `PQL4_ID = SHA384("TRNM/PQ/PQL4FrontierId/v1\\0" || unsigned336)`; the signature's randomness is never a new identity.

A witness holds one exact context-bound SQLite `pins` table and an ordered `events` history, with `BEGIN IMMEDIATE`, `WAL/FULL`, cold DDL/readback revalidation and no in-place overwrites. Every consecutive signed PQL4 link is verified on each audit. Foreign triggers/views/indices, unexpected columns, sequence gaps, PQL4 substitutions, reused checkpoint IDs and malformed signature frames fail. One identical repeat returns `ALREADY_RECORDED`. Historical signatures remain valid archive statements even after their original expiry; *new* appends require expiry.

Challenge-fresh response, big-endian:

| Offset | Field | Bytes |
|---|---|---:|
| 0 | magic `PQL5`, version `01` | 5 |
| 5 | independently pinned witness ML-DSA-65 key ID | 32 |
| 37 | network | 32 |
| 69 | import root | 48 |
| 117 | genesis | 48 |
| 165 | latest sequence (u64) | 8 |
| 173 | PQL4 frontier ID | 48 |
| 221 | caller-supplied nonzero, **fresh random** challenge | 32 |
| 253 | observation time (u64) | 8 |
| 261 | expires at (u64), exactly observation+30 seconds | 8 |
| 269 | signature length `3309` (u16) | 2 |
| 271 | pure ML-DSA-65 signature of `TRNM/PQ/PQL5Witness/v1\0 || unsigned269` | 3,309 |

Total signed frame: **3,580 bytes**. The isolated OpenSSL 3.5+ private-key subprocess is a **developer fixture only**, not a production signing service or key-management boundary.

A verifier must receive three trusted operator ML-DSA public keys independently of local chain state, query at least two *live authenticated operator endpoints* with one newly generated unpredictable challenge, check their 3,580-byte signatures, exact network/import/genesis, expiry, unique keys, and sequence/head agreement. Empty head (sequence 0), 1-of-3, mixed latest sequence, and 2 conflicting latest heads refuse. An absent third operator can be tolerated if the two responding honest operators agree. `Busy`/unavailable != cryptographically invalid, and a rogue signed future claim can deny liveness (must not confer authority).

## Actual isolated validation

Command: `PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql5_quorum.py`

The checked-in original raw transcript and qualification JSON contain actual source/hash/compiler/system facts. Fifteen tests run genuine ML-DSA-65 with OpenSSL (no stub), including 269 individual response-header mutations, wrong roster/classical-key downgrade, stale/noncanonical signatures, cross-challenge/expiry/replay, one offline witness, conflicting signed forks, eight OS processes racing a single `BEGIN IMMEDIATE` append, cold-open DDL refusal, genuine one-journal database clone rollback, and the deliberately retained **two-of-three rollback plus censorship negative**. All keys and witness stores belong to **one administrator on one Linux host**; this is not WAN, physical power loss, independence or audited custody.

## Still mandatory before any PQ Chain claim

1. An **independently administered, hardware-backed non-rewindable latest checkpoint root**, real authenticated multi-operator P2P transport and member rotation/revocation. A local 2/3 SQL quorum is an experimental conditional defence only.
2. Actual production Rust M00/M01/M05–M08/M13 trusted custody, versioned signatures/transactions, imported nonce and Task/Reward/Quota/Escrow obligations, complete historical withdrawal/source proof and deep PoN reorg; old classical key compromise cutoff remains distinct.
3. Genuine PQ M04/M09/M15 WAN Cell retention, model/evaluator and Hepta export/final-use authority, stable operator identities and measured backpressure/throughput.
4. Quantum-effective W1 work hardness/verification amplification and independent adversarial audit; independent cryptographic evaluation, multi-host/power-loss results and explicit release approval.

All activation/independent-acceptance flags remain **FALSE**, and this research must not be auto-merged or interpreted as fully quantum-resistant Chain.
