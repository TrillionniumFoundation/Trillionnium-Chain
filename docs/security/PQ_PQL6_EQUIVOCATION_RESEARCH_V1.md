# PQL6 — PQ witness equivocation evidence (RESEARCH ONLY, HOLD_NO_GO)

**Dependency:** Chain PR #463 (`d7f897ef35023ac48dff868e8cffde42eea9bbc1`), with the inherited PQL5/PQL4 stack. Does not change W1/PNW1, Chainwork, target, the installed classical Ledger, QTX1, any trusted Hepta authority, or activation flags.

## Precisely what was implemented

This isolated auditor accepts **two complete 3,580-byte PQL5 witness frames** and one **externally pinned ML-DSA-65 SPKI key ID**, plus exact externally pinned 32-byte network ID, 48-byte import root and 48-byte genesis. Both frames must have genuine pure ML-DSA-65 signatures on `TRNM/PQ/PQL5Witness/v1\0 || header269`, the same signer, chain/import/genesis and strictly positive same sequence, but **different** nonzero 48-byte PQL4 frontier IDs. Independently signed, same-frontier observations at different challenges are *not* equivocation.

The verifier enforces exact public-key ML-DSA-65 OID and raw 1,952-byte key, canonical PEM (no trailing data), PQL5 signature 3,309 bytes, nonzero challenge, `expiry=observed+30` without u64 overflow and exact signed framing. Evidence is a canonical **7,245-byte PQL6** binary object:

| Offset | Field | Size |
|---|---|---:|
| 0 | `PQL6` + version `01` | 5 |
| 5 | verified witness public-key ID | 32 |
| 37 | lower lexicographic PQL5 header and signature | 3,580 |
| 3,617 | higher lexicographic PQL5 header and signature | 3,580 |
| 7,197 | SHA-384 evidence ID | 48 |

The evidence ID is `SHA384("TRNM/PQ/PQL6Equivocation/v1\0" || witness_key_id32 || first_unsigned269 || second_unsigned269)`, so signature randomness and input order do not create another logical offense. Every verifier must check both signatures afresh. Historical signatures can be checked after expiry: the expiry describes original signing claims, not a future authorization or a usable live witness response.

The returned `EquivocationObservation` is **strictly read-only, non-authoritative**. It cannot revoke a witness, slash rewards, choose a chain tip, create a FinalUse capability or attest the actual external clock. Its external trusted key and chain pins must come from independent sources, not the accused witness or a rewindable SQLite table. A hostile 2-of-3 majority can rewind and consistently re-sign an **identical** old head without producing contradictory signatures. This remains an explicitly open high-severity counterexample requiring independent non-rewindable source anchoring and administration.

## Actual local execution

`PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_pql6_equivocation.py`

Ten real ML-DSA-65 tests passed using OpenSSL 3.5.5 and Python 3.13.5. The negative matrix includes every one of the **269 signed PQL5 header bytes**, different sequence and network/import/genesis, different/Ed25519 keys, malformed PK, altered signatures, noncanonical framing/ordering and expiry/zero bounds. A passing test requires fresh real `openssl genpkey` and `openssl pkeyutl` signing; there is no simulated signature-success path.

**Not executed:** full stacked exact-head Rust CI, native PQL5N cross-language parity, public WAN operators, external HSM signers, production revocation, conflict gossip/reception, quantum-effective W1 hardness, physical power loss. Do not call the whole Chain post-quantum secure. Hold all independent acceptance, integration and production activation flags false.