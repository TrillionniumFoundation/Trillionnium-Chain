# QTX1 — exact post-quantum transfer research profile (NO ACTIVATION)

Parent protocol: [TPQ1](POST_QUANTUM_TRANSITION_V1.md). This is a **separate
research wire**, not a replacement for installed `pon-nakamoto-v1`, W1, devnet
genesis, native M05/M06, consensus work, stored balances or Hepta Final-use.
`QTX1` does not yet have any production transaction authority. Activation is
**forbidden**, even if every local test here passes.

## Research wire (canonical binary, not JSON)

The transfer body has 144 fixed bytes plus a 0–512 byte opaque memo; append one
complete **3,487-byte TPQ1 signed envelope**. `TPQ1` signs all QTX1 body bytes
as purpose=1 with pure FIPS 204 ML-DSA-65. No Ed25519, ECDSA, ML-KEM key,
optional signature or legacy-body reinterpretation is admitted.

| Offset in body | Field | Canonical check |
|---|---|---|
| 0–3 | ASCII `QTX1` | exact |
| 4 | version | `01` |
| 5 | kind | `01` = experimental transfer only |
| 6–37 | network | 32-byte exact context |
| 38–69 | sender account ID | 32 bytes, nonzero |
| 70–101 | recipient account ID | 32 bytes, nonzero, distinct |
| 102–109 | owner generation | big-endian u64, nonzero |
| 110–117 | account nonce | big-endian u64, nonzero |
| 118–125 | expiry | big-endian u64, nonzero |
| 126–133 | transfer amount | big-endian u64, positive |
| 134–141 | fee limit | big-endian u64 |
| 142–143 | memo length | big-endian u16, at most 512 |
| 144– | memo | precisely declared byte length |
| body end onward | TPQ1 | exactly 3,487 bytes, no trailing bytes |

The TPQ1 network equals QTX1 network; context is
`SHA256("TRNM/PoN/QTX1Context/v1\\0" || network || sender)`.
The signed TPQ1 generation, sequence and expiry **must equal** the body
generation, nonce and expiry. TPQ1 payload commitment binds the entire body.
The expected signer is looked up through an externally provided
`AccountView.signer_key_id`, not trusted from the packet.

### Status and cost

The hypothetical research envelope is 3,631–4,143 bytes, so **even an empty
memo exceeds installed 2,048-byte `max_transaction_bytes`**. The 256 maximum-
memo envelopes total 1,060,608 bytes before block headers and proofs, exceeding
the installed 1,048,576-byte block ceiling by 12,032 bytes. The 8,192-byte
research ceiling is **not** an activated consensus parameter; no corresponding
fee schedule, network propagation or CPU budget has been qualified.

The preflight rejects non-integer/bool values, missing or trailing bytes,
unknown version/kind, mismatched network/signer/generation/nonce, expired
signature, inactive account, insufficient declared fee, u64 overflow and
insufficient balance. The research cost formula is
`base_fee + byte_fee * len(exact_signed_transaction)` with checked u64.
No executor, miner or ledger imports this function.

A speculative transaction identity is
`SHA384("TRNM/PoN/QTX1Identity/v1\\0" || BE32(body length) || body ||
signer_key_id)`, *not* a cryptographic proof of inclusion or transaction
authority. It excludes randomized signature bytes to avoid multiple IDs for
the same signed operation; actual replay control must be owned by durable
nonce/chain state. `AccountView` is caller-created and **unauthenticated**;
passing preflight cannot debit balances, return VerifiedWork, settle rewards,
issue Final-use or bind current reorg generation.

## Exact reproducibility

```sh
cd formal/pon-nakamoto-v1
python3 -m unittest -v test_pq_transaction.py
```

Requires OpenSSL 3.5+ with ML-DSA-65 and Python 3.13; cryptographic signatures
are genuinely generated and verified with OpenSSL, without accept-all mocks.
Fixed fixture body (network 00..1f, sender 20..3f, recipient 40..5f,
generation 2, nonce 7, expiry 5000, amount 1200, fee limit 10000, memo
`cell settlement`) is 159 bytes and has SHA-384:

`3d2ba08ff63ae0d98d1f96a588ea8280b7e1d78a638785397e98003140b5bf2975ab8de9442b80268dbca45d3bed3b17`

[Recorded local test scope](../../evidence/pon-pq-qtx1-v1/README.md) is not
full-repository Rust or production qualification.

## Production blockers (must remain open)

- **M00/M01**: independently reviewed native signer/verifier/HSM and consensus
  versioned transaction identity; cryptographic side channels and PQ key policy.
- **M05/M06**: canonical account migration, durable nonce update, exact error
  precedence, fee/byte/CPU calibration, deterministic state/root parity, fork
  replay, transaction indexing and full native command coverage.
- **M02/M03/M04/M07/M08/M13**: work quantum security, signed block/miner
  identity, peer hybrid transport, authenticated state and deep reorg,
  cold-recovery, imported historical liabilities and anti-rollback.
- **M09–M12/M14–M17 and Hepta**: PQ signatures for model/evaluator/storage/
  release/receipt, real authority ownership, independent validation, live
  operational deployment and external acceptance.

Do not alter `config/consensus-mainline.json`,
`config/pon/devnet-v1.json` or production activation based on this research.
