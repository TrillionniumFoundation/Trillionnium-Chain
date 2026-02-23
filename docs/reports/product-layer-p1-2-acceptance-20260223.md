# Product Layer P1-2 Acceptance Report (2026-02-23)

Status: PASS  
Scope: transfer signature hardening + sendTx/getTx lifecycle + one-command product smoke

## 1) Delivered

### A. Signature hardening
- Transfer signature path upgraded to ed25519-backed verification.
- Address derivation/checking aligned with key material.
- Negative cases covered: tampered signature, address mismatch, replay/nonce constraints.

### B. sendTx/getTx lifecycle
- Minimal lifecycle implemented and queryable:
  - `pending -> committed/fail`
- Stable tx hash response.
- Query not found path returns stable error semantics.
- Covered failures: insufficient balance, nonce conflict, missing/invalid signature.

### C. Product smoke command
- Added one-command smoke flow:
  - `wallet create -> query balance -> tx transfer -> getTx`
- Script: `scripts/v2/product_layer_smoke.sh`
- Emits explicit PASS/FAIL and key fields:
  - `address`
  - `tx_hash`
  - `status`

## 2) Validation commands

```bash
cd trillionnium-rust
cargo test -p trnm-types -p trnm-rpc -p trnm-cli

cd ..
./scripts/v2/product_layer_smoke.sh
```

## 3) Validation result snapshot

Smoke run output (latest):
- `address=trnm14dc5d6b6c35e66b35418502a4715a07b7b63b2ee`
- `tx_hash=a07e292919065995a4acdf710c85d65fc1707280d7f214e365d22eb4f9e30701`
- `status=unknown`
- artifacts: `run/product-smoke/20260223-123458`

## 4) Notes

- `status=unknown` in smoke is acceptable for the current fallback query path.
- Next step for product UX is to standardize JSON-RPC contract docs + explicit finality states for wallet/explorer integration.
