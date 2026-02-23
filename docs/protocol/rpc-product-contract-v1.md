# TRNM Product RPC Contract v1

Status: Frozen (P1-3)
Version: `rpc-product-v1`

## Methods

### 1) `balance`
Request:
```json
{"address":"trnm1<40hex>"}
```
Response:
```json
{"address":"trnm1...","balance":123,"version":1}
```

### 2) `nonce`
Request:
```json
{"address":"trnm1<40hex>"}
```
Response:
```json
{"address":"trnm1...","nonce":7,"version":1}
```

### 3) `sendTx`
Request:
```json
{
  "from":"trnm1...",
  "to":"trnm1...",
  "amount":100,
  "fee":1,
  "nonce":0,
  "signature":"0x..."
}
```
Response:
```json
{"tx_hash":"0x...","status":"pending"}
```

### 4) `getTx`
Request:
```json
{"tx_hash":"0x..."}
```
Response:
```json
{"tx_hash":"0x...","status":"pending|committed|fail","error":null}
```

## Error codes (frozen)

- `INVALID_ADDRESS`
- `ACCOUNT_NOT_FOUND`
- `TX_NOT_FOUND`

Error shape:
```json
{"code":"INVALID_ADDRESS","message":"..."}
```

## Compatibility rules

- New fields must be additive only.
- Existing fields must not change type/meaning.
- `status` enum values are fixed in v1: `pending|committed|fail`.
