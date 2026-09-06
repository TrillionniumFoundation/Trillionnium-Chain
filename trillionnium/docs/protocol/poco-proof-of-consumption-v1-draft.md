# PoCO Proof of Consumption v1

Status: Draft  
Scope: application-layer task settlement and reward attribution

## Boundary

PoCO does not replace the native Trillionnium Chain block-consensus protocol.

- Native consensus decides block order and finality.
- PoCO decides whether a produced task output has verifiable downstream consumption and is eligible for settlement.

## Core rule

A worker is not paid merely for generating output. Settlement requires a consumer-authorized receipt bound to the task, worker, output commitment, tokenizer version, billing window, and monotonic consumer nonce.

## Canonical objects

### Output commitment

```json
{
  "task_id": "task_123",
  "settlement_schema": "poco_v1",
  "output_hash": "0x...",
  "reveal_hash": "0x..."
}
```

### Output reveal

```json
{
  "task_id": "task_123",
  "worker_id": "worker_abc",
  "assignment_id": "assign_456",
  "settlement_schema": "poco_v1",
  "tokenizer_id": "llama3-tokenizer",
  "tokenizer_version": "1.0.0",
  "output_hash": "0x...",
  "output_token_count": 512,
  "output_root": "0x...",
  "output_span_commitment": "0x..."
}
```

### Consumption receipt

```json
{
  "task_id": "task_123",
  "worker_id": "worker_abc",
  "consumer_id": "consumer_xyz",
  "billing_window_id": "bw_2026_04_09_0001",
  "tokenizer_id": "llama3-tokenizer",
  "tokenizer_version": "1.0.0",
  "output_hash": "0x...",
  "consumed_token_count": 137,
  "consumed_spans_root": "0x...",
  "consumer_class": "bonded_api_client",
  "consumer_nonce": 44,
  "consumer_signature": "0x..."
}
```

## Validation

A receipt is valid only when:

- task, worker, assignment, output, tokenizer, and billing window match canonical state;
- the consumer signature verifies under an eligible registered key;
- the consumer nonce is strictly monotonic;
- producer and credited consumer are distinct;
- the consumed span is a valid subset of the committed output;
- the receipt tuple has not been used before;
- token counts and policy caps are respected;
- all arithmetic is checked and deterministic.

## Threat model

Primary attacks are self-consumption, sybil consumers, duplicate credit, cross-task replay, tokenizer drift, inflated spans, output farming, and collusive billing windows. V1 must fail closed on malformed or ambiguous receipt data.

## Settlement

A conservative initial formula is:

```text
consumption_units = consumed_token_count * consumer_weight
```

Apply deterministic per-task, per-consumer, and per-window caps. More complex uniqueness or reputation weighting must be versioned and governed.

## Challenges

Supported challenge categories should include:

- output or tokenizer mismatch;
- invalid signature or ineligible consumer;
- replay or duplicate credit;
- invalid span proof or token count;
- self-consumption;
- budget-cap violation.

Resolution must emit a stable code and preserve the complete audit trail.

## Integration targets

- `trnm-pouw`: receipt validation, metering, challenge, and resolution semantics;
- `trnm-state`: receipt, nonce, cap, and settlement state;
- `trnm-node`: native transaction handlers and block-loop integration;
- `trnm-rpc`: receipt and settlement queries;
- `trnm-cli`: consumer submission, challenge, and query commands.

PoCO remains a settlement protocol. Consensus safety, validator security, and network finality remain responsibilities of the native chain implementation.
