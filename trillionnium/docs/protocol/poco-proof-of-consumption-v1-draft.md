# PoCO Proof of Consumption v1 (Draft)

Status: Draft  
Scope: settlement / reward proof for output consumption, intended as a successor candidate to PoUW for application-layer task settlement  
Compatibility: keeps the current chain-level BFT block consensus intact; changes only the task verification and settlement layer

---

## 1. Naming and scope

This document uses **PoCO** (`Proof of Consumption`) instead of `PoA` to avoid confusion with `Proof of Authority`.

PoCO is **not** a replacement for the chain's block consensus.

- Block production / finality can remain Tendermint-like BFT
- PoCO replaces or downweights PoUW in the **task settlement** and **reward distribution** path

In other words:

- **BFT answers:** which block is final
- **PoCO answers:** which task output earned settlement because it was actually consumed

---

## 2. Why move from PoUW to PoCO

PoUW tries to prove that useful work was performed.

That is attractive in principle, but expensive in practice because the chain must reason about:

- whether the work really happened
- whether the proof is bound tightly enough to task context
- whether the work was useful, not merely performed
- whether challenge / resolve can be kept cheap enough for routine settlement

PoCO shifts the question from **"was work done"** to **"was the produced output actually consumed"**.

That changes verification from a semantic-quality problem into a receipt-validity problem.

PoCO should be easier to verify because the chain mainly checks:

- output binding
- canonical token counting
- consumer signature / authorization
- replay resistance
- settlement caps and anti-sybil rules

---

## 3. Core design principle

A worker does not get paid merely for generating output.

A worker gets paid when a downstream consumer submits a **verifiable consumption receipt** for that output.

The minimal PoCO settlement unit is therefore:

```text
consumed output + canonical token accounting + consumer-signed receipt
```

This makes settlement more objective than open-ended usefulness claims, while staying cheaper than full semantic verification.

---

## 4. Non-goals

PoCO v1 does **not** attempt to prove:

- that the output is globally optimal
- that the output is truthful
- that the output is unique in a semantic sense
- that every consumed token is economically valuable at the same rate

Those concerns are handled indirectly via:

- consumer eligibility
- weighting
- spend / settlement caps
- replay / duplication limits
- optional reputation and fraud slashing

---

## 5. Threat model

PoCO is easier to verify than PoUW, but it creates a new primary risk surface: **fake consumption**.

The main attacks are:

1. **self-consumption**
   - worker controls both producer and consumer identities
2. **sybil consumption**
   - many low-cost consumers sign fake receipts
3. **duplicate consumption**
   - the same consumer repeatedly reclaims credit for the same output
4. **inflated token accounting**
   - receipts use a drifting tokenizer or ambiguous output slice rules
5. **template farming**
   - low-value repeated outputs maximize consumed token count without real independent demand
6. **cross-task replay**
   - one valid receipt is replayed across tasks, outputs, or billing windows

PoCO v1 succeeds only if these are explicitly constrained.

---

## 6. High-level protocol summary

### 6.1 Existing flow retained where possible

PoCO should minimize breakage by preserving the current task lifecycle for v1 compatibility:

```text
OPEN -> ASSIGNED -> COMMITTED -> REVEALED -> CHALLENGED -> COMPLETED / SLASHED
```

Interpretation under PoCO:

- `COMMITTED`: worker commits output receipt hash
- `REVEALED`: worker reveals canonical output metadata and consumption-eligible output commitment
- `CHALLENGED`: receipts or settlement claims can be disputed
- `COMPLETED`: payout determined by accepted consumption units, not raw work units

### 6.2 Optional future v2 state split

If the protocol later wants a more explicit settlement stage, it may split:

```text
REVEALED -> ADOPTION_OPEN -> CHALLENGED -> COMPLETED / SLASHED
```

But v1 should avoid that break unless profiling proves it necessary.

---

## 7. Canonical objects

PoCO v1 introduces three canonical objects.

### 7.1 OutputCommitEnvelope

Submitted during `commit`.

```json
{
  "task_id": "task_123",
  "settlement_schema": "poco_v1",
  "output_hash": "0x...",
  "reveal_hash": "0x..."
}
```

### 7.2 OutputRevealReceipt

Submitted during `reveal`.

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
  "output_span_commitment": "0x...",
  "optional_attestation": {
    "kind": "tee",
    "quote_hash": "0x...",
    "measurement": "0x..."
  },
  "reveal_hash": "0x..."
}
```

Meaning:

- `output_hash` binds the full revealed output
- `output_token_count` uses the frozen tokenizer
- `output_root` or `output_span_commitment` allows compact proof of consumed spans
- TEE / ZK remains optional as provenance support, not the main settlement metric

### 7.3 ConsumptionReceipt

Submitted by a consumer during or after reveal, before settlement closes.

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
  "accepted_at_unix_ms": 1775683200123,
  "consumer_signature": "0x..."
}
```

Minimal validity claim:

> consumer `consumer_id` attests that `consumed_token_count` tokens from the output bound by `output_hash` were actually accepted for downstream use inside the declared billing window.

---

## 8. Verification rules

A PoCO receipt is accepted only if all of the following hold.

### 8.1 Binding rules

- `task_id` must match an existing revealed task
- `worker_id` must match the assigned / accepted producer
- `output_hash` must match the revealed output
- `tokenizer_id` and `tokenizer_version` must match the revealed canonical tokenizer

### 8.2 Consumer authenticity rules

- `consumer_signature` must verify under the registered consumer key
- `consumer_nonce` must be strictly monotonic per consumer
- `consumer_id != worker_id`
- consumer must satisfy registry eligibility for the declared `consumer_class`

### 8.3 Consumption accounting rules

- `consumed_token_count > 0`
- `consumed_token_count <= output_token_count`
- `consumed_spans_root` must prove a subset of the revealed output commitment when requested
- duplicate receipts for the same `(task_id, consumer_id, output_hash, billing_window_id)` are rejected

### 8.4 Settlement-cap rules

- per-task billable consumed tokens are capped by policy
- per-consumer contribution can be capped or weighted down beyond threshold
- repeated consumption by tightly correlated consumers may be discounted by policy

---

## 9. Reward metric

PoCO settles on **consumption units**, not raw work units.

Recommended v1 form:

```text
consumption_units =
    consumed_token_count
  * consumer_weight
  * uniqueness_weight
  * budget_weight
```

Where:

- `consumed_token_count`: canonical consumed token count
- `consumer_weight`: policy weight for consumer class or stake tier
- `uniqueness_weight`: anti-template / anti-repeat discount
- `budget_weight`: task or billing-window cap multiplier

### 9.1 Conservative v1 simplification

For first rollout, use a simpler form:

```text
consumption_units = consumed_token_count * consumer_weight
```

with strict caps:

- per-task max settleable tokens
- per-consumer max credited tokens per window
- one accepted consumption receipt per consumer-output-window tuple

This keeps v1 auditable and cheap.

---

## 10. Anti-fraud policy requirements

PoCO v1 should not ship without the following controls.

### 10.1 No self-consumption

The worker / producer cannot also be the credited consumer.

### 10.2 Bonded or registered consumers

Only consumers with one of the following should produce billable consumption receipts:

- bonded on-chain identity
- allowlisted partner service identity
- stake-backed application key
- reputation-bearing enterprise tenant

Anonymous public consumers can exist, but their receipts should either:

- not be billable, or
- receive near-zero settlement weight

### 10.3 Duplicate suppression

Reject or heavily discount:

- repeated consumption for the same output by the same consumer
- same consumption receipt replayed in another billing window
- same consumer splitting one consumption across many nearly identical receipts

### 10.4 Cap long-output farming

Without caps, longer outputs automatically dominate reward.

Required controls:

- per-task settleable token cap
- diminishing returns above threshold
- optional consumption-to-budget ratio limit

### 10.5 Freeze tokenizer semantics

A tokenizer drift is equivalent to a meter drift.

Therefore:

- tokenizer identity is part of the reveal receipt
- consumption receipts using a mismatched tokenizer are invalid
- tokenizer upgrades require governance or version-gated rollout

---

## 11. Challenge categories

PoCO still needs challenge / resolve, but the categories become simpler than PoUW semantic disputes.

Recommended v1 categories:

- `output_hash_mismatch`
- `tokenizer_mismatch`
- `signature_invalid`
- `consumer_ineligible`
- `replay_detected`
- `duplicate_credit`
- `span_proof_invalid`
- `token_count_inconsistent`
- `self_consumption`
- `budget_cap_exceeded`

These are mostly structural, cryptographic, or policy-bound disputes.

---

## 12. Resolve outcomes

Suggested resolve codes:

- `accepted`
- `accepted_discounted`
- `rejected_invalid_receipt`
- `rejected_replay`
- `rejected_consumer_ineligible`
- `rejected_self_consumption`
- `rejected_budget_cap`
- `slashed_fraudulent_receipt`

`accepted_discounted` is important because many anti-gaming policies are better implemented as deterministic discounting than binary rejection.

---

## 13. Recommended migration strategy

Do **not** hard-cut from PoUW to PoCO in one release.

### Phase 0: additive draft mode

- keep PoUW settlement live
- add `poco_v1` receipts and queries
- do not pay on them yet
- collect observability and adversarial traces

### Phase 1: shadow settlement

- compute PoUW payout and PoCO payout side by side
- publish divergence metrics
- identify fake-consumption patterns before money depends on them

### Phase 2: hybrid settlement

Use a blended formula such as:

```text
settlement_score = alpha * pouw_units + beta * consumption_units
```

with `beta` gradually increasing.

### Phase 3: PoCO-primary

- PoCO becomes the primary settlement basis
- PoUW remains optional provenance / attestation support
- governance may retire PoUW-only rewards later

---

## 14. Rust module landing suggestions

### 14.1 `trnm-pouw`

This crate is still the best initial landing zone, even if its name lags the new semantics.

Recommended additions:

- `src/consumption.rs`
  - `ConsumptionReceipt`
  - receipt validation
  - canonical tuple keys for replay prevention
- `src/consumption_metering.rs`
  - `consumption_units(...)`
  - cap / discount helpers
- extend `src/challenge.rs`
  - PoCO challenge categories
- extend `src/resolve.rs`
  - PoCO resolve codes and discount path
- extend `src/metering.rs`
  - shared token-accounting helpers

### 14.2 `trnm-state`

Add durable state for:

- consumption receipt records
- per-consumer nonce tracking
- per-task settlement summaries
- cap usage and discount metadata

Suggested indices:

- `(task_id, consumer_id, output_hash, billing_window_id)`
- `(consumer_id, consumer_nonce)`
- `(task_id)` settlement aggregate

### 14.3 `trnm-node`

Add transaction handlers and block-loop hooks for:

- submit consumption receipt
- challenge consumption receipt
- close settlement window
- emit consumption settlement events

### 14.4 `trnm-rpc`

Add read surfaces:

- `query consumption-summary <task_id>`
- `query consumption-receipts <task_id>`
- `query consumer-consumption <consumer_id>`
- `query settlement-preview <task_id>`

### 14.5 `trnm-cli`

Add operator / consumer commands:

- `tx adopt-output`
- `tx challenge-consumption`
- `query consumption-summary`
- `query settlement-preview`

---

## 15. Event contract suggestions

Minimum event family for PoCO v1:

- `output_revealed`
- `consumption_receipt_submitted`
- `consumption_receipt_rejected`
- `consumption_receipt_challenged`
- `consumption_receipt_resolved`
- `task_settlement_completed`

Recommended fields:

- `event_type`
- `task_id`
- `worker_id`
- `consumer_id`
- `output_hash`
- `consumed_token_count`
- `credited_consumption_units`
- `resolution_code`
- `block_height`
- `state_root`
- `ts_unix_ms`

---

## 16. Key open questions

Before implementation freeze, decide:

1. What consumer classes are billable in v1?
2. Are consumption receipts private, public, or selectively disclosed?
3. Is `consumed_spans_root` mandatory in v1, or only needed on challenge?
4. How aggressive should discounting be for repeated or correlated consumers?
5. Does governance want PoCO-only settlement, or long-term hybrid PoUW + PoCO?

---

## 17. Recommendation

The most practical path is:

1. keep BFT untouched
2. introduce `poco_v1` as an additive settlement schema
3. keep PoUW receipts only as provenance / execution evidence during migration
4. settle initially on conservative, capped consumption units
5. harden anti-sybil controls before scaling payout weight

That path gives Trillionnium a cleaner verification target without pretending that "consumption" is automatically manipulation-resistant.

PoCO makes verification easier.

It does **not** make economics easier unless the protocol treats fake consumption as the primary adversary from day one.
