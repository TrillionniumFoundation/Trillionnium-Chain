# Deterministic MVCC and fee contract v1 candidate

Status: **candidate-non-normative; globally disabled**.

Transactions declare read IDs/versions and write targets. Workers may speculate against one immutable parent snapshot. Results become valid only after canonical-index validation against the already accepted prefix. A version mismatch triggers deterministic re-execution; it never changes transaction order.

Each receipt records outcome, exact read/write versions, whether canonical re-execution occurred, four resource counters, fee, and post-transaction object root. `Reverted` and `OutOfResource` are committed outcomes, not host failures.

Per-transaction fee deltas are reduced in sorted destination order at block end. Execution may reserve or emit settlement intents, but it cannot itself transfer provider payment, refund, reward, slash, burn, treasury value or PoCO weight.
