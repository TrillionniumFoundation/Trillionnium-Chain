# Qualified local decisions and original completed use

Status: engineering readback; no production or portable authorization.

## Separate outcomes

PoN validity, learning outcome, node-local model choice and payment are separate
state machines. A fresh work nonce does not imply a new trained model. A valid
W1 block may contain no model publication. Actual training or evaluation may
finish with `NoUpdate`. A qualified proposal may lead one node to adopt while
another defers or retains its parent. Author, miner and commissioned provider
need not be the same account.

The HEPLCP04 choice is qualified `AdoptCandidate`, `DeferCandidate` or
`RetainParent`. It does not rewrite Evaluation or Proposal as `NoUpdate`.
Both Defer and Retain select the parent, but their local-choice signing payloads
remain different. The native use export's `retained_model` field identifies
the object used, not why that object was selected.

## Explicit completed-use profile

[`cell_learning_local_use_join.py`](../../../../scripts/cell_learning_local_use_join.py)
adds an explicit read-only profile with schema
`trnm-cell-learning-local-decision-completed-use-review-v1`. It requires:

1. Independently pinned original initial request and stage-owner expectations.
2. Original HEPLCP04 Selection-cut bytes, with seven receipts.
3. Original completed HEPLCP04 bytes, with exactly one additional NextUse or
   RetainedModelNextUse receipt and the unchanged seven-receipt prefix.
4. The original native learning-use export, plus separately retained invocation
   expectations, accepted by the unchanged native-use reader.
5. Matching operation, source task, selected source artifact and complete source
   bundle, scope, Selection head, local-choice predecessor and selected model.
6. No pending native work or pending delivery: an outstanding ACK refuses.
7. Exact final observation equality, including next-task partition, bundle,
   checkpoint, selection digest, committed step receipt and publication/cutover.

All file inputs have bounded reads and independent SHA-256 pins. Duplicate JSON
fields, changed native payloads, unknown fields and noncanonical digests retain
the original reader's rejection behavior. Recomputing hashes does not remove
the original request, receipt prefix or cross-material consistency checks.

The historical HEPLCP02 and HEPLCP03 profiles are not silently upgraded. The
new profile accepts only HEPLCP04. The original structural-only
[`cell_learning_local_decision_join.py`](../../../../scripts/cell_learning_local_decision_join.py)
still cannot report completed use. Neither profile changes a learning
coordinator, model owner, payment account or local adoption database.

## Output and claim boundaries

For all three local choices the completed-use report keeps:

```text
evaluation_disposition = qualified
proposal_disposition = update_candidates
no_update = false
```

`retained_model` is true for Defer/Retain and false for Adopt. Only after the
actual exported pending state and exact final receipt match may the report set
`completed_use_observed=true`, `pending_work_and_delivery_clear=true` and
`final_next_use_matches_original_actor=true`. These describe consistency among
the pinned materials. They do not authenticate their origin. An empty pending
queue does not distinguish a task with no output from an explicit output ACK,
so `output_ack_event_verified=false` remains explicit. The local actor fixtures
use empty output deltas; pending-output mutations test the refusal boundary,
not an observed ACK event.

The report retains `DENY_ALL`, `NOT_EXPORTED` and `HOLD_NO_GO`. Receipt and grant
signature verification, initial-freeze custody, Root scope authentication,
independent evaluator/consumer control, actual training, complete costs,
physical installation, settlement, full-state recovery and production
qualification all remain unestablished by this reader. Model STOP is reported
separately; a completed advanced step is not relabelled a stopped model.

Native actor fixtures exercise actual journals, CURRENT, publication and
FinalUse mechanisms with controlled evidence. Their expectation pins remain
fixture-derived. A successful fixture does not count as an ordinary complete
learning chain or independent B/C qualification.

## Local retention and payment

The operator-only [proposal-retention contract](CELL_PROPOSAL_RETENTION_V1.md)
binds a distinct TCV1 proposal to an ordinary TCA1 Retain(parent) event. Its
review reference is not an authenticated bridge from a Hepta bundle to TCV1.
That content mapping and current owner authorization remain explicit inputs to
any later operational integration.

The native `outcome_role_separation` integration test exercises real W1 admission,
M06 model-reward claims and M12 NoGain service payment using different miner,
author, provider and payer accounts. Its score attestations and service resource
records are controlled test inputs; it does not train a model or independently
measure improvement. Model reward, mining subsidy and service payment remain
different budget and authorization paths. In particular, correct completion of
a commissioned NoGain evaluation can be paid without awarding model credit.
