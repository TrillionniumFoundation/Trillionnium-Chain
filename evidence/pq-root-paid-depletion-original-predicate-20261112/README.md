# PQ Root paid-depletion claim: booked credit is not paid CPU

**State:** HOLD_NO_GO / DENY_ALL. No production activation or new native campaign. Original acceptance conditions are unchanged.

## Exact provenance

- Parent audit PR #933 exact head: `eb46a77edfe95c619f239cffc2f80d1079a7af81`.
- Original native source reviewed: `scripts/read_original_native_campaign.py:depletion` from this parent, requiring `remaining_paid_credit_ns < start_reserve_ns` **and** `paid_cpu_debit_ns > burst_ns - start_reserve_ns`, plus conservation with `settlement_discard_ns`, worker limit, live-owner booking, full versus unsettled CPU, and no clock failures.
- Production code and resource/workload requirements remain untouched. This only tightens and corrects the independent report reader.

## Reproduced failure before change (Hepta ai395)

At parent `eb46a77edfe95c619f239cffc2f80d1079a7af81`, `scripts/ci/pq_root_campaign_readback.py` accepted a synthetic reported successful 24-attacker phase with `paid_cpu_debit_ns=0`, `booked_reservation_ns=1,950,000,001`, `stored_credit_ns=49,999,999`, `remaining_paid_credit_ns=2,000,000,000`. The returned `phase_criteria_met=True` and `attack_phases_with_genuine_budget_depletion=1`; **no paid CPU was consumed**. This is a false-positive *audit-reader* result, not an actual native campaign observation.

## Fixed claim conditions

The readback now independently checks both numerical strict bounds, the complete original ledger:
`remaining = initial + credited_refill - paid_cpu_debit - settlement_discard`,
`stored = remaining - booked`,
`booked = live_owners * start_reserve`,
`paid_cpu_debit = live_debited + settlement_residual`,
`unsettled_known_live = paid_cpu_debit - settled_full`,
and additionally compares original meter credit, original profile `worker_limit=2`, and `clock_failures=0`. Evidence flags cannot replace numeric witnesses.

## Controlled verification

- Hepta ai395 original HEAD `eb46a77edfe95c619f239cffc2f80d1079a7af81`: **34/34 tests passed** before patch.
- Hepta ai395 patched working source: **38/38 tests passed**, `git diff --check` passed.
- Added controls: booked-but-unspent false positive refused; exact 1.9 s debit threshold refused; legitimate nonzero settlement discard accepted; incorrect live-owner/CPU reconciliation, worker limit or clock failures refused.
- Base reader SHA-256 `dcee6d784e7af1f18ccbb89cb18a00eeed32983352197979cc111889bb77cbc0`; tested after SHA-256 `6cc287648b7537ac585b4d3ab94ebd4711600d93807e33f065de60b6fc487a12`.
- Base tests SHA-256 `024a2eab229bf06cb19e6fbcda479edd03533ea6eb3ab7cdaf4fd17483d6028f`; tested after SHA-256 `6c386dbb051af769064bc75e09d953cd0a35c17a849d9c1bb014e751be81e653`.
- Original native campaign still **0/3** in [Actions 43134865479](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/43134865479) at tested head `b192712ca096c79766d3570fc4fa224da68d026d`; this is a different source and **not** the new code's CI result.

## Scope limits

This change does not establish independent operators/keys/backup, external rollback-freshness, real M15/FinalUse provider effects/payment/reorg, secure algorithm migration, or numerical eight-domain/multi-key/multi-epoch/shared-hash QROM lifetime bounds. A test pass is not a production native campaign pass or `2^-128` failure bound. All gates remain HOLD.
