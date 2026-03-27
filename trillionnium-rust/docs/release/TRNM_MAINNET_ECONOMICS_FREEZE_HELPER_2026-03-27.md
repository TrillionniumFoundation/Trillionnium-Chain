# TRNM Mainnet Economics Freeze Helper (2026-03-27)

## Purpose

Turn the broad `P0.6 Economics / anti-spam / fee boundary freeze` blocker into one reviewable launch checklist.

This is not a full tokenomics redesign.
It is a **day-1 freeze helper** for deciding whether TRNM can expose a public ingress surface without immediately inviting abuse or undefined subsidy behavior.

## Required freeze tuple

Before any public-mainnet cut, freeze all five items together:

1. **Ingress class split**
   - `free-ingress`: exact transaction classes that may enter without fee-like payment
   - `fee-like`: exact classes that must pay admission cost or spend explicit budget
   - `sponsor-only`: exact classes that are allowed only when a sponsor path is present

2. **Sponsor boundary**
   - who may sponsor (`system`, governance allowlist, protocol module, third-party account, or none)
   - which transaction classes can be sponsored
   - per-sponsor budget cap and per-epoch refill rule
   - revocation / disable path
   - disposition of already-queued sponsored transactions after revocation (`grandfather`, `drain-only`, or `drop`)

3. **Retention pricing rule**
   - which artifacts are retained: proofs, challenge snapshots, collateral metadata, audit evidence
   - minimum retention window for day-1 mainnet
   - who pays for long-tail storage (submitter, challenger, sponsor, treasury, or shared policy)
   - fallback payer / disable rule when a sponsor-funded retention budget is exhausted
   - what happens after the window expires (prune, checkpoint-only, archive-only)

4. **Anti-spam floor**
   - minimum fee-like admission floor, bond floor, or rate budget
   - separate sustained-load rule for free-ingress classes
   - explicit backpressure action when caps are reached

5. **Override authority**
   - exact authority that may change the tuple before launch
   - required audit evidence / changelog
   - timelock or emergency bypass rule

## Default ship/no-ship interpretation

Use this conservative interpretation until governance freezes something stricter:

- **NO-GO** if any public transaction class is both `free-ingress` and uncapped under sustained load.
- **NO-GO** if sponsored admission lacks an explicit sponsor allowlist or hard budget cap.
- **NO-GO** if proof/challenge retention has no payer-of-record for storage-heavy paths.
- **NO-GO** if the anti-spam floor can be changed without an auditable authority path.
- **CONDITIONAL GO** only when all five tuple elements are written, reviewable, and tied to named parameters or explicit launch constants.

## Minimal parameter sheet to freeze

For launch review, the team should be able to fill in this sheet with concrete values:

| Parameter | Freeze question |
| --- | --- |
| `public_free_ingress_classes` | Which tx classes remain free on day 1? |
| `public_fee_like_classes` | Which tx classes must pay or spend explicit budget? |
| `sponsor_allowed_callers` | Which actors/modules may sponsor ingress? |
| `sponsor_epoch_budget` | What is the hard sponsor budget per epoch/account? |
| `sponsor_revocation_path` | How is a sponsor disabled quickly and audibly? |
| `sponsor_revocation_queue_disposition` | What happens to already-queued sponsored txs after revocation? |
| `retention_window_blocks` | How long do proof/evidence snapshots remain queryable? |
| `retention_payer_rule` | Who pays for long-tail retention? |
| `retention_budget_exhaustion_fallback` | What payer or disable action applies when sponsor-funded retention budget runs dry? |
| `anti_spam_floor` | What minimum floor applies under sustained public load? |
| `override_authority` | Who can change these values before launch? |
| `override_timelock_or_bypass` | What timelock or emergency rule governs changes? |

## Evidence expected at freeze time

A launch review should include:

- one document or config surface containing the frozen tuple
- one command/runbook showing how operators inspect current values
- one test or gate proving the state machine/mempool still honors the chosen boundaries
- one rollback path for tightening policy before public launch

## Minimal freeze review packet

To keep this blocker reviewable, attach one concrete answer for each item below:

1. **Frozen source of truth**
   - file, config surface, or governance artifact containing the current tuple
   - owner of record for edits before launch
2. **Operator inspection path**
   - exact command or runbook operators use to print the current tuple
   - expected output fields: ingress classes, sponsor authority/budget, retention window/payer, anti-spam floor, override authority
3. **Behavioral evidence**
   - at least one mempool gate for ingress/sponsor boundaries
   - at least one state gate for retention canonicalization
4. **Tightening rollback**
   - exact prelaunch action for moving from `CONDITIONAL GO` back to `NO-GO`
   - preferred rollback bias: disable sponsorship first, then tighten free-ingress exposure, then shorten retention/query surface if storage payer remains undefined

## Initial evidence hooks already in tree

Until the final launch parameter surface exists, freeze review should at minimum point to
existing targeted gates that exercise sponsor/free-ingress admission and retention
consistency boundaries:

- `cargo test -p trnm-mempool lane_qos_snapshot_reserve_only_immediate_reopen_bound -q`
  - proves reserve-only shared-lane QoS observability does not falsely re-advertise
    sponsor/free-ingress headroom across guarded reopen boundaries
- `cargo test -p trnm-mempool lane_qos_snapshot_zero_capacity_stability_bound -q`
  - proves hard-stop mode keeps public admission closed even under repeated cross-class
    probe noise
- `cargo test -p trnm-state retention_restore_regression -q`
  - proves retained proof/collateral metadata fails closed when challenge-window,
    challenger, or treasury identity snapshots are non-canonical

These are not a substitute for the final frozen parameter sheet, but they give launch review
an auditable starting point: public ingress policy must stay explicitly bounded, and retained
challenge evidence must remain canonical enough to support later sponsor-funded audit paths.

## What this helper deliberately does not decide

This helper does **not** choose final numeric values.
It only forces TRNM to stop carrying ambiguous mainnet economics into a public release candidate.
