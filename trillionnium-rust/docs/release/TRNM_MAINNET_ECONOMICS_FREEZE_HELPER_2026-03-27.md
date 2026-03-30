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
| `sponsor_epoch_refill_rule` | How and when does sponsor budget refill between epochs? |
| `sponsor_revocation_path` | How is a sponsor disabled quickly and audibly? |
| `sponsor_revocation_queue_disposition` | What happens to already-queued sponsored txs after revocation? |
| `retention_window_blocks` | How long do proof/evidence snapshots remain queryable? |
| `retention_payer_rule` | Who pays for long-tail retention? |
| `retention_budget_exhaustion_fallback` | What payer or disable action applies when sponsor-funded retention budget runs dry? |
| `retention_expiry_disposition` | What happens after the retention window expires: prune, checkpoint-only, or archive-only? |
| `anti_spam_floor` | What minimum floor applies under sustained public load? |
| `override_authority` | Who can change these values before launch? |
| `override_timelock_or_bypass` | What timelock or emergency rule governs changes? |

## Evidence expected at freeze time

A launch review should include:

- one document or config surface containing the frozen tuple
- one command/runbook showing how operators inspect current values
- one test or gate proving the state machine/mempool still honors the chosen boundaries
- one rollback path for tightening policy before public launch

## Temporary operator inspection path (until a first-class config surface lands)

Until TRNM exposes a dedicated runtime/config query for the economics tuple, launch review
should use a deterministic repo inspection path so every reviewer sees the same source of truth.

### Inspect the frozen questionnaire

```bash
sed -n '/## Minimal parameter sheet to freeze/,/## Evidence expected at freeze time/p' \
  trillionnium-rust/docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md
```

Expected review fields visible in the output:
- ingress classes (`public_free_ingress_classes`, `public_fee_like_classes`)
- sponsor authority/budget (`sponsor_allowed_callers`, `sponsor_epoch_budget`, `sponsor_epoch_refill_rule`)
- sponsor revocation semantics (`sponsor_revocation_path`, `sponsor_revocation_queue_disposition`)
- retention window/payer (`retention_window_blocks`, `retention_payer_rule`, `retention_budget_exhaustion_fallback`, `retention_expiry_disposition`)
- anti-spam floor + override path (`anti_spam_floor`, `override_authority`, `override_timelock_or_bypass`)

### Inspect the currently documented behavioral evidence

```bash
grep -n "cargo test -p trnm-" \
  trillionnium-rust/docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md
```

This prints the targeted mempool/state gates currently attached to the freeze packet, so
operators can confirm the review is anchored to concrete admission/retention checks rather
than an unaudited prose-only checklist.

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

### Copy-paste freeze packet stub

Use the following stub when a release review needs one artifact that captures the day-1
admission / sponsorship / retention boundary in one place:

```text
TRNM mainnet economics freeze review
- tuple source of truth:
- tuple owner of record:
- operator inspection command:
- ingress split (free-ingress / fee-like / sponsor-only):
- sponsor authority + budget:
- sponsor revocation path + queued-tx disposition:
- retention window + payer of record:
- retention budget exhaustion fallback:
- anti-spam floor / sustained-load rule:
- override authority:
- mempool evidence gate(s):
- state evidence gate(s):
- tightening rollback action:
- review result (GO / CONDITIONAL GO / NO-GO):
```

This keeps freeze review from scattering across issue comments or oral history and makes the
operator handoff auditable even before a dedicated runtime/config query exists.

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
- `cargo test -p trnm-mempool lane_zero_capacity_idle_duplicate_metadata_bound -q`
  - proves a zero-budget / hard-stop lane can preserve restored duplicate knowledge for
    already-seen ids without fabricating queue state or re-opening sponsor/free-ingress
    headroom during idle polling
- `cargo test -p trnm-mempool lane_qos_snapshot_reserve_only_refill_boundary_bound -q`
  - proves duplicate sponsor/free-ingress probe noise stays classification-only while
    reserve-only shared-lane mode still exposes the last real refill slot until fresh
    work actually consumes it
- `cargo test -p trnm-mempool lane_qos_snapshot_reserve_only_multi_refill_probe_stability_bound -q`
  - proves the same classification-only duplicate behavior when reserve-only mode has
    reopened more than one shared slot, so sponsor/free-ingress observability stays
    honest across partial drains instead of only at the final refill boundary
- `cargo test -p trnm-mempool lane_qos_snapshot_borrowed_last_slot_reopen_bound -q`
  - proves a borrowed final reserved slot re-advertises sponsor/free-ingress headroom
    immediately after the borrowed occupant drains, without requiring an extra idle
    scheduler poll to reopen the public admission surface
- `cargo test -p trnm-state retention_restore_regression -q`
  - proves retained proof/collateral metadata fails closed when challenge-window,
    challenger, or treasury identity snapshots are non-canonical
  - specifically covers reserved sponsor/audit identities (`System`, governance pause /
    resolve placeholders, and treasury escrow/forfeit/slash accounts) so retention
    snapshots cannot masquerade as valid third-party challengers
- `cargo test -p trnm-state restore_task_rejects_terminal_challenge_retention_with_mixed_case_challenger_identity -q`
  - proves sponsor-funded retention trails reject mixed-case challenger aliases instead
    of silently canonicalizing them at restore time
  - keeps the freeze packet explicit that retained challenger identities are part of the
    economics boundary, not just cosmetic metadata, because downstream audit/refund
    attribution must key off a single lowercase actor id

These are not a substitute for the final frozen parameter sheet, but they give launch review
an auditable starting point: public ingress policy must stay explicitly bounded, and retained
challenge evidence must remain canonical enough to support later sponsor-funded audit paths.

## What this helper deliberately does not decide

This helper does **not** choose final numeric values.
It only forces TRNM to stop carrying ambiguous mainnet economics into a public release candidate.
