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

3. **Retention pricing rule**
   - which artifacts are retained: proofs, challenge snapshots, collateral metadata, audit evidence
   - minimum retention window for day-1 mainnet
   - who pays for long-tail storage (submitter, challenger, sponsor, treasury, or shared policy)
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
| `retention_window_blocks` | How long do proof/evidence snapshots remain queryable? |
| `retention_payer_rule` | Who pays for long-tail retention? |
| `anti_spam_floor` | What minimum floor applies under sustained public load? |
| `override_authority` | Who can change these values before launch? |
| `override_timelock_or_bypass` | What timelock or emergency rule governs changes? |

## Evidence expected at freeze time

A launch review should include:

- one document or config surface containing the frozen tuple
- one command/runbook showing how operators inspect current values
- one test or gate proving the state machine/mempool still honors the chosen boundaries
- one rollback path for tightening policy before public launch

## What this helper deliberately does not decide

This helper does **not** choose final numeric values.
It only forces TRNM to stop carrying ambiguous mainnet economics into a public release candidate.
