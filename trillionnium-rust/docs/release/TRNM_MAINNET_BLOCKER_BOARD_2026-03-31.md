# TRNM Mainnet Blocker Board (2026-03-31)

## Purpose

This board is the **operator-facing blocker index** for public-mainnet closure work.
It exists to make the current blocker families explicit without weakening the truth-source boundary already defined by:

- `RELEASE_READINESS.md`
- `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`

Interpretation rule:
- this board is a routing / ownership aid, not a release-ready claim
- if this board conflicts with `RELEASE_READINESS.md`, the readiness document wins
- if this board omits a blocker family already listed in the gap matrix, the gap matrix wins

Current top-line state:
- **public mainnet status: NO-GO / not release-ready**
- current repository posture still matches **internal devnet / RC-prep**, not public-mainnet launch candidate

## P0 blocker families

| Blocker family | Launch status | Primary gap | Primary refs |
| --- | --- | --- | --- |
| MN01 / Network bootstrap topology | OPEN | public peer formation / bootstrap peer discipline not closed | `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN02 / Sync catch-up / join-rejoin | OPEN | lagging-node join/rejoin and catch-up behavior not closed | `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN03 / Network config abuse / fail-closed | OPEN | network-level abuse handling and fail-closed config discipline not closed | `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| **MN04 / Genesis ceremony / validator bootstrap** | **PARTIAL** | genesis checklist, bootstrap runbook, and config-bundle validator exist; signed/public-mainnet operator ceremony is still open | `docs/runbooks/genesis-generation-checklist.md`, `docs/runbooks/validator-bootstrap-rebootstrap.md`, `scripts/v2/check_validator_config_bundle.py`, `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN05 / Operator DR / rotation lifecycle | OPEN | validator replacement / rotation automation and DR rebuild evidence still open | `docs/runbooks/validator-bootstrap-rebootstrap.md`, `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN06 + MN07 / Signer hygiene / offline signing | OPEN | secure signer / keystore / offline signing path still MVP/incomplete | `RELEASE_READINESS.md`, `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN08 + MN09 + MN10 / Public read API / read-model / explorer | OPEN | durable historical read path and stable explorer/indexer are not closed | `RELEASE_READINESS.md`, `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN11 + MN12 / Metrics / alerting / SRE | OPEN | unified observability and alerting plane not yet closed | `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN13 + MN14 / Admission / anti-spam / economics freeze | OPEN | day-1 economics tuple and anti-spam freeze remain open | `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |
| MN15 + MN16 / Release evidence / rehearsal / go-no-go | PARTIAL | local evidence and rehearsal helpers exist, but public-mainnet go/no-go still requires path-resolved, identity-consistent evidence on the final candidate | `RELEASE_READINESS.md`, `docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md` |

## MN04-specific closure boundary

What is already present for this blocker family:
- `docs/runbooks/genesis-generation-checklist.md`
- `docs/runbooks/validator-bootstrap-rebootstrap.md`
- `scripts/v2/check_validator_config_bundle.py`

What still keeps MN04 from being marked closed for public mainnet:
- no signed/public-mainnet operator ceremony wired end-to-end
- no captured acknowledgment bundle proving every validator owner reviewed the same packet
- no closed validator replacement / rotation automation
- no DR rebuild drill captured as durable mainnet-facing evidence

## Go / No-Go rule for this board

Treat the blocker board as **NO-GO** for public-mainnet release whenever any P0 family above remains `OPEN` or `PARTIAL`.
In particular, `MN04` remains **PARTIAL**, not CLOSED, until genesis artifact identity, validator packet identity, and operator acknowledgment evidence are all bound together in one auditable ceremony flow.
