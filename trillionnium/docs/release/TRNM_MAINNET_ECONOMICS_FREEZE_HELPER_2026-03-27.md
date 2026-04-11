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
   - whether revoke / drain-only mode must preserve duplicate knowledge for already-seen sponsored ids so replay probes cannot reopen sponsor/free-ingress headroom before the queue truly drains

   ### Sponsor revocation disposition mini-matrix

   Use one label only in the freeze packet, and make the queue semantics explicit:

   | Disposition | Queue effect after revocation | Required duplicate-retention stance | Review bias |
   | --- | --- | --- | --- |
   | `grandfather` | already-queued sponsored txs may continue to admission/settlement under the pre-revocation sponsor grant | duplicate tracking must remain intact until those txs leave the queue; otherwise replay probes can make revocation look softer than stated | avoid for day-1 unless the remaining sponsored exposure is tightly capped and auditable |
   | `drain-only` | no new sponsor-backed ingress is accepted, but already-queued sponsored txs may drain naturally | preserve already-seen sponsored ids as duplicate-classified until the queue truly drains and public headroom stays fail-closed | preferred temporary safety valve when revocation must not fabricate phantom reopen behavior |
   | `drop` | queued sponsored txs are explicitly removed/cancelled at revocation time | duplicate-retention rule must still say whether dropped ids remain classified as seen until the drop is durably reflected everywhere operators inspect admission state | safest for subsidy shutdown, but only if operator/audit surfaces can explain the discard clearly |

   If the review packet cannot say which one of these three dispositions is in force, treat the sponsor boundary as **not frozen**.

3. **Retention pricing rule**
   - which artifacts are retained: proofs, challenge snapshots, collateral metadata, audit evidence
   - minimum retention window for day-1 mainnet
   - who pays for long-tail storage (submitter, challenger, sponsor, treasury, or shared policy)
   - fallback payer / disable rule when a sponsor-funded retention budget is exhausted
   - what happens after the window expires (prune, checkpoint-only, archive-only)

   ### Retention exhaustion / expiry mini-matrix

   Freeze review should name both the **budget exhaustion** behavior and the **post-window expiry** behavior so operators do not have to infer whether TRNM silently widens treasury liability or silently keeps storage hot forever.

   | Surface | Candidate label | Required freeze wording | Review bias |
   | --- | --- | --- | --- |
   | sponsor-funded retention budget exhaustion | `disable-new-growth` | no new sponsor-funded retention growth is accepted once the budget is exhausted; existing retained artifacts stay governed by their already-frozen window | safest default for day-1 because it fails closed without inventing a new payer |
   | sponsor-funded retention budget exhaustion | `fallback-to-explicit-payer` | new retention growth continues only when the submitter/challenger/caller becomes the payer-of-record under an already-frozen rule | acceptable only if the payer transition is operator-visible and auditable |
   | sponsor-funded retention budget exhaustion | `fallback-to-treasury` | treasury absorbs additional retention cost after sponsor exhaustion | avoid for day-1 unless governance has explicitly capped and approved this liability |
   | retention window expiry | `prune` | the heavy artifact payload is deleted after the frozen window, leaving only whatever metadata the packet explicitly promises | lowest storage risk, but only if audits do not rely on the discarded payload |
   | retention window expiry | `checkpoint-only` | only a compact checkpoint / state-root / minimal audit marker survives after expiry | preferred conservative default when full archival funding is not frozen yet |
   | retention window expiry | `archive-only` | artifacts leave the hot query path but remain recoverable from an explicitly named archive tier/payer | acceptable only if archive ownership, retrieval expectations, and cost responsibility are frozen too |

   If the freeze packet names a retention payer but does not also name one exhaustion label and one expiry label, treat retention pricing as **not frozen**.

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

## Freeze decision rubric (attach to the review packet)

Use one of these labels only after the tuple sheet, evidence packet, and wording checks are all reviewed together.
Do not treat a green compile/test slice by itself as a launch decision.

| Decision | Minimum required state | Typical blocker that keeps this from upgrading |
| --- | --- | --- |
| `GO` | all five tuple elements are frozen with concrete values; sponsor revocation disposition + duplicate-retention stance are named; retention payer + exhaustion label + expiry label are named; adversarial rehearsal slice is green; operator/public wording matches the tuple; rollback/tightening path is recorded | none inside the economics packet; any remaining launch blocker should be outside this economics scope |
| `CONDITIONAL GO` | tuple is mostly frozen and the targeted rehearsal slice is green, but one or more non-widening review artifacts are still missing (for example: inspection/runbook command not yet attached, public wording not yet updated, or rollback wording still draft) | evidence packet or wording drift means reviewers still cannot audit the frozen boundary cleanly |
| `NO-GO` | any tuple element is still undecided, any unresolved field would widen public ingress/subsidy/retention semantics, or the targeted rehearsal slice is red / unexplained | launch economics boundary is still mutable, ambiguous, or contradicted by the current gate results |

Escalation rule:
- if reviewers cannot tell whether a gap is merely documentation drift or a real widening of ingress/subsidy semantics, classify it as `NO-GO` until the ambiguity is removed.
- if a fix only tightens wording/evidence without changing economics behavior, it may move `NO-GO -> CONDITIONAL GO`.
- only a packet with frozen values **and** green targeted evidence may move `CONDITIONAL GO -> GO`.

## Minimal parameter sheet to freeze

For launch review, the team should be able to fill in this sheet with concrete values:

| Parameter | Freeze question |
| --- | --- |
| `public_free_ingress_classes` | Which tx classes remain free on day 1? |
| `public_fee_like_classes` | Which tx classes must pay or spend explicit budget? |
| `sponsor_only_classes` | Which tx classes are disallowed unless an approved sponsor path is present? |
| `sponsor_allowed_callers` | Which actors/modules may sponsor ingress? |
| `sponsor_allowed_classes` | Which transaction classes are allowed to consume sponsor-backed admission? |
| `sponsor_epoch_budget` | What is the hard sponsor budget per epoch/account? |
| `sponsor_epoch_refill_rule` | How and when does sponsor budget refill between epochs? |
| `sponsor_revocation_path` | How is a sponsor disabled quickly and audibly? |
| `sponsor_revocation_queue_disposition` | What happens to already-queued sponsored txs after revocation? |
| `sponsor_revocation_duplicate_retention` | During `drain-only`, must already-seen sponsored ids remain duplicate-classified until the queue truly drains? |
| `retention_window_blocks` | How long do proof/evidence snapshots remain queryable? |
| `retention_payer_rule` | Who pays for long-tail retention? |
| `retention_budget_exhaustion_fallback` | What payer or disable action applies when sponsor-funded retention budget runs dry? |
| `retention_expiry_disposition` | What happens after the retention window expires: prune, checkpoint-only, or archive-only? |
| `anti_spam_floor` | What minimum floor applies under sustained public load? |
| `anti_spam_backpressure_action` | When public caps are reached, what exact fail-closed action happens: reject, queue-with-budget, sponsor-only, or another explicitly named path? |
| `override_authority` | Who can change these values before launch? |
| `override_timelock_or_bypass` | What timelock or emergency rule governs changes? |

## Fail-closed defaults for unresolved freeze fields

If launch review has not frozen a field yet, do **not** let operator wording or temporary configs silently widen the public economics surface. Use these conservative placeholders until an explicit tuple value is approved:

| Unresolved field | Required fail-closed default |
| --- | --- |
| `public_free_ingress_classes` | treat as empty for public launch review; no class should be described as generally free by default |
| `public_fee_like_classes` | keep candidate classes outside public day-1 exposure until the admission floor and payer semantics are named |
| `sponsor_allowed_callers` / `sponsor_allowed_classes` | treat as `none`; do not imply governance-or-third-party sponsorship exists yet |
| `sponsor_epoch_budget` / `sponsor_epoch_refill_rule` | treat as zero budget / no refill |
| `sponsor_revocation_queue_disposition` | prefer `drain-only` only if duplicate-retention semantics are also frozen and evidenced; otherwise fail review rather than improvising queue behavior |
| `retention_payer_rule` | disable storage-heavy retention claims for public launch review; do not assume treasury absorption by default |
| `retention_budget_exhaustion_fallback` | fail closed to `disable new sponsor-funded retention growth` rather than silently rolling costs into an unspecified payer |
| `retention_expiry_disposition` | describe as `checkpoint-only` or stricter until an explicit archive/prune rule is approved |
| `anti_spam_floor` | treat public sustained-load admission as not frozen / not launch-ready |
| `anti_spam_backpressure_action` | treat cap-hit behavior as fail-closed reject / no-new-admission until an explicit operator-visible action is frozen |
| `override_authority` / `override_timelock_or_bypass` | treat tuple changes as unauthorized for launch review evidence |

These defaults are not the target economics policy. They are a review discipline: when a field is blank, the burden stays on the reviewer to freeze it explicitly rather than letting ambiguity widen subsidy, retention, or admission behavior.

## Evidence expected at freeze time

A launch review should include:

- one document or config surface containing the frozen tuple
- one command/runbook showing how operators inspect current values
- one test or gate proving the state machine/mempool still honors the chosen boundaries
- one rollback path for tightening policy before public launch

## Operator/public wording alignment checklist

Before calling the economics tuple frozen, make the operator packet and any public-facing launch wording restate the same admission boundary without softer synonyms.

Minimum wording checks:
- `free-ingress` only names the exact day-1 classes listed in `public_free_ingress_classes`; do not paraphrase this as "generally free" or "default free".
- `fee-like` only names the exact classes listed in `public_fee_like_classes`; if budget-spend semantics are used, say so explicitly instead of implying universal token fees.
- `sponsor-backed` / `sponsor-only` wording must match the frozen `sponsor_only_classes`, sponsor authority, epoch budget, refill rule, and revocation semantics; never imply unrestricted third-party subsidy when the tuple says allowlist or protocol-only.
- retention wording must name the payer-of-record and exhaustion fallback, so operators do not infer indefinite free storage for proof/evidence-heavy paths.
- anti-spam wording must point to the actual floor/budget/bond rule and the cap-hit backpressure action rather than generic QoS language.
- prelaunch change wording must name the override authority plus timelock/bypass rule, so readers can tell whether the tuple is still mutable.

If any operator runbook, launch checklist, or public release note describes a broader or softer ingress surface than the frozen tuple, treat the economics freeze as evidence-incomplete until the wording is corrected.

### Minimal adversarial rehearsal slice

To satisfy the blocker-board requirement that the frozen tuple survives one concrete spam /
fairness rehearsal, attach at least one small reproducible command packet alongside the
frozen sheet. Run the commands below from the **repo root** (the directory that contains
`trillionnium/`), because the Cargo workspace itself lives under that subdirectory:

```bash
cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q
```

Why this is the minimum useful slice:
- `lane_zero_capacity_public_contract_bound` exercises hard-stop public admission so a
  freeze cannot quietly leave sponsor-backed or free-ingress retries looking open under
  sustained probe noise.
- `lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound` exercises the shared
  reserve-only refill edge so duplicate sponsor/free-ingress retries stay
  classification-only until fresh work truly re-consumes capacity.
- `lane_borrowed_last_slot_backpressured_retry_reuse_bound` exercises the sponsor-boundary
  borrowed-slot edge so once the final shared slot is already borrowed, cross-class retries
  stay backpressured until that exact occupant drains instead of fabricating new sponsor-backed
  headroom.
- `retention_restore_regression` checks that retained proof/collateral metadata still
  fails closed when challenger/treasury identities are non-canonical, which keeps the
  retention payer/audit trail inside the same freeze review.

If any command above fails, the economics tuple should remain at least `CONDITIONAL GO`
until the mismatch is explained or the freeze packet is tightened.

### Optional sponsor-boundary stability spot checks

When launch review wants slightly stronger evidence without widening into a repo-wide
rehearsal, append these focused checks to the same packet:

```bash
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_zero_capacity_stability_bound -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_guarded_reopen_probe_stability_bound -q
cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound -q
```

Why these are useful extensions:
- `--test lane_qos_snapshot_zero_capacity_stability_bound`
  runs the integration gate showing that repeated idle polls and cross-class probe noise
  do not make a fully closed public lane look open again.
- `--test lane_qos_snapshot_guarded_reopen_probe_stability_bound`
  runs the integration gate showing that partially reopened capacity does not falsely
  widen the externally visible sponsor/free-ingress surface while the last reserved
  critical slot is still guarded.
- `--test lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound`
  demonstrates the exact `drain-only` revocation edge: already-seen sponsored ids stay
  duplicate-classified until the surviving queued work truly drains, so replay probes do
  not fabricate sponsor-backed headroom during revocation.

These are still targeted economics-boundary checks, not a substitute for the frozen tuple
itself; use them to harden evidence when sponsor revocation or reserve-only visibility is
still under review.

### Existing gate coverage mapped to the freeze tuple

Before a first-class economics config/query surface exists, reviewers still need a crisp
answer to: "which current gates actually defend each frozen boundary?" The mapping below
keeps that review bounded and auditable.

| Freeze tuple element | Current gate/evidence anchor | What it proves today |
| --- | --- | --- |
| ingress class split | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q` | When public capacity is hard-stopped, sponsor-backed and free-ingress probe noise cannot make the externally visible admission surface look open again. |
| sponsor boundary / duplicate retention | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q` | Once a reopened shared slot is re-consumed, sponsor/free-ingress retries remain classification-only until a real drain happens again; retry noise cannot silently widen sponsor-backed headroom. |
| sponsor boundary / borrowed-slot discipline | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q` | If the last admissible shared slot is already borrowed, fresh cross-class retries stay backpressured until that exact borrowed occupant drains. |
| sponsor revocation / drain-only duplicate retention | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound -q` | The reserve-only revocation gate keeps already-seen sponsored ids duplicate-classified until the surviving queued work truly drains, so replay probes cannot silently reopen sponsor-backed headroom during a `drain-only` sponsor shutdown. |
| anti-spam floor / hard admission boundary | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_reserve_clamp_borrow_policy_bound -q` | Under an oversized-reserve clamp, the final truly free shared slot remains borrowable until aggregate anti-spam capacity is actually exhausted, then fresh normal ingress fails closed once that floor is consumed. This gives the freeze packet one explicit gate tied to the sustained-load admission floor rather than only to sponsor/duplicate semantics. |
| retention timing freeze after challenge | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q` | Once challenge-side retention timing is snapshotted, later governance changes do not silently rewrite the resolve window. This keeps the retention window side of the economics tuple frozen at the task/challenge boundary instead of drifting with later config edits. |
| retention pricing / retention safety | `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q` | Retained proof/collateral metadata remains canonical and fail-closed under restore/replay pressure, which keeps the future payer/audit path reviewable instead of silently accepting malformed identities. This remains a **required companion gate** even though it lives outside the mempool/`trnm-pouw` compile slice. |
| tuple integrity packet | `cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q` | The current mempool / proof-retention surfaces still compile together as one economics-review slice, rather than drifting independently. This compile check does **not** replace the targeted retention-window snapshot gate or the retention restore regression above; reviewers need all of those signals in the packet. |

This is intentionally **evidence of current guardrails**, not proof that the economics tuple is
fully frozen. Launch review must still bind these behaviors to named launch constants,
authorities, and operator-visible inspection commands. In particular, do not treat a green
`cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q`
as sufficient evidence that retention payer/restore semantics were exercised; the
`trnm-state` retention regression remains the explicit retention-side proof point until a
first-class economics review harness folds both surfaces into one operator command.

### Minimal evidence capture companion

When the rehearsal slice is run for a launch review, preserve the exact command packet and
its pass/fail result in one artifact instead of scattering shell snippets across chat/logs.
Until a first-class release wrapper lands, the following minimal capture pattern is enough.
If the review is attached to a specific lane ticket/worktree, fail closed on that assigned
identity *before* the packet runs; do not infer the expected path/ref from the current shell.

```bash
EXPECTED_WORKTREE_ROOT="/absolute/path/from-ticket"
EXPECTED_BRANCH_REF="refs/heads/lane/example-economics-freeze"
mkdir -p trillionnium/run/mainnet-economics-freeze
(
  set -euo pipefail
  ./trillionnium/scripts/v2/verify_lane_worktree.sh \
    --expected-worktree-root "$EXPECTED_WORKTREE_ROOT" \
    --expected-branch-ref "$EXPECTED_BRANCH_REF"
  status_summary="$(git status --short)"
  if [ -n "$status_summary" ]; then
    printf 'git_status_summary=dirty\n'
    printf '%s\n' "$status_summary"
    echo 'result=FAIL_DIRTY_WORKTREE'
    exit 1
  fi
  date -u +"generated_at=%Y-%m-%dT%H:%M:%SZ"
  printf 'origin_main=%s\n' "$(git rev-parse origin/main)"
  printf 'expected_worktree=%s\n' "$EXPECTED_WORKTREE_ROOT"
  printf 'expected_branch_ref=%s\n' "$EXPECTED_BRANCH_REF"
  printf 'worktree=%s\n' "$(pwd)"
  printf 'branch=%s\n' "$(git branch --show-current)"
  echo 'git_status_summary=clean'
  printf 'command[1]=cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q\n'
  cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q
  printf 'command[2]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q\n'
  cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q
  printf 'command[3]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q\n'
  cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q
  printf 'command[4]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q\n'
  cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q
  printf 'command[5]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q\n'
  cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q
  printf 'command[6]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q\n'
  cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q
  echo 'result=PASS'
) | tee trillionnium/run/mainnet-economics-freeze/minimal-rehearsal.txt
```

If this packet aborts before `result=PASS`, treat the freeze review as non-green and attach the
failing command + rollback/tightening action directly to the same review artifact.

### Inspect a captured rehearsal artifact

Once `trillionnium/run/mainnet-economics-freeze/minimal-rehearsal.txt` exists, reviewers
should inspect the same artifact instead of re-running ad hoc shell history.

```bash
sed -n '1,160p' \
  trillionnium/run/mainnet-economics-freeze/minimal-rehearsal.txt
```

Expected fields visible in the capture:
- `generated_at=` for evidence timing
- `origin_main=` for the exact truth-source snapshot paired with `RELEASE_READINESS.md`
- `worktree=` and `branch=` for identity
- `git_status_summary=clean` for fail-closed clean-tree evidence before the packet runs
- `command[n]=...` lines for the exact rehearsal packet
- `command[1]=cargo check --manifest-path trillionnium/Cargo.toml -p trnm-mempool -p trnm-pouw -q` so the packet records the compile-slice integrity check that keeps the economics review anchored to one joint mempool/retention surface
- `command[2]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q` so the packet explicitly captures the hard-stop admission boundary evidence for the public ingress split
- `command[3]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q` so the packet records the duplicate-retention guard that keeps sponsor/free-ingress retries classification-only after the reopened shared slot is re-consumed
- `command[4]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_borrowed_last_slot_backpressured_retry_reuse_bound -q` so sponsor borrowed-slot backpressure evidence is explicitly present in the recorded freeze packet
- `command[5]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q` so the packet explicitly proves challenge-time retention snapshots stay frozen even if governance changes later
- `command[6]=cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q` so the packet still captures the retention-side fail-closed restore evidence instead of only admission-side checks
- terminal `result=PASS` only when the full slice finished green

If the artifact is missing any of those fields, if it records `git_status_summary=dirty`, or the
file ends before `result=PASS`, treat the freeze review as evidence-incomplete rather than
silently accepting a partial rehearsal.

## Temporary operator inspection path (until a first-class config surface lands)

Until TRNM exposes a dedicated runtime/config query for the economics tuple, launch review
should use a deterministic repo inspection path so every reviewer sees the same source of truth.

### Inspect the frozen questionnaire

```bash
sed -n '/## Minimal parameter sheet to freeze/,/## Evidence expected at freeze time/p' \
  trillionnium/docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md
```

Expected review fields visible in the output:
- ingress classes (`public_free_ingress_classes`, `public_fee_like_classes`, `sponsor_only_classes`)
- sponsor authority/budget (`sponsor_allowed_callers`, `sponsor_allowed_classes`, `sponsor_epoch_budget`, `sponsor_epoch_refill_rule`)
- sponsor revocation semantics (`sponsor_revocation_path`, `sponsor_revocation_queue_disposition`, `sponsor_revocation_duplicate_retention`)
- retention window/payer (`retention_window_blocks`, `retention_payer_rule`, `retention_budget_exhaustion_fallback`, `retention_expiry_disposition`)
- anti-spam floor + backpressure action (`anti_spam_floor`, `anti_spam_backpressure_action`)
- override path (`override_authority`, `override_timelock_or_bypass`)

### Inspect the currently documented behavioral evidence

```bash
grep -n "cargo test --manifest-path trillionnium/Cargo.toml" \
  trillionnium/docs/release/TRNM_MAINNET_ECONOMICS_FREEZE_HELPER_2026-03-27.md
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
   - expected output fields: ingress classes, sponsor-only classes, sponsor authority/budget/classes, sponsor revocation duplicate-retention rule, retention window/payer, retention expiry disposition, anti-spam floor, anti-spam backpressure action, override authority
3. **Behavioral evidence**
   - at least one mempool gate for ingress/sponsor boundaries
   - at least one state gate for retention canonicalization
4. **Launch-packet attachment metadata**
   - exact artifact path or release-note section where this freeze review is attached
   - commit/revision snapshot reviewers are signing off against
5. **Tightening rollback**
   - exact prelaunch action for moving from `CONDITIONAL GO` back to `NO-GO`
   - preferred rollback bias: disable sponsorship first, then tighten free-ingress exposure, then shorten retention/query surface if storage payer remains undefined

### Copy-paste freeze packet stub

Use the following stub when a release review needs one artifact that captures the day-1
admission / sponsorship / retention boundary in one place:

```text
TRNM mainnet economics freeze review
- truth-source snapshot (`origin/main`):
- review artifact path / launch-packet section:
- tuple source of truth:
- tuple owner of record:
- operator inspection command:
- ingress split (free-ingress / fee-like / sponsor-only):
- sponsor authority + allowed classes + budget:
- sponsor revocation path + queued-tx disposition:
- sponsor revoke duplicate-retention rule:
- retention window + payer of record:
- retention expiry disposition:
- retention budget exhaustion fallback:
- anti-spam floor / sustained-load rule:
- anti-spam backpressure action:
- override authority:
- override timelock or emergency bypass:
- mempool evidence gate(s):
- state evidence gate(s):
- tightening rollback action:
- reviewer commit / revision snapshot:
- review result (GO / CONDITIONAL GO / NO-GO):
```

This keeps freeze review from scattering across issue comments or oral history and makes the
operator handoff auditable even before a dedicated runtime/config query exists.

## Freeze decision rubric

Use the same result words everywhere in the launch packet so MN14 evidence does not drift
between helper docs, rehearsal artifacts, and the final GO/NOGO memo.

### `GO`

Only mark the economics tuple `GO` when all of the following are true:
- the full tuple is frozen with explicit values or named launch constants;
- operator inspection path is written and reproducible from the repo/runbook surface;
- at least one targeted mempool gate and one retention-side gate were run green against the
  current tuple review;
- sponsor revocation semantics, duplicate-retention behavior, and retention payer fallback are
  stated without ambiguity;
- operator/public wording matches the frozen tuple without broader marketing shorthand.

### `CONDITIONAL GO`

Use `CONDITIONAL GO` when the tuple is mostly reviewable but at least one launch-critical
edge still needs tightening before any public-mainnet claim, for example:
- the tuple is written but not yet bound to named config/constants;
- the gates are green but the evidence artifact is partial or not yet attached to the launch packet;
- sponsor revocation, drain-only duplicate retention, or retention-budget exhaustion fallback is
  described in prose but not yet pinned as an operator-facing rule;
- operator/public wording still uses softer ingress language than the actual frozen boundary.

### `NO-GO`

Mark the economics tuple `NO-GO` immediately if any of the following hold:
- any public transaction class is effectively uncapped `free-ingress` under sustained load;
- sponsor-backed admission lacks an explicit authority boundary or hard budget cap;
- retention-heavy paths have no payer-of-record or no exhaustion fallback;
- the anti-spam / admission floor can still move without auditable authority and timing rules;
- the review packet cannot show one concrete inspection path plus one concrete mempool/retention
  evidence slice.

### Minimal reviewer shortcut

If the reviewer has less than five minutes, ask only these three questions:
1. can I print the exact frozen tuple right now?
2. can I point to one green admission gate and one green retention gate tied to that tuple?
3. would the public wording cause a reasonable operator to infer a broader subsidy/free-ingress
   surface than the tuple actually allows?

If any answer is `no`, keep the economics package below `GO`.

## Initial evidence hooks already in tree

Until the final launch parameter surface exists, freeze review should at minimum point to
existing targeted gates that exercise sponsor/free-ingress admission and retention
consistency boundaries:

- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_immediate_reopen_bound -q`
  - proves reserve-only shared-lane QoS observability does not falsely re-advertise
    sponsor/free-ingress headroom across guarded reopen boundaries
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_zero_capacity_stability_bound -q`
  - proves hard-stop mode keeps public admission closed even under repeated cross-class
    probe noise and idle scheduler polls
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_public_contract_bound -q`
  - proves a fully hard-stopped lane keeps both sponsor-backed and free-ingress retries
    backpressured across repeated cross-class probes without poisoning tx ids into
    duplicate state or fabricating any queued admission surface
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drain_only_duplicate_retention_bound -q`
  - proves a zero-budget / hard-stop lane can preserve restored duplicate knowledge for
    already-seen ids without fabricating queue state or re-opening sponsor/free-ingress
    headroom during idle polling
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_zero_capacity_idle_poll_public_invariants_bound -q`
  - proves repeated idle scheduler polls under a hard-stop / zero-budget lane keep both
    the public queued-count surface and QoS snapshot flat across fresh/retry cross-class
    noise, so freeze review covers public invariants in addition to duplicate retention
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_refill_boundary_bound -q`
  - proves duplicate sponsor/free-ingress probe noise stays classification-only while
    reserve-only shared-lane mode still exposes the last real refill slot until fresh
    work actually consumes it
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_multi_refill_probe_stability_bound -q`
  - proves the same classification-only duplicate behavior when reserve-only mode has
    reopened more than one shared slot, so sponsor/free-ingress observability stays
    honest across partial drains instead of only at the final refill boundary
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_reopen_probe_stability_bound -q`
  - proves the first reopened shared slot in reserve-only mode closes again as soon as
    fresh sponsor-backed work actually consumes it, and that later cross-class fresh or
    duplicate probes remain classification-only instead of re-advertising phantom headroom
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_duplicate_noise_bound -q`
  - proves drain-only style duplicate retention stays classification-only after the shared
    lane drains, so already-seen sponsored ids cannot reopen sponsor/free-ingress headroom
    before fresh work actually re-consumes capacity
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_reserve_only_drained_retry_resaturates_bound -q`
  - proves the same drained-retry boundary closes the externally visible sponsor/free-ingress
    snapshot again as soon as the drained id is re-admitted, so freeze review covers both the
    classification-only duplicate phase and the immediate re-saturation phase of shared-lane reuse
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_guarded_reopen_probe_stability_bound -q`
  - proves partially reopened capacity does not falsely widen free-ingress observability:
    when the last reserved critical slot is still guarded, repeated fresh-normal and
    cross-class probe noise stays classification-only and cannot advertise phantom headroom
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_qos_snapshot_borrowed_last_slot_reopen_bound -q`
  - proves a borrowed final reserved slot re-advertises sponsor/free-ingress headroom
    immediately after the borrowed occupant drains, without requiring an extra idle
    scheduler poll to reopen the public admission surface
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-mempool --test lane_reserve_clamp_borrow_policy_bound -q`
  - proves the hard anti-spam floor stays fail-closed once the last reserved critical
    slot is truly occupied: normal ingress cannot borrow its way past the sustained-load
    boundary just because the lane was previously borrowable in reserve-only mode
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-pouw --lib tests::legacy_revealed_snapshot_freezes_resolve_timing_after_challenge_despite_later_gov_change -- --exact -q`
  - proves the challenge-time retention window stays frozen once the reveal/challenge
    snapshot exists, even if governance changes later in the launch-prep window
  - keeps the retention side of the economics tuple anchored to task-local evidence
    instead of letting later config edits silently soften or extend resolve timing
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --test retention_restore_regression -q`
  - proves retained proof/collateral metadata fails closed when challenge-window,
    challenger, or treasury identity snapshots are non-canonical
  - specifically covers reserved sponsor/audit identities (`System`, governance pause /
    resolve placeholders, and treasury escrow/forfeit/slash accounts) so retention
    snapshots cannot masquerade as valid third-party challengers
- `cargo test --manifest-path trillionnium/Cargo.toml -p trnm-state --lib tests::restore_task_rejects_terminal_challenge_retention_with_mixed_case_challenger_identity -- --exact -q`
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
