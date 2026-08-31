# Trillionnium Chain all-version audit and consolidation record

Audit ID: `trnm-chain-all-versions-audit-2026-08-26`
Date: 2026-08-26 (Asia/Shanghai)
Canonical audited ref: `docs/chain-poco-bft-mainline-20260825`
Canonical audited commit: `b1c71e189bf6f31ba278f1f0806a13196107b354`
Canonical worktree: `/home/alex/projects/worktrees/trillionnium-chain/poco-mainline-20260825`
Canonical plan SHA-256 at consolidation close:
`8252ffa583cc996e8504551d6d5e6ccda0090efaa4b0830722da586504ff6395`
Audit mode: read-only inventory plus documentation consolidation; no fetch, push,
branch/worktree deletion, reset, or history rewrite. One bounded v1
design-truth sweep was run after the ref migration; it reached candidate
checks and stopped at the pre-existing dirty-source compile blocker recorded
below. No source file was edited by the sweep.

## 1. Verdict

There is one defensible production direction: **Rust-native PoCO-BFT**. CometBFT
is migration residue and a differential/historical oracle, not a second
production route. The Chain is not a production candidate yet. The machine
truth at audit time is:

```text
stage = G1-native-host-incomplete
production_candidate = false
production_consensus_activation = false
Comet cleanup eligible = false
PoCO listeners observed = 0
completed validator run = false
AI-native v1 specification = draft / design-only / not implemented
```

The repository contains substantial reusable protocol, state, persistence,
formal, and candidate AI-plane kernels. It does not yet contain a live
authoritative validator process with production P2P, signer custody, state
sync, RPC/indexer, or an end-to-end Agent → DA → Verify → Settlement path.
Therefore “超越一线公链” is a target and acceptance contract, not a current
claim.

The single active plan is now:

[`docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md`](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)

Old live plan paths were removed from the development namespace. Their contents
were moved to `docs/audits/` as historical evidence so Git provenance remains
available without leaving multiple executable roadmaps.

## 2. Scope and source-of-truth hierarchy

Audited surfaces:

- physical Chain root `/home/alex/projects/trillionnium-chain`;
- compatibility path `/home/alex/.openclaw/workspace/TrillionniumChain`;
- canonical PoCO worktree above;
- all local heads, remote-tracking refs, tags, and linked worktrees;
- Cargo workspace/excludes, config truth, protocol status/manifests, source
  entry points, CI gates, release readiness, architecture ADRs, evidence, and
  all plan/roadmap/board/delivery filenames.

When text conflicts, use this order:

1. `trillionnium/Cargo.toml` metadata and `config/consensus-mainline.json`;
2. `TRNM_POCO_BFT_MAINLINE_CUTOVER_2026-08-25.md` and `RELEASE_READINESS.md`;
3. frozen v0/v1 contracts, schemas, vectors, and status files;
4. the canonical development plan and signed evidence;
5. source/tests (implementation detail, never an automatic promotion);
6. `docs/audits/**` and `docs/archive/**` (historical context only).

## 3. Git version topology

The audit found **103 local heads (99 unique tips)**, **6 remote-tracking
refs**, **4 tags**, and **102 linked worktrees** (71 project paths, 31 `/tmp`
paths). Six worktrees are detached and 14 are dirty. All four tags are
ancestors of the PoCO mainline. No branch or worktree was deleted.

| Generation/ref | Representative tip | Meaning | Authority |
| --- | --- | --- | --- |
| Legacy mock/Comet | pre-2026-07-27 history | Original simulated loop, Comet/ABCI runtime, local receipts | Historical/differential only |
| Public-testnet/old main | `e73d1a930991` (2026-08-04) | Comet runtime and old March plans; no current PoCO protocol tree | Superseded |
| Remote PoCO v0 | `eea8be5a6f40` (2026-08-10) | First frozen v0 contracts/schemas and delivery tranche | Historical v0 candidate |
| Local `feature/chain-poco-bft-v0` | `2d5fbf8568f4` (2026-08-25) | v0 work with older plan generation, no current cutover board | Stale development branch |
| Root checkout `feature/chain-paper-raid-receipt-v2` | `7444ccc9a817` (2026-08-15) | Paper Raid/release artifact lane, diverged from PoCO | Integration checkout, not plan authority |
| Canonical PoCO mainline | `b1c71e189bf6` (2026-08-26) | Native cutover ADR, v0/v1 schemas, current blockers and evidence | **Only active development authority** |
| AI-native v1 design | files under `docs/protocol/poco-ai-native-v1/` | Five planes, schemas and bounded candidates | Draft/non-normative; no activation |

The root checkout and canonical mainline share merge-base `e73d1a930`; the
root is 17 commits unique to itself while the mainline is 492 commits ahead of
that base. The 65 non-ancestor heads whose patches are cherry-equivalent and
the 22 heads with unmatched commits are candidates for review, not automatic
merge targets. Important unmatched families include CheckTx signer binding,
wire preflight/mutation, P2P leases, remote signer seams, state-sync sequence,
and lab/site integration. Keep them in their branches until individually
reviewed and tested.

### 3.1 Unmerged families requiring disposition

| Family | Representative refs/commits | Disposition |
| --- | --- | --- |
| Paper-Raid/JMT research | `feature/chain-paper-raid-receipt-v2` (17 commits, tip `7444ccc9a`), pre-split WIP (7), persistent-JMT (6) | Preserve as research/provenance; do not merge into native PoCO production |
| Stage0 truth/evidence | `3dbaca94a`, `d09b2afce`, `206b702bd`, `f6d2f9344` | Reconcile evidence hashes/status only; no automatic code promotion |
| P1/P2 protocol/node | `a618af3a2` CheckTx signer, `78454b4ca` process2, `e989246bc` wire mutation, `80deee191` wire preflight | Range-diff, independent review, focused tests, then cherry-pick or reimplement |
| P2P/signer | `6103743b6`, `625e1931a`, `c9d821814`, `a08a75f83`, `7860f82b0`, `9f3d7ca25`, `8ffce0ace` | Treat as authority/security candidates; never infer live networking/custody |
| Lab/site seams | runtime external signer, site-design and fleet branches | Keep outside consensus/release gate unless a separate lane accepts them |

No branch/worktree in these families was removed during this consolidation.

## 4. Current architecture truth matrix

| Domain | Reusable/implemented | Candidate only | Missing or release-blocking |
| --- | --- | --- | --- |
| Consensus | CEV0 codecs, Ed25519 checks, weighted arithmetic, chained-QC/3-chain core, local formal/simulator evidence | Finality permit joins, admission-WAL, ordered queue, fail-closed host seams | Live Core/SafetyRules, proposal/vote/TC signing, pacemaker/epoch runtime, independent review |
| Node/durability | SQLite journals, signer intent chain, watermark/CAS seams, checkpoint types | G1f process lifecycle, cross-store lock, recovery owners | Default node proposal→vote→finalize→apply, power-loss/atomic K/P proof, anti-rollback |
| Execution/state | Runtime/JMT/ICS23 reusable; Comet path is oracle | Native execution-v0, overlay/reopen, bounded MVCC/fees | Node AppHash authority, full validation, real parallel workers, state-sync network |
| P2P | Schemas, preflight/fencing fixtures | Bounded admission/transport interfaces | Listener, authenticated sessions, discovery, pacemaker, WAN/Byzantine evidence |
| DA | Local transaction-batch/blob candidate | Retrieval-before-preview and bounded certificates | Network DA, erasure/sampling, withholding/repair/retention authority |
| RPC/light client | Dev CLI/local-file RPC; bounded one-handoff/three-hop verifier | Typed state-sync proof seams | Production RPC/WS/indexer, arbitrary trust progression, independent client |
| Keys/security | Strict Ed25519 verification and journal formats | Unix/remote signer seams and identity fences | HSM/KMS custody, rotation/revocation, anti-equivocation, external audit |
| Economics/governance | Checked arithmetic, local escrow/settlement helpers | Candidate fee/consumption kernels | Activated staking/slashing/issuance/fees, governance, parameter migration |
| AI-native planes | Four external-contract MVP crates and bounded G2A–G2F candidates | Local Agent/Market/Verify/MVCC/settlement/readback | Canonical AI transaction wire, artifact DA, multi-verifier path, node integration, end-to-end settlement |
| Operations/release | Evidence schemas, local formal/build fixtures, migration types | Fleet probes and projection verifier | Real validator/fault/WAN/soak runs, signed release, SBOM, external audit, C0/C1 |

The five uncommitted files at audit time are exactly:

```text
trillionnium/crates/trnm-consensus-core/src/core.rs
trillionnium/crates/trnm-consensus-core/src/lib.rs
trillionnium/crates/trnm-consensus-core/src/model.rs
trillionnium/crates/trnm-consensus-core/src/tests.rs
trillionnium/crates/trnm-consensus-safety-rules/src/lib.rs
```

They add a SafetyRules-finality permit/predecessor binding and tests. They may
change public receipt/API behavior and are not release truth until reviewed,
formatted, compiled, vector/schema hashes regenerated, and committed. They
were deliberately preserved, not overwritten.

The existing v1 design-truth sweep was run once after the documentation
consolidation. Its bounded vector and candidate-plane checks reached green, but
the run failed when compiling the dirty consensus change:

```text
error[E0061]: SafetyRulesFinalityPermitV1::verify_v1 takes 5 arguments
but trnm-consensus-core/src/core.rs supplied 4 (missing
SafetyRulesFinalityPredecessorV1)
```

This is a source/worktree integration blocker, not a documentation failure.
The run did not alter the five source files or any truth flag; no production,
node, or v1 implementation claim is inferred from the preceding candidate
passes.

The native PoCO workflow surface is separated from legacy authority, but the
tree still contains automatic/manual migration residue such as
`trnm-cometbft-spike.yml`, `rust-l1-testnet-preflight.yml`,
`rust-l1-nightly-health.yml`, and `p1-rust-sidecar.yml`. Their Comet/ABCI,
legacy-harness, or `26657` references are not release evidence. Workflow
cleanup remains blocked by the machine `C0-cutover-not-passed` gate and is not
represented as complete in the canonical plan.

## 5. Plan/document generations and disposition

The following SHA-256 values were recorded before consolidation:

| Previous live path | SHA-256 | Disposition |
| --- | --- | --- |
| `docs/development/TRNM_POCO_AI_NATIVE_V1_DELIVERY_PLAN_2026-08-13.md` | `ac9e8f3058bb6f6697ebc2ae88212325b06207e1cf9884b3917e5cc4da484f08` | Renamed/reworked into the sole canonical plan |
| `docs/development/TRNM_POCO_BFT_DELIVERY_PLAN_2026-08-04.md` | `397bd22cfd78daef400f1bc387622a874b7e2bab9d7d0c354ff40c61a64ac3a0` | Moved to `docs/audits/TRNM_POCO_BFT_V0_IMPLEMENTATION_AUDIT_2026-08-26.md` |
| `docs/development/TRNM_POCO_BFT_EXECUTION_BOARD_2026-08-25.md` | `bed85f248c1d51f50bdc551872f1d7c43635293a20bb2bb6bd982d60e631056b` | Moved to `docs/audits/TRNM_POCO_BFT_EXECUTION_BOARD_AUDIT_2026-08-26.md` |
| `docs/development/TRNM_POCO_P2_STORE_WRITER_MATRIX_2026-08-26.md` | `5691961daa08e7f80f340e5befe491df06a4fa32a18267d619d232d0219644e2` | Moved to `docs/audits/TRNM_POCO_P2_STORE_WRITER_MATRIX_AUDIT_2026-08-26.md` |
| `trillionnium/SPLIT_ROADMAP_2026-03-19.md` | `442a150f1eac5c91e179e44aea37081614b5c5cfbf93614f4393d7030c93ef12` | Moved to `docs/audits/legacy/` |
| `trillionnium/docs/development/TRNM_4_WEEK_SPRINT_PLAN_2026-03-19.md` | `5d4d3cca80606965d7c78e59e427206ddfaa282ab9b0c394afa200e6adecddd6` | Moved to `docs/audits/legacy/` |
| `trillionnium/docs/development/TRNM_90_DAY_EXECUTION_PLAN_2026-03-19.md` | `266773c73d7bd30ff759f90fdc5ba766cf98f64767af015d7f24f2f967b3f548` | Moved to `docs/audits/legacy/` |

`docs/archive/dev-plans/**`, `docs/archive/root-history/**`, old Web4 plans,
and the 2026-04 release/checklist cluster remain explicitly historical or
non-Chain release evidence; they were not treated as live Chain authority.
They must not be linked from the canonical development navigation. Deleting
those unrelated evidence clusters would require a separate lane-specific
review because scripts and Web4 documentation still reference some of them.
The remaining `trillionnium/docs/development/TRNM_HOTSPOT_REVIEW_CHECKLIST_2026-03-24.md`
is a historical review checklist for the legacy/game-adjacent surface, not a
Chain roadmap or release gate; it remains outside the live Chain navigation.

## 6. Required reference migration

Before the old live paths can be considered fully quarantined, all active
references must point to the canonical plan or an audit file:

- `config/consensus-mainline.json` must name the canonical plan and audit
  matrix paths, not the deleted execution-board path.
- v1 `spec-manifest.toml` and its design-truth checker must use the canonical
  plan in `delivery_plan_path` and `required_files`.
- v1 DA/Agent/Verify/MVCC/Settlement/Cross-plane/Global boundary scripts must
  use the canonical path.
- v0 workflow/CI truth must use the canonical plan plus the v0 audit where a
  historical G1 wording assertion is intentional.
- `README.md`, `docs/README.md`, `RELEASE_READINESS.md`, cutover/dual-track
  ADRs, and protocol gap registers must distinguish canonical plan, ADR, and
  audit evidence.
- `scripts/ci/check_canonical_development_plan.sh` must fail if a live file
  references an old plan basename or a second active plan, and must keep the
  plan's workflow-residue wording consistent with the still-open C0/C1
  cleanup gate and v1 `design_only` machine status.

## 7. Acceptance checks after consolidation

Run these from the canonical worktree after reference migration (Cargo is not
required for the documentation checks):

```bash
git status --short --branch
git diff --check
rg -n --hidden -g '!**/.git/**' -g '!**/target/**' \
  -g '!docs/audits/**' -g '!docs/archive/**' \
  -g '!scripts/ci/check_canonical_development_plan.sh' \
  'TRNM_POCO_(AI_NATIVE_V1_DELIVERY_PLAN|BFT_DELIVERY_PLAN|BFT_EXECUTION_BOARD|P2_STORE_WRITER_MATRIX)' .
find docs/development -maxdepth 1 -type f -print | sort
find trillionnium/docs/development -maxdepth 1 -type f -iname '*plan*.md' -print | sort
bash scripts/ci/check_canonical_development_plan.sh
```

Expected result: `docs/development` contains one Chain development plan
(plus the unrelated OpenClaw operations runbook); old names occur only in the
audit/consolidation record or explicit historical indexes, not in active
config/manifest/CI/README paths. Then run the existing static TOML/YAML/shell
truth gates. The canonical-plan guard also confirms that the nested Chain
package has no competing `*plan*.md`, legacy workflow residue is marked
non-authoritative until C0/C1, and the v1 design-only status remains intact.
Full Cargo and multi-host evidence remain separate gates in the canonical plan
and were not claimed by this audit.

## 8. Limitations and follow-up

This audit did not fetch remotes, execute a validator, or measure a competitor.
Apart from the bounded design-truth sweep and its recorded compile failure, it
did not run a general compiler/build/test campaign. Quantified superiority bars
in the canonical plan are proposed engineering gates and must be calibrated
with reproducible harnesses.
The next implementation decision is to review the five dirty SafetyRules/
finality files, then close protocol/independent-reproduction blockers before
starting performance, DA, or activated economics work. No branch, worktree,
tag, remote, secret, or user-owned source change was deleted.
