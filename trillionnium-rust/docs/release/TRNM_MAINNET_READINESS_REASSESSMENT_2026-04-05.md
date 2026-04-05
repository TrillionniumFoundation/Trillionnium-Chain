# TRNM Mainnet Readiness Reassessment (2026-04-05)

## Truth-source snapshot

This reassessment is intentionally tied to the **current local integrated mainline**, not only the last pushed remote snapshot.

- local `main = d63284852e281975bf8e3ad905b396eb5cf347de`
- `origin/main = 35da4109e92321ecfdd9aa86b0738b968ea519d9`
- local `main` vs `origin/main`: **ahead 613**
- branch state: single local branch (`main`) only
- local worktree state: single worktree only
- working tree status at review time: clean

Companion truth sources:
- `RELEASE_READINESS.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_GAP_MATRIX_2026-03-26.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_BLOCKER_BOARD_2026-03-31.md`
- `trillionnium-rust/docs/release/TRNM_MAINNET_LAUNCH_COUNTDOWN_2026-04-03.md`
- `trillionnium-rust/docs/release/TRNM_PUBLIC_MAINNET_GO_NO_GO_PANEL_2026-04-04.md`
- `trillionnium-rust/docs/release/TRNM_GENESIS_CLOSURE_STATUS_2026-04-04.md`

Important boundary:
- this document reassesses the **current local integrated `main`** after branch closure / residual absorption / local branch pruning;
- it does **not** by itself upgrade the repository to release-ready;
- it also does **not** mean `origin/main` has already inherited this exact snapshot.

---

## Headline judgment

### Public mainnet claim
**Judgment: still NO-GO.**

TRNM should still **not** be described as public-mainnet ready.

### Current stage name
The most accurate phase label for the current local `main` is still:

> **late RC-prep / prelaunch-closure**

not:

> **public mainnet candidate**

### What has changed since the earlier blocker docs
One genuine meta-blocker is now closed locally:

> lane/backlog fragmentation is no longer the mainline problem.

The repository has been pulled back to:
- one local branch (`main`)
- one local worktree
- one integrated mainline snapshot

So the launch distance should now be described almost entirely as **production-perimeter closure**, not branch integration debt.

---

## Current code-level sanity signal

A focused compile-slice check across the main launch-critical crates passes on the current local `main`:

```bash
cargo check -p trnm-node -p trnm-rpc -p trnm-cli -p trnm-state -p trnm-pouw -p trnm-mempool -p trnm-worker-agent -q
```

Result at review time:
- **PASS (warnings only)**

Interpretation:
- the current integrated mainline is not obviously broken at the crate integration layer;
- but compile-slice green is only a hygiene signal, not a public-mainnet release proof.

---

## What clearly improved on the current local `main`

## A. Bootstrap / config / startup fail-closed surface is materially stronger

The current local mainline now carries stronger operator-facing fail-closed coverage around:
- bootstrap topology invariants
- startup preflight path aliases
- `load_config` path / canonical-path diagnostics
- `node_id` / listener literal hygiene
- symlink / path escape diagnostics
- README / truth-source alignment for shipped bootstrap fixtures

Interpretation:
- TRNM is much less likely than before to fail opaquely on bootstrap/config drift;
- operator-visible diagnostics are stronger and better anchored to real paths;
- but this is still **bootstrap/config hardening**, not the same thing as a full public-network formation model.

## B. Signer / keystore hygiene is stronger

The signer side is clearly less fragile than in older snapshots:
- path hygiene is stronger
- input fail-closed behavior is stronger
- keystore/signer safety surface is more explicit

But the CLI still presents itself as:

> `Trillionnium native CLI (wallet/query/tx MVP)`

So the current local `main` is stronger than before, but still not at a “finished public-mainnet signer story” state.

## C. Truth-source / runbook drift is lower

Recent work reduced some of the highest-risk truth-source confusion points:
- README / runbook claims are more tightly bound to current harness reality
- bootstrap residuals that used to live only in shadow surfaces are more explicitly represented in the real test harness
- lane-history closure is no longer leaving “is this still unmerged?” ambiguity on the local branch graph

Interpretation:
- the repository is easier to reason about correctly;
- but truth-source cleanup is supporting work, not release closure by itself.

---

## Why this still remains NO-GO

The blocker taxonomy remains structurally the same as in the gap matrix / blocker board / launch countdown.
The main difference is that branch integration is no longer one of the mainline concerns.

### Remaining launch distance
The current local `main` still looks like:
- **6 P0 blockers**
- **1 integrated prelaunch rehearsal / GO-NO-GO package**
- plus **3 optional P1 packages** if Day-1 scope includes oracle / bridge / verifier productization

That means the current repository is now better described as:

> “an integrated, hardened late-RC-prep mainline that still lacks operator-grade production perimeter closure”

rather than:

> “a public mainnet launch candidate”

---

# P0 Blockers — reassessed against current local `main`

## P0.1 Explorer / indexer / stable read-model
**Status: still the hardest blocker.**

### Why it still blocks launch
The explorer/read surface remains the most obvious gap between “chain kernel can run” and “public network can be operated and integrated against”.

The current explorer runbook explicitly says the scaffold is:
- a **deployment placeholder**
- **not** a durable production indexer
- **not** proof that the public-mainnet explorer blocker is closed

It also explicitly states that the current scaffold does **not** satisfy durable indexer closure by itself.

### What current `main` already has
- clearer Day-1 read-contract discussion
- stronger query/read-only contract scaffolding
- placeholder operator handoff shapes
- richer explorer scaffold contract than older snapshots

### What is still missing
- durable indexer pipeline
- historical read-model
- stable explorer backend/API
- archive / read replica strategy
- production read SLOs / retention policy
- a real operator-grade non-placeholder deployment packet

### Current judgment
Still **P0-open / Rank 1**.

---

## P0.2 Secure wallet / signer / keystore path
**Status: advanced, but still launch-blocking.**

### Why it still blocks launch
The signer/CLI surface is much better hardened, but it still does not amount to a complete public-mainnet operator signer model.

### Code-derived evidence
The CLI still labels itself as:
- `wallet/query/tx MVP`

### What current `main` already has
- keystore path hardening
- signer input fail-closed behavior
- stronger wallet/signer path safety tests
- improved keystore/signer hygiene around local operator use

### What is still missing
- approved Day-1 keystore model
- operator-grade offline signing path
- HSM / remote signer / multisig posture
- compromise / rotation packet tied to the launch path
- explicit signer safety checklist bound to the release packet

### Current judgment
Still **P0-open / Rank 2**.

---

## P0.3 Real network formation / peer sync / join-rejoin
**Status: advanced, but still launch-blocking.**

### Why it still blocks launch
The current `trnm-node` mainline is materially stronger on fail-closed config/bootstrap behavior, WAL/recovery hardening, and operator-facing diagnostics.
But the runtime-facing network model is still much thinner than what a public network needs.

### Code-derived evidence
The config surface still fundamentally centers on the minimal shipped tuple:
- `node_id`
- `rpc_addr`
- `p2p_addr`

That is a much better-defended bootstrap/config contract than before, but it still is not equivalent to a production peer-management / discovery / sync model.

### What current `main` already has
- stronger bootstrap topology discipline
- stronger config/load/startup fail-closed coverage
- stronger path/canonical-path diagnostics
- stronger recovery / WAL / checkpoint hardening
- stronger join/rejoin-adjacent bootstrap hygiene

### What is still missing
- explicit public bootstrap peer management
- discovery / sync model for public-network operation
- lagging node acceptance matrix
- operator-visible sync diagnostics tied to real deployment
- realistic multi-node formation / catch-up rehearsal bound to launch packet

### Current judgment
Still **P0-open / Rank 3**.

---

## P0.4 Genesis + validator / operator lifecycle
**Status: documented and candidateized, but not operationally closed.**

### Why it still blocks launch
The current genesis closure doc already says the area is:

> **documented but not operationally closed for public mainnet**

It also explicitly calls out two still-open gaps:
- missing real signed genesis ceremony packet
- missing live operator-artifact-driven bootstrap evidence

### What current `main` already has
- genesis generation / validation checklist
- validator bootstrap / re-bootstrap runbook
- validator rotation / DR runbook
- validator config-bundle checker
- local-rehearsal genesis candidate bundle and packet skeleton

### What is still missing
- real signed ceremony packet
- real operator acknowledgments / ownership evidence
- real bootstrap / handoff packet tied to current mainline
- DR rebuild evidence / replacement-rotation evidence
- operational closure rather than documentation-only closure

### Current judgment
Still **P0-open**.

---

## P0.5 Unified observability / alerting / SRE plane
**Status: starter-pack exists, full operational plane still open.**

### Why it still blocks launch
The observability starter pack explicitly says it closes only the **runbook-shape** part of the blocker, not the whole blocker.
It also explicitly lists open items that remain even after the starter pack exists.

### What current `main` already has
- shared severity / label vocabulary
- starter alert set
- minimum dashboard bundle guidance
- incident handoff block preserving replay/rollback pointers

### What is still missing
- real exporter payload contract enforcement
- production dashboard wiring
- frozen thresholds beyond starter heuristics
- emitted ticket/page consistency in the live path
- replay/failure-attribution proven against real rehearsal evidence

### Current judgment
Still **P0-open**.

---

## P0.6 Economics / anti-spam / fee boundary freeze
**Status: meaningful code exists, launch freeze still open.**

### Why it still blocks launch
The economics blocker is now less about “no code exists” and more about “the Day-1 public tuple is not frozen and evidenced strongly enough”.

The gap matrix still requires one explicit Day-1 freeze tuple, and explicitly says that if any of the five freeze elements remain “to be decided”, economics should remain **NO-GO**.

### What current `main` already has
- substantial mempool / sponsor / fairness / anti-spam work
- economics freeze helper doc and related compile/test anchors

### What is still missing
- final ingress-class split
- sponsor boundary/caps
- retention pricing rule
- anti-spam/admission floor
- change authority/timelock for prelaunch freeze
- one real freeze packet tied to launch review

### Current judgment
Still **P0-open**.

---

## Integrated launch gate package — still missing

Even if the six code-adjacent P0 areas are all improved, the current local `main` still cannot be promoted to a public-mainnet claim without one integrated package containing:
- full rehearsal on the current integrated mainline
- path-resolved evidence bundle
- replay / rollback preservation
- current-head GO / CONDITIONAL GO / NO-GO memo
- operator-facing decision packet

This is not optional polish.
It is the step that turns “harder-to-break code and better runbooks” into “credible release evidence”.

Current judgment:
- still **open**
- still required before any public-mainnet claim

---

# P1 packages (scope-dependent)

If Day-1 scope explicitly includes them, the following still need separate productization closure:
- oracle online subsystem
- bridge settlement / relay productization
- verifier / checkpoint sidecar productization

These should not be allowed to hide or delay the P0 public-mainnet perimeter closure unless Day-1 scope explicitly depends on them.

---

## Distance-to-launch statement

The current local `main` is **not** “far” in the sense of missing a chain kernel.
It **is still materially far** in the sense of missing the final operator-grade production perimeter.

The shortest accurate description is:

> **TRNM still needs one full operator-grade prelaunch closeout phase.**

That phase still needs to convert current code/runbook hardening into:
- real read-surface/indexer closure
- real signer/keystore closure
- real network/bootstrap/join-rejoin closure
- real genesis/operator lifecycle closure
- real observability/economics freeze closure
- one integrated rehearsal / evidence / GO-NO-GO packet

---

## Practical priority order for the next phase

### Rank 1
Explorer / indexer / stable read-model

### Rank 2
Secure signer / keystore / offline signing

### Rank 3
Real network formation / sync / join-rejoin

### Rank 4
Integrated prelaunch rehearsal / evidence / GO-NO-GO

### Rank 5
Unified observability / alerting / SRE plane

### Rank 6
Economics / anti-spam / fee freeze

### Rank 7
Validator / operator lifecycle closure

Interpretation:
- Rank 1–3 are still the shortest launch path.
- Rank 4 is the package that converts engineering progress into release credibility.
- Rank 5–7 remain launch blockers even if they are not always the first coding target.

---

## Final judgment

For the current local integrated mainline:

- **release-ready?** No.
- **public mainnet claim?** NO-GO.
- **best stage label?** late RC-prep / prelaunch-closure.
- **what closed recently?** local branch/worktree fragmentation and a large amount of bootstrap/config fail-closed residual work.
- **what still blocks launch?** the same production-perimeter package set: read surface, signer, network, operator lifecycle/genesis, observability, economics, and integrated launch rehearsal.
