# TRNM MN01 Residual Closure (2026-04-05)

Truth-source snapshot:
- local `main = e08c43d18`
- `origin/main` is behind local `main` by **452** commits at this snapshot
- `lane/mn01-peer-bootstrap-topology` vs local `main`:
  - lane behind local `main`: **452**
  - lane ahead local `main`: **130**

---

## Headline judgment

`MN01` should **not** be treated as “130 commits still waiting to merge”.

By 2026-04-05 noon local time, the large majority of `MN01` has already been absorbed into local `main` by:
- direct merge-sweep work on adjacent lanes,
- targeted manual cherry-pick / rewrite on `main`,
- or stronger replacement semantics added directly to `main`.

The right summary is:

> **MN01 is mostly closed by semantic absorption; the remaining actionable tail is concentrated in apply-preflight only.**

---

## What happened

After the broad lane merge sweep, `MN01` could not be merged wholesale because it collided with the already-merged `MN02` on:
- bootstrap / rejoin / recovery semantics,
- WAL reuse / auto / fail-if-exists behavior,
- and `trnm-node` startup summary expectations.

A direct merge attempt produced large `trnm-node` test fallout, so the lane was then reduced by hand into safe, independently-gated micro-absorptions on `main`.

That manual closure path absorbed a long sequence of `MN01` concerns into `main`, including:
- bootstrap fixture guidance,
- bootstrap alias fail-closed coverage,
- DNS-style / trailing-dot / localhost-dot bootstrap id rejection,
- listener mismatch diagnostics,
- startup preflight path variants,
- shipped bootstrap anchor / slot / stride topology locks,
- README single-source / alias-ban authority,
- fixture-discovery fail-closed behavior,
- `load_config()` diagnostics and path-guard hardening,
- IPv6 loopback / IPv4-compatible listener rejection,
- main-side alias mirror reaching parity with `config.rs`.

Because many of these were absorbed by different patches than the original lane commits, `git cherry -v` still shows many `+` commits even when the underlying semantics are already present on `main`.

---

## Residual classification

At this snapshot, the `MN01` residual should be read in three buckets.

### A. Covered / absorbed on `main`

This is the dominant bucket.

These are commits whose patch text is still unique to `MN01`, but whose *meaning* has already been absorbed into `main` through other commits. This bucket includes the major clusters around:
- bootstrap alias fail-closed enforcement,
- host-like / path-like / delimiter bootstrap id rejection,
- shipped bootstrap anchor and slot topology locks,
- path normalization (`repo-root`, `workspace-prefixed`, `curdir`, `inner-curdir`),
- README authority and alias-ban locking,
- fixture discovery fail-closed,
- `load_config()` operator-path / resolved-path diagnostics,
- IPv6 loopback / IPv4-compatible listener rejection,
- main/config alias-mirror parity.

Representative already-absorbed examples include subjects equivalent in spirit to:
- default CLI bootstrap anchor pinning
- inner-curdir shipped bootstrap paths
- slot alias / listener stride locking
- localhost-dot bootstrap ids
- main alias mirror parity
- config URI delimiter surface unification
- non-UTF8 fixture-name fail-closed

### B. Explicitly superseded

These residual commits should **not** be re-absorbed, because `main` now carries a stronger or more precise semantic.

The clearest examples are:
- `1bee4a316` `mn01: clarify node4 tail-slot recovery guard`
- `45d4d03f7` `mn01: cover checkpoint-only scaffold reuse guard`
- `fd9b35714` `mn01: cover checkpoint-only wal scaffold in fail-if-exists`
- `b0e8f842e` `mn01: cover truncated fresh bootstrap recovery summary`

Why they are superseded:
- `comment-only checkpoint scaffold` is already covered more strongly on `main`.
- `fresh_bootstrap_after_tail_repair` on `main` is a **more precise** state than the older `MN01` simplification back toward plain `fresh_bootstrap`.
- Reapplying these commits would risk weakening the currently accepted `main` recovery language.

### C. Still-useful unmerged tail

This is the only bucket still worth active pursuit.

At this snapshot, the still-useful tail is concentrated in **apply-preflight** and related drift/diagnostic helpers:
- `f48a73aa6` `mn01: fail closed reserved listener ranges in apply config`
- `cf2cb84ec` `mn01: tighten apply bootstrap node id guards`
- `804a1ecb8` `mn01: cover invisible bootstrap peer ids in apply preflight`
- `c55fc15b1` `mn01: surface operator path on validation drift`
- `8ad79e71e` `mn01: extend apply bootstrap alias fail-closed coverage`
- `5f835f219` `mn01: surface apply config alias error paths`
- `d612fe907` `mn01: cover seed addr alias drift in apply preflight test`

These are still potentially valuable because they target the `apply` path specifically rather than the now-mostly-closed `main`/`config` path.

---

## Recommendation

### Recommendation for `MN01`
**Status: soft-close the lane for manual slicing, except for apply-preflight follow-up**

The right next move is **not** to continue treating `MN01` as a general-purpose lane with 130 meaningful residual commits.

Instead:
1. treat the lane as **semantically mostly absorbed**;
2. mark the recovery-side residuals as **superseded / do not merge**;
3. isolate the remaining actionable tail as an **apply-preflight mini-track**;
4. only continue hand-slicing if each follow-up patch can be independently gated with current `trnm-node` tests.

### What not to do
Do **not**:
- re-open the large recovery merge attempt,
- try to mechanically merge the remaining `MN01` branch,
- or re-absorb the checkpoint/truncated-fresh-bootstrap commits that now conflict with stronger `main` semantics.

### What is still worth doing
If further work is needed, constrain it to the 7-item apply-preflight tail above.

---

## Final judgment

Best single-sentence summary:

> **MN01 is no longer a broad unmerged branch problem; it is effectively closed on `main` except for a small apply-preflight residual tail, while the recovery-side leftovers should be treated as superseded rather than merged.**
