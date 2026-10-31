# PN0–PN6 implementation convergence, 2026-10-31

This directory accompanies the existing development plan. It records a source
integration and component repairs, not a second acceptance plan. Every PN exit
remains **HOLD** until its original conditions are met. No production network,
whole-chain PQ claim, migration or activation is authorized here.

## Source and configuration

The Chain candidate joins the actual #632 startup/archive repair and #634
authority/research stack, both descended from #559's `bbc511c7942de24b75054d1b4c3e5d0e4f4a5ab3`.
The new ordinary Hepta Cell host is reviewed in
[Hepta #4497](https://github.com/TrillionniumFoundation/hepta-private-ci/pull/4497).
Its original paired Chain is still c165, not this PQ candidate. Comparing #559's
`bbc511c7942de24b75054d1b4c3e5d0e4f4a5ab3` with
`c16507147b65285ea94dead22d3b93c5db7295af` yields 828 differing paths outside
`evidence/` with rename detection disabled (`git diff --no-renames --name-only`).
That count describes those two historical tips, not the current integrated tree.
Their histories diverge; the tip-tree comparison is not a successful three-way
merge or an accepted joint source.

See [the configuration matrix](PROFILE_COMPATIBILITY.md) and its
[machine-readable source inventory](profile-compatibility.json). The matrix
distinguishes explicit PQ transport/application owners, continuous startup,
native growth, one-packet History, Cell retrieval and ordinary FinalUse. A binary
containing all of these modules does not establish one compatible configuration.

## Implemented boundaries

- PN1: a real nine-class, thirteen-constructor, three-challenge reuse regression
  preserves complete W1 proofs and misses, and reaches the exact Product and
  Transcript rejection boundaries. It is correctness evidence. The thirteen-arm
  V2 cost matrix's setup horizons remain modeled. The separate, explicitly
  selected V3 observes actual setup followed by four independent searches for
  every supported arm, with complete miss/winner and dual-verifier accounting.
  Its diagnostic observations do not inherit default-release or cross-hardware
  qualification; the separate release runner requires committed-clean bytes.
- PN2: one exact complete History extension uses the original signed validation
  and activation allocations, one durable operation and one CPU interval.
  Direct receiver admission now also enforces the original delegation's nonce
  window. Unfinished intervals retain unknown debt across reopen; post-commit
  cancellation preserves the packet and the original recovery HOLD.
- PN3: canonical TCD1 declares a bounded file/dependency closure over unchanged
  TCM1/TCR1 identities. The real `trnm-cell fetch-closure` command uses existing
  aggregate transport and cache budgets. Hepta's explicit ordinary Cell host
  verifies the eleven-object profile through its original CURRENT/selector and
  FinalUse owners; scanning and physical load share the original 120 seconds.
  The explicit producer mode builds and checks that same eleven-object closure
  against independently supplied owner pins, calls the actual native fetch, and
  execs the original host through its measured ELF descriptor. Its existing
  35-second aggregate transfer includes materialization and final readback.
  Missing owner inputs return NOT_CONFIGURED before cache creation. A synthetic
  transport/exec probe is retained separately from actual model use acceptance.
  Sealed anonymous executables cannot preserve the current ordinary helper path
  across its sandbox namespace; the explicit Hepta entry rejects them before
  owner admission. The explicit protected-installed v3 profile retains a stable,
  independently pinned, root-installed ELF and the original unprivileged caller.
  Its deployment controls require a separate real root-owned CI fixture and the
  actual paired native daemon; parser controls and sealed-v2 probes cannot
  substitute for those results. Root installation and system loader/libraries
  remain trusted deployment conditions.
  A retrieved completion marker is not an installation or learning receipt.
- PN4: retiring a native Cell requires exact completed-effect readback from its
  original trusted M12 journal and original chain context. A different chain's
  higher height, pending effect or unreconciled intent cannot release capacity.
  Reservations are not money, and chain height is not finality.
- PN5: the existing evidence reader has an explicit v2 format with confirmation,
  retrieval, repair and recovery outcomes. Each operator/cohort/time-window has
  its own frozen denominator, resource and tail requirements. The arithmetic
  reader never verifies physical WAN duration or administrator independence.
- PN6: source coverage now includes non-PQ-named History, TCD, retention,
  retirement, funding, rehearsal and research-handoff owners. Static coverage
  guards still emit HOLD and retain every migration/activation flag as false.

## Remaining acceptance boundaries

PQ and growth still require an explicit wire/backend/account-authority design;
removing their mutual-exclusion checks would not implement that design. General
continuous fork/history synchronization and bounded authenticated historical
summaries remain unfinished. The ordinary Hepta host still uses its original
Ed25519 FinalUse route; an available ML-DSA API or unmerged PQ branch does not
change that caller. Real installation, ordinary subsequent tasks, independently
evaluated learning benefits and valid no-update outcomes require their own owner
receipts. Blocking filesystem calls remain cooperatively cancellable after OS
return, not forcibly preemptible.

At least three genuinely independent administrators and at least 72 hours of
the original frozen WAN/fault campaign have not been supplied or executed by
this work. All PN1–PN4 entry conditions must also be satisfied before that
campaign can qualify. There is no governed release activation decision.

Original failures are retained alongside later repairs. A local sandbox bind
failure, compiler SIGKILL, missing dependency or early rejection cannot be
relabelled as a passing behavioral or full-work observation. Applicable current
source-head and base-merge CI remain separate requirements.
