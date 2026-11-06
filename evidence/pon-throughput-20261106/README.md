# Throughput continuation: bounded hot work and unchanged acceptance

Status: implementation candidate; native validation is in progress. This record
does not establish production TPS, independent WAN capacity, production work
hardness, whole-chain PQ readiness or activation. Terminal results and every
failed/unknown observation will be retained in this directory before publication.

## Source composition

The performance parent is `b173c1f52d927522af67df30dd08ecfb2e3a1bb0`
(existing integration PR #688). The PQ parent is
`cad4c18fe146b7d742ac7fa8872044cd4136c22b` (PR #723). Both histories are
retained by baseline commit `3e676aa230b8888c83a56fe37a70b4ceaec82964`, tree
`51fd2b87858f7c08be25574f84d119312029a178`. This baseline is an explicit
composition, not an assertion that either historical run tested the composition.
The sole manual merge conflict was the exact-source corpus manifest. Its source
paths are the union of both parents; hashes identify actual merged bytes. All
capability assertions remain false. The independent composition review retains
the decisions for the authority scanner, Cargo graph and embedded source list.

## Original failures remain failures

| Original run | Observed result | Interpretation |
| --- | --- | --- |
| [Native campaign, three complete attempts](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737862) | All three fail; first baseline confirmations 14.585549165, 14.998208439 and 14.811700851 seconds; no attack-phase confirmation | Original business acceptance fails; no conversion to production TPS |
| [Fixed Host F0](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737677) | First late baseline confirmation 27.299782829 seconds; zero of six scheduled slots meet the four-second SLO | Service target fails; late and unobserved slots stay in the denominator |
| [Large-state CPU](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737753) | Original corresponding run passes | That CPU experiment only; no public throughput conclusion |
| [Workspace](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737656) | Original post-write registry contains 25 tests while selection expects 23 | Registry scheduling error, not 25 executed semantic failures |
| [PQ](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42165737716) | Required registry contains 52 tests while workflow expects 49 | Required controls were not fully executed; this is not an algorithm failure |

The PQ run's complete Node library step records 1,136 passed, zero failed and
31 ignored. It does not replace the missing required-control execution.
The original native campaign's round criterion operates inside its original
30-second phase. F0 separately introduces the four-second scheduled-slot SLO,
including queue and final-observer time. Neither criterion is rewritten here.
Development-fixture depth-six latency is not real-difficulty public confirmation
latency. F0's cleanup and resource record is complete; its business failure is
not relabeled as infrastructure failure.

The original raw profiles reveal a concrete cost center: Host checkpoint CPU is
75.05%–75.78% of baseline client-import thread CPU across the three campaign
attempts, and 84.08% in F0 baseline. The ratios use known calling-thread intervals
and include failed imports; overlapping stage costs are not added. The F0 ROOT
phase has no observed import rows, so its ratio is unknown, not a zero-cost pass.
The accompanying machine summary retains exact run/job/artifact identifiers,
ZIP SHA-256 values, field paths and all phase denominators.

## Candidate changes

### Required controls and routing

Keep the exact original 25 post-write controls and corrected PQ roster of 52.
Add 12 separately named history controls and eight Host file/identity controls.
CI selector regression tests execute the actual inline workflow builders and
reject stale counts, missing/duplicate/extra/empty registries. Source-generated
fixtures test those builders; they are explicitly not native libtest execution.
F0 must be triggered by production runtime, configuration and toolchain changes
as well as changes to its harness. Original budgets, scheduled slots, profiles,
failure preservation and cleanup remain unchanged.

### Same-transaction completed history reuse

The authenticated store can retain completed suffix verification for only its
original four nominated records after the writer's final write. A hit requires
the same live connection/write transaction, observed write epoch, schema,
complete starting Record and the very same immutably borrowed Settings. A full
successful walk through the actual genesis snapshot, initial State and genesis
graph is necessary before sealing a receipt. Partial, failed or cancelled work
does not seal one.

Every hit freshly reads/verifies the current starting record, block, parent and
deltas. Entry/exit progress and final transaction fences remain. A write during
first use disables the receipt and falls back to the original full verifier;
mutation after a consumed result is refused by the existing final fence. Cold
reopen, recovery, no-scope and non-nominated paths continue to verify full
history. There is no Node-global history verdict, cross-write graph reuse or
new ledger. The omitted already-verified ancestors also omit their associated
progress callbacks; this does not assert the whole candidate has an unchanged
checkpoint count.

### Fresh Host limit reads relative to the original directory

Keep an O_PATH handle only to the original identity-checked parent directory.
Each original Host check still freshly reads complete boot identity, the actual
thread's cgroup membership and all five limit files. The limit files are opened
afresh with NOFOLLOW, read through actual EOF, parsed in the original order and
closed; no resource contents or successful resource decision is cached.
Absolute path/inode/owner/permission checks bracket the relative file reads.
The additional final fence rejects a parent replaced while the limits were
being read. This change does not reduce Host-check frequency or increase its
resource budget. Ordinary temporary directories in controls cannot qualify as
the public fixed Host.

## Validation design and limits

Use the unchanged pinned Rust 1.95.0 and exact Cargo lockfiles. The independent
OpenSSL differential provider is the original script's OpenSSL 3.5.9 build with
its pinned source tarball and real sign/verify/wrong-message smoke controls.
Verify that the native SQLite layout witness is actually compiled; a build
warning that declares it UNQUALIFIED is not a qualified native artifact.

Two finite performance observations are declared before their measurements:

1. The unchanged signed-seed component runs baseline/candidate/candidate/baseline,
   once per slot. It prepares 1,024 signed transfers in four seed blocks,
   rejects three valid-work wrong-root calls through the ordinary public service,
   verifies unchanged durable state, then accepts one legal call after cold
   reopen. Retain all CPU/wall results and packet identities. This local test
   has no fixed Host and is not the original saturation campaign.
2. One complete three-arm Host component runs original absolute reads, absolute
   reads plus the final identity fence, and fresh relative reads plus that fence.
   Its fixed pairwise ABBA schedule contains 192 samples/12,288 checks. Actual
   proc context is read, but the five limit files are ordinary temporary files,
   not cgroup kernfs files. It cannot qualify the original fixed Host campaign.

No best-sample selection, relaxed SLO or successful subtest replaces a failed
business gate. Native safety controls, component cost and original CI business
outcomes are reported separately. Whole-state graph validation, cold recovery,
PQ verification cost, data-plane/control-plane contention, malicious-load
fairness and useful-work economics remain explicit capacity work.

## Reproduction

Run `bash scripts/project-preflight.sh` before build/edit/commit/push operations.
Use `cargo +1.95.0` through the actual rustup proxy, an absolute selected `RUSTC`,
the original Cargo profiles and an isolated target directory. Do not change the
SQLite build fence to make a locally misconfigured build appear qualified.

The original GitHub workflows are the authoritative unchanged campaign/F0
entrypoints because they provision and verify their actual fixed Host resource
ownership. Running their ignored test function bare is not an equivalent run.
Exact-source test receipts, source checks and retained failures are added with
their measured source identity; documentation publication never retroactively
changes that identity.
