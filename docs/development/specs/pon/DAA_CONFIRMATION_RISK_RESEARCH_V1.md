# P1-B — Dual-gate reorganization-risk research

**Scope: research-only.** This augments the already non-authoritative
`daa_fork_outage_research.py` simulation without changing any native PoN
consensus profile, header byte grammar, fork-choice, timestamp rules, leased
source authority, signed Q4 fields, Rev12 Maintenance work, or production flag.

## Issue found

The previous source-loss / partition-heal simulator counted orphaned blocks at
least six descendants deep. Actual native `Node::confirmations_with_progress`
uses **two** conditions: `(observed.height - included.height) >= depth` **AND**
`(observed.chainwork - included.chainwork) >=
required_work(included.target) * work_multiplier` (development settings:
`depth=6`, `multiplier=6`). Merely reaching depth six is not equivalent to
passing the installed client's confirmation policy when DAA changes difficulty.

In particular a highly difficult included block can be followed by six very
low-difficulty blocks whose accumulated chainwork does not meet six times the
included block's own required work. A depth-only *risk* count is a loose upper
bound, not a count of already policy-confirmed effects. Reorged real-world
effects still need independent reconciliation and are not reversed by this
model.

## Change and executable contract

`daa_confirmation_risk.py` independently walks winner/loser ancestry and checks
linked integer work and depth with finite row budgets, then returns:

- `depth_only_removed`: previous metric, retained unchanged for compatibility.
- `depth_and_work_confirmed_removed`: orphaned blocks meeting both conditions
  **at the losing branch's own pre-heal tip**.
- `depth_satisfied_work_insufficient`: blocks that met depth but not the
  cumulative-work policy.

The source-loss fork simulator adds an expressly synthetic
`losing_branch_depth_work_confirmed_removed` report field. Before overriding
its tips on partition heal it cross-checks the new depth-only count against
the original metric. A missing/cyclic parent, inconsistent height/work,
invalid target, exceeding ancestry budget or winner with less work is refused.
The input graph's BlockIds, W1 proofs and state are still untrusted simulation
identifiers, not independently valid native Header/Packet facts.

Run from repo root:

```sh
python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p 'test_daa_confirmation_risk.py' -v
python3 -m unittest discover -s formal/pon-nakamoto-v1 \
  -p 'test_daa_fork_outage_research.py' -v
```

2026-10-26 local independent new-component test: 5/5 PASS, including a
constructed depth-six-but-insufficient-work fork, a true dual-policy positive,
a shared-prefix fork, corrupt ancestry/work and same-tip no-op. This test is
pure Python and does not execute existing native W1 or real network discovery.
The existing source-loss fork tests must separately run on the integrated
exact tree. No model evidence, third-party operator or deployment is implied.

## Strict open gates

P1-B: actual native PNW1 packets under partition/withholding, valid branches,
real client receipts and timed hostile peers; quantified common-prefix and
transaction policy-confirmation rollback probabilities under frozen budgets.
P1-C: distinct reviewed DAA/consensus profile with independent Rust proof,
branch-local anchor, restart and genuine client confirmation. P0-C W1 cost
hardness and P2 multi-admin WAN experiments remain independently open.

This is a subordinate research note under the sole development plan, not a
new validator quorum, finality guarantee or fallback algorithm.
