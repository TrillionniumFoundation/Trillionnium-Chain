# Branch-local incremental ASERT summary — research contract

Status: **research only; no production consensus target, signature or chainwork authority**.
Source lineage: stacked on PR #336 at `831d70b194d6145c064884112b1098ed9210a53f`; existing Q4, r12 Genesis Maintenance,
W1 relation and 16-block installed DAA are unchanged.

## Concrete blocker and scope

The existing genesis-anchored DAA shadow at height >4096 cannot walk a 4096-read
budget all the way to its anchor. Removing the cap or accepting a peer-supplied
skip/header claim is not safe. The new `daa_incremental_summary.py` is a
**bounded per-verified-parent research projection**, not a skip-proof verifier.

For each *already fully work-/context-/time-/body-/state-validated* header,
the owning process derives exactly one branch-local summary from its previously
validated parent summary. It carries bounded last-11 timestamps, the frozen
activation anchor identity/target, its predecessor identity and the predecessor
time clocked consistently with the selected raw/MTP11 rule.

A full 8192-header synthetic lineage is processed with constant per-header
lookback (<=11 timestamps); correctness is checked against the standalone
ASERT oracle, and independent pre-activation and post-activation forks retain
their own anchors and clock values. An unavailable summary is
`ASERT_SUMMARY_UNAVAILABLE`, **not** invalid chainwork, a reduced target,
permission to import a DHT cache or activation of a different work primitive.
Already validated ancestor summaries need a separately qualified durable
native owner; cached Python objects or their content hashes are not consensus
proofs.

## Original safety boundaries

- No call to the existing `consensus::retarget`, mining selector, work verifier,
  header validator, service, state writer, DAA upgrade activation or W1.
- A summary input from a peer has **no authority**. The research
  `observe_already_validated` interface must only be fed from an actual
  original native validator, after independent complete work and state checks.
- At activation height the *legacy* expected target must still govern admission.
  The first hypothetically ASERT-eligible child is at activation+1; there is no
  cross-network reinterpretation or hidden new consensus context.
- On reorg, reconstruct the right branch state from its own verified parent.
  No operator-fixed irreversible anchor hash or unrelated fork's median is used.
- If a persisted owner loses a branch summary, recover from verified immutable
  parent state and authenticated state history before any research target result.
  There is no automatic peer summary ingestion and no default-success fallback.
- Full acceptance requires native on-disk atomic branch summary/reorg journal,
  fault-cut cold reopen, valid original W1 parent assertions, independent
  cross-operator reference vectors, anti-shortcut W1 cost qualification,
  public adversarial service and 72-hour independent WAN operation.

## Executable local research evidence

```sh
python3 -B formal/pon-nakamoto-v1/test_daa_incremental_summary.py -v
```

The local research environment observed **10/10 PASS** on those exact Python
source contents, including height 8192, long-window MTP, independent activation
anchors, fake ancestry / mutation controls, and 300+ source-independent ASERT
arithmetic comparisons. This does not assert a Rust build or native signed
proof campaign; the corresponding strict P0-C / P1-C / P2 blockers remain open.

This is subordinate to the sole development plan and does not change the
existing profile registry, stored schemas, launch flags or formal acceptance.
