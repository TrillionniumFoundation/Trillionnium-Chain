# Exact native-store roster repair

Source inspected: `6ee529046d295e3175f09112492abee373f1f54c`;
prospective merge `d5c2de69af98a7f3e0ce8ae34d5711f4467353e2`;
both use tree `a045ad8f2eb9340ff73278236cc69350c1ddc424`.

[Original run 41985421045](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985421045)
failed in all four lanes after the unchanged release native-store suite returned
**7 passed, 0 failed, 2 ignored**. The stale grep demanded six passes. This is a CI
roster defect, not a native test failure and not evidence of full gate success.

Retained invocation excerpts remove only the GitHub timestamp prefix. Full original
logs remain available at these exact jobs:

- [ARM prospective merge, 127104910293](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985421045/job/127104910293): [excerpt](127104910293.txt).
- [x64 head, 127104910652](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985421045/job/127104910652): [excerpt](127104910652.txt).
- [x64 prospective merge, 127104910725](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985421045/job/127104910725): [excerpt](127104910725.txt).
- [ARM head, 127104910967](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41985421045/job/127104910967): [excerpt](127104910967.txt).

The replacement requires all seven exact passing names and both exact ignored
names from the actual source, one invocation, no extra/duplicate results, and the
complete 7/0/2/0 terminal summary. It rejects a same-count name replacement,
changed outcome, missing result, failed summary or truncated transcript. No
production Rust, Cargo selection/profile, deadline, architecture, full suite,
explicit ignored-cost execution, migration, public service or Clippy command is
changed. The shell retains `set -euo pipefail`; transcript checks cannot turn a
nonzero Cargo exit into success. This does not authenticate arbitrary test stdout.

Reproduction:

```
python3 scripts/ci/test_native_constants_roster.py
for f in evidence/ci-native-constants-roster-20261105/*.txt; do
  python3 scripts/ci/check_native_constants_roster.py "$f" || exit
done
python3 scripts/ci/check_ci_contract.py
python3 scripts/ci/test_ci_contract.py
python3 scripts/ci/check_pq_research_integration.py
python3 scripts/ci/test_pq_research_integration.py
python3 scripts/refresh_distributed_source_inventory.py --check
python3 scripts/ci/check_repository.py
```

Nine Python methods (including adversarial subcases) and all four historical
transcript replays pass. They are reader controls, not four new native runs.
Later per-test constant/cost commands and all subsequent batch/migration,
work/public-service and Clippy steps were not reached in the original failed jobs.
A fresh complete hosted gate is still required; no #639 confirmation, performance,
PQ qualification, release or activation gate is promoted.
