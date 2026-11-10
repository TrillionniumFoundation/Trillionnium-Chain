# PQ Root #881 exact-source dependency register repin — HOLD

Date: 2026-11-10 UTC. Scope: stacked Draft PR #887 on #881's immutable head `c298b8194d3a5c3a3b6c30e6877fbf65172bb69d`.

## Original failures preserved

- Head [required-baseline repository-truth job #129890877457](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42833907470/job/129890877457).
- Prospective-merge [repository-truth job #129890877471](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42833907470/job/129890877471).
- Both failed: `source hash mismatch: trillionnium/crates/trnm-pon-node/tests/recovery_floor_v4_native.rs`. This was a *different register* from the corpus Git Blob corrected by #881. The excerpt in `repository-truth-failure-excerpt.log` preserves original lines, not the entire CI log; consult the linked jobs for full original logs.

## Independent native-host frozen-source verification

Host: `ai395`; separate worktree: `/home/qq/pq-root-register-repin-20261110`. Started from fixed V4 #837 `44330b91`, copied the remote #881 native rollback test bytes whose Git Blob independently matched `8aafd512b6f4dab05478fa15a231a5089eefaebf`; restored the exact #881 corpus pin before applying only the three reviewed source-pin updates.

Durable heptaruntime job `1a1c726a749-5074-36d` exited 0; complete unmodified stdout/stderr copied into this directory.

- Command: `python3 -m unittest scripts.ci.test_pq_root_dependency_register -v`; 42 passed, 0 failed.
- Command: `python3 scripts/ci/pq_root_dependency_register.py --root <frozen-root>`; returned `status=HOLD`, all eight domain actual failure bounds `null`, no external custody or effects qualification.
- Stdout size/SHA-256: 7906 / `b5116317e8507d1597a60c75fd990411b5a541e34ec4d8679ae7e91910d890f8`.
- Stderr size/SHA-256: 9741 / `bc77e81d4914f69a6ee9a5c7f2e323ae3ac49e15e99867427d893aa0d01ec8f9`.
- Native test source SHA-256: `3616d905976853c2a6a8d7b7b98db156b653d056f9f170f77454ce3b66602fe1`.
- Revised reviewed map digest: `701c997d43af71efb986c7c1c86853d90a2c5ab0570ff2e41626f0ad5a666da2`.
- Git Blob identities verified by remote readback: manifest `5cb0fede4eb0fde783a9065ca5895da93dcee4fa`, script `7b69eddd6bb4c9f619b9d108d05957cc59152b53`, corpus `f4d681463d93d9be40b8ceddf40ddbab23417fb7`.

## Explicit nonqualification

This is **only a source-map CI integrity repair**. It neither authorizes nor demonstrates independent physical/operator custody, a lower bound surviving common rollback of owner + all anchors + pins, real M15/FinalUse/provider/payment/resource/reorg effects, post-quantum algorithm migration, or a whole-life eight-domain quantum failure bound. The original 3×30s native campaign remains 0/3. No budget, window, success condition, or root production activation is changed.

`HOLD_NO_GO`; `actual_lifetime_failure_bound=null`; `whole_chain_pq_qualified=false`; `production_activation=false`.
