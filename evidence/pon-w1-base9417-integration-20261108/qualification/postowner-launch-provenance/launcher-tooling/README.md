# C8 post-owner qualification launcher

Source: 4e007a87ceecbec8d265f6a70cfd71d512a514b5; tree: 19a4f1a6e1cec5c27e595fa555b97cddc4717a3c.

Preparation only. No gate authorizes execution merely because a manifest appears. Before launch, retain exact-owner-02's authoritative successful terminal, all original command/log pins, the successful strict import and its terminal, the imported owner ELF, and m12_owner's explicit same-target handoff. Root authorized sequential execution after those prerequisites; no additional confirmation is required.

The launcher is external experiment tooling. Source, plans, generic driver d3c6953430a8efce70396eac88c891aa91501633013c09d5018f0b00e9fb7d1f, helper and old attempts remain unchanged. It validates pinned UTF-8 finite JSON, exact command inventories/counts and raw logs, source HEAD/tree/cleanliness and unchanged owner ELF. The advisory lock coordinates only these post-owner launches; it is not evidence that arbitrary other Cargo writers cannot exist. The explicit owner handoff remains mandatory.

Stage 1: historical-regressions-plan.json -> root-validation/exact-historical-regressions-01. Four actual commands including preflight and source guards; ten Rust test methods, zero failed and ignored. Original inner test timeout is 900 seconds. New outer runtime limit: 1800 seconds.

Stage 2: history-local-plan.json -> root-validation/exact-history-local-01, only after retained actual Stage 1 success. Five actual commands. Release compile uses --no-run with its original 1800-second inner limit; helper uses the exact ignored test name with --exact --ignored --list, not full execution, with original 120-second command limit. New outer runtime limit: 2400 seconds. Zero test passes are claimed by compile/list.

The target originates from an independent copy of qualified C7 owner and History caches. It is reused after exact C8 owner qualification, fresh_cargo_target=false, and is neither empty nor an independent clean-room build. Registry/toolchain remain reused. No complete 4105-block History workload, fake HostedCI context, proof generation, new operation, payment or deadline change is authorized here.

Each stage gets a new output and launch-record directory. Existing outputs are never overwritten or retried under a new identity. A failed guard, missing/unknown terminal, failed import, count mismatch or nonzero qualifier stops the sequence; all partial evidence remains. A missing result after wrapper termination is not a pass.
