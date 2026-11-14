# Final gate inventory

Source checkpoint: 5c04c60e463462d9df8884786e0d5bb32af08a64 (tree 8f26631e80c14a3c750210019606df13327d633f). Reviewed from dba81d56 and checked against the final T03 merge. This is a read-only command/source inventory; no tests, native workload, source edits or remote actions were performed.

Execute only after final bindings and report are committed on the final clean candidate. Keep the exact final head in FINAL_HEAD and put fresh receipts in CHECK_OUTPUT outside the checkout. Do not use old checkpoint success as evidence for the final committed source.

## Existing complete lanes

| Lane | Original entrypoint | Local execution boundary | Existing hosted job timeout |
| --- | --- | --- | ---: |
| repository-truth | bash scripts/ci/ci_job.sh repository-truth | Complete recipe on Linux with its real /dev/shm fixtures and pinned Python dependency |45min |
| external-evidence-contract | bash scripts/ci/ci_job.sh external-evidence-contract | Complete retained historical evidence replay with exact source inputs and dependencies |45min |
| fuzz-smoke | bash scripts/ci/ci_job.sh fuzz-smoke | Original all-target coverage-guided fuzz recipe with pinned installed tools; no reduced target/time selection |45min |
| rust-baseline | bash scripts/ci/ci_job.sh rust-baseline | Local complete recipe with real native/platform prerequisites; hosted current-run shard/fan-in identities remain separate |180min per hosted shard and fan-in |
| protocol-contract | bash scripts/ci/ci_job.sh protocol-contract | Complete lane is hosted-only: includes the fixed Host provisioner. The exact body lists non-provisioning component commands in original order, but these alone do not satisfy this lane |240min |

The exact current bodies of all five lanes and every command reference are in the JSON and final-gate-exact-lane-bodies/*.txt. These are verbatim inventory files, not altered wrappers or skip switches.

## Source, PQ, documentation and inventory checks

- bash scripts/project-preflight.sh --audit — AGENTS/project-boundary, current sole plan/source ownership and no retired/privileged boundary drift. Source: AGENTS.md; scripts/project-preflight.sh; scripts/ci/project_boundary.py::check.
- python3 -B scripts/ci/verify_ci_source.py --kind head --expected-head "$FINAL_HEAD" --output "$CHECK_OUTPUT/source-before.json" — Immutable committed source before execution; same command without output after execution. Source: scripts/ci/verify_ci_source.py::verify/main; required workflow before/after steps.
- python3 scripts/ci/check_repository.py — Complete package/Cargo graph ownership; frozen all-false declarations; every current local Markdown link, JSON/TOML parsing; nested CI/detailed/applicability/invariant/current-doc validators. Source: scripts/ci/check_repository.py::check.
- python3 scripts/refresh_distributed_source_inventory.py --check — Exact generated distributed native source inventory without rewriting it. Source: scripts/refresh_distributed_source_inventory.py::render and __main__.
- python3 scripts/ci/check_ci_contract.py — All actual required lanes, literal inline Git blob pins, original native rosters/counts, T03 typed pending control registration, no skipped or swallowed failures. Source: scripts/ci/check_ci_contract.py::validate and check_typed_pending_worker_controls.
- python3 -B scripts/ci/test_ci_contract.py -v — Full positive/negative CI fixture suite; no zero-discovery shortcut. Source: scripts/ci/test_ci_contract.py; repository-truth explicit command.
- python3 scripts/ci/test_ci_execution.py — Original source-integrity execution and refusal controls. Source: scripts/ci/ci_job.sh repository-truth.
- python3 scripts/ci/check_pq_research_integration.py — Every current corpus pinned Git blob; selected required coverage; fixed PNQ2/NPQ6 research boundaries and all false qualification flags. Source: scripts/ci/check_pq_research_integration.py::check/_check_pq_source_coverage.
- python3 scripts/ci/pq_authority_effect_register.py — Reviewed seven-route/44-input current source consistency, always HOLD. Source: scripts/ci/pq_authority_effect_register.py::inspect/validate_manifest.
- python3 scripts/w1_lifetime_current_observation.py — Reviewed ordered20 current observation with frozen7150 reader/pins and unknown security bound. Source: scripts/w1_lifetime_current_observation.py::load/report.
- python3 scripts/w1_qrom_current_implementation_audit.py — Separate current QROM source map, preserving historical implementation identities and security HOLD. Source: scripts/ci/ci_job.sh repository-truth explicit current reader.
- python3 scripts/ci/test_w1_qrom_closure_current_controls.py — Current QROM source-closure negative controls. Source: scripts/ci/ci_job.sh repository-truth explicit current tests.
- python3 scripts/ci/report_current_implementation.py --check — Generated documentation matches existing registries. Source: scripts/ci/report_current_implementation.py::validate; check_repository nested; repository-truth explicit.

Most entries above already execute in repository-truth, including the full CI contract negative suite; avoid redundant same-head repeats. The direct cross-branch corpus check is an explicit final-binding audit entry. check_repository also invokes CI contract, detailed module procedures, applicability, invariants and current implementation documentation checks, and checks every current local Markdown link and JSON/TOML file.

## Exact environment and source evidence

Rust1.95.0 with rustfmt/clippy, original Cargo --locked graph, workflow build jobs2 and test threads1. Conformance Python requirements are numpy1.26.4 and cryptography50.0.2. Runtime verifier uses packaging26.3 under its exact wheel hash. Use the existing verified OpenSSL3.5.9 provider contract. Fuzz uses cargo-fuzz0.13.2/nightly2026-10-01; supply chain uses cargo-deny0.20.2 and both graphs with the retained advisory snapshot.

Before and after each execution, use the existing verify_ci_source.py --kind head --expected-head "$FINAL_HEAD"; retain before output and original failures outside the checkout. Prospective merge verification must also supply exact base/head/merge identities and ordered parents. Do not manufacture GitHub run environment locally to satisfy shard or Host wrappers.

## Hosted Host gate and unchanged original budgets

Original command: python3 scripts/ci/run_from_zero_host.py -- python3 scripts/ci/run_from_zero_native.py --out "$TRNM_CI_RECEIPT_DIR/from-zero-native". outer/outer_owned explicitly reject local provisioning. The unit remains CPUQuota25%/period100ms, MemoryMax2GiB/swap0 and TasksMax256; kernel cpu.max25000 100000, cpu.max.burst0, memory.max2147483648, memory.swap.max0 and pids.max256. Original child service uses KillMode=control-group, TimeoutStopSec20s, Delegate=no, NoNewPrivileges=yes and empty capabilities.

The native runner still has900s preparation/exact build,60s complete formatting,90s for each of its five original named tests, the4,000,000,000ns pressure window,16 workers,4096 construction attempts,1024 worker cap and2000ms per-call deadline. Source/binary/format identity, complete denominators, full fresh Host checks, CPU settlement and independent confirmation replay remain mandatory. Larger orchestration timeouts do not enlarge any business budget.

- caller_cpu_clock_keeps_missing_overflow_and_wrong_owner_distinct
- from_zero_search_preserves_misses_exhaustion_and_full_replay_rejection
- four_from_zero_w1_traces_keep_native_state_and_chainwork_unchanged
- from_zero_service_shares_cpu_with_honest_work_and_reopened_owner
- from_zero_signed_business_reports_confirmation_in_original_pressure_window_against_same_packet_baseline

## Final CI delivery

Normal authenticated fast-forward synchronization of PR847 produces both exact-head and prospective merge checks. Existing concurrency preserves the older running evidence; default single pending may be replaced by a later candidate. Keep all required names, gates, failure propagation and original budgets. workflow_dispatch does not replace prospective merge checks.

Machine inventory: /private/tmp/chain-ci-final-source-binding-and-gates-review-20261114/final-gate-inventory-v1.json
This inventory grants no production, performance, whole-chain PQ or merge qualification.
