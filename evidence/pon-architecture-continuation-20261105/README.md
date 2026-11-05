# Permissionless architecture continuation — 2026-11-05

**Scoped engineering and finite ordering controls passed. The original native
business comparison remains HOLD:** all 18 final integrated samples report
`PUBLIC_HOST_KERNEL_PARENT`; none qualifies as a successful business trial.

Continue the existing Draft PR #688 from
`6ee529046d295e3175f09112492abee373f1f54c`. Protected main was
`dd6e1c3cbeacbdc532b0679297835b3a0aac78f0` at inspection.
The [existing development plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
and [comparison contract](../../docs/protocol/pon-nakamoto-v1/details/ARCHITECTURE_COMPARISON_V1.md)
remain authoritative. This package does not qualify a complete Bitcoin-NG, Prism,
OHIE or GHOSTDAG native successor.

## Source and composition

| Anchor | Meaning |
| --- | --- |
| `c54e1e325b3174b0f671bb064ab8b07924cba62d` | Initial frozen implementation and model/reader/CI controls |
| `dda4cc47362065819e9591f11f713933e7a853bf` | Concurrent #688 update, retained in full |
| `d992451cc8bfb3d69a1c9f1906bee6732255fad6` | Integrated native build, component tests, business failure, GHOSTDAG campaign and replay |
| `28b379ed75d4503da634ef71fb54ce51edb96d57` | Correct the two existing source-registry blob pins; all native, Python and CI executable source remains byte-identical to the integrated anchor |

The merge retains all 45 concurrent changed paths, both development-plan entries,
and the union of the generated inventory. The `dda4cc47..d992451c` merge delta
contains exactly 14 intended paths; the later registration repair adds the
corpus manifest as the fifteenth changed source path. Independent composition review verifies that
the 12 non-shared candidate paths retain their previously tested bytes; plan and
inventory combine only additions. No remote file disappears.

The integrated PQ source guard correctly rejected stale pins for `ci_job.sh` and
the generated inventory. The final registration commit changes only those two
existing blob values. A locked compile check confirms the native test binary
remains byte-identical to the tested integrated binary. The original failure,
exact repair, strict checker and its
35 negative/positive controls are retained. All HOLD and false-acceptance fields
remain unchanged. The evidence commit changes only this evidence directory.

## Implemented changes and concrete controls

1. **OHIE bounded-model proposal selection.** An invalid spent-input prefix could
   occupy every proposal slot indefinitely while a later valid transaction never
   became selected. Stable executable selection uses a temporary ledger view and
   rescans for dependencies within the unchanged block cap. All pool entries are
   retained for dependency arrival or reorganization. The same eight new controls
   yield six failures on the original model and eight passes on the candidate;
   the complete 36-test suite passes. The concrete same-profile conflict-prefix
   case confirms the valid transaction after the repair. All 18 existing standard
   scenario/seed runs retain byte-identical summaries and traces. This is a
   synthetic-model fix, not a demonstrated native-chain attack or liveness proof.
2. **Architecture observation consistency.** The reader binds sequential wall
   lower bounds, positive equal frame bytes per workload, exact signed payload
   bytes and integer counters. Concurrent pool calls contribute each round's
   maximum; overlapping waiters are not summed. The old reader fails 22 subtest
   assertions under the new controls. The new suite has 22 test methods in total,
   including eight added methods; these are different denominators. Report
   consistency does not authenticate execution or establish a second W1 oracle.
3. **Absolute dissemination budgets.** Connect/header/body/ACK share the original
   frame end; all cells retain the original campaign end. Errors cancel siblings,
   every started thread is joined, and original failures survive derived
   cancellation. Nine real-socket controls cover fragments, shared header/body
   deadlines, backpressure, cancellation, EOF and late completion. Two signed
   durable-material controls plus the retained equivocation/withholding control
   bring the selected native component count to 12. Pending connect may consume
   its remaining two-second frame budget. Filesystem/kernel stalls are not
   universally preemptible: the 15-second campaign deadline rejects late success
   after an operation returns, rather than promising a hard process-return time.
4. **GHOSTDAG bounded Algorithm 1 ordering.** The uniform-work kernel requires a
   complete single-genesis DAG, deterministic tie/merge order, all existing blue
   vertices' anticone constraints, and retention of every red vertex. Unsupported
   work/profile and resource exhaustion refuse success. An independent set oracle
   covers all earlier-ID parent subsets through six vertices and `k=0..n`:
   10,106 graphs, 70,367 comparisons, zero differences. Exact replay reproduces
   the transcript. A five-vertex counterexample catches the incorrect shortcut
   of checking only the new candidate. A separate reviewer used a further set
   implementation; overlapping small graphs are not counted as independent
   scientific sample sizes. No native work, PQ, dynamic difficulty, confirmation,
   WAN or Kaspa implementation equivalence follows from these finite results.

## Actual validation

| Execution | Result | Source / scope |
| --- | --- | --- |
| OHIE model | 36 PASS | Initial frozen source; unchanged implementation inputs verified at integration |
| Architecture reader | 22 PASS | Same scope; exact denominators retained |
| Host adapter controls | 17 PASS | Python adapter/refusal tests, not a configured Host |
| GHOSTDAG unit controls | 29 PASS | Repeated on integrated source |
| GHOSTDAG max6 campaign and replay | 70,367 comparisons, zero differences; replay PASS | Exact integrated commit and three file hashes bound |
| Native component selection | 12 PASS, one full-business selector filtered | Integrated release binary; omitted selector separately executed below |
| Native full-business selector | FAIL, exit 101 | 18 samples, zero met targets; every sample retains `PUBLIC_HOST_KERNEL_PARENT` |
| Complete business execution owner | FAIL, exit 2 | Full raw report and source-before/source-after retained |
| Original CI unit controls | 233 executions, 190 distinct methods PASS | 98 contract + 43 source + 16 boundary + 76 execution; the last imports the same 43 source tests |
| Integrated CI controls | 98 contract + 9 constants-roster tests PASS | CLI fixture checks are explicitly synthetic; they do not run the native constants workload |
| Registered-source checker and controls | HOLD_NO_GO source check PASS; 35 tests PASS | Final registration commit; research qualification stays false |
| Target release build, strict Clippy, formatting, inventory and repository checks | PASS | Command records retain exact stage, tree, lockfile graph and binary hash |

No timings above are reported as TPS, speedup, WAN capacity or cross-protocol
security equivalence. Failed full-business samples do not enter successful
performance summaries. The existing cold-reopen equality observations do not
erase failed native admission or confirmation.

## Inspecting the records

- [execution-summary.json](execution-summary.json): source anchors, input hashes,
  native commands and explicit remaining qualification flags.
- [ghostdag-order-max6.json](ghostdag-order-max6.json) and
  [ghostdag-replay.json](ghostdag-replay.json): exact finite ordering evidence.
- [business-failure.json](business-failure.json) and
  [business-manifest.json](business-manifest.json): original refusal and execution
  owner result, without turning process completion into success.
- [records-index.json](records-index.json): SHA-256 and sizes for each retained raw
  record, plus the archive hash.
- [raw-records.tar.gz](raw-records.tar.gz): original stdout/stderr, command receipts,
  both complete failed native reports, pre-repair red controls, source snapshots,
  composition review and capture scripts. Earlier exploratory results retain
  their original uncommitted/provenance labels.

Extract the archive into a new directory with `tar -xzf raw-records.tar.gz` and
check entries against the index. Native executables, Cargo caches and generated
SQLite stores are not archived. The business manifests retain the original
hashes and paths of those omitted runtime stores; the full report and failure
logs are present. No historical successful report was borrowed as current
compatibility evidence.

## Reproduction

Use a clean checkout of `28b379ed75d4503da634ef71fb54ce51edb96d57` for the
combined registered source below, pinned Rust 1.95.0,
and the unchanged lockfile. Earlier anchors retain their earlier source-registry
failures; their own receipts remain scoped to those anchors. Use separate Cargo
home/target directories for
concurrent projects. Generated receipts must go outside the checkout.

```sh
bash scripts/project-preflight.sh
python3 -B formal/pon-nakamoto-v1/test_parallel_variable_ohie.py -v
python3 -B formal/pon-nakamoto-v1/test_ghostdag_order_reference.py -v
python3 -B formal/pon-nakamoto-v1/experiments/test_architecture_compare.py -v
python3 -B scripts/ci/test_architecture_host_ci.py -v
python3 -B formal/pon-nakamoto-v1/experiments/ghostdag_order_campaign.py --max-blocks 6 --output /absolute/new/ghostdag.json
python3 -B formal/pon-nakamoto-v1/experiments/ghostdag_order_campaign.py --replay /absolute/new/ghostdag.json
cargo test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare --no-run
cargo test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare -- --skip signed_dag_delivery_comparison_uses_same_native_business_and_confirmation_contract --nocapture --test-threads=1
cargo clippy --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-pon-node --test architecture_delivery_compare -- -D warnings
cargo fmt --manifest-path trillionnium/Cargo.toml --all -- --check
python3 scripts/refresh_distributed_source_inventory.py --check
python3 -B scripts/ci/check_pq_research_integration.py
python3 -B scripts/ci/test_pq_research_integration.py -v
python3 scripts/ci/check_repository.py
```

Run the original full-business selector separately through its complete execution
owner and actual original fixed Host:

```sh
python3 formal/pon-nakamoto-v1/experiments/architecture_compare.py --out /absolute/new/architecture-business
```

The local runs retained their actual environment and did not fabricate CI/Host
markers. The original no-attack and four-second/16-hostile-W1 acceptance,
depth **and** required-work confirmation, 4,105-block History, complete current PQ
roots, native state/effect recovery, independently operated WAN and successor
security assumptions remain open. Production activation remains false.
