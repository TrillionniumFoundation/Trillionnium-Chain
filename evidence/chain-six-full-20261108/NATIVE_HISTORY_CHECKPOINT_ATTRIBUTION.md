# F3 native History checkpoint attribution — observed failure retained

## Finding and scope

The high-frequency Host checkpoint work in the F3 native campaign is an existing #812 path. It was not introduced by this round's money/epoch changes. Eight inspected callback and storage traversal files have identical Git blobs at base `7e044b65454f4c9ea505591727332acffb33e7e5` and F3 `1a446a79700cc093a2b1a7f10367ef4a5ddbd680`. The complete `store.rs` diff changes an internal open-parameter name and adds PermanentAccountGrowthV2 observation/confirmation dispatch; it does not change the admission epoch, original authenticated traversal, activation, or commit checkpoint bodies. The measured campaign selects `authenticated-v1`, so the new Growth branches do not run here.

This is a read-only source and saved-receipt attribution. No native experiment, performance comparison, benchmark, or crypto proof was rerun for this report. It does not establish an A/B speed difference between releases. The original three F3 executions remain failed; the baseline, from-zero, and late-product phases each report 0/3 confirmed rounds in every execution. Seven honest ACKs in a phase do not establish independent confirmation.

## Exact sources and evidence

Repository: https://github.com/TrillionniumFoundation/Trillionnium-Chain
Workflow: https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/42518203879
F3 HEAD: `1a446a79700cc093a2b1a7f10367ef4a5ddbd680`
F3 tree: `928b180bf769a813e5643827329667cb11f2a3a5`
Original artifact ID: `13632763228`
Original ZIP SHA-256: `f10ae7989fd89b12b6e4547bdb8ea9c72ea43e19c821eecf4074673da528f6be`
Original derived cost summary SHA-256: `5a5ca779e209820eb030c36414d84dd03b90b8b21b50cd1e3f1eb776d4746011`

The package retains the three unmodified phase-readback JSON files and the original derived cost summary. A separate manifest binds their exact bytes, the selected original source blobs, and the complete `store.rs` base-to-F3 diff. The phase reader's own scope remains intact: it does not run native admission or authenticate the host/source merely by reading JSON. The original source and resource receipts remain the authority for their stated local observations.

## Actual call path

1. [ingress.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/ingress.rs), `receive_public_page_from_before_observed` (around lines 2586–2617), resolves the original fixed Host parent, checks it initially, and passes a resource closure into the full History importer. Every invocation of that closure calls `kernel.verify()` inside a Host checkpoint measurement. The final Host check is retained after native cleanup.

2. [history_import.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/ingress/history_import.rs), `Control::check`, checks the original absolute deadline and then invokes that resource closure. `verify_history_work` passes it at each existing W1 boundary. `admit_packet` passes the same check into original context checks, bounded M06 execution, native admission, and final activation. `activate_packet` (around lines 400–425) calls `activate_observed_with_termination` with that same checkpoint and original operation.

3. [scalar_cpu.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/ingress/public_v3/scalar_cpu.rs), `history_checkpoint` delegates to `LiveRequestCpu::observe_with_control` (around lines 685–716). It invokes the resource check before the live CPU observation. If the original exclusive owner must wait for refill, it checks the resource again before the original bounded sleep and on the next iteration. Shared History cannot wait while owning the Node mutex. These are the existing same-account CPU/deadline rules.

4. [store.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/store.rs), `activate_observed_with_termination` (around lines 6667–6684), checks the original observed history and proceeds through `activate_with_fault_and_progress`. A complete page can require original staging, delta application, per-step persisted-state verification, transactional readback, cancellation, and final publication. `resume_intent_with_progress` preserves the existing progress checks at every reorganization step and persisted-state boundary.

5. [native_authenticated.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/store/native_authenticated.rs), `verify_state_with_readback` (around lines 674–790), keeps current record, root, and account graph validation. The callback reaches [native_store.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_store.rs), `verify_account_values` (around lines 510–564), whose actual stack traversal invokes `progress()` for every visited node. [native_scoped_readback.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/account_archive_prototype/native_scoped_readback.rs) also preserves the progress call at each real traversal step. A large Host count therefore is not a count of W1 proofs or SQL epoch queries.

6. [host_kernel_parent.rs](https://github.com/TrillionniumFoundation/Trillionnium-Chain/blob/1a446a79700cc093a2b1a7f10367ef4a5ddbd680/trillionnium/crates/trnm-pon-node/src/host_kernel_parent.rs), `KernelBudget::verify/check` (around lines 336–361 and 422–424), performs fresh reads on each successful check: boot ID, the actual calling thread's `/proc/thread-self/cgroup`, and five cgroup limit files (`cpu.max`, `cpu.max.burst`, `memory.max`, `memory.swap.max`, `pids.max`). It also calls `symlink_metadata` on the fixed parent and compares ownership, mode, device/inode identity, boot ID, membership, and limits. These readers reopen the actual paths and complete their reads; their comments explicitly prohibit retaining descriptors, file contents, or prior resource decisions across checks. This describes the code's required I/O, not a separately measured syscall trace.

## Saved measurements

The last baseline import is the seventh import. All three saved executions accepted the preceding six imports and refused this final import with `PUBLIC_REQUEST_DEADLINE`.

| Execution | Last-import Host checkpoint calls | Host-check CPU sum (s) | Host-check wall sum (s) | Importer-thread CPU (s) | Import wall time (s) |
| --- | ---: | ---: | ---: | ---: | ---: |
| run 1 | 29,390 | 1.807465306 | 2.582565197 | 2.175519954 | 9.602049013 |
| run 2 | 29,136 | 1.787949770 | 2.251233154 | 2.156216574 | 9.575968462 |
| run 3 | 28,596 | 1.766860370 | 2.383027194 | 2.132915848 | 9.471952782 |

In run 1, the immediately preceding accepted import had 8,783 Host checkpoint calls, 0.539065674 seconds of Host-check CPU, and 2.705125153 seconds of import wall time. The seventh import's packet-level measurements separate the work that completed from the later failure:

| Run 1, last packet phase | Result | Importer-thread CPU (s) | Wall time (s) |
| --- | --- | ---: | ---: |
| W1 work | accepted | 0.070465897 | 0.300914124 |
| Admission | accepted | 0.550041958 | 2.404831201 |
| Complete-page submit_result / activation | PUBLIC_REQUEST_DEADLINE | 1.552198143 | 6.893051964 |
| History epoch open | accepted | 0.000257552 | 0.000642964 |
| History epoch close | accepted | 0.000066578 | 0.000118287 |

The first three rows are packet phases. Epoch open/close are outer page phases. The report does not sum these rows as a total. Admission itself contains nested preparation, execution, and commit measurements.

This directly locates the final additional delay in the existing complete-page activation path after successful W1 work and admission. It is consistent with the source's repeated authenticated state/account-graph and transactional progress checks. The original observer aggregates Host checkpoint calls across the import; it does not tag every call by source site. Consequently, the saved data cannot allocate an exact number of the 29,390 checks to W1, each graph traversal, reorganization, or refill iterations.

## Epoch comparison

`AdmissionStateEpoch`, `admission_state_epoch()` (`PRAGMA data_version` plus SQLite total changes), header input-freshness fencing, and private prepared-parent reuse are all present in the #812 base bytes. The full store diff proves these bodies were not introduced or changed by this integration. They are boundary observations and do not replace the high-frequency Host guard. The page's history CPU epoch is another existing mechanism; its separately measured open/close intervals above are not the observed multi-second activation interval. Neither should be relabeled as a new money epoch regression.

## Measurement limits and outcome

Host CPU sums each actual invoking thread's measured Host-check intervals. Import phase CPU measures only the importing thread and excludes scoped worker CPU. Host spans, packet phases, and page phases overlap. They must not be added or divided into a whole-process percentage without an appropriate common accounting scope. The Host timer also has its own measurement overhead: observer bookkeeping and clock reads are not a zero-cost subtraction from native work. These saved observations do not quantify an observer-free counterfactual or complete worker CPU.

The selected evidence shows a material existing checkpoint/activation cost under the unchanged Host and business limits. It does not prove that removing that cost would meet confirmation targets. No cache, descriptor reuse, lower checkpoint frequency, larger CPU allowance, longer deadline, new cancellation behavior, or WAL/reorganization gate change is proposed or applied here. Such changes would alter current Host observation or lifecycle boundaries and require a separate design and the original migration/limit-change/cancellation counterexamples.

No safe, validated performance fix is claimed in this round. The three native executions remain genuine FAIL observations; independent confirmation, work economics, same-resource net benefit, full quantum reliability, and production qualification remain unestablished.
