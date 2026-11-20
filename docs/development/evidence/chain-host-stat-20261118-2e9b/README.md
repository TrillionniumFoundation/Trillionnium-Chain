# Current Host metadata observation candidate

The unchanged fixed-Host ROOT F0 campaign at source 7e3e454f failed with 1/6 confirmations in the original thirty-second phases and 0/6 against the scheduled four-second target. The baseline's History imports spent 5.1597 seconds of nested CPU in 121,963 actual Host checkpoints. Full originals and independent readback are retained in #958.

This candidate replaces the current metadata reads in the same Host guard positions with the existing rustix fstat/statat APIs. It preserves every current open, the exact parent identity/type/owner/mode checks, all five nonblocking nofollow limit reads through EOF, the actual calling-thread membership and boot reads, error ordering and the final named-path fence. No descriptor, file content or Host verdict is retained across checks. Request, workload, deadline, CPU allowance and activation policy are unchanged.

The complete original Host negative controls remain. One additional test compares all consumed fields with the original std metadata readers and checks current symlink/permission outcomes. A separately invoked ABBA observation measures only the seven metadata reads on temporary files, without granting Host or business qualification. Current source correspondence refreshes only the two changed source blob pins; historical claims remain frozen.

## Completed native validation

Source `eeef078c7dd12dd2456d6a202c2839f7b8af316d` is frozen in Draft #959. Native job `1a1ef193d1b-ffbe-3fa` completed on ai395 with Rust 1.95.0: 46 original Host controls passed, 2 controls remained explicitly ignored in that selector, the separately invoked metadata observation passed, and strict library Clippy passed. The 1,704 source/vector hashes were identical before and after execution. The first sparse-checkout missing-vector compilation failure is included in the originals; its retry materialized the exact original Git blobs.

The six old metadata samples averaged 5,850,010.67 ns and six raw metadata samples averaged 5,140,905 ns, each per 5,000 groups of six descriptor stats and one nofollow named stat. This is 12.12% in that isolated metadata segment, approximately 142 ns per group. It is not a full Host checkpoint or service latency measurement and cannot establish the four-second target.

`native-originals.tar.xz`: 95,324 bytes, SHA256 `5ce4e0c28fd2db84eff3739504d464adc881dc64b84e34572d5e106814239bca`. It retains both attempts, exact logs/exits, source hashes, the submitted native patch and actual native source bytes. Native test ELF identities are recorded; full test ELF bytes are not in this archive.

## Original F0 result: failed

The unchanged original F0 workflow ran once on the frozen #959 source: [run 44328450170](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/44328450170), job 134886019562, artifact 14440407162. Both thirty-second phases ended with no confirmed round: **0/6 in the original windows and 0/6 at four seconds**. Baseline had 7 timely ACKs and ROOT had 2; across the fixed 42 exposures, 32 were unattempted and 1 was attempted without a timely ACK. ACKs remain distinct from confirmation. All failed, late and unobserved denominators are retained.

The original native selector exited 101. Original readers refuse with BASELINE_MUST_PASS and F0_ALL_SIX_SCHEDULED_FOUR_SECOND_TARGETS_REQUIRED. All six controller boundaries and actual actor ownership/reaping were checked; all exact owned services were empty. Cleanup is not business success. The original CPU/memory, workload, 24 ROOT attackers, 1/5/9-second schedules and deadlines were unchanged.

The baseline's 7 imports made 81,441 Host checkpoints and spent 5,038,819,332 ns nested Host CPU inside 5,916,494,724 ns caller CPU. ROOT performed no History imports, so its absent import work cannot be treated as a completed cheap service. This run does not demonstrate service benefit from the metadata substitution. Different GitHub-hosted runner allocations and different completed-work counts prevent treating the two raw totals as a paired causal speed estimate.

`f0-original.zip`: 16,750,521 bytes, SHA256 `ccc502e88fac262153d821eadb53dedd549c405d65fd8d331a687284295314d9`, equal to the GitHub artifact digest. The actual report SHA256 is `57a6fb7a86a9b5154fcab02e94d01ca14ecdc0e13496a1f6810d0353b9ff2405`; the retained native business ELF is 13,130,416 bytes, SHA256 `341abb2009e8fdb09d55668b73826a3618d6646a9335c7290645de05797587b1`.

`f0-readback.py` pins the twelve unchanged original reader blobs and verifies all 443 manifest members, source/tree before/after, original preparation controls, actual native ELF, receipts, business failures, all 42 exposures and controller/cleanup scope. Its independently produced `f0-independent-readback.json` preserves the failures. This evidence belongs only to source `eeef078c7dd12dd2456d6a202c2839f7b8af316d`, tree `44059af7054f72e3e1cb22691aee76932bfad836`.

Project preflight, the exact current-source correspondence and the original omission/mutation negative control passed. Source correspondence still reports HOLD_NO_GO, cryptographic_acceptance=false and node_activated=false. No production activation or complete physical-cost qualification.
