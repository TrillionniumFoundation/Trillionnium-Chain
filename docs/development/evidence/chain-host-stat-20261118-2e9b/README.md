# Current Host metadata observation candidate

The unchanged fixed-Host ROOT F0 campaign at source 7e3e454f failed with 1/6 confirmations in the original thirty-second phases and 0/6 against the scheduled four-second target. The baseline's History imports spent 5.1597 seconds of nested CPU in 121,963 actual Host checkpoints. Full originals and independent readback are retained in #958.

This candidate replaces the current metadata reads in the same Host guard positions with the existing rustix fstat/statat APIs. It preserves every current open, the exact parent identity/type/owner/mode checks, all five nonblocking nofollow limit reads through EOF, the actual calling-thread membership and boot reads, error ordering and the final named-path fence. No descriptor, file content or Host verdict is retained across checks. Request, workload, deadline, CPU allowance and activation policy are unchanged.

The complete original Host negative controls remain. One additional test compares all consumed fields with the original std metadata readers and checks current symlink/permission outcomes. A separately invoked ABBA observation measures only the seven metadata reads on temporary files, without granting Host or business qualification. Current source correspondence refreshes only the two changed source blob pins; historical claims remain frozen.

## Initial validation record

- Project preflight and exact current-source correspondence passed; the latter retains HOLD_NO_GO, cryptographic_acceptance=false and node_activated=false.
- Original ownership omission/mutation negative control passed.
- Exact Rust 1.95.0 formatting is retained.
- Full native Host controls and the ABBA observation are running in isolated ai395 job 1a1ef193d1b-ffbe-3fa. The first attempt's sparse-checkout missing-vector build failure is retained; the retry materializes the two exact original Git blobs.
- The original F0 workflow is dispatched on this immutable candidate after publication. Its actual result will be retained separately. No performance or four-second closure is claimed here.

Draft stacked on #958. No production activation or complete physical-cost qualification.
