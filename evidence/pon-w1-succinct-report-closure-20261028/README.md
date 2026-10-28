# Strict readback of complete-certificate loopback cost

Independent review of frozen source `90d130e47def9ee3b1498336fff94e4202ab76a0`
found a concrete reporting gap. Its native path already transmitted and
verified the complete `PWSR0001` certificate, but its final reader did not bind
the detailed loopback result to the actual native and transport supervisor
files. By control-flow inspection, changing only a reported negative duration
or a nested child exit code could leave that reader's success predicates
satisfied. This was a report/measurement integrity issue, not a forged STARK
or a relaxation of the original W1 relation. No synthetic complete proof or
hosted run was created to claim reproduction of a full successful report.

The original frozen source remains unchanged. This independent follow-up
anchors all sixteen actual loopback files, including received certificate
bytes and both native logs, in an output inventory. The successful loopback
stdout records the inventory's exact hash, and the existing outer phase
wrapper hashes that stdout after closing its complete owned process family.
A new pure `finalize-loopback` then rechecks the inventory and actual records
after outer cleanup; it cannot start or retry proving or transport. Failure
still retains the known file inventory and outer terminal.

The final reader independently checks that anchor again. It compares the
actual native supervisor files and sole certificate-verification log records
with their nested report entries. It uses the existing closed-process gate,
the exact 900-second/8-GiB native profile, and the actual per-role remaining
deadline within the shared 30-second/128-MiB transport profile. It rechecks
the received certificate byte for byte against the sent certificate and
binds the full original input hash, complete proof hash, image and claim.
Transport roles, distinct PIDs, reciprocal localhost endpoints, connection
nonce hashes, payload counts, 160 framing bytes and receive fsync records
must agree. All reported duration/CPU nanoseconds must be nonnegative
integers; observed total wall duration cannot undercount the sequential
transport and two native observations.

All 123 recursion stages and their original 3,500/3,600/300-second budgets,
worker counts, SDK/Cargo locks, Rust helper, original relation and PoW-off
setting remain unchanged. The existing PNW1 codec is unchanged. This change
adds no new proof authority. Its byte readers run after the measured phase
and are explicitly outside that phase's CPU total; inner CPU details are
already included in the outer phase and must not be added twice.

## Actual controls and retained failures

The updated suite has ten methods: the original seven controls, a measured
nanoseconds boundary control, a file-inventory substitution control, and an
**actual** small localhost TCP component with reported-cost and child-terminal
substitution negatives. The TCP component carries approximately 2.5 KiB of
clearly labelled non-proof data and never calls the final proof report.
The inventory-only dummy files cannot pass any native proof verifier.

The first normal sandbox invocation failed because socket creation returned
`EPERM`. The exact receiver traceback, failed worker/supervisor and component
record remain under [default-sandbox-loopback](default-sandbox-loopback/).
The same bounded localhost component then ran with approved local-socket
access. Its first reader version incorrectly expected success JSON on worker
stdout; the pinned byte worker actually writes `worker.json` and prints no
success record. That real failure is retained in
[controls-native-loopback-01.stderr.log](controls-native-loopback-01.stderr.log).
The corrected reader uses the actual worker JSON and binds its normally empty
raw stdout as a file. The next complete invocation passed **10/10**, with
no skipped control, in
[controls-native-loopback-02.stderr.log](controls-native-loopback-02.stderr.log).

These are source, byte-reader and actual TCP controls. No native SDK build,
native Succinct positive gate, recursion proof or complete-certificate native
acceptance ran locally for this follow-up. Those remain mandatory hosted
gates on the exact published source. The original shared dependency graph,
native source and resource policy are unchanged.
