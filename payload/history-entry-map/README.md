# R1 4105-block history entry map

This is only a fixed-source entry/budget/artifact map for job 132475258347. The job metadata was supplied by root; this map has not read the original failed job log and does not assert its cause.

Workflow: original 180-minute native-priorities job, separate prepare, then run_from_zero_host.py -> run_history_native.py -> the exact prepared ancestry_long_sync release ELF and one original ignored selector. The history adapter introduces no execution timeout or from-zero 900-second bound. The Host systemd TimeoutStopSec=20s is cleanup, not a runtime deadline.

The original test creates/adopts all 4105 real work blocks, renews the V3 task four times, checks corruption refusal, and serves paid PublicV2 loopback RPC for a separate strict public History verifier. The server has an original finite lifetime of1800s and original2s policy; this is not the four-second/16-worker confirmation experiment.

Inspect the actual server exit evidence, independent sync error/stage/cursor, native history.log, summary.json and runner manifest before attributing failure. The recorded completed-import count is not a durable-block count. No native test/helper or captured source was executed; no network, source/ref/config or stage mutation occurred.
