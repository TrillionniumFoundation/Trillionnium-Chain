# Current Stage0 fleet/readiness observation

This directory contains the fresh, read-only operator observations collected
through ordinary SSH on `p4-x230` on 2026-08-23. The reports were produced
from the canonical PoCO worktree at commit
`af6c2737e1bf9d770076f8cb8b5a61887df619c7`, with Git tree
`03bbc502b9fc716990806968f44da05805db6a39` and
`trillionnium/Cargo.lock` SHA-256
`72e254afa47d8b92fe8803b35869990bcfaa7f8106d9f0d4ecb45d127fbe150b`.

`current-fleet-probe.json` passed the current `probe-fleet-v1` acceptor and
`current-run-readiness.json` passed the current `run-readiness-v2` acceptor.
They are current infrastructure observations only: both reports retain
`build=false`, `validator_run=false`, `multihost_run=false`,
`geo_wan=false`, and `production=false`. No validator binary, key, listener,
or persistent service was started by these probes.

The fleet identifier in the producer is the frozen inventory identifier
`trnm-poco-lan-six-host-2026-08-13`; the reports' observation timestamps are
the authoritative freshness marker for this run. Hashes and byte lengths are
bound in the parent `status.toml`.
