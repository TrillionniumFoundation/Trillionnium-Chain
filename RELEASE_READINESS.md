# Release readiness

Stage: `executable-contract-and-portable-components`. Native consensus runtime and qualified work profile:
**false**. Production candidate, consensus activation, public testnet and release: **false**.

Old source/protocol/deployment trees are deleted. The portability inventory names the
actual reusable components. Their tests are not deployed recovery, model efficacy or
independent acceptance. The sole development plan retains PN1-PN6 implementation work.

## Local test environment observations

Disk-backed local test runs retained peer-lease request-deadline and short-lease expiry
failures under the observed host I/O load. Those runs are failed evidence, not passes.
A separate tmpfs-backed temporary-directory run can test complete logical file/IPC,
restart, mutation and ownership behavior with all assertions retained; it cannot qualify
block-device latency, fsync durability or physical power loss. The exact report must name
the temporary filesystem and test concurrency. No production SLO is granted by cleanup.

Native work/codec candidates and the executable Python ledger/model loop now exist.
Their controlled evidence does not activate a public network. Full-recompute proof
admission has measured asymmetry; external independent work and model acceptance remain false.
