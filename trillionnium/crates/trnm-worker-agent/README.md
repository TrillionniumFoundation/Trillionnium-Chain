# trnm-worker-agent

Owner: M10. Reusable candidate component; no consensus activation.

Bounded real child process, task workflow and evidence adapters; not a miner.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.

The worker is not a miner. Its default model adapter is an explicitly named mock;
new-protocol transaction integration must be supplied independently.

```bash
cargo test --locked -p trnm-worker-agent --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).
