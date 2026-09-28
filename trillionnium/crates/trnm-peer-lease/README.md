# trnm-peer-lease

Owner: M04. Reusable candidate component; no consensus activation.

Cross-process scope/generation fencing, append-only replay and bounded Unix transport.

Domains and data schemas use a fresh portability namespace. Never open a deployed
historical database as an upgrade shortcut. Retained tests cover local behavior only.


```bash
cargo test --locked -p trnm-peer-lease --all-targets --all-features
```

Run from `trillionnium`. See [modules](../../../docs/modules/README.md) and
[ownership](../../../config/portability-inventory-v1.json).

## Network versus storage qualification

The partial-client socket-progress regression keeps its 750 ms request deadline and
three-second complete sequence bound. On Linux it uses a dedicated private `/dev/shm`
fixture to isolate network scheduling from block-device flush contention. It still
runs the real daemon and full journal operations; it is not a physical-storage latency
or power-loss test. Other persistence, restart, corruption and concurrency tests use
the normal disk-backed temporary directory. A previously observed slow-disk deadline
failure remains evidence of unqualified host service latency, not a successful SLO.
