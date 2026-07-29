# TRNM Public-Testnet Multi-Host and Soak Runbook

Status: **unverified design draft**. No multi-cloud deployment, HSM/KMS signer,
continuous 72-hour/7-day run, or public-testnet SLO gate is implemented by this
document.

## Target Topology (Not Deployed or Verified)

- Four to seven validators across at least three regions and two cloud providers.
- Validators expose no public P2P or RPC listener. Each connects through two sentries in separate failure domains.
- At least two public seeds and two RPC nodes are non-validating.
- Persistent peers use stable node IDs and authenticated private transport.

## Target Signer Boundary (Not Implemented)

CometBFT `priv_validator_key.json` must not be copied into an image, archive, or
shared volume. A future production deployment must use `priv_validator_laddr`
with a reviewed remote-signer implementation backed by a compatible HSM/KMS.
No such integration is claimed here. File keys are permitted only in disposable
local fixtures.

Before startup, record the consensus public key, remote-signer endpoint, key version, operator, region, and recovery owner. Replacement requires a governance transition and key-possession proof; copying the old private key is not recovery.

## Target Chaos Matrix (Not Automated)

- 100, 250, and 500 ms one-way latency.
- 1%, 3%, and 5% packet loss.
- 3-1 and 2-2 partitions.
- ±500 ms clock skew without changing monotonic process time.
- Disk exhaustion at 20%, 10%, and 2% free space.
- Application and CometBFT OOM kill.
- Validator loss, replacement, rolling upgrade, and snapshot restore.

A future multi-host gate must preserve zero conflicting final blocks and record
all measurements defined by `config/public-testnet-slo.json`. The current local
repetition harness neither injects this matrix nor measures those SLOs.

## Measurement Contract (Specified, Not Collected)

- Commit latency starts on a node's monotonic clock when that node receives a
  complete valid proposal block and ends only after application commit and
  CometBFT state persistence complete. Catch-up commits are excluded. P95/P99
  use nearest-rank `ceil(p*n)` without interpolation over a 15-minute window
  with at least 1,000 eligible samples.
- Recovery starts when the external orchestrator acknowledges the injected
  fault, restart, replacement, or restore action. It ends when the target is
  within one block of the network head and remains there for 60 seconds.
- Daily storage growth compares allocated bytes on the same volumes across a
  24-hour window and includes CometBFT block/state data, application SQLite
  plus WAL/SHM, snapshots, and indexer state.
- Conflicting-final-block evidence must be derived by grouping independently
  collected block IDs by chain ID and height. A literal or default zero is not
  acceptable evidence.

These definitions make the draft thresholds testable, but no collector currently
implements them. Consequently `config/public-testnet-slo.json` remains
`enforced=false`.

## Local Repetition Smoke (Not a Soak Gate)

```bash
TRNM_COMETBFT_BIN=/path/to/cometbft \
TRNM_SOAK_MODE=smoke \
TRNM_SOAK_ITERATIONS=3 \
./trillionnium/scripts/consensus/run_cometbft_soak.sh
```

The compatibility-named script repeatedly creates fresh local loopback fixtures.
It records the underlying gate marker and hashes of its canonical and safety
evidence, but it does not represent a continuous network. Modes `72h`, `7d`, and
`multihost` intentionally fail closed until a real external orchestrator and
measurement pipeline exist. `smoke` and its `test` alias are development-only
harness checks and are never release evidence.

## Honest Boundary

This repository currently provides draft topology, SLO, chaos, and evidence
requirements only. It does not prove a multi-cloud deployment, completed soak,
remote signer, or public-testnet SLO until real-host artifacts are attached and
independently reviewed.
