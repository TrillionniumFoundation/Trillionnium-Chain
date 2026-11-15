# PQL2 PQG1→PQS1→nonce/liability bridge: local research evidence

This directory records a **single-host local source/format regression**. It does not claim to have re-run PR #431/#434 cryptographic signature suites or Rust tests and does not represent any production on-chain migration or independent cryptographic acceptance.

- Source: `formal/pon-nakamoto-v1/pq_genesis_state_bridge.py`
- Unit tests: `formal/pon-nakamoto-v1/test_pq_genesis_state_bridge.py`
- Technical contract: `docs/security/PQ_GENESIS_NONCE_LIABILITY_BRIDGE_V1.md`
- Command: `PYTHONWARNINGS=error::ResourceWarning python3 -m unittest -v test_pq_genesis_state_bridge.py` from `formal/pon-nakamoto-v1`
- Observed: **18 tests passed**, **0 failures/errors**, single local Python 3.13.5 run, Linux x86_64 overlayfs.
- An initial local test returned 17 PASS / 1 ERROR due to a plain `TypeError` for invalid non-byte PQS1 input; the bridge was repaired to return the typed `Reject`. The retained `local-unittest.log` contains the final complete passing run; no assertion was relaxed or removed. Prior failure is documented here, not relabeled as a pass.

This new compatibility projection rejects omissions and nonce replay gaps when bytes and trusted anchors are correct. It does not itself verify upstream ML-DSA/Ed25519 signatures or source ownership; the unchanged upstream PQG1 module is the separate cryptographic conformance layer and still not production authority.

`local-qualification.json` contains the executed source hashes, local environment and explicit false production flags. It is not an M17 independent external signed receipt.
