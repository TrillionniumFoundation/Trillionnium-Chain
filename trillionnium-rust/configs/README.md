# TRNM shipped bootstrap topology

This directory ships a deterministic four-node local bootstrap fixture for peer-formation and join/rejoin rehearsals.

## Day-1 bootstrap topology

The shipped topology is intentionally small and fail-closed:

- `node1.toml` → node id `node1`, P2P `127.0.0.1:26656`, RPC `127.0.0.1:26657`
- `node2.toml` → node id `node2`, P2P `127.0.0.1:27656`, RPC `127.0.0.1:27657`
- `node3.toml` → node id `node3`, P2P `127.0.0.1:28656`, RPC `127.0.0.1:28657`
- `node4.toml` → node id `node4`, P2P `127.0.0.1:29656`, RPC `127.0.0.1:29657`

All four nodes bind the same loopback IP (`127.0.0.1`) and keep a deterministic `+1000` port spacing between neighboring peers. This preserves a single explicit bootstrap topology for local formation and operator rehearsal.

This fixture is local-only and rehearsal-scoped. Do not treat it as proof that public-mainnet bootstrap peer management, discovery, or sync closure is complete.

## Startup / join / rejoin model

1. Start `node1` first as the initial anchor.
2. Start `node2`, `node3`, and `node4` in slot order.
3. If `node1` is absent, do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise.
4. For a join or rejoin rehearsal, bring the node back with the same config file and the same `node_id`/listener tuple. Treat any drift from the shipped tuple as invalid until reviewed.
5. Treat `configs/node1.toml` through `configs/node4.toml` as slot-bound fixtures: do not rename them, swap them between peers, or reinterpret a later slot as the bootstrap anchor during operator recovery.
6. If a config contains unknown fields, whitespace drift, path-like ids, non-canonical socket literals, privileged ports, wildcard listeners, or mixed listener IP families, the config loader must fail closed.

## What this fixture is for

Use these files to keep peer/bootstrap topology assumptions explicit while the public-mainnet bootstrap peer-management path is still being hardened. The regression tests in `crates/trnm-node/src/config.rs` are the source of truth for the exact fixture invariants.
