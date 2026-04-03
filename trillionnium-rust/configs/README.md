# TRNM shipped bootstrap topology

This directory ships a deterministic four-node local bootstrap fixture for peer-formation and join/rejoin rehearsals.

## Day-1 bootstrap topology

The shipped topology is intentionally small and fail-closed:

- `node1.toml` → node id `node1`, P2P `127.0.0.1:26656`, RPC `127.0.0.1:26657`
- `node2.toml` → node id `node2`, P2P `127.0.0.1:27656`, RPC `127.0.0.1:27657`
- `node3.toml` → node id `node3`, P2P `127.0.0.1:28656`, RPC `127.0.0.1:28657`
- `node4.toml` → node id `node4`, P2P `127.0.0.1:29656`, RPC `127.0.0.1:29657`

All four nodes bind the same loopback IP (`127.0.0.1`), keep RPC exactly one port above the matching P2P listener for each slot, and keep a deterministic `+1000` port spacing between neighboring peers. This preserves a single explicit bootstrap topology for local formation and operator rehearsal.

This fixture is local-only and rehearsal-scoped. Do not treat it as proof that public-mainnet bootstrap peer management, discovery, or sync closure is complete.

## Startup / join / rejoin model

1. Start `node1` first as the initial anchor.
2. Start `node2`, `node3`, and `node4` in slot order.
3. If `node1` is absent, do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise.
4. For a join or rejoin rehearsal, bring the node back with the same config file and the same `node_id`/listener tuple. Treat any drift from the shipped tuple as invalid until reviewed.
5. Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.
6. Treat `configs/node1.toml` through `configs/node4.toml` as slot-bound fixtures: do not rename them, swap them between peers, or reinterpret a later slot as the bootstrap anchor during operator recovery.
7. If a config contains unknown fields, whitespace drift, host-like or path-like ids, URI-like delimiters, non-canonical socket literals, privileged ports, wildcard listeners, reserved documentation/benchmarking listener ranges, or mixed listener IP families, the config loader must fail closed.

## Join / rejoin acceptance table

| Scenario | Expected operator action | Acceptance |
| --- | --- | --- |
| Fresh bootstrap start | Start `node1` first, then `node2` → `node3` → `node4` in slot order | Accept only when each node keeps its shipped slot-bound config and listener tuple |
| Follower join while `node1` is healthy | Start the joining follower with its original config file (`node2.toml`, `node3.toml`, or `node4.toml`) | Accept only when `node_id`, `rpc_addr`, and `p2p_addr` exactly match the shipped tuple |
| Follower rejoin after restart | Bring the same follower back with the same filename and the same tuple | Accept only when the rejoining node does not drift slots, IDs, or listener addresses |
| Anchor rejoin after restart | Bring `node1` back only with `node1.toml`; resume follower startup/rejoin only after the shipped anchor tuple is restored | Accept only when `node1` regains the shipped anchor tuple before later slots continue |
| `node1` missing during recovery | Restore `node1` first; do not promote a later slot into the anchor role | Reject until the shipped `node1` anchor tuple is back in place |
| `node2` missing during startup or rejoin | Keep `node3` and `node4` stopped until `node2` returns with `node2.toml` and its shipped tuple | Reject while a later follower tries to skip the missing `node2` slot |
| `node3` missing during startup or rejoin | Keep `node4` stopped until `node3` returns with `node3.toml` and its shipped tuple | Reject while `node4` tries to skip the missing `node3` slot |
| Any tuple drift or config mutation | Stop and review before startup | Reject on renamed files, swapped slots, unknown fields, whitespace drift, non-canonical socket literals, or listener-family drift |

This table is intentionally local-fixture scoped: it documents the minimum fail-closed acceptance rule for shipped bootstrap rehearsal, not a claim that public-mainnet peer discovery, sync, or dynamic topology management is complete.

## What this fixture is for

Use these files to keep peer/bootstrap topology assumptions explicit while the public-mainnet bootstrap peer-management path is still being hardened. The regression tests in `crates/trnm-node/src/config.rs` are the source of truth for the exact fixture invariants.
