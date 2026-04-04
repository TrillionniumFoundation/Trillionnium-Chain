# TRNM shipped bootstrap topology

This directory ships a deterministic four-node local bootstrap fixture for peer-formation and join/rejoin rehearsals.

## Day-1 bootstrap topology

The shipped topology is intentionally small and fail-closed:

- `node1.toml` → node id `node1`, P2P `127.0.0.1:26656`, RPC `127.0.0.1:26657`
- `node2.toml` → node id `node2`, P2P `127.0.0.1:27656`, RPC `127.0.0.1:27657`
- `node3.toml` → node id `node3`, P2P `127.0.0.1:28656`, RPC `127.0.0.1:28657`
- `node4.toml` → node id `node4`, P2P `127.0.0.1:29656`, RPC `127.0.0.1:29657`

All four nodes bind the same loopback IP (`127.0.0.1`), keep RPC exactly one port above the matching P2P listener for each slot, and keep a deterministic `+1000` port spacing between neighboring peers. This preserves a single explicit bootstrap topology for local formation and operator rehearsal.

`node1` is the unique shipped bootstrap anchor because it alone owns the lowest shipped P2P port (`127.0.0.1:26656`); later slots must never reuse that listener or identity.
`node1` also owns the lowest shipped RPC port (`127.0.0.1:26657`); later slots must never drift downward into an equivalent anchor-shaped RPC tuple during startup, join, or rejoin.

This fixture is local-only and rehearsal-scoped. Do not treat it as proof that public-mainnet bootstrap peer management, discovery, or sync closure is complete.

## Startup / join / rejoin model

1. Start `node1` first as the initial anchor.
2. Start `node2`, `node3`, and `node4` in slot order.
3. If `node1` is absent, do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise.
4. For a join or rejoin rehearsal, bring the node back with the same config file and the same `node_id`/listener tuple. Treat any drift from the shipped tuple as invalid until reviewed.
5. Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.
6. Treat `configs/node1.toml` through `configs/node4.toml` as slot-bound fixtures: do not rename them, swap them between peers, or reinterpret a later slot as the bootstrap anchor during operator recovery.
7. If `node4` is absent, keep `node1` through `node3` in their shipped slots; do not rename another config into the `node4` role, and if `node4` returns it must come back with `node4.toml` and its shipped tuple.
8. If a config contains unknown fields, whitespace drift, host-like or path-like ids, URI-like delimiters, non-canonical socket literals, privileged ports, wildcard listeners, reserved documentation/benchmarking listener ranges, or mixed listener IP families, the config loader must fail closed.
9. If startup fails because a shipped config introduces an ad-hoc peer/bootstrap alias such as `bootstrap_nodes`, `seedPeers`, or `persistentNode`, treat the exact field named in the parse error as the operator fix target; do not guess or silently translate aliases.
10. When `load_config` fails, use both the operator-supplied config path and the resolved canonical path printed in the error to identify which shipped slot drifted; do not “fix” a different file that merely looks similar.
11. Do not substitute IPv6 loopback `[::1]` for the shipped IPv4 loopback `127.0.0.1` during bootstrap or rejoin; listener-family drift is invalid even if both addresses are loopback.

## Join / rejoin acceptance table

| Scenario | Expected operator action | Acceptance |
| --- | --- | --- |
| Fresh bootstrap start | Start `node1` first, then `node2` → `node3` → `node4` in slot order | Accept only when each node keeps its shipped slot-bound config and listener tuple |
| Follower join while `node1` is healthy | Start the joining follower with its original config file (`node2.toml`, `node3.toml`, or `node4.toml`) | Accept only when `node_id`, `rpc_addr`, and `p2p_addr` exactly match the shipped tuple |
| Follower rejoin after restart | Bring the same follower back with the same filename and the same tuple | Accept only when the rejoining node does not drift slots, IDs, or listener addresses |
| Anchor rejoin after restart | Bring `node1` back only with `node1.toml`; resume follower startup/rejoin only after the shipped anchor tuple is restored | Accept only when `node1` regains the shipped anchor tuple before later slots continue |
| `node1` missing during startup or recovery | Restore `node1` first; do not promote a later slot into the anchor role | Reject until the shipped `node1` anchor tuple is back in place |
| `node2` missing during startup or rejoin | Keep `node3` and `node4` stopped until `node2` returns with `node2.toml` and its shipped tuple | Reject while a later follower tries to skip the missing `node2` slot |
| `node3` missing during startup or rejoin | Keep `node4` stopped until `node3` returns with `node3.toml` and its shipped tuple | Reject while `node4` tries to skip the missing `node3` slot |
| `node4` missing during startup or rejoin | Keep `node1` through `node3` in their shipped slots; if `node4` returns, bring it back only with `node4.toml` and its shipped tuple | Accept the remaining slots only while no other config is renamed or promoted into the `node4` role |
| Any tuple drift or config mutation | Stop and review before startup | Reject on renamed files, swapped slots, unknown fields, whitespace drift, non-canonical socket literals, port-spacing drift, or listener-family drift |

This table is intentionally local-fixture scoped: it documents the minimum fail-closed acceptance rule for shipped bootstrap rehearsal, not a claim that public-mainnet peer discovery, sync, or dynamic topology management is complete.

## What this fixture is for

Use these files to keep peer/bootstrap topology assumptions explicit while the public-mainnet bootstrap peer-management path is still being hardened. When logging startup/join/rejoin incidents, prefer the exact repo-root paths `trillionnium-rust/configs/node1.toml`, `trillionnium-rust/configs/node2.toml`, `trillionnium-rust/configs/node3.toml`, and `trillionnium-rust/configs/node4.toml` as the unambiguous slot references; `configs/nodeN.toml` and `./configs/nodeN.toml` should canonicalize to the same shipped files, but incident notes should name the repo-root path first. Triage them in shipped slot order: `trillionnium-rust/configs/node1.toml` is the anchor, `trillionnium-rust/configs/node2.toml` is follower slot 2, `trillionnium-rust/configs/node3.toml` is follower slot 3, and `trillionnium-rust/configs/node4.toml` is follower slot 4; do not relabel a later file as an earlier slot when diagnosing bootstrap failures. Do not add ad-hoc `bootstrap_nodes`, `bootstrap_node`, `bootstrap_peers`, `bootstrap_peer`, `bootstrapNodes`, `bootstrapNode`, `bootstrapPeers`, `bootstrapPeer`, `bootstrap_addr`, `bootstrap_addrs`, `bootstrapAddr`, `bootstrapAddrs`, `seed_nodes`, `seed_node`, `seed_peers`, `seed_peer`, `seedNodes`, `seedNode`, `seedPeers`, `seedPeer`, `seed_addr`, `seed_addrs`, `seedAddr`, `seedAddrs`, `seeds`, `bootnodes`, `bootnode`, `bootNodes`, `bootNode`, `boot_peers`, `boot_peer`, `boot_addr`, `boot_addrs`, `bootAddr`, `bootAddrs`, `bootPeers`, `bootPeer`, `persistent_peers`, `persistent_peer`, `persistent_addr`, `persistent_addrs`, `persistentAddr`, `persistentAddrs`, `persistentPeers`, `persistentPeer`, `persistent_nodes`, `persistent_node`, `persistentNodes`, or `persistentNode` fields to these shipped fixtures; the local rehearsal schema stays the minimal three-field contract until a real peer-management surface exists. Do not add extra shipped topology files such as `node5.toml`, alternate slot aliases, or helper sidecar configs under `configs/`; the deterministic local bootstrap fixture remains exactly `README.md` plus `node1.toml` through `node4.toml` until a separate peer-management surface is introduced. The regression tests in `crates/trnm-node/src/config.rs` are the source of truth for the exact fixture invariants.
