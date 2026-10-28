# Independent hosted History V6 native readback

The original complete History V6 group passed on the independently built
release candidate `afc8d6dcb11168fa5d9799222c99dba2424dd520`, tree
`473a6ff2a297a635c9e72b245b3bba4e84900a21`. This is evidence for the frozen
publication and settled-epoch runtime, not the later uncommitted Startup
callback or material-seal implementation.

## Source and original execution

- [Draft PR 526](https://github.com/TrillionniumFoundation/Trillionnium-Chain/pull/526).
- [Workflow run 40615369561](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615369561),
  job `122576500317`, `history-native`, concluded `success` with every step successful.
- [Original artifact 12785735566](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40615369561/artifacts/12785735566).
  The exact downloaded ZIP is retained here as `artifact-12785735566.zip`:
  2,596,150 bytes, SHA-256
  `02022560d614dcee8343b1a7683a45942e50697a1e56c0decdda8f374f1b63cc`.
- `artifact-members.json` records all 1,196 members, every uncompressed size,
  compressed size, SHA-256 and mode stored by ZIP. The ZIP contains 34,103,194
  uncompressed bytes; only selected small members were also extracted. ZIP does
  not attest original inode, uid/gid or nanosecond timestamps.
- The full decoded GitHub job log is retained without whitespace normalization
  in `job-122576500317.log.gz`; `job-log-transport.json` pins compressed and
  decompressed hashes and lengths. The native log remains complete in the ZIP.
- The source checks before and after execution, and final workflow source check,
  agree exactly: all 5,228 tracked entries, 735,144,380 bytes, exact candidate and
  tree above. The runtime source is unchanged from the locally tested
  `8d7741028eb650f0600e61fcab46ff3d14b50767`; later commits added mandatory CI,
  evidence and transport splitting of the retained earlier binary gzip.

The workflow ran `cargo +1.95.0 test --release --locked -p trnm-pon-node --lib
--no-run` from that exact source. Cargo's original artifact row reports opt-level
3, debuginfo 0, debug assertions false and overflow checks false. Its executable
was `/home/runner/work/_temp/history-target/release/deps/trnm_pon_node-3c979170ab0a2d4d`,
SHA-256 `9855feed4ce0fb9f4142c16d43e3f2449140e8718b61cb48177f5a34b6064a6c`.
The executable bytes were not included in this workflow artifact; its identity
is supported by the original build artifact row, before/after binary digest,
native invocation and every process guardian digest. This readback does not
claim an independent hash of absent executable bytes.

## Complete suite and child boundaries

The raw `execution/native/native.log` ends with exactly one summary:

```
test result: ok. 15 passed; 0 failed; 1 ignored; 0 measured; 734 filtered out; finished in 315.14s
```

The owned invocation terminal records actual wait4 status 0 and 315.29021582
seconds including its enclosing command owner. All original 15 methods ran in
one invocation; none was assembled from multiple attempts. The sole ignored
method is `history_effect_v6_process_child_helper`, invoked separately with
exact fixture inputs by the mandatory process cases. Every expected method name
and the single terminal summary are independently checked by `readback.py`.

The original limits remained unchanged:

| Boundary | Observed requirement |
| --- | --- |
| Complete native group | 600 seconds |
| Volatile CPU burst | 2,000,000,000 ns |
| Signed operation allowance | 4,000,000,000 ns |
| Parent snapshot attempts | At most 4 |
| Matching complete snapshots | 2 |
| Registered worker limit | 2 |

All 23 guardian receipts have actual wait4 status 9, exact helper name and exact
release executable SHA. Fourteen kill a V6 operation and include a closed-process
receipt. Nine kill publication administration before any native operation or
new CPU epoch; these deliberately do not mint a V6 closed-process receipt. This
distinction is preserved in `readback.json`. The 14 completed process windows
each advance through their original recovery/restart flow, reject a duplicate
recovery, retain earlier records, and end with no pending operation or open
epoch. The archive reader also checks each retained journal filename hash,
sequence, previous hash and terminal cold anchor.

The final-synced publication window that exceeded the local debug build's CPU
burst succeeded here. Its two journal Startup settlements measured 66,621,288 ns
and 64,278,725 ns, respectively, with no worker CPU, no live refusal and available
accounting. These are observations on this release fixture, not a claimed
optimization or cross-machine speedup. The local opt-level-0 node build's
2,087,314,423 ns failure, failed snapshot windows and failed isolated retry stay
unchanged in the earlier complete failure evidence.

## Independent archive checks and limits

Run `python3 evidence/pon-history-hosted-afc8d6d-20261028/readback.py` to reproduce
the archive readback. It checks the original ZIP digest and all member hashes,
source identities, Cargo profile, complete roster/summary, unchanged original
limits, 23 guardian terminal receipts, 14 finished windows, 28 successful
Startup CPU receipts and every retained final journal chain. Its initial local
reader error is retained in `readback-initial-failure.json`: an overly uniform
schema assumption about publication administration was corrected without
changing the ZIP or any runtime result.

The command-owner wrapper proves the pinned leader's terminal state and its
final signal to the owned group. It does not certify arbitrary descendant
quiescence. The native guardians separately provide the existing bounded
thread-only fixture death observation, not historical arbitrary process-tree
coverage, machine power-loss durability or independent production attestation.
The disclosed fixture source identity is not a production build authority.

This result closes the previously missing successful complete original fixture
suite for this frozen runtime and host. It does not close remaining Startup or
Close pending-debt windows, partial-reorg continuation, exhausted lifetime
ceiling reauthorization, journal/store capacity qualification, general process
trees or production readiness. The new Startup callback/seal candidate has not
inherited this result and must pass its own exact-source native gate.
