# TRNM PoCO-BFT G1/G2 progress audit — 2026-08-27

This is a candidate-progress record, not a gate promotion or production
readiness certificate. It records the 4a0de0cd0 baseline plus the currently
uncommitted hardening slice, historical reproducible-build facts, the bounded
LAN transport smoke, and the remaining safety/ownership blockers.
`production_candidate`, `production_consensus_activation`, and all G3/G4
promotion bits remain false; a final clean-source replay is necessary but not
sufficient for any gate promotion.

## Authority and immutable evidence

- Canonical worktree: `/home/alex/projects/worktrees/trillionnium-chain/poco-mainline-20260825`
- Branch: `docs/chain-poco-bft-mainline-20260825`
- Baseline code commit: `4a0de0cd076c16081f009af302a79bbcdc9916c5`
- Baseline tree: `23c98ec9e08656596db4f5f31f4c80ec5939f5cd`
- Historical code-bound source candidate (its embedded plan/config/lock are a
  predecessor snapshot, not the final documentation authority):
  `/home/alex/.openclaw/workspace/artifacts/g3-final-4a0de0cd07-20260827T104254Z/source-candidate.tar`
- Source candidate SHA-256:
  `41b4d475812ef66a1a424bff43ed7b1be99c8e40bb2aca0226c439120b9d1260`
- Immutable evidence root (build/smoke files are added below):
  `/home/alex/.openclaw/workspace/artifacts/g3-final-4a0de0cd07-20260827T104254Z/`
- Source profile is `clean-commit-v1`; the source status digest is the empty
  Git-status digest `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The final plan manifest is bound only after a source-only hardening commit and
an ensuing documentation/configuration commit. The historical archive and
build/smoke facts below must not be read as evidence for that final tuple.

No remote push, system service, persistent listener, package installation, or
phone key/state deployment was performed.  The LAN smoke used a narrowly
scoped temporary firewall window; the exact rules were removed and the
post-removal state is recorded in
`firewall-rollback-verification.json`.

## Source seams and claims

| Seam | Commit(s) | Proven in this candidate | Explicitly not claimed |
| --- | --- | --- | --- |
| Core/SafetyRules authority and bounded effect driver | `7e66e66b0`, `b6488c083`, `a852dba5b` | Non-cloneable Core-owned Vote/Timeout authority, generation fencing, persist/readback before signing, checkpoint CAS and signed outbound binding | Production constructor, arbitrary execution, finality, pacemaker, recovery takeover |
| Real process and ordinary-D seam | `db6092166`, `32e00eefa`, `7cd53879b` | Feature-gated OS process; strict JSON/backpressure; synced Proposal application-seal → Core `Valid` → same-owner AuthorityVote; ordinary Proposal remains fail-closed | Native receipts for arbitrary payloads, production signer/watermark, finality or crash closure |
| Watermark and migration candidates | `75c969a48`, `5d3458e0e`, `4958bbf17`, `e4581a9c1` | Lower-watermark rejection, typed fresh-genesis boundary, offline target-JMT replay record/head with reopen/divergence checks | Coherent whole-namespace anti-rollback, trusted Comet reader/anchor, quorum handoff or cutover |
| Authenticated wire and payload replay | `f898f1adf`, `504e4aad0`, `2853cb481` | Independent nested signature corpus; hash-chain payload replay WAL with lease revalidation and namespace/session/generation/sequence binding | Persistent handshake anchor, atomic Core acknowledgement, production socket owner |
| Candidate socket/lease/Core ingress | `dc501c0bc` → `4a0de0cd0` + current hardening | Feature-gated one-shot Unix listener, authenticated `TRNH`/`TRNF`, conservative uncertainty responses, exact live-acquire retry, bounded deadlines, private identity checks, pending replay breadcrumb, durable replay admission and private Core ingress | Production listener, independent recovery owner, replay-to-Core atomicity, descriptor-anchored namespace |
| Shared deployment transport binding | `11c98ef52` | Live network/mesh constructors use one coordinator-manifest commitment; the binding regression passes. The six-host c04 smoke is predecessor evidence, not an exact final-source run | Peer MAC/cross-platform authentication, WAN/finality, G3 activation |
| Lease lifecycle/path hardening | `bce0cffaa`, `965163f6f`, `59f7177ce`, `e79fc2148`, `fefc9281e`, `c04bb76c4`, `4a0de0cd0` + current hardening | Absolute connect/daemon/client/frame budgets, Linux same-UID credentials, private roots/artifacts/ancestors, nonce-separated retained publication evidence, inode-aware socket lifecycle, pinned daemon stream/lease identity and explicit opt-in fence | Descriptor/openat namespace authority, MAC/non-Linux peer auth, crash recovery or production ownership |

The feature/package metadata still keeps production and activation flags false.

## Focused source checks

Checks were run serially in the Chain workspace to avoid Cargo-cache lock
contention:

```text
cargo fmt --all -- --check                                      # pass
cargo test --locked -p trnm-consensus-peer-lease --lib -- --test-threads=1
                                                               # predecessor count; final source must be rerun
cargo test --locked -p trnm-consensus-peer-lease --test cross_process -- --test-threads=1
                                                               # 2/2 pass
cargo test --locked -p trnm-consensus-peer-lease --test payload_replay_cross_process -- --test-threads=1
                                                               # 2/2 pass
cargo test --locked -p trnm-poco-lab-validator --test external_fenced_mesh -- --test-threads=1
                                                               # 3/3 pass
cargo test --locked -p trnm-poco-lab-validator --bin trnm-poco-lab-validator -- --test-threads=1
                                                               # 4/4 pass
cargo clippy --locked -p trnm-consensus-peer-lease --all-targets -- -D warnings
                                                               # pass
cargo test --locked -p trnm-poco-node --features g1-process-test-support --lib persistence_security_tests -- --test-threads=1
                                                               # predecessor count; final source must be rerun
cargo test --locked -p trnm-poco-node --features g1-process-test-support --test effect_driver_process_e2e -- --test-threads=1
                                                               # 7/7 pass
```

These counts are predecessor checks from the 4a/c04 source state; they are not
final-source evidence until rerun after the source-only hardening commit. The
changed peer-lease/poco paths are warning-clean. A whole-crate
`trnm-poco-lab-validator` `-D warnings` run still has a pre-existing backlog;
that backlog is retained as a release blocker and is not counted as a pass.
The full Core and broader feature matrices are not re-labelled as G1 exits by
this focused audit.

## Reproducible build and deployment facts

The c04 build report (`reproducible-build-report.json`) records two
independent byte-identical builds per architecture using the same locked
source:

| Target | Binary | SHA-256 | Bytes |
| --- | --- | --- | ---: |
| `x86_64-unknown-linux-gnu` | `trnm-poco-lab-validator` | `ba84f1e5b10408a7c90760c0e6e3f1b263ef76e64140b2b13e25e98afbe13fe2` | 16,256,400 |
| `x86_64-unknown-linux-gnu` | `trnm-poco-lab-material-builder` | `4d92614975d7282c1c385bb86c19df5fd9d46156e264df56485c63222e7af484` | 5,458,952 |
| `aarch64-apple-darwin` | `trnm-poco-lab-validator` | `e31522d061f656869bd35084d895a0f8bc7864e015d201df7897d4b57bd61a9e` | 12,177,728 |
| `aarch64-apple-darwin` | `trnm-poco-lab-material-builder` | `81662926e79f4f57d003476efabb808f53e430228659d7f86206f4d340b99f4f` | 4,035,056 |

Run material and the seven-validator deployment contract were prepared and
checked under `run-material-7-c04/` and `deployments-7-c04-fleet/`.  The
coordinator manifest commitment is
`168733a8bf8f9433a720ba48ee2bd2cc1da6feef19bd67a3d9011790434fb412`.
All role secrets remain absent from external deployment configs; material is
ephemeral and private-mode.

## LAN transport smoke (candidate evidence only)

The accepted bounded run is:

`/home/alex/.openclaw/workspace/artifacts/g3-final-c04bb76c4-20260827T083505Z/network-smoke-c04-run-fw/network-smoke-summary.json`

It used run ID `poco-g3-7-20260827T084500Z-c04bb76c`, source candidate
`a09090776a173ebc7a0a63f309fbda42409c85b529ddb5c8c05420817d3eb1a5`, Linux
binary `ba84f1e5b10408a7c90760c0e6e3f1b263ef76e64140b2b13e25e98afbe13fe2`,
macOS binary
`e31522d061f656869bd35084d895a0f8bc7864e015d201df7897d4b57bd61a9e`, and
coordinator commitment
`168733a8bf8f9433a720ba48ee2bd2cc1da6feef19bd67a3d9011790434fb412`.

The runner and independent macOS observer verified:

- `validator_count=7`, `signed_report_count=7`, and
  `observer_verified_report_count=7`;
- all six hosts participated (five Linux validator hosts plus the macOS
  observer), with `peer_session_count=12` in every validator report;
- fresh authenticated transport context, common topology/source/binary hashes,
  and signed report semantics; `cleanup_failures=[]`;
- the complete direct 21-pair mesh was observed by the seven reports.

This is transport-smoke evidence only.  The sealed summary deliberately says
`validator_run_completed=false`, `g3_lan_multihost_evidence=false`,
`fault_matrix_completed=false`, `performance_evidence=false`,
`geo_wan_evidence=false`, and `production_activation=false`.  It is not a
consensus/finality run and does not prove replay-to-Core atomicity.

The first c04 smoke without firewall changes failed closed at the local
`0/6` inbound timeout.  This diagnosed host filtering rather than a protocol
success; no result from that failed directory is counted.  For the accepted
rerun, only these temporary LAN-restricted TCP rules were added and then
deleted:

```text
local       31000:31001/tcp from 192.168.0.0/24
p4-x230     31002/tcp       from 192.168.0.0/24
p4-desktop  31003/tcp       from 192.168.0.0/24
p4-rog      31004:31005/tcp from 192.168.0.0/24
p4-j3160    31006/tcp       from 192.168.0.0/24
```

No default policy or SSH rule was changed.  The exact add/delete output,
before/after firewall captures, final reserved-listener checks, and their
hashes are in `/home/alex/.openclaw/workspace/artifacts/g3-final-c04bb76c4-20260827T083505Z/firewall-c04/` and
`/home/alex/.openclaw/workspace/artifacts/g3-final-c04bb76c4-20260827T083505Z/firewall-rollback-verification.json`; all tagged rules and reserved
listeners were absent after cleanup.  The macOS host was an observer and the
Android phone received only a public wire vector; no validator key, state, or
service was sent to it.

## Opt-in lease probe and explicit non-result

The c04 opt-in daemon probe used a short private parent because Unix
`sun_path` has a platform length limit.  The first long artifact path was
rejected explicitly with `peer-lease socket path exceeds Unix sun_path limit`.
The corrected probe created a mode-0600 socket, mode-0700 authority
directory, mode-0600 journal/head/lock, and then ran one validator with the
external lease socket.  The process exited at the bounded 25-second probe
timeout while waiting for the full 12-session mesh; no consensus report was
accepted and the temporary authority/socket was cleaned.  This is a useful
negative/timeout observation, not a validator-run result.

## Remaining blockers (not waived)

The residual review found the following release-blocking gaps:

1. The source slice now classifies post-commit response/write/release failures
   as `uncertain`, retries an exact live acquire once, and retains failed
   publication evidence. There is still no separately authenticated external
   status/recovery owner for an acquire/head response-loss cut; recovery remains
   an operator-owned, candidate-only action.
2. A prepared pending breadcrumb blocks a fresh owner until explicit
   acknowledgement, but replay admission is still durable before enqueue,
   drive, and Core acknowledgement. A crash or queue/Core failure can advance
   the durable head while Core never processed the input; the contract is
   deliberately “admitted, not Core committed”.
3. Parent-directory sync, owner-private mode/nlink checks, symlink/ancestor
   checks, nonce-separated retained temporaries, and descriptor/path identity
   rechecks are candidate-covered. A complete openat/dirfd-anchored namespace
   owner and coherent anti-rollback across all artifacts are not implemented.
4. Linux same-UID peer credentials and one absolute bounded client/daemon/frame
   budget are candidate-covered. Cryptographic MAC/attestation and equivalent
   peer authentication on non-Linux Unix remain absent; fixed TTL renewal and
   an atomic lease-plus-Core fence are not production claims.
5. Path collision/alias, minimum remaining TTL, stale-temporary, hardlink, and
   unknown-root-inventory negatives are being added to the final source sweep.
   Unix portability and adversarial namespace behavior remain unverified.
6. Coverage still lacks response-loss/crash-cut campaigns at every boundary,
   daemon restart/tamper/forged response, stale-socket/path-race, stalled-peer
   expiry, invalid signature/sequence/sender/body, and multi-frame/generation
   matrices. The lab-validator whole-crate `-D warnings` backlog remains open.

## Next executable order

1. Commit the source-only hardening slice, rerun its focused tests, and bind the
   exact source/tree/lock hashes in the manifest.
2. Add an authenticated external status/recovery owner and a descriptor/dirfd
   namespace owner; then run the missing crash/tamper/expiry/multi-frame tests.
3. Join replay admission to an explicit Core acknowledgement, or keep the
   admitted-not-Core-committed contract permanently candidate-only.
4. Only after those gates, bind the candidate to arbitrary ordinary execution,
   finality/pacemaker, signer/watermark ownership, and restart recovery.
5. Re-run the G1 crash/fault matrix and a full seven-validator consensus run;
   then evaluate G3/G4 evidence, WAN, performance, migration, and cutover.

None of these blockers is waived by LAN reachability, the phone observer, the
reproducible binaries, or the transport smoke.  Production flags stay false
until signed G1/G2/G3/G4 exits exist.
