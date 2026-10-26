# P1: Outbound pinned-peer WAN polling requires the original physical CPU parent

Status: **candidate source mitigation, not production qualification**. Frozen
parent: `563a8c982106dc38880f4a8cbaf37f4f89fa9cb4` (Chain PR #340).
This changes neither the W1 49,188-byte proof, consensus ticket, target,
chainwork, signed V3 Cookie, exact peer protocol, nor Node adoption authority.

## Demonstrated gap in PR #340's source

The earlier `peer_polling.rs::admit_page` patch correctly debits the existing
`Node::public_service_cpu_domain()` for full verification plus M06. However,
the CLI's `serve` command enforces the fixed physical cgroup only when the
*local listener* is nonloopback. A service can listen on `127.0.0.1` and
simultaneously poll a remotely hosted, operator-pinned peer. Even a signed
remote peer can return ticket-valid false transcript data, and such an
outbound polling worker still had no mandatory physical Host parent check.
A volatile shared CPU token bucket alone is not cross-process/kernel
resource containment.

## Candidate correction

- Before first peer RPC, examine the full frozen peer configuration. **If any
  peer address is nonloopback**, require the existing
  `host_kernel_parent::require_for_listener(peer.address)`. The same
  root-owned `/sys/fs/cgroup/trnmponpublic.slice` physical parent as V3 must
  contain the *actual calling poller thread*, independent of what local
  address the V3 listener uses. The checker never creates a cgroup.
- Carry that exact `HostKernelBudget` identity through `PollContext` for
  the entire polling run. Re-verify the unchanged kernel parent before/after
  each engine cycle, before peer requests, and before/after each imported
  W1/M06 packet. A transient kernel check failure cannot be reported as
  completed and qualified sync. Native committed blocks are never rolled
  back as a workaround for postcommit resource faults.
- Keep the **same** original Node's `public_service_cpu_domain()` and
  existing `ServiceMutationCpuOperation` from #340; do not start a separate
  per-peer allowance, listener, Node, ledger or cryptographic authority.
  Loopback-only local development peers still use the existing local
  development policy.
- The native negative test
  `peer_polling::tests::wan_pinned_peer_cannot_bypass_fixed_host_parent_using_loopback_listener`
  uses a reserved nonloopback address and covers both an all-remote and
  a mixed loopback/WAN pinned roster. Without the approved parent, both
  must fail **before networking or complete W1**, preserve Node state
  and propagate the original typed kernel error.

## Explicit limits

- The test source and security guards require Rust build, fixed-host
  readbacks and physical hostile-peering runs on the exact committed SHA.
  Static source changes do **not** close P1 in production.
- A loopback TCP proxy to a remote attacker cannot be distinguished by
  address alone. Deployments must bind actual relay topology and host trust
  assumptions; no arbitrary forwarded loopback endpoint is qualified.
- Parent verification bounds *aggregate physical* CPU/memory/PIDs; it
  cannot guarantee all honest requests meet latency deadlines or that
  the attacker paid equal economic cost. P2 genuine GPU/hardware pricing,
  P3 mixed attack and high-cost valid-W1 wrong-StateRoot, P4 A03 full
  original campaign, P5 cryptographically secure and efficient W2,
  and P6 independent cryptanalyst validation all remain OPEN.
- Root/host admin can change placement or kernel enforcement outside this
  user-mode project. The unchanged kernel checker detects fixed parent
  mutation/membership across its checkpoints, but this is not a guarantee
  against a malicious root administrator.

Source remains DRAFT / SHADOW_ONLY / HOLD_NO_GO; no production activation.
