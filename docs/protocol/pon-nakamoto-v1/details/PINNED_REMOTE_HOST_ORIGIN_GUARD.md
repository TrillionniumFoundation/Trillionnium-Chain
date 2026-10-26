# P1: pin the actual physical Host owner for remote pinned-peer W1 traffic

Status: DRAFT / HOLD_NO_GO. Parent is Chain PR #340 at exact commit
`563a8c982106dc38880f4a8cbaf37f4f89fa9cb4`. This is a source
mitigation, NOT a physical experiment, independent acceptance or activation.

## The security failure

A V3 development service can listen only on `127.0.0.1` while its same
process polls **nonloopback** signed pinned peers for arbitrary History
packets. In the original service CLI the administrator cgroup guard was
selected by the LISTENER bind address only. Thus a local-loopback service
with a WAN polling peer could skip the original fixed physical cgroup,
despite polling full untrusted W1 proofs through the original shared V3
software CPU meter (after PR #340). A software token bucket is not a
host-wide kernel cap, especially with multiple processes or namespaces.

## Additive safeguards

- `main.rs::public_host_resource_address` selects an actual configured
  nonloopback pinned Peer as the resource-scope address when the listener
  is loopback. The already pinned `host_public_guard::require_host_kernel_budget`
  then requires the original administrator-owned
  `/sys/fs/cgroup/trnmponpublic.slice` with finite, authenticated CPU,
  memory, swap and PID caps. No new cgroup, process token, identity budget,
  trust root, history checkpoint or consensus rule is introduced.
- Exported `run_pinned_peer_polling` enforces the **same condition itself**,
  preventing library callers from bypassing CLI policy. Its fixed source
  permits one immutable Host kernel budget handle for all nonloopback peers,
  captured before any public RPC/History request, retaining the original
  cgroup identity and limits. Distinct trusted signers are not resources.
- The actual pinned poller thread checks this original handle at each cycle,
  immediately before W1 admission and after complete W1/M06 CPU settlement.
  The branch-activation path checks it again before and after selecting
  the native accumulated-work branch. A post-commit Host failure makes the
  synchronization report fail; it does not fabricate a rollback.
- Loopback-only fixed peer tests remain local development cases. Unit
  controls test loopback listener + remote IPv4/IPv6 selection and a remote
  pinned peer whose kernel host checker must never return `Ok(None)`.

## Remaining original safety obligations

This condition closes a **source-level route check**, not PN1 or
permissionless/public readiness:

1. Remote peers can be proxied into loopback through a host-local relay.
   A network address cannot establish the *actual upstream origin*. Such
   deployments must use the root-controlled Host budget regardless of the
   immediate socket peer and record the relay topology and cgroup placement.
2. Signed pinning does not rate-limit malicious full W1 rejects, valid-work
   invalid StateRoots or Sybil churn. The original shared mutation CPU domain
   is finite but does not mathematically guarantee honest-client fair access.
3. The existing public untrusted History sync and legacy authenticated
   submission paths are separate entrypoints (Chain PR #342). Full P1
   acceptance needs host-wide caller graph, actual physical cgroup
   before/after samples, clean/crash restart, cancellation and bounded
   adversarial concurrent workloads.
4. The new Rust source was committed via GitHub API without an executable
   checkout in this tool session: the repository preflight, compiler,
   formatting, native tests and real host readback **were not run**.
   Do not claim source qualification or merge/production readiness.
5. P0 actual source-pinned four-forgery native replay, P2 CPU/GPU Hashcash
   economics, P3 mixed adversarial workloads, P4 A03 3 modes × 3 runs ×
   3/3 timely confirmations, P5 qualified complete low-cost W2 cryptographic
   work and P6 external independent review all remain OPEN.

All W1 byte grammar, Target, VerifiedWork, chainwork, genesis state,
runtime final-use and application policy remain unchanged. Status remains
SHADOW_ONLY / HOLD_NO_GO.
