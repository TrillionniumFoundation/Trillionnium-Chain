# P1: outbound pinned remote peers require original host cgroup

**Candidate source remediation only.** Parent: Chain PR #340
'7ed523093e89bd50ce85775ca023028fdc3a58c7'.
No work grammar, PoN difficulty, reward, public V3 Cookie, Node
authority, model final-use or production flag changed.

## Specific residual bypass

PR #340 made each peer-sourced W1 history packet debit the same original
per-Node V3 'ServiceMutationCpuDomain', including real scoped execution,
late false proof and resource-unknown outcomes. But the V3 library only
requires the fixed administrator cgroup for a **nonloopback listener**.
A service that binds solely to 127.0.0.1 may actively connect to a
pinned **external** peer. The remote peer is signature authenticated,
not necessarily honest or CPU-funding. Distinct service processes can
each have finite local paid buckets while sharing no physical CPU ceiling.
Therefore CPU accounting by identity/Node alone does not close P1.

## Native change

'peer_polling.rs' now runs 'original_remote_host_owner(config)' immediately
after verifying the finite peer roster and **before any outbound RPC or
complete remote W1**.

- If every selected peer address is loopback, retain the existing explicitly
  local development behavior and original Node CPU domain.
- If **any** selected pinned peer address is nonloopback, require the
  **one existing root-provisioned** 'trnmponpublic.slice' cgroup via
  'host_kernel_parent::require_for_listener'. Empty or unavailable owner
  fails closed. This is not a new CPU bucket, per-peer entitlement or
  proof-validity rule.
- The actual poller calling thread checks original kernel cgroup identity,
  boot ID, CPU, memory and PID limits before/after each authenticated RPC,
  after a whole peer cycle, before/after complete history admission and at
  bounded W1 replay checkpoints. Within transcript tiles it checks only
  the first (column=0, inner=0) tile in each row group; checking all 512
  would itself increase per-proof verifier CPU and invite a cost DoS.
- Post-admission host-budget failure is an operational sync failure.
  Already durable validated blocks are not retroactively invalidated,
  refunded or rolled back. Original V3 mutation CPU still fully settles.
- An additional native test verifies loopback-only configuration selects no
  kernel requirement, whereas the exact nonloopback documentation-address
  configuration never proceeds without a verified physical kernel owner.
  On preprovisioned hosts that owner must verify successfully; on ordinary
  developer hosts it must fail before remote packet acquisition.

## Unclosed conditions

Physical test evidence is still required on target Linux hosts with a
real root-owned cgroup: at least two simultaneous V3 Node instances with
loopback listeners, malicious signed external pinned peers, sustained
64/256/1024/4096-cell equivalents and real CPU/memory/pid readback.
Also rehearse cgroup quota changes and loss during a full W1 replay and
after durable admission. Current source-only check cannot demonstrate
an in-flight thread move, actual host hardware cap or fair scheduling.

Loopback-relayed remote content remains an explicit trust/deployment
ambiguity: a malicious proxy could make an external service appear
loopback-only. Preventing that requires trusted remote-origin provenance
or enforcing the original kernel owner on every externally influenced
transport, including relays; this patch cannot infer original origin
from an endpoint address.

This patch intentionally does **not** claim a host CPU fairness theorem:
an attacker can still buy a new valid client/peer ticket more cheaply
than the server rejects an invalid W1 transcript. CPU/GPU/ASIC price
(P2), actual mixed-state/identity attacks (P3), A03 3×3×3 (P4),
cryptographically sound and economical W2 (P5) and independent
external review (P6) remain **OPEN**.

Status: SHADOW_ONLY / HOLD_NO_GO.
