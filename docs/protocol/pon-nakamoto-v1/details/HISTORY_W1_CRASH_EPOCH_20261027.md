# P1 standalone History W1 CPU crash fence

Status: **research-only draft / SHADOW_ONLY / HOLD_NO_GO**.

Base: Chain PR #493 at exact head
`1054ced294397c9729dee270aaa08c75eb033edd`.
This change is a child of the existing original-account W1/M06 Host
integration, not an independently enabled network protocol or rewrite
of the original V3 signed-domain/consensus rules.

## Reproduced design gap

The original Node-owned remote History account starts with zero credit
and bills each W1/M06 operation. In the parent candidate, the only
durable CPU epoch marker belonged to an ordinary public V3 **listener**,
not a standalone History **import**. If the latter exits/crashes while
CPU debt is unknown, a new process could reopen the same Node, find no
V3 active marker and obtain a new zero-credit epoch. Starting with
zero credit avoids the original warm two-second burst but does **not**
account for unresolved debt or prove safe crash reconciliation.

The existing `ordinary-public-v3-epoch-v1` durable metadata row can
fence both **without** creating a second credit/account authority.

## Source controls

- Node-private `begin_remote_history_cpu_epoch` starts the original
  ordinary-public-service SQLite active marker only when no other
  ordinary listener has already claimed this Node and the Node is not
  under its existing continuous owner. A History importer never steals
  V3's last-close ownership.
- `receive_page` first rejects bounded malformed top-level
  `Page` schema/number/size inputs. Only before the **first**
  metered decode/packet-ID/W1/M06 task does it durably arm the original
  marker. No proof body is replayed before the marker is established.
- The entire page's CPU-owned decoder, W1 verification, M06 and
  activation execute within that scope. All operations settle
  independently with the already existing scalar CPU account.
- On normal (including mathematically invalid) returns the import
  checks the original CPU account: zero in-flight, accounting
  available, nonnegative stored credit and a consistent native flow
  snapshot. Only then is the persistent marker cleared via
  `finish_ordinary_public_service_epoch(true)`.
- Negative CPU debt, unavailable native clock or unbalanced flow
  forces `finish_ordinary_public_service_epoch(false)`, retaining
  the persisted active row. A cold reopened Node refuses new History
  credit with `OWNER_PUBLIC_SERVICE_UNCLEAN_EPOCH`; it cannot
  create a different epoch by rotating keys, peer identity or ports.
- A valid block already committed just before a local CPU failure
  remains durably committed. Such a failure refuses sync *completion*
  but does not change mathematical W1 validity or fabricate a rollback.
- With an active ordinary V3 listener, the import shares V3's
  existing CPU domain and durable epoch; the importer may not clear
  that listener's marker. Continuous owner mode keeps its own
  original persistent operation-accounting contract.

### Negative and positive selectors added

- `ingress::tests::history_paid_epoch_crash_cut_refuses_new_cold_credit`:
  simulate a crash cut by dropping an open Node after its persistent
  History epoch begins; reopening must reject a new CPU account.
- `ingress::tests::malformed_paid_history_rejection_closes_known_epoch_without_poisoning_cold_reopen`:
  submit a cheap valid Page wrapper containing malformed packet
  bytes, force actual metered decoder rejection, and require clean
  settlement, absent epoch marker, identical State and the ability
  to reopen one cold zero-credit account.
- `ingress::tests::standalone_history_does_not_steal_live_v3_listener_epoch`:
  an existing V3 listener remains the only last-close owner.
- The original PR #493 late Product / Transcript / valid-work / M06
  and Host fault tests remain unchanged. The original security
  expectations are not weakened to make new source look qualified.

## Exact limitations / open P0–P6 gates

The synthetic `drop(node)` crash cut tests the persistent SQLite
active-marker semantics; it is **not a physical process kill or power
cut**. An actual abrupt kill inside a native W1/M06 interval,
atomic journal/fsync ordering, multi-process source identity, kernel
CPU samples and process restoration still need source- and binary-
pinned native experiments.

This mechanism conservatively blocks a History cold reopen after
an interrupted epoch; it does not reconstruct the exact unknown CPU
debt or provide a trusted proof of reclaim. Resolving held work and
explicit operator remediation requires its own controlled recovery
contract, not deletion of the durable marker or blind retry.

The shared `&mut Node` History importer also retains expensive
writer-lock/refill intervals. Honest read/submit fairness under
sustained hostile traffic and a real original A03 matrix
(3 hostile modes x 3 runs x 3/3 timely confirmations per run)
remain **OPEN**. Attacker GPU/ASIC admission cost, W1 mining hardness,
W2 sound/economical proof and independent third-party P6
cryptographic audit are also **OPEN**.

The original source still has no production consensus activation.
The current tool environment cannot execute the complete project
preflight, rustfmt/Cargo/Clippy or a physical cgroup campaign.
No pass or release qualification is inferred from commits or
unit-test source. Do not mark Ready, self-approve, bypass
branch protection or merge/activate automatically.
