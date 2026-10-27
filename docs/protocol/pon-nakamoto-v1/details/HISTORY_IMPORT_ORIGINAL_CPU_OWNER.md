# P1 history-page W1: original Node CPU owner, not only a Host quota

Status: DRAFT / HOLD_NO_GO. Parent of this branch is Chain #342
'e55107450eb1a1f051a6c98101f3f88b7afa8f91'. This does **not**
change W1 canonical proof, target, transcript, BlockId, Chainwork,
genesis, signed Cookie or the native consensus profile.

## Why the previous P1 fix was not complete

The existing 'ingress::receive_page_from' enforces the administrator's
fixed `trnmponpublic.slice` cgroup for nonloopback destinations.
However its module-private page loader still called 'Node::admit' for
up to 16 remotely sourced 49,188-byte PNW1 proofs per page, possibly
4096 pages per Sync, without each attempt being paid from the Node's
original `ServiceMutationCpuDomain`. An aggregate cgroup CPU quota is
not the original local admission credit, cancellation or fairness
proof. Even a signed remote peer can submit expensive bad transcripts.

## Added original CPU-domain ownership

1. The existing 'Node::remote_history_cpu_domain' returns the exact
   original V3/continuous Node budget when already bound. It rejects
   an unclean public-service CPU epoch, even if a bound handle remains.
   A standalone import owner binds ONE original zero-credit domain
   in its Node for its entire lifetime. This is not a new entitlement
   per requester, page, peer key, trace or retry. A standalone import's
   credit refills using the original 0.25 CPU-sec/sec equation.
2. For EACH remotely supplied packet, `receive_page` now starts a
   `ServiceMutationCpuOperation` with the original 100ms reservation.
   The original task/parent checks, full W1 replay and M06 native
   execution share one CPU operation. W1 uses its production
   `verify_with_progress` and original per-noise/row/tile/product
   checkpoints; all real scoped M06 workers charge the same domain.
3. After fixed-size Page shape checks, canonical hex/packet decoding,
   packet-ID calculation and contiguous-parent checking receive a
   **separate** CPU operation before any full W1. This avoids an
   unmetered decoder batch and avoids double charging nested W1 CPU.
   A malformed packet is still rejected without Native acceptance.
4. Success, false Product/Transcript, cancellation and expensive
   state failures each settle the original CPU account exactly once.
   A known start refusal may wait at most two seconds for the ORIGINAL
   refill; no credit is minted. An unknown CPU clock fails closed and
   the existing owner is marked unavailable. If a block was already
   committed before an unknown settlement, no false rollback or
   automatic replay authority is created.
5. Page-complete native activation, including possible chain switching,
   gets its own original CPU reservation. This is a worker-thread
   metering interval, NOT guaranteed preemption inside every deep
   SQLite/state/root primitive.
6. The existing exact canonical page, parent, task, target and BlockId
   checks remain mandatory; a locally full queue or exhausted CPU
   returns a local capacity error and does NOT mark a possibly valid
   historical packet as consensus-invalid.

## Native negative and positive tests (pending execution on exact source)

- `ingress::tests::loopback_history_false_product_charges_one_cold_node_cpu_domain`:
  use an honest winning ticket with only C corrupted, require
  `WORK:Product` and unchanged live/cold Node State, zero in-flight
  settled CPU and the SAME Node account on retry.
- `ingress::tests::loopback_history_valid_work_still_accepts_under_cold_cpu_meter`:
  original valid W1 and native Page must still be admitted and activated
  under the cold-start metered import.
- `ingress::tests::mixed_false_then_valid_history_across_source_ports_reuses_one_cpu_owner`:
  invalid C from loopback port A is rejected, the exact corresponding
  valid statement from port B still commits under the identical Node CPU
  domain, then an incompatible duplicate C cannot replace it.
- `ingress::tests::unclean_public_epoch_cannot_mint_fresh_remote_history_credit`:
  reject a new entitlement after the original public epoch is marked
  unclean.


- `ingress::tests::malformed_remote_history_decode_pays_original_cpu_and_preserves_state`:
  malformed packet decoding also returns an error, with no live CPU
  reservation after return, no accounting-unknown event and no state
  mutation. Its initial ordinary Page shape checks remain bounded and
  outside this decoder interval.

The earlier #342 remote no-cgroup negative still runs *before*
creating or debiting any Node CPU account. The new code is an
unqualified source candidate until its native compiler and original
project-preflight checks are available.

## Read-only regression for future merge safety

`python3 scripts/ci/test_remote_history_cpu_owner.py -v` is wired to
the existing repository-truth lane. Its in-memory negative mutations
reject restoration of `node.admit` as an unchecked History parser,
per-request warm `standalone()` CPU credits, or any use of a
nonzero cold-import startup burst. Its checks are **source assertions
only** and do not substitute for `cargo test`, the actual Host cgroup
budget, an independent oracle or security qualification.

## Remaining blockers (must not silently close P0–P6)

- Host `trnmponpublic.slice` quotas must be physically checked across
  inbound V3, sync CLI, automatic peer polling, process restarts and
  third-party/loopback forwarding. A loopback proxy remains outside
  origin detection; a root/administrator who clones running services
  must be considered separately.
- Original CPU credit starts at zero for a standalone Node, which
  changes initial legitimate Sync readiness. Measure actual throughput,
  honest catch-up times and failure/retry dynamics on real machines.
  Refill is not a guarantee that every valid page will meet its caller
  deadline, especially under competing false work.
- A request that obtains expensive genuine W1 but fails StateRoot is a
  separate M06 abuse mode. Native HTTP/TCP congestion, unsigned peer
  churn, GPU/ASIC hash advantages and source-independent quotas remain.
- The original A03 run matrix requires three attack modes, each with
  three independent trials and **3/3 timely real confirmations per run**.
  The revised exact Rust code and physical Host tests have not been
  executed here; old test receipts do not certify this new source.
- W2-A sampling is unsound without a full binding proof. W2-B is a
  full-replay witness rather than a succinct sound proof. W2-C has
  remaining attacker/receiver cost amplification even with per-receiver
  tickets. Security hardness, real compute usefulness, and independent
  third-party cryptanalysis remain unqualified.
- No CI queue result, stub, in-memory unit test, speculative SHA,
  branch merge or documentation gate alone enables production.

Do not merge to protected main, change the signed protocol
unreviewed or activate the public PoN network.
