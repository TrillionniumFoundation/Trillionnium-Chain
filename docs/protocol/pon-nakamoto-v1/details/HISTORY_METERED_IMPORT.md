# P1: exact owner CPU accounting on remote History imports

Status: **DRAFT / HOLD_NO_GO**, follow-up to Chain #342 at
`e55107450eb1a1f051a6c98101f3f88b7afa8f91`. Source only;
no production activation, W1 protocol, difficulty, chainwork, task authority,
V3 signed Cookie, profile or migration change.

## Reproduced source gap

Before this candidate, the source-bound `ingress::receive_page_from` verified
the administrator-provisioned fixed cgroup before/after each History page,
but its private parser delegated to `Node::admit` for every contained W1
packet **without the one original V3 `ServiceMutationCpuDomain`**.
A remote History page can include up to 16 packets, with up to 4096 pages
requested by a single client sync operation. Fixed Host CPU quotas prevent
unbounded physical consumption, but do not establish request-local work
ownership, known W1 CPU settlement or honest caller scheduling within that
Host. Canonical packet parsing and Page validation also occurred outside a
request-local mutation CPU reservation.

## Candidate source changes

1. `receive_page_from` still requires the original fixed Host cgroup for
   nonloopback sources. It now resolves the **same existing Node owner CPU
   domain**, not an identity-, peer- or request-supplied account. For a WAN
   source with no Node account, refuse `OWNER_PUBLIC_SERVICE_DOMAIN_UNBOUND`
   before any untrusted page parsing or full W1.
2. `receive_page_with_cpu` creates exactly one original paid CPU operation
   **before Page validation / packet hex decoding**. The operation covers
   the *whole page*: parent/context binding, every full W1, all registered
   M06 scoped workers, active-tip transition and native error tails. The
   original worker CPU debit is never added twice to the parent thread.
   Every relation error, decoded error and cancellation still settles
   known CPU; unknown accounting fences subsequent operations. Native
   durable effects already completed are never rewritten as invalid work.
3. The kernel source guard is still checked before and after the
   operation. A cgroup fault after durable admission is reported as an
   operational sync failure, not as an invalid mathematical certificate.
4. Ordinary remote `sync_from`, authenticated `sync_from_authenticated`,
   durable `sync_from_authenticated_durable` and CLI public-V3 `sync`
   bind the **same original cold Node CPU epoch once** on entering the
   operator-initiated sync, after proving actual Host membership. It
   starts at **zero CPU credit**, and waits at most two seconds for the
   unchanged 250 ms CPU/s refill to buy the original 100 ms start reserve.
   A fresh process cannot receive the earlier warm two-CPU-second burst.
   Already-bound V3/continuous owners are reused unchanged.
5. The local loopback-only development exception is explicit: an
   unbound local developer import may use its original unmetered parser,
   and cannot be cited as production/P1 independent admission safety.
   An untrusted loopback relay/tunnel or falsely declared source address
   remains a blocker for operator deployment; the source locator is not a
   cryptographically attested network origin.

The new `Node::prepare_remote_sync_cpu_domain` does not allow the remote
peer to select a Host parent or CPU budget. It refuses loopback invocation,
verifies the already-fixed root-owned Host parent and its calling-thread
membership, and creates a cold account only if that **same Node** has never
been bound. An existing domain is never replaced. `await_one_mutation_start`
can observe refill but grants no standalone authorization or new burst.
Per-page budget exhaustion is local `PUBLIC_MUTATION_CPU_BUDGET`, never
`WORK:...`, Chainwork, or a peer-invalid record.

## Regression contracts (source committed, execution not attested here)

- `ingress::tests::metered_history_rejects_false_product_and_keeps_same_ticket_valid`:
  a false C with a correct Header/trace/ticket causes late
  `WORK:Product`, no state/Chainwork change, settled original in-flight
  CPU zero; the correct proof under the same block identity still admits,
  activates and survives cold database reopen.
- `ingress::tests::history_cpu_reservation_exhaustion_is_local_busy_not_invalid_work`:
  both original CPU worker slots are actually reserved; a subsequent
  otherwise valid History page returns local
  `PUBLIC_MUTATION_CPU_BUDGET`, not mathematical invalidity, and stores
  no block.
- `scalar_cpu::cold_sync_replay_tests::remote_sync_begins_at_zero_then_uses_only_original_refill`:
  actual zero-credit starting observation, bounded refill, one reservation,
  shared clone and full settlement without another credited burst.
- Existing `ingress::tests::remote_sync_without_original_host_cgroup_rejects_before_any_network_or_w1`
  retains its original three source-bound refusal semantics.

## Remaining blockers

This is a **source implementation**, not an evidence-qualified physical
service. The current work container cannot access this repository as a
complete checkout, Rust compiler or administrator-provisioned physical
host. Exact-source preflight, rustfmt/cargo tests, actual process CPU
measurements including workers, authenticated WAN and loopback proxy
adversaries, multi-process cgroup/clock/restart readbacks, cancellation
and full 3-mode × 3-run × 3/3 A03 honest service remain open.
The per-process cold account is volatile; an unclean process restart
does not by itself restore operation debt. Host cgroup quotas remain
the physical ceiling, not durable accounting.

Beyond P1, V3 Cookie CPU/GPU/ASIC economics (P2), paid/unpaid and
wrong-StateRoot identity-churn campaigns (P3), original A03 campaign
(P4), actually sound and cost-qualified W2 (P5), and independent
cryptography/operational signoff (P6) are **not closed** by this code.


## Final intake boundary refinement: raw / decoded value imports

The first candidate wrapped only the already-deserialized `Page`. This did
not charge the original resource account for JSON-to-Page conversion. The new
source uses one common private `receive_page_from_decoder` that verifies the
same Host parent, acquires the **original Node CPU operation before invoking
its JSON decoder**, executes the private `receive_page_with_operation`,
settles actual thread/scoped-worker CPU even for early parsing failures,
and rechecks Host membership after any native side effect.

The supported source-bound export forms are:

| Entry | Interpretation | Original resource reservation |
| --- | --- | --- |
| `receive_page_wire_from(node,source,raw,...)` | bounded raw frame into typed History Page | Before `serde_json::from_slice`, canonical byte decode, W1/M06 |
| `receive_page_value_from(node,source,value,...)` | decoded client JSON `Value` into Page | Before `serde_json::from_value`, canonical packet decode, W1/M06 |
| `receive_page_from(node,source,page,...)` | already typed Page, retained library compatibility | Before all native canonical packet decode, W1/M06 |
| private `receive_page_with_operation` | exact local parser / execution owner | Not externally callable; no unguarded public Work path |

Ordinary native `sync_from` uses the raw-frame method; authenticated and
durable authenticated variants, and CLI V3 public History, call the decoded
value method rather than performing typed conversion outside the original CPU
reservation. All four derive `complete` from the independently validated
cursor equality `after == tip`, not an untrusted remote boolean. Structural
parser errors are local input rejection, not Chainwork or VerifiedWork.

`ingress::tests::raw_and_value_history_parsers_reserve_cpu_before_json_decode`
holds both original mutation worker reservations and submits intentionally
malformed raw JSON and malformed `Value`. The required result is the
**original local CPU Busy** before typed parsing. After releasing the
reservations, the same malformed inputs must fail their real parsers,
settle full CPU, and leave active and stored State unchanged.

This strengthens **JSON-to-Page conversion ownership only**. Upstream network
buffer allocation, authenticated response verification, outer JSON-to-Value
conversion and HTTP/socket per-frame handling retain their independent
existing bounded transport owners; they do not become free CPU or proven
Sybil-fair by the existence of this wrapper. Public-V3 source authenticity
still depends on its actual signed Cookie/transport and operator origin
policy; a local proxy could falsely present remote bytes as loopback.
The P1 public readiness verdict remains OPEN until the complete physical
intake ledger and honest-service campaign reconcile these boundaries.
