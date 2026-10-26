# P1 History import: same original Host kernel and Node CPU epoch

**Development candidate.** Parent: Chain #342 head
'e55107450eb1a1f051a6c98101f3f88b7afa8f91'. The published child
does not rewrite PNW1, W1 challenge/target, source eligibility, fork selection,
reward, chainwork, final-use, V3 signed Cookie policy or production flags.

## Verified source gap and remediation

The earlier source-bound 'receive_page_from' required the existing
administrator-provisioned fixed 'trnmponpublic.slice' when the source address
was nonloopback. That is an **aggregate cgroup hard cap**, but up to sixteen
attacker-chosen PNW1 packets per History page could still consume CPU without
debiting the Node's original V3 mutation account. The older private parser
called 'Node::admit' and activated an entire History page without cooperation.

The candidate now retains the private 'receive_page' for local fixtures and
routes the PUBLIC 'receive_page_from' through one 'receive_page_with_cpu'.
The full original address/Host kernel guard remains mandatory:

1. For nonloopback, 'receive_page_from' requires an *already bound*
   'Node::public_service_cpu_domain()' and fails closed with
   'OWNER_PUBLIC_SERVICE_DOMAIN_UNBOUND' before parsing/verification if
   missing. For loopback, a previously bound CPU domain is ALSO charged;
   only an unbound local development caller follows the unchanged native
   path. A malicious loopback relay remains a deployment/trust boundary.
2. Before every new remotely sourced W1 proof, CPU credit must naturally
   refill to the original **100ms reservation** (bounded to 10 seconds).
   The unmodified 'ServiceMutationCpuDomain::begin()' then atomically
   reserves the actual original shared bucket. Waiting is NOT a reservation
   and races can still return a local budget refusal.
3. The same live CPU checkpoint wraps parent/State prechecks, complete W1
   verification through every original progress callback, and the M06 native
   admission and registered worker accounting via the existing
   'ExecutionControl'. No second Node, cache, work verifier or store exists.
   Native errors ('WORK:Transcript', 'WORK:Product', etc.) never grant
   VerifiedWork. All started paid operations call the original .finish()
   after native returns, even for false proofs and local cancellation.
4. When a page is complete, the original 'activate_observed' is charged
   to the same bucket in a distinct original CPU operation. Deep activation
   and SQLite remain individually nonpreemptive; a local accounting fault
   after durable commit cannot roll back native facts or be relabelled
   a proof-invalid consensus error.
5. Trusted standalone remote sync has no concurrently running V3 server:
   'bind_host_verified_history_cpu_domain' first proves the original
   fixed Host cgroup *for the calling thread*, then binds a **single
   zero-credit** CPU domain to that Node if unbound. The same owner rejects
   any different domain for the rest of the Node lifetime. All three
   native 'sync_from' variants and CLI public-V3 'sync' initialize this
   only for nonloopback; existing bound V3 and continuous owners are reused.
   The remote peer, caller key, proof bytes and address cannot mint credit.
6. Linux cgroup CPU/memory/PID caps contain independent processes even if a
   caller restarts and binds a new zero-credit Node. This is containment,
   not a proof of per-peer fairness or kernel lower bound on an attacker.

## Source tests introduced (not executed by this artifact)

- 'loopback_proxy_with_original_cpu_owner_pays_for_false_history_and_valid_activation':
  an exact, current-parent valid packet is modified ONLY in claimed C,
  forcing a late WORK:Product refusal. The existing domain is charged
  and settled, no native state moves, then a correct page is admitted and
  activated with the same account.
- 'trusted_history_cold_cpu_starts_at_zero_and_cannot_rebind_same_node':
  verify zero start credit; rebinding another domain is rejected;
  natural refill permits the original reservation, which settles.
- 'externally_guarded_history_requires_cpu_owner_when_original_host_is_present':
  a physically eligible remote Host without an already bound Node owner
  cannot enter Page parsing, W1 or State.
- Existing #342 raw/authenticated/durable remote-source tests remain.

The exact Rust source has not been compiled or executed on an actual cgroup
host in this assistant environment (GitHub network is accessible only through
the connected GitHub tools; local cargo and repository checkout are absent).
A code commit and these test definitions are **not** runtime qualification.

## Unresolved blockers and operational tradeoffs

- The existing public Native 'Node::admit' is a local trusted/CLI interface.
  Local signed or anonymous loopback proxies could relay hostile WAN bytes
  and bypass the remote-address check if they call that trusted interface
  instead. Physical egress/ingress policy and actual local operator trust
  are mandatory; this code alone does not prove proxy identity.
- Cgroup caps plus scalar CPU accounting do not ensure *honest fairness*
  under attacker traffic. W1 false transcript costs remain asymmetric.
  CPU refill wait increases legitimate sync latency and can cause local
  Budget refusals under contention; these are not Invalid consensus.
- Start CPU credit is zero, but real elapsed time creates original refill.
  A new Node/CLI restart may get a fresh accounting clock, and physical
  group membership/aggregate charges must be validated under crash and
  multi-process workloads rather than assumed.
- P0 actual full native regression, P2 measured attacker GPU/hash and honest
  Cookie costs, P3 mixed rotation/invalid-root/service, P4 exact A03
  3 modes x 3 complete runs x 3/3 timely honest confirmations, P5 secure
  efficient fully proved W2, and P6 independent external cryptanalysis are
  OPEN. This branch alone cannot certify 0 remaining blockers.

Final state: SHADOW_ONLY / HOLD_NO_GO / no production activation.


## Additional P3 fault: real W1 + deliberately wrong StateRoot

The native test
'paid_history_valid_w1_with_false_state_root_rejects_without_chainwork'
changes the StateRoot of a normally mined genesis-child packet and searches
new nonces using the exact source A/B under the CHANGED header challenge.
The full W1 production verifier must first accept that exact new proof;
the imported History page then must fail at 'ROOT' during native block
application, with no new active or stored chain state and a fully settled,
actually charged original CPU account. A wrong-root packet cannot simply
reuse an earlier valid W1 proof with another challenge and call it a
late-root attack.

This is an **authored test**, not an executed current-head physical stress
campaign. Even if it passes, one fixed signed local candidate with no
mixed caller/key churn, no honest 3/3 confirmation and no independent WAN
operators does not close P3/P4/A03.
