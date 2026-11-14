# Joint PoN source, clock and resource continuation

Status: **HOLD / NO-GO**. This is an execution note under the sole
[development plan](../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md),
not an alternative protocol or a production activation decision.

## One source and distinct obligations

The continuation starts from complete #821 commit
`e798d7125724d4b9f98c24d00cc80031f2eab4a9`, tree
`f77b6240b845425e0fc75e88abb09e6cfa3a71c0`. This candidate contains the #811
fixed-probability research and #812 integration ancestry. The implementation
and evidence commits of this continuation have their own identities; a pass
on its parent or another branch cannot qualify a changed executable.

| Obligation | Implementation change here | What remains unproved |
| --- | --- | --- |
| Actual acquisition cost | Stream setup, search, individual attempt and full-verifier observations before/after work, keeping unfinished costs unknown | A lower bound over every allowed classical/quantum strategy, retained initial state, preparation and task/branch selection |
| Current clock and cumulative credit | Use the existing observed-history activation owner at the public PGH2 submission boundary | Joint timestamp/DAA/credit security, authenticated clock assumptions, all recovery/mining entry points and a native fixed-probability credit bridge |
| Bounded rejection and honest service | Recheck the original absolute deadline after Host observation and before a History owner action | A full worst-case resource envelope and a positive honest-service lower bound under the declared adversary |

## History owner deadline boundary

The existing `Control::check` checked the deadline, then executed the mandatory
resource callback. A successful callback could itself return after that same
deadline. The caller could then enter the next owner action with an already
expired budget. The corrected sequence is:

1. Check the original absolute deadline.
2. Execute the original mandatory Host/resource callback once.
3. Preserve any callback error as the original refusal.
4. Recheck the same deadline before returning authority to start the action.

The deadline is never restarted. No Host file read, CPU check, source check,
cleanup, cancellation or resource limit is removed. Existing completion logic
continues to observe final resources and account for durable work; an expiry
does not mean that earlier committed work was rolled back.

The added controls cover a deadline already expired before resource observation,
timely completion, a successful late callback, a late failing callback's original
error priority, and real exclusive/shared Node owner callbacks. The old-source
observation and corrected-source observation must remain separate receipts.

## Public Growth current-clock activation

PGH2 already has `Node::activate_observed`. Its history reader checks every
selected ancestor's timestamp against the supplied current observation and
checks the corresponding native header/credit chain under the original storage
epoch. However, the public Growth submission's final helper previously selected
`Node::activate`, which does not accept a clock.

A currently eligible target header does not imply that every retained ancestor
is currently eligible. The original median-time rule permits a valid lower
timestamp after an isolated larger timestamp. The public helper now obtains a
fresh current time and calls the existing observed-history activation API for
both newly admitted and exactly duplicated packets.

The regression uses actual PGH2 packets, native storage and signed local TCP
requests. It retains an ordinary prefix, a future-dated retained ancestor and a
target whose own timestamp passes the original current-clock admission checks.
The receiver must retain a newly admitted target, refuse activation with
`TIME_DEFERRED`, leave active tip/generation unchanged, and repeat that refusal
for the exact duplicate. Full-verification work remains charged, while a
duplicate cannot manufacture a second W1 completion.

The existing postcommit tail remains noncancellable and fully charged to its
original outer CPU interval. No signed domain, stored schema, request opcode or
resource profile is reinterpreted. The additional complete clock walk is
O(history depth). Correct rejection here is not evidence of improved throughput,
bounded latency or full time/DAA security. The unobserved local recovery API is
unchanged; callers and their clock assumptions require separate qualification.
See the [Growth service contract](../protocol/pon-nakamoto-v1/details/NATIVE_ACCOUNT_GROWTH_V2.md).

## Interrupted cost observations

The [V4 contract](PON_W1_LIFECYCLE_COST_V4.md) introduces a separate diagnostic
entry and record namespace. V2/V3 example selectors and record meanings remain
intact. The shared generator retains its legacy wrapper, while V4 receives
events before each native generation attempt and after completion/failure.

A started record is not proof that the subsequent instruction executed. A
missing finish has unknown consumed cost, even when the process later exits or
is cancelled. Flush exposes the observation to the collector; it does not prove
power-loss durability, independent resource accounting or actual-device cost.
The separate production/reference full verifiers must both complete before a
search is reported as fully verified, and no observer event adds chain credit.

The fixed diagnostic target has ideal terminal-hash density one half. It must
not fill the MU1 one-sixteenth fixed-probability experiment or its sixteen
unknown classical/quantum cost points. Timing scopes overlap and are not
additive. Startup, collection, final flush, unobserved devices and externally
billed resources require their own receipts.

A complete fixed-roster run and a separate real terminated-process run exercise
different properties. In the termination observation, the collector retains
the actual PID, signal request, exit status, stdout/stderr and byte identities.
It must not claim that a signal landed inside a particular native instruction.
The reader must classify the retained unfinished prefix as incomplete and keep
unfinished cost null, irrespective of how many completed attempts preceded it.

## Joint acceptance requirements remain unchanged

The original public contract still requires CPU 0.25 core, 2 GiB RAM, zero swap,
256 PIDs and the original four-second/16-hostile service case. The original
three-run campaign, full History, capacity/churn and independent confirmation
criteria retain their own deadlines and denominators. Local component tests
under an ordinary development process do not meet that resource contract.

The #821 evidence retains real confirmation failures, including attack-free
failure. Its [checkpoint attribution](../../evidence/chain-six-full-20261108/NATIVE_HISTORY_CHECKPOINT_ATTRIBUTION.md)
must be read before interpreting scheduler or rejection changes as a throughput
improvement. Native activation, root/readback work, current resource observations,
rollback/cleanup and response completion all belong in the same end-to-end
budget. Required Host observations cannot simply be cached or sampled away.

A total CPU cap alone does not imply a positive service floor for an honest
request. A service guarantee needs a declared bound on the admitted competing
work or an explicitly justified allocation assumption, plus measured bounds on
all work inside and after each reservation. Identity validity, a Cookie or an
individual timeout alone does not supply that premise. The finite original
hostile-request campaign remains a concrete test, not a universal availability
theorem.

For a qualification change, retain together: complete source/tree and paired
dependencies; provider/build identity; actual loaded executable hashes; the
original resource contract; unique process/run identity; all outcomes including
errors, exits, cancellation and Unknown; full source-before/source-after
receipts; raw-byte artifacts; and current confirmation results. The absence of
one such receipt must not be replaced by an unrelated branch's passing result.

## Research boundary

The 2026 [Komargodski--Weinstein ESA publication](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.ESA.2026.2)
still states optimal protocol hardness as a conjecture. Its
[full fixed version](https://arxiv.org/html/2504.09971v4) distinguishes the main
single-instance definition from additional streaming requirements. It supplies
useful research structure, not an all-implementation lower bound for this Node.

[Quantum multi-solution Bernoulli search](https://quantum-journal.org/papers/q-2023-03-09-944/)
establishes query-model results under stated classical-honest assumptions.
Translating actual work, reusable preparation, variable credit and receiver
congestion into that model remains a separate reduction. No finite native
campaign in this continuation supplies that reduction or changes the existing
false/null production and security qualification flags.
