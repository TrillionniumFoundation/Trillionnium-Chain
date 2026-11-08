# Grouped work: verifier resources, shared admission and propagation v0

Status: **research HOLD; actual chainwork and production activation zero**.
This continuation retains the exact
[sealed grouped profile](GROUPED_FRESH_WORK_FLOOR_V0.md). It changes no W1 rule,
numeric relation, target algorithm or consensus work registration. Its new
authority namespace belongs to an explicitly trusted research service.

The questions are which owner performs the work, how many times a correct or
incorrect packet can induce verification, and what evidence would connect a
real task to delivery and payment. A local cap, signed fixture or source hash
does not establish independent demand or a public-network resource bound.

## 1. A constructive useful-work limitation

The current business product is `F(task,input,model)` and is lawfully cacheable
within the fixed scope. The fresh challenge changes the security seal, while a
producer can reuse the same product. The implemented sparse-merged producer
has zero fresh business contractions after preparation. Since operation counts
are nonnegative, a **strictly positive per-challenge producer contraction floor
is refuted for this cache scope**, rather than merely awaiting a larger sample.

The independent receiver can still recompute the business relation. Its cost
belongs to the receiver; it cannot be silently attributed to the producer.
A new intrinsic useful-work claim needs a different useful relation and explicit
assumptions covering the cheapest legal algorithm, preparation, storage, input
selection, cache scope and amortization horizon. A finite-domain table can move
online arithmetic into preparation and storage without becoming cost-free.

## 2. A conservative bound with disclosed verifier work

The [resource-transfer model](../../../../formal/pon-nakamoto-v1/fresh_work_resource_transfer_v0.py)
retains the prior classical aggregate theorem and its chronology, independent
seed, injective domain and once-per-candidate credit premises. Let
`M = 2^lambda`, `L` be the fixed number of step queries, and `C` the theoretical
nominal credit. Define:

- `Q_A <= q_A`: all coalition step queries, including its preparation and
  delegated producer computation;
- `Q_V <= B_V`: all other step queries whose results or derived information can
  assist that coalition, including verifier replays and external helpers;
- `mu_A = E[Q_A]`.

Then the aggregate theorem gives

\[
\mathbb E[C]\leq\min\left\{
L(\mu_A+B_V),\quad
\mu_A+B_V+\frac{L(q_A+B_V)(q_A+B_V+1)}{2M}
\right\}.
\]

This substitution allows complete disclosure of the charged verifier's
classical transcript, result and timing. It therefore does not require the
stronger hidden endpoint-equality premise. It still excludes uncharged
oracle-dependent advice, and **does not turn `B_V` into the attacker's own bill**.
The numerical premise `B_V` must be justified by the actual deployment.

For one owner that starts at most `K` callbacks, each executing at most `R`
complete `L`-step replays, `Q_V_callbacks <= K R L`. When those callbacks cover
every assisting step query, one may choose `B_V = K R L`; other owners, epochs,
public producer services and independent re-verification must otherwise be added.
A crashed started callback retains its full possible cost until evidence narrows
it. A cached response may add zero step queries while still consuming signing,
parsing, storage and network resources. Seed queries and all non-step costs
are reported separately; the theorem grants the independently fixed seed.

The older endpoint-only coalition inequality remains conditional. Nothing in
this service proves constant-time behavior, a physical cost floor, the global
query transcript or a quantum bound. A development `Node::expected_target`
observation binds a value; it does not authorize this new profile, chainwork
formula or production difficulty policy.

## 3. Exact counterexamples and quantum scope

The independent tests enumerate finite endpoints or state vectors, using exact
rational arithmetic rather than Monte Carlo confidence claims.

| Control | Consequence |
|---|---|
| Eight independent local budgets of 16 for one candidate | The submission allowance is 128; substituting one journal's 16 into a coalition inequality can fail. |
| Each reply additionally reveals one requested endpoint bit | A zero-chain-query claimant can reconstruct the endpoint, even when successful equality closes the candidate; this is not an equality-only verifier. |
| One unqueried winning endpoint guess at `L=64,T=1` | Expected nominal credit remains 32, independent of hash length. Small probability cannot replace an award cap. |
| Fixed ideal Grover search over independent candidates | The explicitly classical credit envelope does not apply to coherent queries. |

The quantum control uses 64 candidates, a precommitted target probability
`1/64`, and five Grover iterations. It averages over every marked subset by its
exact binomial multiplicity, including the no-winner worlds. It charges 320
forward step queries, 320 inverse queries, 64 measured-candidate reconstruction
queries and 64 independent verifier queries. This is an abstract strategy,
not a native SHA256 circuit, fault-tolerant implementation, energy estimate or
proof of the cheapest quantum algorithm.

[Zalka's black-box search analysis](https://arxiv.org/abs/quant-ph/9711070)
and the separate
[post-quantum PoSW work](https://arxiv.org/abs/2006.10972)
address different security statements. The
[compressed-oracle analysis](https://eprint.iacr.org/2020/1305)
also requires analysis of the complete PoSW protocol; a sequential-chain lemma
cannot simply certify endpoint lottery fairness. No quantum safety flag is set.

## 4. One explicit verification owner

The new [native authority](../../../../trillionnium/crates/trnm-pon-node/src/grouped_verification_authority_v0.rs)
freezes one epoch, generation, authority key, set of receiver keys, candidate
registry, aggregate reservation limit and per-candidate limit. It authenticates
the existing admission capsule against the actual local Node and binds the
complete model and original request bytes before forming its registry.
Canonical statements are fixed before any security-chain probe in the campaign.
All capsule, requester, source, receiver and owner signatures in this campaign
use public test keys. Running the real signature checks demonstrates the code
path, not external identity, production key custody or operator independence.

The owner itself executes the original-coefficient grouped verifier and the
64-step seal. It never hands out a reusable permission for receivers to replay
the computation independently. Its public research service has reserve and
execute operations, without an unmetered producer operation.

The journal enforces these transitions:

1. Authenticate the receiver/action and the complete bounded request fingerprint.
2. Atomically allocate a reservation against both fixed limits.
3. Commit `started` before any expensive full Cell or seal work.
4. Commit the complete result and close a successful candidate atomically.
   A mathematically valid target miss also closes the candidate.
5. Return an authenticated receipt. An exact completed retry returns the cached
   receipt with zero additional callback queries. A different request under
   the same idempotency identity is rejected.

Cached responses explicitly set `new_candidate_completion=false` and identify
the receipt as historical. They do not revalidate the current Node state or
expiry; a historical `first_record=true` is not a new admission or award.

A reserved abandoned request is not refunded. A process that dies after
`started` leaves an indeterminate request; reopen marks it unknown, retains the
full possible replay cost and refuses a fresh execution. File locking excludes
two cooperative owners of the same journal. Separate files, copied authorities,
filesystem rollback, administrator modification and a bypassed service remain
outside that guarantee. A new epoch is not an automatic quota renewal.

The scope is one explicitly trusted owner and its declared receivers. This
trades receiver-independent full verification for a shared admission trust and
availability dependency. If every receiver independently verifies again, its
replays return to `B_V`. Public decentralized deployment needs an actual
consensus admission or funded service mechanism and a defined total accounting
horizon; this research owner does not supply that mechanism.

Parsing, receiver authentication, invalid/out-of-scope requests, receipt signing,
transport and storage remain outside the callback count. Full Cell calls can
return early on a malformed claim; 37,008 MAC is the complete reference count,
not the asserted actual arithmetic of every invocation.
Initial preparation and every owner process startup also reconstruct the direct
canonical business products for every registered nonce. The campaign counts
five preparations of sixteen candidates outside the callback quota. This is
additional service assistance and cost; it cannot disappear from resource
accounting merely because it performs no security-chain step queries.
Reported bytes cover retained application frames. Buffered reads may prefetch
malicious trailing data; socket overhead and all possible prefetched bytes are
not certified by that frame count.

## 5. Independent receiver fanout and honest cost denominators

The [fanout campaign](../../../../formal/pon-nakamoto-v1/experiments/grouped_fresh_fanout_v0.py)
fixes topologies of one, two and four independent Python receiver processes,
each with its own native child and journal. It sends the same canonical packet
over real localhost TCP. Six cases per receiver are fixed in advance: a valid
packet, carrier replay, forged endpoint, truncated sender cancellation, complete
send with intentionally discarded response, and a post-cap refusal.

Each local journal is actually filled to 256 and reopened. Its 257th request
must stop before full Cell verification. The sum of reservations is therefore
observed per topology, and is never relabelled as a single global 256 cap.
Content identity is separate from work identity and economic demand identity:
two customers can legitimately request identical content, while many tickets
over one retained input do not demonstrate many customers.

The original raw frames and receipts, all planned slots, failed startups,
incomplete attempts, child exits and wait4 usage remain in the denominator.
Native-only CPU is a subset of receiver-and-descendant CPU. Bytes accepted by a
sender's kernel do not prove the peer read them; a successful server write does
not prove business consumption. Where measurements run on tmpfs, process
restart/readback is not a physical-disk or power-loss durability experiment.
The campaign reports the output filesystem rather than hiding that difference.

## 6. Actual demand and native payment composition

The [source-owner audit](../../../../formal/pon-nakamoto-v1/grouped_fresh_deployment_cost_v0.py)
identifies existing M06 task leases, requester/source authorization, Node funding
snapshots, exact native payment-transition replay, M12 effect journals and
consumer-context verification. Their presence does not join this new relation
to a genuine task, fund it or establish a consumer's current FinalUse.

A production join must bind one authorized task and profile, immutable input
and model, actual funding subject, receiver/output commitment, current consumer
authorization and an exact observed settlement. Source/requester signatures
cannot prove operator independence; a held-out corpus is not new customer
demand; consumption declarations are not external effects. This continuation
does not fabricate a customer, payment, installation or independent controller.

## 7. Validation and adoption boundary

The retained validation driver keeps all 21 prior gates and adds three: resource
transfer controls, native authority controls and the release authority build.
The ordinary protocol CI also requires the new finite theory and native tests;
negative CI controls reject removal, duplication and swallowed failures.
The expanded validation report uses new v1 report namespaces and binds all
three executables to the exact source and Cargo target graph.

Campaigns and finite controls do not establish the minimum physical resource
price, exhaustive legal-strategy optimality, an independent task market, full
WAN/availability economics or quantum security. Existing integration delivery
and original business/resource gates remain required. Actual chainwork stays
zero until those separate qualifications are established.
