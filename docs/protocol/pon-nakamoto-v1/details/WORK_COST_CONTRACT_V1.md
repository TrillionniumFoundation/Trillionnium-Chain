# Frozen W1 work and lifecycle cost contract V1

## Exact decision

The contract freezes the implemented `pon-matmul-transcript-64-v1` relation at
Chain source `b16bae2824e6c8236ef2011fc93a74df3ac7f039`, tree
`49392edc1b49a1ad92c1956f8a37c741d835677a`. The native subtree is
`bf84f89b235adfcffcb0d3540c22c120f4031e13`.

The [machine contract](../../../../formal/pon-nakamoto-v1/contracts/work-cost-contract-v1.json) covers
all 1,747 baseline files in the native and formal trees, the Rust toolchain and
the complete baseline configuration tree: 27,613,671 bytes. Each entry retains
its path, mode, Git blob identity, length and SHA-256. The roster is independently
derived from the immutable baseline tree during checking. Rehashing a shortened
caller-supplied inventory cannot omit a source file.

The [checker](../../../../formal/pon-nakamoto-v1/work_profile_contract_v1.py)
does not refresh pins during validation. Its explicit capture operation refuses
an existing destination. It refuses source replacement refs, grafts, escaping
paths, symlinks, mode changes, changed file identities during a read, duplicate
JSON keys and numeric aliases. New candidate modules are separately included in
the named-runner input inventory and the hosted full tracked-source checks;
they are not retroactively described as files in the historical baseline.

This is source and contract identity. It is not an observation that those bytes
were compiled or loaded. The contract deliberately records no guest image,
control root or AIR identity for this recomputation backend. The separate
STARK candidate is not imported by naming it. Runtime binary identity, full
cryptographic qualification and production activation remain unestablished.

## Inputs, freedom and exact success

The relation retains the canonical field `q = 4,294,967,291`, dimension 64,
noise rank 8, little-endian four-byte words, 128 hash expansions per noise
label and the 49,188-byte PNW1 proof. Products, intermediate values, transcript
order and decoded output use the exact existing semantics in
[WORK_PROFILE.md](WORK_PROFILE.md). No approximate neural arithmetic is
introduced into this relation.

A successful work result means complete W1 verification at the original
branch-derived expected target and exact challenge. The accepted-work predicate
is distinct from native block admission and complete state application. A
diagnostic all-`ff` filter can force a complete replay of a lottery miss, but
it grants no work credit at the original target.

The attacker retains every legal freedom: input and eligible-task choices,
parent branches, timestamp choices, nonce, transaction roots, miner identities,
witness fields, batching and alternative algorithms. A canonical proof grammar
removes serialization aliases; it does not remove alternative computations of
the same accepted relation. A cache is bound to the full statement and does not
turn a replayed block into new work.

## Full lifecycle cost model

Initial advice, public model and input, preprocessing, cached products, unused
results, nonce banks and quantum state all belong to the initial-state game.
The ledger of resource use includes setup, every attempt, failure, cancellation,
withheld work, work already in flight after the first hit, proof construction,
verification, transport, storage, recovery, helpers and retained state across
versions. A chain reorganization does not refund already consumed physical work.

Record CPU and wall time, concurrent peak RSS, GPU use, byte-seconds of storage,
network bytes, physical energy and provider charges separately. `null` is an
unknown measurement; it is not zero. A sum of sequential RSS maxima is not a
concurrent memory observation. Measured code running time is neither a joule
measurement nor a provider payment receipt.

For quantum strategies the model also accounts for state preparation,
reversible execution, clean uncomputation, physical oracle construction,
measurement and cross-round state. A black-box query estimate supplies none
of these physical costs automatically.

Every demonstrated legal implementation gives an **upper bound** on minimum
legal cost. Adding an implementation to the catalog may lower that upper bound.
The catalog cannot certify completeness over all algorithms. A lower-bound
certificate requires a named computational model, a resource-simulation
reduction, covered initial states and a theorem with its explicit losses.

## Fixed probability and variable work

At the development threshold `T = 2^255 - 1`, the arithmetic probability is
`p0 = (T + 1) / 2^256 = 1/2` **under the uniform-ticket hypothesis**. Neither
uniformity nor independence is proved by this arithmetic. The native W1 profile
still has one fixed dimension and relation; it does not implement variable `u`.

A variable-work successor needs a separately committed mandatory joint
relation. Repeating a nominal operation count, multiplying the published work
by `u`, or reusing identical cached statements does not implement that relation.
The cost comparison must use the same success probability target, deadline and
round horizon for every resource class. Cost per expected accepted output is a
different functional and cannot silently substitute for fixed-success cost.

Komargodski and Weinstein already describe fixed success probability with
variable task size in Remark 5.2 of
[arXiv:2504.09971v4](https://arxiv.org/html/2504.09971v4). Their Section 5 also
distinguishes multi-instance and streaming hardness from the simpler single
instance definition. This contract makes those obligations explicit; it does
not claim the design choice itself as new or resolve their conjecture.

## Deployment and Hepta joining requirements

The observed Hepta main is
`732e934ba496d90fbe042b8d41d479ef901643e5`. There is no single deployed
cross-repository identity in this contract. The newer runtime, proof, payment
and original-owner readback candidates have their own source identities and
cannot be combined by adding their passing test counts.

The eventual evidence join must bind one task, frozen parent model, candidate,
evaluation plan, original operation ID, Chain and Hepta source/build identities,
resources and deadlines. Real admission, independent network reception, recovery,
complete resource billing and positive payment require separate original
receipts. Chain ordering and payment do not grant the original Hepta owner's
adoption permission. Protected installation, actual loaded model identity and
next-task use remain current-owner operations. A legitimate `NoUpdate` retains
the entire parent identity without an invented reset or improvement bonus.

## Reproduction and claim boundary

```sh
python3 formal/pon-nakamoto-v1/work_profile_contract_v1.py
python3 -m unittest discover -s formal/pon-nakamoto-v1 -p 'test_work_profile_contract_v1.py' -v
```

The checker returns `contract_and_source_consistent=true` only for matching
source and contract bytes. Its overall status remains `HOLD_NO_GO`. It always
keeps the all-algorithm lower bound, variable-work native relation, native time
upgrade, joint CP/CQ/CG proof, same-iteration deployment, real Hepta product loop
and production activation unqualified. A missing lifetime security bound stays
`null`; the program cannot turn an unreviewed assertion into security bits.
