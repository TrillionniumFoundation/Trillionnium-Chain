# W1 general integer-paired producer research

Status: source review, exact algebra and finite Python-model checks. This is a
research producer for the existing pure matrix W1 relation. It changes no
consensus byte, task permission, verifier, target, reward, chainwork or activation
flag. This document makes **no measured speedup or minimum-cost claim**. Campaign
measurements, if retained separately, must identify their actual source, binary,
hardware and complete accounting scope under the
[cost-security game](W1_COST_SECURITY_GAME.md).

The existing implementation baseline is
`630f871293e48588e0a1ceae7ceb64973d3ec31d`. The new research support file is an
addition to that baseline, not code claimed to exist in the baseline commit.
The final integration receipt must identify the actual revision containing it.

## 1. What is new, and what was already present

The new
[`IntegerPairedGeneral`](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_cost_game_producers.rs)
accepts any two canonical W1 operands: exactly 64 by 64 elements in
`[0, q)`, where `q = 2^32 - 5`. It calculates their real product during
construction and returns the unchanged complete PNW1 proof for each challenge.
"General" describes this input scope; it does not mean arbitrary dimensions,
arbitrary integer ranges, arbitrary fields or automatic native task eligibility.

| Existing implementation | Existing property | Relation to the new arm |
| --- | --- | --- |
| [`PreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs) | General canonical inputs, actual fixed product cached, fresh complete transcript | Same preparation/reuse boundary, different arithmetic kernel |
| [`PairedPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/paired_product.rs) | General canonical inputs and the same paired identity, with cross sums and factors canonicalized in the field | Already has the same general-multiplication count; new arm changes the reduction schedule and intermediate widths |
| [`integer_paired`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/integer_paired.rs) | Existing exact unreduced integer factors and cross products | Same identity and width argument; this is not a newly invented multiplication algorithm |
| [`MaintenanceIntegerPairedPreparedTask`](../../../../trillionnium/crates/trnm-crypto-primitives/src/pon_work/maintenance_prefix.rs) | Existing integer-paired noise and direct full-prefix transcript, with fixed maintenance material admission and periodic setup | New arm lifts the material restriction and uses a general paired fixed-product constructor |
| `MaintenancePrefixPreparedTask` in that same module | Additional periodic decomposition of each maintenance transcript prefix | This specialization is not present in the new general arm |

The existing [implementation comparison](W1_IMPLEMENTATION_COMPARISON.md) already
describes general field pairing, maintenance integer pairing, their counts,
complete transcript obligations and the separation between counts and timings.
The increment here is a complete input-general **integer-paired** research arm
and its explicit comparison under the new resource-budget experiment. It does
not establish a new asymptotic matrix-multiplication exponent.

## 2. Exact integer identity and complete W1 output

For canonical nonnegative words, the integer identity is

```text
(x0+y1)*(x1+y0) - x0*x1 - y0*y1 = x0*y0 + x1*y1.
```

For an even inner dimension `d`, define the unreduced factors

```text
F(x) = sum_{h=0}^{d/2-1} x[2h]*x[2h+1]
F(y) = sum_{h=0}^{d/2-1} y[2h]*y[2h+1].
```

The new `dot` computes

```text
S = prior + sum_h (x[2h]+y[2h+1])*(x[2h+1]+y[2h])
D = S - F(x) - F(y)
output = D mod q.
```

Over the integers, `D = prior + sum_k x[k]*y[k]`. The subtraction is nonnegative,
including when either operand is zero. Row factors are shared across output
columns and column factors across output rows; these sharing opportunities are
part of the actual algorithm, not separately charged copies of the same work.

The constructor validates both complete inputs using the original `task_id`,
computes `AB` with this kernel, and caches `PNW1 || A || B || AB`. This constructor
also hashes the task material; ordinary `PreparedTask::new` only validates it.
The arithmetic table below does not erase that additional hashing cost.

Every `prove(challenge)` call then:

1. Expands the original four rejection-sampled arrays `EL`, `ER`, `FL`, `FR`.
2. Computes `E=EL*ER`, `F=FL*FR` and canonical `AP=A+E`, `BP=B+F`.
3. Computes fresh row/column factors for each eight-coordinate block of `AP`
   and `BP`. These factors are challenge-local, not part of the persistent cache.
4. Emits every original running product prefix in `bi,bj,bk,i,j` order and
   hashes the same canonical little-endian words.
5. Clones the fixed prefix and appends the new transcript digest.

There remain 512 transcript tiles and 32,768 four-byte prefix words. The trace
hash receives 131,072 prefix bytes after its 16-byte domain and 32-byte challenge.
The proof remains 49,188 bytes. It stores the digest, not the entire prefix-word
stream. All four noise streams retain the original 128-counter limit and exact
rejection rule. The minimum successful expansion uses 256 noise-hash calls in
total; rejections can require more, so 256 is not an exact universal count.

The old scalar producer recovers `AB` from the perturbed product using the
existing four correction multiplications. The prepared producers instead compute
and cache the actual fixed `AB`. Both routes produce the same bytes; their
different computation schedules must not be collapsed into one reference cost.

## 3. Width bounds and reduction preconditions

Let `M=q-1=2^32-6`, and let `0 <= prior <= M`. Each cross sum is at most `2M`,
so it needs 33 bits. A cross product can need 66 bits. With `d` even,

```text
each factor <= (d/2)*M^2
S <= M + 2*d*M^2
D <= M + d*M^2.
```

The largest possible bit lengths at the two dimensions actually used are:

| Quantity | `d=8` | `d=64` |
| --- | ---: | ---: |
| Cross sum | 33 | 33 |
| Single cross product | 66 | 66 |
| Row or column factor | 66 | 69 |
| Sum before subtracting both factors | 68 | 71 |
| Sum after both factor subtractions | 67 | 70 |

These are integer bounds for the full canonical input range, not sample
observations. The current code casts each word to `u128` **before addition**,
accumulates the exact cross products and factors in `u128`, and reduces only
after both exact factors have been subtracted. Thus the reducer receives a
nonnegative value strictly below `2^70`, including the 64-coordinate constructor.

For `b=2^32` and `0 <= D < 2^70`, two folds use `b = 5 (mod q)`:

```text
first  = low32(D) + 5*high32(D)
second = low32(first) + 5*high32(first).
```

Here `first < 321*b`, and `second < b+1600 < 2q`. Both fold stages fit in `u64`;
one final conditional subtraction gives the exact canonical remainder. The
pre-subtraction 71-bit `S` is not passed to the reducer. A caller changing this
order would violate the documented reducer precondition.

A `u64` cross product is invalid for the full domain: with all four words equal
to `q-1`, the exact cross product is `4 mod q`; truncating it to 64 bits first
gives `4294967220 mod q`. This is a concrete counterexample to a narrower port,
not a finding against the current `u128` implementation.

The new local helpers are private and receive the fixed `N=64`, `R=8` dimensions.
Their `chunks_exact(2)` loops do not implement an odd-coordinate tail. Changing
these dimensions or exposing arbitrary lengths requires fresh validation and a
tail implementation; current correctness must not be generalized to odd `d`.

## 4. Source-level arithmetic counts

### 4.1 Multiplication schedule

For an `m by d` matrix times a `d by p` matrix, with even `d`, the paired kernel
performs

```text
row/column factor products = (m+p)*d/2
cross products            = m*p*d/2
total general products    = (m*p+m+p)*d/2.
```

For transcript prefixes, the row/column factors are computed once per original
eight-coordinate block and reused across its output cells. With `n=64`, `r=8`:

| General scalar-product operations | Scalar original | Prepared generic | General field-paired | General integer-paired |
| --- | ---: | ---: | ---: | ---: |
| Fixed `AB` construction per new cache | 0 | 262,144 | 135,168 | 135,168 |
| Both noise products per challenge, including factors where used | 65,536 | 65,536 | 33,792 | 33,792 |
| All transcript prefixes per challenge, including factors where used | 262,144 | 262,144 | 135,168 | 135,168 |
| Product-correction multiplications per challenge | 131,072 | 0 | 0 | 0 |
| **Per-challenge total** | **458,752** | **327,680** | **168,960** | **168,960** |

The scalar constructor's zero is only a fixed-product arithmetic count. It still
validates/hashes/copies material in the research wrapper. Its four corrections
are `(A*FL)*FR` and `EL*(ER*BP)`, each multiplication contributing `n^2*r` products.
Consequently its online total is `n^3+6*n^2*r`, not a guessed direct `AB` cost.

The integer-paired per-challenge total is

```text
n^3/2 + n^2*r + n^2 + 2*n*r = 168,960.
```

Of these, **5,120** factor products multiply two canonical 32-bit words, while
**163,840** cross products multiply two potentially 33-bit sums. Setup similarly
has 4,096 factor products and 131,072 cross products. Treating all of these as
one unit is only the table's declared logical counting convention. In particular,
a 33-by-33 product cannot be equated with one 32-bit SIMD multiply or an ML
accelerator instruction. All three scalar/prepared schedules use `u128` source
expressions; compiler lowering and operand bounds still differ.

The 48.4375% online multiplication-count reduction relative to prepared generic
was already present in the general field-paired schedule. The new integer arm
does not improve that count. It trades canonical cross-sum/factor reductions
for wider integer intermediates. Nothing in this table establishes a latency,
throughput, energy, monetary-cost or adversarial-work advantage.

### 4.2 Additions, subtractions and reduction points

To make the counting convention checkable, the following counts include each
source accumulation from an initial zero, both cross-sum additions, the two
factor subtractions per output, and the ordinary `AP/BP` additions. They exclude
index arithmetic, allocation, bounds checks, hashing and serialization.
Arithmetic *inside* a remainder/fold routine is counted as one reduction point,
not counted again as ordinary adds or multiplies. A compiler can eliminate or
fuse operations, so these are not instruction counts.

| Schedule | General products | Additions/accumulations | Subtractions outside reduction | Reduction points |
| --- | ---: | ---: | ---: | ---: |
| Prepared generic setup | 262,144 | 262,144 | 0 | 4,096 |
| General integer-paired setup | 135,168 | 397,312 | 8,192 | 4,096 |
| Scalar original online | 458,752 | 471,040 | 8,192 | 62,464 |
| Prepared generic online | 327,680 | 335,872 | 0 | 49,152 |
| General integer-paired online | 168,960 | 504,832 | 81,920 | 49,152 |

For one paired matrix multiply the addition count is
`(m+p)*d/2 + 3*m*p*d/2`, and the outside-reduction subtraction count is `2*m*p`.
For the new complete online path, 5,120 factor accumulations, 327,680 cross-sum
additions, 163,840 cross accumulations and 8,192 perturbed-operand additions give
504,832. Its 40,960 noise/prefix output reductions each have two factor
subtractions, giving 81,920. The scalar total additionally includes the final
`cp + 2q - correction1 - correction2` for every product cell.

The prepared producer's `AP/BP` additions currently use `% q`, while the new arm
uses its fold reducer. Equal numbers of reduction points therefore do not mean
equal machine costs. Existing
[zero paired cost accounting](W1_ZERO_PAIRED_COST_ACCOUNTING.md) already retains
a separate historical example in which fewer counted products did not make
the tested integer-paired producer faster. Those old timings are not timings
of this new arm.

### 4.3 Preparation and reuse horizon

For `t` actually executed challenges on one task, the product-operation schedules
are:

```text
scalar original:       458,752*t
prepared generic:      262,144 + 327,680*t
general integer-paired:135,168 + 168,960*t.
```

Even this restricted metric shows why a cached-reference denominator matters:
prepared generic costs 589,824 products for one cold challenge, versus 458,752
for scalar original. Their multiplication counts tie at `t=2`. These statements
do not determine the timing break-even point. Cache copies, validation, hashing,
memory layout, factor storage, failed attempts, adaptive training and destruction
remain in the actual resource accounting. An externally supplied `AB` cannot be
silently counted as zero-cost preparation.

No rank assumption or zero/identity/sparse shortcut is used by the new arm.
Its same loops accept full-rank near-`q` inputs. That is an input-generality
property, not a lower bound: another algorithm may exploit low rank, sparsity,
periodicity, task reuse, batching or hardware more effectively. Shared setup
must be paid once across a multi-parent search; challenge-bound factors must
remain fresh. A mathematical cache carries no parent eligibility or reward.

## 5. Finite verification and falsifiable conditions

The independent Python check performed during this review used arbitrary-precision
integers and the retained [scalar oracle](../../../../formal/pon-nakamoto-v1/work_oracle.py).
It passed 3,125 two-coordinate boundary combinations, 512 seeded dot products
of lengths 8/64, 4,102 reducer checks, and eight complete proof equalities over
zero, identity, full-rank near-`q` and seeded dense matrices with all-zero/all-255
challenges. This checks a Python model of the reviewed formula against the old
scalar schedule. It is **not native Rust execution, a benchmark or an exhaustive
proof over every 64-by-64 input**.

The new Rust support module also contains named checks for extreme dot products,
complete scalar/native proof equality and both original full verifiers. A release
receipt must separately record whether those actual tests ran on the released
source; their presence alone is not a passing test result. Existing maintenance
tests are useful controls but do not by themselves certify the new general arm.

The following failures would falsify the corresponding claim:

| Claim | Concrete counterexample or required rejection |
| --- | --- |
| General canonical input support | Any valid 64-by-64 input returns a wrong product/prefix or is silently substituted with maintenance material |
| Complete byte equivalence | Any full proof differs from the original scalar proof on the same input and challenge, including trace order and canonical bytes |
| Width safety | Any allowed factor/cross sum wraps before its intended reduction, or a post-subtraction value reaches `2^70` |
| Fresh challenge handling | A reused challenge-local factor produces an invalid proof under a new challenge or parent-bound header |
| Input validation | Wrong length or an element `>=q` reaches arithmetic instead of rejection |
| Honest operation count | The claimed count omits factor construction, reconstructs only a final product instead of every prefix, or adds setup per fork when it was actually shared |
| Resource advantage | A claimed speedup lacks equal-input complete cold/hot receipts, drops failed/unsupported/slower arms, or omits producer costs |
| Consensus work credit | Alternate algorithms, proof encodings or repeated training challenges count the same semantic ticket more than once |

The general helper currently lacks the cooperative generation checkpoints of
the older maintenance producer. It is a bounded research `prove` call, not a
drop-in replacement for the native cancellable mining owner. Its nonpreemptive
overshoot remains charged and separately reported by the cost experiment.

## 6. Auxiliary work, deduplication and timing interpretation

The reviewed
[native-context helper](../../../../trillionnium/crates/trnm-pon-node/examples/support/w1_cost_game_context.rs)
now retains two sibling-parent winners and three template winners, and submits
all five through the original `Node::admit`. It records their headers, challenges,
traces, tickets, semantic identities and both production/admission completion
times. They are excluded from the selected arm's counter but included in the
deduplicated `all_work` numerator. Training arms share the selected-arm semantic
set; auxiliary and selected outputs share a separate all-work set.

That addresses the earlier omission of acquisition wins. These are different
candidate statements on a parent forest, not additive canonical-chain rewards.
Repeated counterfactual cohorts can reproduce the same sibling-parent statements;
sum-of-cohort observations must not be described as a global count of newly
created distinct statements. The reader's global semantic set has a different
purpose from cohort-level statistical sums.

The inclusive completion fence uses **production completion**, with later full
verification/native admission establishing validity. Thus an in-budget result
means "produced within the observed budget and subsequently confirmed valid."
It does not mean native admission itself completed within that budget. An `N_B`
claim timed to completed admission needs the separately recorded admission
completion boundary. Checking that auxiliary completion times, first selected
trial and cohort end share one monotone timeline is part of reader acceptance.

The inclusive timing subtracts explicitly measured observer verification and
admission calls from the cohort clock, and retains other observed overhead such
as dispatch and logging. Core-stage timing remains a separate denominator.
Global public-material construction is explicitly excluded. The end snapshot
also precedes dropping `Game` and its `NativeContext`, so final Node/temporary-
database close/delete work is outside that interval. These are observation
boundaries, not a process-lifetime total or a complete operational hardware bill.
The main loop can stop on core-stage exhaustion while the inclusive completion
fence independently denies credit to later outputs. Its actual overshoot must
not disappear into the next cohort or be reported as a strict execution cap.

These qualifications preserve the resource-to-ticket question without confusing
receiver measurement, acquisition, proof validity and admission latency. None
qualifies W1 hardness or authorizes production activation.

## 7. Small exact arithmetic reproduction

After the usual project preflight, this standalone check can run from the
repository root. It uses no native build, hardware timing or third-party package.
The broader full-proof check above additionally compared the paired Python model
to `work_oracle.prove`; this short reproduction isolates the algebra, width and
count claims most vulnerable to an incorrect narrow-word port.

```sh
python3 -B - <<'PY'
from itertools import product
from random import Random
q, n, r = 2**32 - 5, 64, 8
M = q - 1
def reduce(x):
    assert 0 <= x < 2**70
    a = (x & (2**32-1)) + 5*(x >> 32)
    b = (a & (2**32-1)) + 5*(a >> 32)
    return b-q if b >= q else b
def check(a, b, prior):
    f = lambda v: sum(v[i]*v[i+1] for i in range(0, len(v), 2))
    s = prior + sum((a[i]+b[i+1])*(a[i+1]+b[i])
                    for i in range(0, len(a), 2))
    assert s >= f(a)+f(b)
    d = s-f(a)-f(b)
    assert d == prior + sum(x*y for x,y in zip(a,b))
    assert reduce(d) == d % q
values = [0, 1, 2, q-2, q-1]
for a0,a1,b0,b1,prior in product(values, repeat=5):
    check([a0,a1], [b0,b1], prior)
rng = Random(20261025)
for inner in (r, n):
    for case in range(256):
        a = [rng.randrange(q) for _ in range(inner)]
        b = [rng.randrange(q) for _ in range(inner)]
        prior = rng.randrange(q)
        if case == 0: a = b = [M]*inner; prior = M
        check(a, b, prior)
    print(inner, 'pre/post bits',
          (M+2*inner*M*M).bit_length(), (M+inner*M*M).bit_length())
for x in [0,1,q-1,q,q*q,2**70-1] + [rng.randrange(2**70) for _ in range(4096)]:
    assert reduce(x) == x % q
assert ((2*M)**2 % q, ((2*M)**2 % 2**64) % q) == (4, 4294967220)
assert n**3 + 6*n*n*r == 458752
assert n**3 + 2*n*n*r == 327680
assert (n*n+2*n)*(n//2) == 135168
assert n**3//2 + n*n*r + n*n + 2*n*r == 168960
print('PASS: 3125 pair boundaries, 512 longer dots, 4102 folds; no timing claim')
PY
```
