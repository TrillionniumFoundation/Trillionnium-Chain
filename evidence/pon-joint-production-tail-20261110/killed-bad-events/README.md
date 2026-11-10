# Good-subkernel credit tails with a separate bad-event budget

Status: conditional probability interface and finite arithmetic evidence only.
This specializes standard killing, Ville and union-bound arguments to the
existing joint-tail accounts. It claims no new general probability inequality,
actual W1 law, all-legal-strategy coverage or native qualification. The installed
formal checker, native sources, source pins and CI semantics are unchanged.

The original joint-tail note warns that conditioning on eventual successful
clock/bootstrap/delivery can change the law. This packet supplies an explicit
sufficient construction for that boundary rather than assuming away bad paths.

## Conditional theorem under the actual full history

Work under one fixed initial history, with D_0=0 and actual f_0 retained.
Let F_n be the common classical filtration, D_n=A_n+E_n-J_n, f_n>=1 finite
and adapted, and z>1 fixed before examining future outcomes. Let T>=1 be the
first bad cut, a stopping time in that filtration, with T=infinity if none.
Values of f and D after T can be assigned arbitrarily: they are never used.
The bad event must cover every violation of the stated clock, participation,
parent target/time/credit, initial-state and complete delivery/service premises.
Merely naming a report a bad event does not establish this coverage or timing.

Suppose positive finite predictable kappa_n satisfy, on {T>n-1},

    E[ 1{T>n} (f_n/f_(n-1)) z^(Delta D_n) | F_(n-1) ] <= kappa_n.   (K)

The expectation uses the actual joint law at that history and every allowed
action. In particular, it is not an expectation under the renormalized law
given T>n, nor under T=infinity. Put C_0=1 and C_n=product_(i<=n) kappa_i.
Then

    M_n = 1{T>n} f_n z^D_n / C_n

is a nonnegative supermartingale, M_0=f_0. **Proof:** on {T>n-1}, factor the
F_(n-1)-measurable f_(n-1) z^D_(n-1)/(C_(n-1) kappa_n) out of the conditional
expectation and apply (K). On {T<=n-1}, both M_(n-1) and M_n are zero.
Finite conditional moments and finite f_0 provide integrability by induction.
This directly proves the killed process inequality; it does not invoke
optional stopping at the generally non-stopping time T-1.

If C_n<=Cbar at all cuts n<T, for fixed Cbar>=1, f_n>=1 and Ville give

    P[exists n<T: D_n>=d] <= min(1, f_0 Cbar z^(-d)).              (V)

The result includes the initial cut, and uses the trivial bound one when its
right-hand side is at least one. Without a justified simultaneous compensator
ceiling there is no fixed-gap lifetime conclusion. All parameters in (V) are
fixed under the conditioned initial history; for random initial histories,
average the full conditional bound, not separately selected factors.

For predictable b_n in [0,1], suppose

    P[T=n | F_(n-1)] <= 1{T>n-1} b_n,
    sum_(n>=1) 1{T>n-1} b_n <= beta  almost surely.               (B)

Disjoint first-bad events and monotone convergence give
P[T<infinity] <= E[sum 1{T>n-1}b_n] <= beta. Therefore a separately proved
native reduction

    {native failure} subset {T<infinity} union {exists n<T: D_n>=d}

would give min(1, beta+f_0 Cbar z^(-d)), without any independence assumption.
Neither that reduction nor (K)/(B) is established for native W1 here. A bad
initial event needs its own allowance; the theorem assumes a safe initial cut.
Conditioning on an F_0-measurable initial event and paying its probability is
different from conditioning on eventual future service success.

## Composition with the existing marginal and residual interfaces

On an alive history set U=(f_n/f_(n-1)) z^Delta(A+E) and H=z^(-Delta J).
Conditional Cauchy-Schwarz gives a sufficient good-subkernel bound

    E[1{T>n} U H | F_(n-1)]
      <= sqrt(E[1{T>n} U^2 | F_(n-1)] E[1{T>n} H^2 | F_(n-1)]).

Both expectations keep their subprobability mass under the same full history.
They do not multiply ordinary marginal means. If one instead supplies valid
conditional marginals given this step is good, the one-step good mass must
also be retained: the previous sharp rearrangement upper is multiplied by
that good mass. This uses additional conditional-law premises, not empirical
pooling over selected successful samples.

For residual quantum state f=sqrt(V), the first squared term contains
(V_n/V_(n-1)) z^(2 Delta(A+E)) with the same good indicator. An actual quantum
application still needs a valid good subinstrument/operator inequality covering
all permitted private states, or a proved ideal-real coupling. An arbitrary
unobserved private-state predicate need not define a physical completely
positive subinstrument. The classical table supplies no such construction.
Outstanding entry/carryover E, retained progress and physical spending cannot
be discarded at restarts or when reporting a bad result.

For a shared global T and stopping-time claim starts tau_i<T, separately prove
each conditional pre-T crossing allowance alpha_i at its actual start. A
predictable, complete, non-refundable claim bank with pathwise sum alpha_i<=a,
together with (B), gives a+b for the union of all registered failures. Shared
bad-event risk is paid once only if it really is one proved global union;
different bad-event families need their own union accounting. The existing
persistent ledger checks declared local expenditure, not these probability,
world-coverage or pre-registration premises. Delayed detection does not justify
moving T after the first transition on which a required law already failed.

## Exact finite helper and independent controls

`check.py` accepts only in-process declared finite rational laws. It certifies
the direct kappa=1 inequality for every supplied state/action, including unused
ones. A None next-state denotes a bad outcome whose probability is paid; its
zero credit fields are unused canonical placeholders, not a claim of zero
physical cost or credit. Good outcomes retain their original probabilities.
The helper separately maximizes the finite bad-or-crossing event and the bad
event over adaptive policies by Bellman recursion. Its hazard allowance is the
finite pathwise ceiling horizon * maximum declared one-step bad mass. That
finite ceiling does not extend to an unbounded lifetime unless justified.

One benign control has good increments +1 with probability 1/8, -1 with 3/4,
and bad mass 1/8, z=2, f=1, gap=2, horizon=2. Its good-subkernel moment is
5/8. Independent arithmetic gives bad probability 15/64 and good two-up
crossing probability 1/64, hence union probability 1/4. The certificate gives
crossing allowance 1/4 plus hazard allowance 1/4, or 1/2 total. This is a
finite control, not a measured network reliability or native security bound.

Another control has good +1 with mass 1/2 and bad mass 1/2. Its killed
multiplier expectation is one, but its renormalized good-law multiplier is two.
Thus replacing the good subkernel by its normalized law changes the premise.
A retained residual release f=2 to f=1 with Delta D=1 correctly permits a
certain crossing; resetting f_0 to one would falsely reduce its allowance.

Seven tests include a separate enumeration of every tiny history-dependent
policy tree, without Bellman maximization, over 16 gap/horizon pairs; strict
mass/type/resource rejection; unused-action refusal; and residual controls.
Limits: 8 states, 32 total actions, 128 total branches, 64-bit rational parts,
per-field credit 0..4, horizon 0..8 and gap 0..16. The helper refuses beyond
8,192 arithmetic bits, 20,000 DP cells or 200,000 branch expansions. These
limits are research-helper limits, not native network or physical work bounds.

Run `python3 test_check.py -v` and `python3 check.py` from this directory.
Installed qualification is untouched: all thirteen actual obligations remain
open, native CP/CG/CQ and six-successor/lifetime risk bounds remain null, and
production activation false. Qualification remains **HOLD_NO_GO**.

Primary background: Howard, Ramdas, McAuliffe and Sekhon, *Time-uniform Chernoff
bounds via nonnegative supermartingales*, Probability Surveys 17 (2020),
257-317, section 2.3, Lemma 1. The checked author revision is arXiv v8,
17 December 2025: https://arxiv.org/html/1808.03204v8 . Its Ville argument is
standard background; the killed good-law specialization above is proved here
and is not presented as an existing native security theorem.

## Executed identity and retained checks

Seven methods and the exact control completed on evidence source
`85905b41943cd872fbaedbcfe19ea753839847ef`, tree
`949f5972d2b2d766cd2f229c680a83e66412b521`. Full tracked-source verification,
repository/link and CI-contract readers passed there. Qualification consistency
returned 0 while promotion correctly refused with exit 3. These are local
research checks, not Rust/native execution. This follow-up retains their raw
streams and source receipt without reassigning execution to its later head.
The retained snapshot of preceding head 3a4b46d has twenty queued/pending
workflows and no conclusions; original failed ROG r1 is not resubmitted.
