# Exact qubit good-instrument tail certificate

Conditional mathematics and finite declared-model checking only. This supplies
an executable operator-level specialization of the earlier residual-state and
killed good-subkernel interfaces. It is not a new general probability theorem,
actual W1 oracle construction, native law, quantum hardware qualification or
claim that any of the thirteen actual joint obligations has closed. Installed
qualification, source pins, native code and CI acceptance rules are untouched.

## One history, complete instruments, retained initial state

Fix one initial classical history, z>1, and a finite cut horizon H before seeing
future outcomes. D starts at zero and records A+E-J along good cuts. At each
declared public state h, a normalized conditional qubit state rho is retained;
rho is not inserted as a fully observed classical random variable. Every
operation, including any measurement used to select a later action, must be
represented in the declared instrument history. Unrepresented measurements,
coherent action selection, oracle calls and active external registers are not
covered by merely selecting a favorable declared action.

For every declared action at h, each outcome o has a real rational 2x2 Kraus
matrix K_o, next public state h_o or a bad label, and a good credit increment
delta_o. The checker first requires sum_o K_o^* K_o = I, including the bad
outcomes. Thus these matrices specify a complete abstract CP instrument.
They do not establish its native implementability or physical resource cost.
Distinct Kraus outcomes are declared observed outcomes; treating hidden Kraus
indices as observed requires a separate model refinement, not an inference.

Let F_h be a real symmetric witness satisfying F_h >= I. For every action
require the exact PSD inequalities

    sum_good z^delta_o K_o^* F_(h_o) K_o <= F_h,                 (QK)
    sum_bad K_o^* K_o <= b_(h,a) I,     0 <= b_(h,a) <= 1.       (QB)

These are matrix inequalities, not checks of diagonal entries, sampled states
or a renormalized successful law. The adjoint identity proves (QK) uniformly
over all complex qubit density operators: outcome probability is
p_o=Tr(K_o rho K_o^*) and its normalized successor is K_o rho K_o^*/p_o.
For p_o=0 the contribution is zero; no division is needed in the certificate.
Multiplying by p_o and summing good outcomes gives

    E[1{next good} Tr(F_next rho_next) z^delta | current history]
      = Tr(rho sum_good z^delta K_o^* F_next K_o)
      <= Tr(rho F_h).

If T is the first modeled bad outcome, the killed process
M_n=1{T>n} z^D_n Tr(F_(h_n) rho_n) is a nonnegative supermartingale.
On already dead histories its next value is zero. The full residual initial
potential Tr(F_initial rho_initial) is kept. All-action inequalities allow
adaptive selection and stopping among those declared actions; they do not
prove that the finite action class simulates every legal algorithm.

With f_upper I >= F_initial, Ville bounds a pre-bad crossing of gap d by
min(1,f_upper z^(-d)). The implementation uses the rational Gershgorin bound
max_i(F_ii + sum_(j!=i) |F_ij|) for f_upper, so it does not assume knowledge
of the private initial density operator. (QB), disjoint first-bad events and
the union bound give H*b_max as an unrefunded finite spending ceiling and
min(1,H*b_max) as its probability cap. The reported union allowance is capped
at one. It is not an unbounded lifetime spending theorem. A bad initial cut
requires a separate allowance; safe initialization is a premise here.

The same PSD inequalities tensored with an identity remain valid for a passive
reference entangled with the qubit, when every instrument really acts as
K_o tensor I and every witness as F_h tensor I. This does not cover an active
adversarial ancilla, purified oracle registers acted on by future queries, or
unmodeled memory merely because it is called a reference. The prior full
joint-state operator requirement remains mandatory for those cases.

Only a separately proved inclusion of the native failure event in bad-or-gap
events would transfer this conditional calculation to CP/CG/CQ or the exact
native two-threshold confirmation rule. Such an inclusion, the native marked
set/cost reduction, dynamic participation model, complete delivery/service
laws and lifecycle spending are not supplied by these matrices. Zero unused
credit fields on a bad branch do not erase its physical costs or inventory.

## Exact checker and independent controls

For real symmetric 2x2 matrices, nonnegative diagonals and determinant are
necessary and sufficient for PSD; this also tests order against arbitrary
complex qubit density operators. All arithmetic is Fraction arithmetic with
bounded inputs and intermediate bit counts. This is an in-process certificate
API, not a parser for untrusted network or disk models. Scope: at most8 public
states,32 actions,128 total outcomes, real rational 2x2 matrices with64-bit
input parts,8192-bit intermediate arithmetic, credits0..4 per field, z in(1,4],
H0..8 and gap0..16. No native budget or input threshold is changed.

The fixed benign instrument uses scalar Kraus factors3/13,12/13,4/13 for
good+1, good-1 and bad, respectively. The complete probability is one. For
z=2,F=I the good moment is90/169; the bad mass is16/169. At H=2,gap=2,
independent disjoint-event arithmetic gives bad-or-crossing probability
5233/28561. The certificate's upper allowance is297/676. These numbers are
declared-model controls, never observed network risks.

Thirteen tests include an independent enumeration of all scalar outcome
histories over25 horizon/gap pairs; a noncommuting rational rotation of a
witness; and a coherent projection control whose good moment has both
diagonals equal to one but eigenvalue two. A diagonal-only or maximally mixed
state check would miss that violation; the PSD check refuses it. A certain
residual release requires initial witness2I; resetting it to I is refused.
Other controls retain all instrument mass, bad-event charges, unused actions,
and spending greater than one without refunding it to its probability cap.

Run from this evidence directory:

    python3 -m unittest -v test_check.py
    python3 check.py

No archived workload, native test, service, wallet or third-party target is
executed. No exploitation/reproduction workflow is generated. The evidence
implements only abstract linear algebra and original mathematical controls.
All actual production bounds remain null and qualification HOLD_NO_GO.

Background within this repository: the adjoint-instrument proof in
[STATEFUL_RESOURCE_TAIL_V1.md](../../../formal/pon-nakamoto-v1/STATEFUL_RESOURCE_TAIL_V1.md)
and the [killed classical good-subkernel note](../killed-bad-events/README.md).
This executable specialization addresses the latter note's missing declared
qubit subinstrument check, not its missing full native quantum reduction.
