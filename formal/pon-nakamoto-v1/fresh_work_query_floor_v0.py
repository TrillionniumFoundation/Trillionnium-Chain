"""A conditional classical random-oracle query floor, not SHA-256 hardness.

This is an executable *model audit*, not a consensus profile, an oracle-query
attestation, or an activation switch. The research seal fixes L=64. Smaller or
larger L below are parameters of the mathematical model and its finite tests;
they do not negotiate the native seal's profile. Actual chainwork remains zero.

THEOREM (fixed L, classical black-box model).
Let M=2**bits. A candidate c uniquely and immutably determines its public seed,
legal target T_c, profile and length L before ANY index-L query for that c,
including speculative wrong-predecessor probes before registration/admission.
The seed is independent of the chain-step oracle's unrevealed outputs. Giving
this seed to the adversary for free only strengthens it. For i=1,...,L define

    z_0 = seed(c),   z_i = H(profile, c, i, z_(i-1)).

All tuples have injective encodings and disjoint domains across c, profile and
i. The ticket is z_L itself: there is no outer lottery over proof/carrier bytes.
T_c and the award L*floor(M/(T_c+1)) cannot be chosen after an earlier final-step
probe is retrospectively declared noncanonical. At most one award is counted
per c. Acceptance entails the
unique correct endpoint, the independently admitted useful relation and the
fixed target. Every accepted endpoint's first oracle evaluation is in the
accounting horizon, including verification of a claimed, previously unqueried
endpoint. All preprocessing, delegated, rejected, aborted and verifier queries
are charged; repeated queries may be charged too. There is a deterministic cap
q on total queries Q, including preprocessing before the measured online phase.

Then for a classical adaptive algorithm and any stopping time Q<=q, nominal
accepted credit C obeys

    E[C] <= min(L*E[Q], E[Q] + L*q*(q+1)/(2*M)).

The small additive term handles lazy guesses; it is not obtained by conditioning
on a collision-free execution. No matrix-arithmetic lower bound is assumed.

PROOF.
Immediately before each *first* final-step query, classify its input using the
past transcript. If all canonical prefix inputs are already in that transcript
and its predecessor is correct, call it prefix-revealed. This classification,
the target and the award are predictable. Its fresh answer is uniform, hence
its expected nominal award is at most L. Prefix-revealed final queries for
different candidates have disjoint sets of L queried inputs. Consequently
their total charge is pathwise at most Q, even if the prefix inputs themselves
were evaluated out of order. The bounded-stopping supermartingale argument
therefore bounds their expected credit by E[Q]. Eventual validity can only
remove awards; it need not be known when the query is made.

If the canonical prefix is not yet revealed, let s be the number of distinct
prefix-oracle inputs already queried for that c. Deferred decisions give

    P[true z_(L-1) equals the guessed predecessor | past] <= (s+1)/M.

To see this, explore the unique canonical prefix without granting the adversary
extra queries. After its first unknown response, exploration stays at fresh
inputs unless a response hits a predecessor label of an already queried prefix
input. There are at most s such labels in total, at their respective indices.
If none is hit, matching the guessed endpoint costs one further 1/M event.
Index separation prevents a new node from being an earlier exploration node.
Union bounding these events proves the inequality (clamped at one). This is a
statement about the underlying random function; later adaptive choices cannot
change whether the guessed predecessor was its unique correct value.

The current final-step answer is independent of these unknown prefix values
because its domain has index L. Multiplying by the precommitted target win
probability cancels the inverse-probability weight, so a lazy query's expected
eventual credit is at most L*(s+1)/M, without a maximum-award assumption. At the
t-th query, s+1<=t. Summing through the cap q gives the additive term above.
Ignoring prefix validity altogether gives the separate bound L*E[Q]. Both are
unconditional bounds. A known wrong predecessor cannot earn credit.

SCOPE AND TRANSFER OBLIGATIONS.
* This is an aggregate oracle-query floor, not a producer's own-wallet, CPU,
  energy, gate-count, memory, wall-time or neural-MAC lower bound. Full verifier
  replay can supply every query for a lucky producer guess. Owner labels in a
  submitted log are observations, not authentication or completeness proofs.
* A hashed challenge is not an injective candidate encoding as a mathematical
  fact. For the native seal, candidate/seed binding, canonical serialization,
  independently expected authorization and target, and no late digest
  rebinding remain separate cryptographic/protocol obligations. A bounded
  failure transfer needs an explicit admission cap and award cap; see
  bounded_failure_allowance. A collision probability alone does not bound
  unbounded credit or repair an unrestricted duplicate-credit rule.
* Several profiles require disjoint domains, predictable pricing by their own
  L, and the corresponding sum of charges; the fixed-L bound must not silently
  award one profile another profile's more expensive nominal cost. Selecting
  among legal candidates or bulk precommits is allowed and all queries count.
* An outer lottery over allowed mutable or unbound proof/carrier bytes, or an
  additional selectable nonce, can create extra independent cheap tickets.
  Hashing one unique canonical proof alone does not create that multiplicity.
  Reusing a correct Cell product is lawful and contributes no multiplicative
  credit. This model neither proves W1 hardness nor supplies a quantum bound.
* Classical random-oracle sequentiality is not a lower bound for all SHA-256
  implementations. Coherent quantum queries do not have this per-query
  conditional-uniform classical transcript and need a separate analysis.

Primary background (the special finite accounting lemma above is stated here,
not attributed as an unchanged theorem from these papers):
https://eprint.iacr.org/2018/183  (Cohen--Pietrzak, sequential work)
https://eprint.iacr.org/2018/559  (Ball et al., non-amortizable PoW)
https://eprint.iacr.org/2016/989  (Alwen et al., model-specific memory hardness)
https://arxiv.org/abs/quant-ph/9711070  (Zalka, quantum search)
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from fractions import Fraction


RESEARCH_STEPS = 64
RESEARCH_PROFILE = 'pon-grouped-int257-sealed-research-v0'
OWNERS = frozenset(('producer', 'preprocessing', 'delegate', 'verifier'))
MAX_LOG_QUERIES = 100_000
MAX_MODEL_STEPS = 4096
COALITION_IMPLEMENTATION_TRANSFER_ESTABLISHED = False
COALITION_PHYSICAL_COST_FLOOR_PROVED = False


def integer(value, name, minimum=0, maximum=None):
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise ValueError(name)
    return value


def modulus(bits):
    return 1 << integer(bits, 'BITS', 1, 256)


def nominal_award(target, *, bits=256, length=RESEARCH_STEPS):
    """Theoretical security-query denomination, never native chainwork."""
    size = modulus(bits)
    integer(target, 'TARGET', 1, size - 1)
    integer(length, 'LENGTH', 1)
    return length * (size // (target + 1))


def lazy_predecessor_bound(prefix_queries, *, bits=256):
    integer(prefix_queries, 'PREFIX_QUERIES')
    return min(Fraction(1), Fraction(prefix_queries + 1, modulus(bits)))


def backward_edge_union_bound(query_cap, *, bits=256):
    """A prior guessed edge meets a later fresh answer; no conditioning claim."""
    integer(query_cap, 'QUERY_CAP')
    return min(Fraction(1), Fraction(query_cap * (query_cap - 1), 2 * modulus(bits)))


def expected_credit_bound(query_cap, *, bits=256, length=RESEARCH_STEPS,
                          expected_queries=None):
    """Exact unconditional theorem envelope, under the module's assumptions."""
    integer(query_cap, 'QUERY_CAP')
    integer(length, 'LENGTH', 1)
    size = modulus(bits)
    mean = Fraction(query_cap) if expected_queries is None else expected_queries
    if type(mean) is not Fraction or not 0 <= mean <= query_cap:
        raise ValueError('EXPECTED_QUERIES')
    lazy = Fraction(length * query_cap * (query_cap + 1), 2 * size)
    return min(length * mean, mean + lazy)


def bounded_failure_allowance(probability, *, maximum_admissions, maximum_award):
    """Explicit transfer error; does not establish the binding-failure premise."""
    if type(probability) is not Fraction or not 0 <= probability <= 1:
        raise ValueError('FAILURE_PROBABILITY')
    integer(maximum_admissions, 'ADMISSION_CAP')
    integer(maximum_award, 'AWARD_CAP')
    return probability * maximum_admissions * maximum_award


def coalition_feedback_denominator(query_cap, verification_cap, *, bits=256):
    """The positive residual space in the separate hidden-verifier corollary."""
    integer(query_cap, 'QUERY_CAP')
    integer(verification_cap, 'VERIFICATION_CAP')
    remaining = modulus(bits) - verification_cap * (query_cap + 1)
    if remaining <= 0:
        raise ValueError('FEEDBACK_BUDGET_EXHAUSTS_ORACLE_SPACE')
    return remaining


def coalition_credit_bound(query_cap, verification_cap, maximum_award, *,
                           bits=256, length=RESEARCH_STEPS, expected_queries=None):
    """Separate coalition-query corollary with GENERAL endpoint feedback.

    This does not change the global-query theorem at the top of this module.
    In addition to its immutable identity, seed, statement, target and profile
    premises, assume all of the following:

    1. The classical adversarial coalition makes Q_A<=q chain-oracle queries.
       All its preprocessing, purchased/delegated work and externally supplied
       chain states are charged. Public seeds are granted for free but are
       independent of all still-hidden chain-step oracle values. There is no
       additional oracle-dependent advice. Domains for different candidates
       and indices are disjoint; hashed native identities require a separate
       binding argument. The unique canonical Cell statement is fixed BEFORE
       any speculative chain probe or verifier call, not selected afterward.
    2. At most K verifier calls reveal whether a supplied endpoint equals that
       unique canonical endpoint. This is an endpoint-EQUALITY oracle, not an
       arbitrary one-bit predicate of the internal chain. Guesses may be
       outside the winning set. Internal states, computed endpoints, timings,
       cache behavior, callbacks and all other execution side channels are
       hidden. Failure conveys at most that endpoint inequality. The first
       successful equality closes the candidate for credit, even for a miss;
       a winning candidate can receive at most one award. Subsequent repeated
       presentations cannot create fresh credit or new verifier information.
    3. The target is fixed before ALL probes/verification. Each nominal award
       W_c=L*floor(M/(T_c+1)) is at most the supplied Wmax. A fixed target floor
       T_min gives Wmax=nominal_award(T_min); this helper does not authenticate
       a caller's asserted cap. All credited candidates pass one of these K
       checks, including ones whose endpoint the coalition already computed.
    4. q and K are deterministic aggregate caps over the whole considered
       coalition, all verifiers, retries and restarts. Let D=M-K*(q+1)>0.

    Then, for mu=E[Q_A], nominal accepted credit satisfies

        E[C] <= min(K*Wmax,
                    (M/D)*mu + L*q*(q+1)/(2*D) + K*Wmax/D).

    The endpoint-guess allowance is explicitly K*Wmax*delta_guess, where
    delta_guess=1/D. It is NOT negligible uniformly in the legal target. With
    no coalition calls and one guessed winning endpoint, its exact mean award
    is L*floor(M/(T+1))/M; for T=1 this is L/2, independent of lambda. Thus a
    small success probability alone cannot establish a negligible mean award.
    For K*(q+1)<=M/2 and T>=T_min, the endpoint allowance is at most
    2*K*L/(T_min+1). Choosing an acceptable error requires an explicit target
    floor/award cap and submission cap, not just a large hash output length.

    PROOF OF THE FEEDBACK STEP.
    Fix a complete observed history and an as-yet-unclosed candidate c. First
    condition only on the oracle equalities described by the coalition's
    queried inputs/answers, holding the history's concrete queries fixed. This
    defines a base measure; it is not the distribution obtained by pretending
    the adaptive algorithm actually ran without its verification replies.
    The event of that full adaptive history additionally imposes the recorded
    equality/inequality replies. By domain and seed independence, predicates
    for other candidates do not further restrict c's remaining oracle values.
    Its own failed checks exclude a set S of at most K endpoint values.

    If c's canonical chain is not fully revealed in the coalition table, the
    same deferred-decisions frontier argument as the global theorem gives
    maximum endpoint point mass (s+1)/M <= (q+1)/M in this base measure. Here s
    counts previously queried chain inputs, including prequeried final inputs.
    After the first unknown response, reaching a known suffix requires hitting
    one of at most s known next-index labels; otherwise the final answer is
    fresh. Therefore the base probability of avoiding S is at least D/M.
    Conditioning on the failed checks increases any nonnegative expectation
    by at most M/D. This explicitly accounts for verifier-rejection feedback.

    A prefix-revealed fresh final query has base mean award at most L. After
    feedback it has mean at most L*M/D; disjoint L-input charges bound the
    aggregate contribution by (M/D)*E[Q_A]. A lazy first final query has base
    mean eventual award at most L*(s_prefix+1)/M, so conditioning and summing
    its predictable query positions gives L*q*(q+1)/(2*D).

    The remaining accepted claims have a canonical final input still UNQUERIED
    by the coalition at submission. Under the base measure their last-index
    answer is fresh, even if the prefix later joins a known earlier suffix;
    the joint event of an unqueried final input and the claimed output has
    probability at most 1/M. Failed-check conditioning makes this at most 1/D.
    At most K such submissions contribute K*Wmax/D. These classes cover every
    first credited candidate. The universal cap K*Wmax gives the minimum.

    TRANSFER IS UNESTABLISHED.
    A metered native research fixture does not prove hidden verifier state,
    lack of timing leakage, the coalition's query count, or a global K limit.
    A 4096-nonce window bounds identities in ONE capsule, not verifier calls:
    repeated endpoint guesses for one nonce must also consume K. A local
    journal alone cannot cap other receivers or restarted/copied authorities.
    Existing native seal helpers also accept a caller's statement hash; the
    independently verified full Cell/admission owner must fix the one valid
    statement before the corollary can apply. Actual chainwork remains zero.

    A native binding-failure game hop needs a separately proved probability
    and bounded consequences. For a deterministic q-budget formulation one
    can add Nmax*Wmax*delta_binding to its capped ideal-game bound. When using
    an expected Q_A from a different coupled game, its possible change must
    also be bounded; do not condition away the bad event or silently transfer
    that expectation. No physical resource or concrete SHA-256 theorem is
    supplied here.
    """
    remaining = coalition_feedback_denominator(query_cap, verification_cap, bits=bits)
    integer(maximum_award, 'AWARD_CAP')
    integer(length, 'LENGTH', 1)
    mean = Fraction(query_cap) if expected_queries is None else expected_queries
    if type(mean) is not Fraction or not 0 <= mean <= query_cap:
        raise ValueError('EXPECTED_QUERIES')
    queried = Fraction(modulus(bits), remaining) * mean
    lazy = Fraction(length * query_cap * (query_cap + 1), 2 * remaining)
    guessed = Fraction(verification_cap * maximum_award, remaining)
    return min(Fraction(verification_cap * maximum_award), queried + lazy + guessed)


@dataclass(frozen=True)
class Candidate:
    """An immutable full identity in the finite model, not a claimed hash ID.

    Inputs must already have an independently fixed target, seed and profile.
    Giving this model a candidate does not authenticate an external authority.
    """
    identity: bytes
    seed: int
    target: int
    profile: str = RESEARCH_PROFILE
    length: int = RESEARCH_STEPS


@dataclass(frozen=True)
class Query:
    identity: bytes
    index: int
    predecessor: int
    answer: int
    owner: str = 'producer'


@dataclass(frozen=True)
class Claim:
    identity: bytes
    endpoint: int
    after_queries: int
    carrier: bytes = b''


def _candidate(candidate, size):
    if type(candidate) is not Candidate:
        raise ValueError('CANDIDATE_TYPE')
    if type(candidate.identity) is not bytes or not 1 <= len(candidate.identity) <= 4096:
        raise ValueError('CANDIDATE_IDENTITY')
    if type(candidate.profile) is not str or not 1 <= len(candidate.profile) <= 128:
        raise ValueError('PROFILE')
    integer(candidate.seed, 'SEED', 0, size - 1)
    integer(candidate.target, 'TARGET', 1, size - 1)
    integer(candidate.length, 'LENGTH', 1, MAX_MODEL_STEPS)
    if candidate.profile == RESEARCH_PROFILE and candidate.length != RESEARCH_STEPS:
        raise ValueError('RESEARCH_PROFILE_FIXED_LENGTH')


def _input(candidate, index, predecessor):
    return candidate.profile, candidate.identity, index, predecessor


def _path(candidate, table, *, limit, stop_before_final=False):
    state = candidate.seed
    path = []
    stop = candidate.length - int(stop_before_final)
    for index in range(1, stop + 1):
        key = _input(candidate, index, state)
        record = table.get(key)
        if record is None or record['first_query'] > limit:
            return None
        path.append(record)
        state = record['answer']
    return state, path


def audit_query_log(candidates, queries, claims=(), *, bits=256):
    """Audit a complete supplied finite transcript; never infer its completeness.

    Answers are supplied by an external oracle/test fixture. Consistency is
    checked; uniformity, ownership, real execution and no omitted calls are not
    certified. All queries, including repeats and those of refused claims,
    remain in resource totals. Claim failure does not erase a query.
    """
    size = modulus(bits)
    if type(candidates) not in (tuple, list) or not candidates:
        raise ValueError('CANDIDATES')
    if type(queries) not in (tuple, list) or len(queries) > MAX_LOG_QUERIES:
        raise ValueError('QUERIES')
    if type(claims) not in (tuple, list) or len(claims) > MAX_LOG_QUERIES:
        raise ValueError('CLAIMS')
    registry, profiles = {}, {}
    for candidate in candidates:
        _candidate(candidate, size)
        previous = registry.get(candidate.identity)
        if previous is not None and previous != candidate:
            raise ValueError('CANDIDATE_REBINDING')
        old_length = profiles.get(candidate.profile)
        if old_length is not None and old_length != candidate.length:
            raise ValueError('PROFILE_SCALING_CONFLICT')
        registry[candidate.identity] = candidate
        profiles[candidate.profile] = candidate.length

    table, query_rows, owners = {}, [], Counter()
    prefix_final, lazy_final = [], []
    for ordinal, query in enumerate(queries, 1):
        if (type(query) is not Query or type(query.identity) is not bytes or
                query.identity not in registry):
            raise ValueError('QUERY_CANDIDATE')
        candidate = registry[query.identity]
        integer(query.index, 'QUERY_INDEX', 1, candidate.length)
        integer(query.predecessor, 'QUERY_PREDECESSOR', 0, size - 1)
        integer(query.answer, 'QUERY_ANSWER', 0, size - 1)
        if type(query.owner) is not str or query.owner not in OWNERS:
            raise ValueError('QUERY_OWNER')
        key = _input(candidate, query.index, query.predecessor)
        existing = table.get(key)
        if existing is not None and existing['answer'] != query.answer:
            raise ValueError('INCONSISTENT_ORACLE')
        classification = 'repeat' if existing is not None else 'prefix'
        if existing is None and query.index == candidate.length:
            prefix = _path(candidate, table, limit=ordinal - 1, stop_before_final=True)
            if prefix is None:
                classification = 'lazy-final'
                lazy_final.append(ordinal)
            elif prefix[0] == query.predecessor:
                classification = 'prefix-revealed-final'
                prefix_final.append((ordinal, candidate.identity, candidate.length))
            else:
                classification = 'wrong-known-predecessor'
        if existing is None:
            table[key] = dict(first_query=ordinal, answer=query.answer, input=key)
        owners[query.owner] += 1
        query_rows.append(dict(query=ordinal, first=existing is None,
                               classification=classification, owner=query.owner))

    completed, backward_edges, complete_charge = [], [], 0
    for candidate in registry.values():
        path = _path(candidate, table, limit=len(queries))
        if path is None:
            continue
        endpoint, records = path
        complete_charge += candidate.length
        completed.append(dict(identity=candidate.identity.hex(), endpoint=endpoint,
                              length=candidate.length,
                              first_queries=[row['first_query'] for row in records]))
        for index in range(1, len(records)):
            if records[index - 1]['first_query'] > records[index]['first_query']:
                backward_edges.append(dict(identity=candidate.identity.hex(),
                    predecessor_step=index, next_step=index + 1,
                    predecessor_query=records[index - 1]['first_query'],
                    guessed_query=records[index]['first_query']))

    claim_rows, accepted, nominal_credit, last_claim = [], set(), 0, 0
    for ordinal, claim in enumerate(claims, 1):
        if (type(claim) is not Claim or type(claim.identity) is not bytes or
                claim.identity not in registry):
            raise ValueError('CLAIM_CANDIDATE')
        integer(claim.endpoint, 'CLAIM_ENDPOINT', 0, size - 1)
        integer(claim.after_queries, 'CLAIM_TIME', last_claim, len(queries))
        if type(claim.carrier) is not bytes or len(claim.carrier) > 4096:
            raise ValueError('CLAIM_CARRIER')
        last_claim = claim.after_queries
        candidate = registry[claim.identity]
        path = _path(candidate, table, limit=claim.after_queries)
        award = 0
        if path is None:
            outcome = 'UNREVEALED_CHAIN'
        elif path[0] != claim.endpoint:
            outcome = 'ENDPOINT_MISMATCH'
        elif claim.endpoint > candidate.target:
            outcome = 'TARGET_MISS'
        elif claim.identity in accepted:
            outcome = 'DUPLICATE'
        else:
            outcome = 'MODEL_ACCEPTED'
            accepted.add(claim.identity)
            award = nominal_award(candidate.target, bits=bits, length=candidate.length)
            nominal_credit += award
        claim_rows.append(dict(claim=ordinal, identity=claim.identity.hex(),
                               after_queries=claim.after_queries, outcome=outcome,
                               nominal_model_credit=award, actual_chainwork=0))

    prefix_charge = sum(item[2] for item in prefix_final)
    if complete_charge > len(table) or prefix_charge > len(table):
        raise AssertionError('DISJOINT_QUERY_CHARGE')
    return dict(schema='pon-fresh-work-query-floor-model-v0', bits=bits,
        total_queries=len(queries), distinct_queries=len(table),
        query_counts_by_owner=dict(sorted(owners.items())), query_rows=query_rows,
        prefix_revealed_final_queries=[item[0] for item in prefix_final],
        lazy_final_queries=lazy_final,
        prefix_revealed_chain_query_charge=prefix_charge,
        completed_chain_query_charge=complete_charge, completed_chains=completed,
        backward_edges=backward_edges, claim_rows=claim_rows,
        accepted_unique_candidates=len(accepted), nominal_model_credit=nominal_credit,
        actual_chainwork=0, transcript_completeness_proved=False,
        producer_own_resource_floor_proved=False, physical_cost_floor_proved=False,
        neural_work_floor_proved=False, sha256_hardness_proved=False,
        quantum_bound_proved=False, production_activation=False)
