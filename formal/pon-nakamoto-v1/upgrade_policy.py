"""Conditional continuous-upgrade policy, not a native release or payment owner.

An independently pinned review key attests the declared conditions; its signature
does NOT prove beneficial ownership, fresh sampling, truthful costs or actual use.
The existing admission/evaluation/operations owners must supply those facts and
persist this bounded observation without rewinding it. Recreating this in-memory
object or restoring the entire host is not an anti-rollback mechanism.

For each precommitted control, D is paired utility minus all declared costs.
Z=(D-margin)/bound lies in [-1,1]. Under the CONDITIONAL-mean null
E[Z_i | previous observations] <= 0, product(1+bet*Z_i) is a nonnegative
supermartingale. Markov/Ville bounds its threshold crossing by alpha_k/4.
alpha_k=alpha/[k(k+1)] sums to alpha, including failed/cancelled attempts.
Fresh conditional validity is an assumption, not a consequence of a new digest.
The filtration includes all earlier candidates, outcomes, failures, cancellations
and choices made at begin; a merely marginal-mean null is insufficient under
arbitrary dependence. Canary receipts are observational gates, not a statistical
guarantee about a later population or a continuation of this e-process.
There is one fixed-size readout per attempt, not a sign test or a reused holdout.
"""
from __future__ import annotations
import copy
import json
from fractions import Fraction
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from contract_wire import H, canonical, unique
from strict_signature import verify

CONTROLS = ('current', 'best_single', 'mean_merge', 'pooled')
MODELS = ('candidate',) + CONTROLS
COST_PARTS = ('compute', 'evaluation', 'availability', 'serving')
SCHEMA = 'pon-continuous-upgrade-plan-v1'
FLAGS = dict(independent_acceptance=False, native_adoption_authorized=False,
             reward_authorized=False, production_activation=False)


def require(condition, code):
    if not condition:
        raise ValueError('UPGRADE_' + code)


def integer(value, low=0, high=(1 << 63)-1):
    require(type(value) is int and low <= value <= high, 'INTEGER')
    return value


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'DIGEST')
    return value


def rational(value):
    require(type(value) is list and len(value) == 2, 'RATIONAL')
    n, d = integer(value[0], -(10**9), 10**9), integer(value[1], 1, 10**9)
    result = Fraction(n, d)
    require([result.numerator, result.denominator] == value, 'RATIONAL_CANONICAL')
    return result


def ratio(value):
    # Ratios avoid canonical JSON's integer range; small summary values only.
    return [str(value.numerator), str(value.denominator)]


def root(domain, value):
    return H('continuous-upgrade-' + domain + '-v1', canonical(value)).hex()


def costs(value):
    require(type(value) is dict and set(value) == set(COST_PARTS), 'COMPLETE_COSTS')
    return sum(integer(value[name], 0, 10**12) for name in COST_PARTS)


def freeze_plan(**p):
    """Caller freezes actual artifacts, conversion and full fixed-cost allocation.

    Cost numbers use the one declared unit. Unknown GPU/storage/training costs
    cannot be represented as None or silently converted to zero here. A supplied
    zero remains a declaration requiring the accepting owner's evidence.
    Compute includes training/data acquisition; evaluation includes all controls.
    The frozen cost-unit contract must allocate migration, network and retention
    to these buckets. Rewards or subsidies do not reduce resource costs.
    """
    fields = {'context', 'parent', 'candidate', 'controls', 'window', 'canary_window',
              'data_owner', 'evaluation_protocol', 'independence_root', 'producer_control',
              'cost_unit', 'cost_conversion', 'overhead', 'utility_cap', 'cluster_cost_cap',
              'clusters', 'freeze_height', 'future_height', 'evaluate_until', 'canary_until',
              'margin', 'bet', 'bonus_units'}
    require(set(p) == fields, 'PLAN_FIELDS')
    for name in ('context', 'parent', 'candidate', 'window', 'canary_window', 'data_owner',
                 'evaluation_protocol', 'independence_root', 'producer_control', 'cost_unit'):
        digest(p[name])
    require(p['parent'] != p['candidate'] and p['window'] != p['canary_window'], 'PLAN_ALIAS')
    require(type(p['controls']) is dict and set(p['controls']) == set(CONTROLS), 'CONTROLS')
    for artifact in p['controls'].values():
        digest(artifact)
    require(p['controls']['current'] == p['parent'], 'CURRENT_CONTROL')
    require(type(p['overhead']) is dict and set(p['overhead']) == set(MODELS), 'OVERHEAD')
    for value in p['overhead'].values():
        costs(value)
    integer(p['utility_cap'], 1, 10**6); integer(p['cluster_cost_cap'], 1, 10**12)
    integer(p['clusters'], 20, 512); integer(p['bonus_units'])
    for name in ('freeze_height', 'future_height', 'evaluate_until', 'canary_until'):
        integer(p[name])
    require(p['freeze_height'] < p['future_height'] < p['evaluate_until'] < p['canary_until'], 'DEADLINES')
    require(rational(p['cost_conversion']) > 0 and rational(p['margin']) >= 0 and
            0 < rational(p['bet']) <= 1, 'POLICY_RANGE')
    plan = dict(schema=SCHEMA, **copy.deepcopy(p))
    raw = canonical(plan)
    require(len(raw) <= 32768, 'PLAN_LIMIT')
    return raw, root('plan', plan)


def signed_receipt(key, *, context, attempt, plan, phase, body, parent, height, expires,
                   independence='reviewed', window='fresh', cost='complete', adoption='not-applicable'):
    """Owner tooling/fixtures provide keys. This function creates no authority."""
    record = dict(schema='pon-continuous-upgrade-owner-receipt-v1', context=context,
                  attempt=attempt, plan=plan, phase=phase, body=root('body', body), parent=parent,
                  height=height, expires=expires,
                  conditions=dict(independence=independence, window=window, cost=cost, adoption=adoption),
                  signer=key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex())
    return dict(record=record, signature=key.sign(H('continuous-upgrade-owner-sign-v1', canonical(record))).hex())


class UpgradePolicy:
    """Append-only bounded policy observations; monetary/native authority stays out.

    The pin and entire history belong to the existing durable owner. This class
    has no round reset, parent-adoption, issuance, transfer or history restore API.
    'proposed_bonus_units' only limits aggregate proposals, not actual chain funds.
    """
    def __init__(self, *, context, owner_key, alpha, bonus_cap, max_attempts=64):
        self._context, self._owner_key = digest(context), digest(owner_key)
        self._alpha = rational(alpha)
        require(0 < self._alpha <= Fraction(1, 20), 'ALPHA')
        self._bonus_cap = integer(bonus_cap)
        self._max_attempts = integer(max_attempts, 1, 1024)
        self._entries, self._events = {}, []
        self._candidates, self._clusters, self._contents, self._uses = set(), set(), set(), set()
        self._height, self._proposed = 0, 0

    def _at(self, height):
        integer(height)
        require(height >= self._height, 'HEIGHT_REWIND')

    def _event(self, attempt, phase, height, value):
        self._at(height)
        self._events.append(dict(attempt=attempt, phase=phase, height=height, value=copy.deepcopy(value)))
        self._height = height

    def _entry(self, attempt, status):
        digest(attempt)
        require(attempt in self._entries and self._entries[attempt]['status'] == status, 'PHASE')
        return self._entries[attempt]

    def _result(self, entry):
        return dict(attempt=entry['attempt'], status=entry['status'],
                    reason=entry.get('reason'), proposed_bonus_units=entry.get('bonus', 0), **FLAGS)

    def _no_update(self, entry, reason, height):
        entry.update(status='NoUpdate', reason=reason)
        result = self._result(entry)
        self._event(entry['attempt'], 'NoUpdate', height, result)
        return result

    def _receipt(self, entry, receipt, phase, body, height, minimum_height):
        require(type(receipt) is dict and set(receipt) == {'record', 'signature'}, 'RECEIPT_FIELDS')
        record = receipt['record']
        fields = {'schema', 'context', 'attempt', 'plan', 'phase', 'body', 'parent',
                  'height', 'expires', 'conditions', 'signer'}
        require(type(record) is dict and set(record) == fields, 'RECEIPT_FIELDS')
        require(record['schema'] == 'pon-continuous-upgrade-owner-receipt-v1' and
                record['context'] == self._context and record['attempt'] == entry['attempt'] and
                record['plan'] == entry['digest'] and record['phase'] == phase and
                record['body'] == root('body', body) and record['parent'] == entry['plan']['parent'] and
                record['signer'] == self._owner_key, 'RECEIPT_BINDING')
        integer(record['height']); integer(record['expires'])
        require(max(entry['plan']['freeze_height'], minimum_height) <= record['height'] <= height <=
                record['expires'], 'RECEIPT_TIME')
        conditions = record['conditions']
        require(type(conditions) is dict and set(conditions) == {'independence', 'window', 'cost', 'adoption'}, 'CONDITIONS')
        for value in conditions.values():
            require(type(value) is str and value in {'reviewed', 'fresh', 'complete', 'observed',
                    'not-applicable', 'unknown', 'revoked', 'conflict'}, 'CONDITIONS')
        signature = receipt['signature']
        require(type(signature) is str and len(signature) == 128 and
                all(c in '0123456789abcdef' for c in signature), 'SIGNATURE')
        try:
            verify(bytes.fromhex(self._owner_key), bytes.fromhex(signature),
                   H('continuous-upgrade-owner-sign-v1', canonical(record)))
        except (InvalidSignature, ValueError) as error:
            raise ValueError('UPGRADE_SIGNATURE') from error
        return conditions == dict(independence='reviewed', window='fresh', cost='complete',
                                  adoption='not-applicable' if phase == 'evaluation' else 'observed')

    def begin(self, raw, expected_digest, *, current_parent, height):
        self._at(height); digest(expected_digest); digest(current_parent)
        require(type(raw) is bytes and len(raw) <= 32768, 'PLAN_LIMIT')
        plan = json.loads(raw, object_pairs_hook=unique)
        require(type(plan) is dict and plan.pop('schema', None) == SCHEMA, 'PLAN_SCHEMA')
        replay, identity = freeze_plan(**plan)
        require(replay == raw and identity == expected_digest, 'PLAN_BINDING')
        require(plan['context'] == self._context and plan['parent'] == current_parent, 'CONTEXT_OR_PARENT')
        require(height == plan['freeze_height'], 'FREEZE_HEIGHT')
        require(len(self._entries) < self._max_attempts, 'ATTEMPT_LIMIT')
        require(plan['candidate'] not in self._candidates, 'CANDIDATE_REPLAY')
        sequence = len(self._entries) + 1
        attempt = root('attempt', dict(context=self._context, sequence=sequence, plan=identity))
        alpha = self._alpha / (sequence * (sequence + 1))
        self._entries[attempt] = dict(attempt=attempt, sequence=sequence, plan=plan, digest=identity,
                                      status='frozen', alpha=alpha)
        self._candidates.add(plan['candidate'])
        self._event(attempt, 'frozen', height, dict(plan=identity, sequence=sequence, alpha=ratio(alpha)))
        return attempt

    def cancel(self, attempt, *, reason, height):
        self._at(height)
        digest(attempt)
        require(attempt in self._entries and self._entries[attempt]['status'] in
                {'frozen', 'conditional-evaluation-eligible', 'conditional-canary-observed'}, 'PHASE')
        entry = self._entries[attempt]
        require(type(reason) is str and reason in {'cancelled', 'timeout', 'execution-failed'}, 'CANCEL_REASON')
        return self._no_update(entry, reason, height)

    def evaluate(self, attempt, rows, receipt, *, current_parent, height):
        self._at(height); digest(current_parent)
        entry = self._entry(attempt, 'frozen'); p = entry['plan']
        require(p['future_height'] <= height <= p['evaluate_until'], 'EVALUATION_TIME')
        require(type(rows) is list and len(rows) == p['clusters'], 'FIXED_SAMPLE')
        conversion, margin, bet = (rational(p[n]) for n in ('cost_conversion', 'margin', 'bet'))
        overhead = {m: Fraction(costs(p['overhead'][m]), p['clusters']) for m in MODELS}
        bound = p['utility_cap'] + conversion * (p['cluster_cost_cap'] + max(overhead.values())) + margin
        evalues, sums = {m: Fraction(1) for m in CONTROLS}, {m: Fraction(0) for m in CONTROLS}
        clusters, contents = set(), set()
        for row in rows:
            require(type(row) is dict and set(row) == {'cluster', 'content', 'height', 'models'}, 'ROW_FIELDS')
            cluster, content = digest(row['cluster']), digest(row['content'])
            require(cluster not in clusters | self._clusters and content not in contents | self._contents, 'REUSED_HOLDOUT')
            clusters.add(cluster); contents.add(content)
            require(p['future_height'] <= integer(row['height']) <= height, 'FUTURE_WINDOW')
            models = row['models']
            require(type(models) is dict and set(models) == set(MODELS), 'MODEL_ALIGNMENT')
            net = {}
            for model, value in models.items():
                require(type(value) is dict and set(value) == {'utility', 'costs'}, 'MODEL_FIELDS')
                utility = integer(value['utility'], 0, p['utility_cap'])
                charge = costs(value['costs'])
                require(charge <= p['cluster_cost_cap'], 'COST_BOUND')
                net[model] = utility - conversion * (charge + overhead[model])
            for model in CONTROLS:
                difference = net['candidate'] - net[model]
                z = (difference - margin) / bound
                require(-1 <= z <= 1, 'NET_BOUND')
                evalues[model] *= 1 + bet*z
                sums[model] += difference
        accepted_conditions = self._receipt(entry, receipt, 'evaluation', rows, height,
                                            max(row['height'] for row in rows))
        summary = dict(rows=root('body', rows), receipt=root('receipt', receipt), clusters=len(rows),
                       alpha=ratio(entry['alpha']), per_control_alpha=ratio(entry['alpha']/len(CONTROLS)),
                       evalue_encoding='hex-rational-pair',
                       evalues={m: [hex(evalues[m].numerator), hex(evalues[m].denominator)] for m in CONTROLS},
                       net_means={m: ratio(sums[m]/len(rows)) for m in CONTROLS})
        self._clusters.update(clusters); self._contents.update(contents)
        entry['evaluation'] = summary
        self._event(attempt, 'evaluated', height, summary)
        if current_parent != p['parent']:
            return self._no_update(entry, 'stale-parent', height)
        if not accepted_conditions:
            return self._no_update(entry, 'owner-conditions-unqualified', height)
        if any(evalues[m] * entry['alpha'] < len(CONTROLS) or sums[m] <= margin*len(rows) for m in CONTROLS):
            return self._no_update(entry, 'insufficient-net-benefit-evidence', height)
        entry.update(status='conditional-evaluation-eligible', evaluated_at=height)
        return self._result(entry)

    def observe_canary(self, attempt, observation, receipt, *, current_parent, height):
        self._at(height); digest(current_parent)
        entry = self._entry(attempt, 'conditional-evaluation-eligible'); p = entry['plan']
        require(entry['evaluated_at'] < height <= p['canary_until'], 'CANARY_TIME')
        fields = {'candidate', 'window', 'consumer_control', 'operation', 'height', 'uses', 'net_gain', 'safety_failures'}
        require(type(observation) is dict and set(observation) == fields, 'CANARY_FIELDS')
        for name in ('candidate', 'window', 'consumer_control', 'operation'):
            digest(observation[name])
        require(observation['candidate'] == p['candidate'] and observation['window'] == p['canary_window'], 'CANARY_BINDING')
        require(entry['evaluated_at'] < integer(observation['height']) <= height, 'CANARY_TIME')
        integer(observation['uses'], 0, 10**6); integer(observation['safety_failures'], 0, 10**6)
        gain = rational(observation['net_gain'])
        require(observation['operation'] not in self._uses, 'CONSUMER_REPLAY')
        qualified = self._receipt(entry, receipt, 'canary', observation, height, observation['height'])
        self._uses.add(observation['operation'])
        entry['canary'] = dict(observation=root('body', observation), receipt=root('receipt', receipt),
                               observed_at=observation['height'], recorded_at=height)
        self._event(attempt, 'canary', height, entry['canary'])
        if current_parent != p['parent']:
            return self._no_update(entry, 'stale-parent', height)
        if not qualified or observation['consumer_control'] == p['producer_control']:
            return self._no_update(entry, 'canary-owner-conditions-unqualified', height)
        if observation['uses'] == 0 or gain <= 0 or observation['safety_failures']:
            return self._no_update(entry, 'canary-no-benefit-or-safety-failure', height)
        entry['status'] = 'conditional-canary-observed'
        return self._result(entry)

    def proposal_body(self, attempt):
        entry = self._entry(attempt, 'conditional-canary-observed')
        return dict(evaluation=copy.deepcopy(entry['evaluation']), canary=copy.deepcopy(entry['canary']),
                    bonus_units=entry['plan']['bonus_units'])

    def propose(self, attempt, receipt, *, current_parent, height):
        self._at(height); digest(current_parent)
        entry = self._entry(attempt, 'conditional-canary-observed'); p = entry['plan']
        require(height <= p['canary_until'], 'PROPOSAL_TIME')
        body = self.proposal_body(attempt)
        qualified = self._receipt(entry, receipt, 'proposal', body, height, entry['canary']['recorded_at'])
        if current_parent != p['parent'] or not qualified:
            return self._no_update(entry, 'stale-parent-or-current-owner-conditions', height)
        if self._proposed + p['bonus_units'] > self._bonus_cap:
            return self._no_update(entry, 'proposal-budget-exhausted', height)
        self._proposed += p['bonus_units']
        entry.update(status='conditional-promotion-proposal', bonus=p['bonus_units'])
        result = self._result(entry)
        self._event(attempt, 'proposal', height, result)
        return result

    def observation(self):
        return dict(schema='pon-continuous-upgrade-observation-v1', context=self._context,
                    attempts=len(self._entries), alpha_spent=ratio(sum((e['alpha'] for e in self._entries.values()), Fraction(0))),
                    proposed_bonus_units=self._proposed, proposal_budget=self._bonus_cap,
                    history_root=root('history', self._events), events=copy.deepcopy(self._events),
                    results=[self._result(e) for e in self._entries.values()],
                    durability_owner='existing-evaluation-artifacts-and-operations-outbox', **FLAGS)
