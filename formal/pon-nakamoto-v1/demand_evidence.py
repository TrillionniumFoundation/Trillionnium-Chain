"""Compose funded-demand evidence; observe money, never issue or authorize it.

This is a new, bounded research namespace. Role keys and the common-control
registry root must be pinned outside a producer's bundle. Signatures authenticate
owner statements, not their truth, independence, native execution or motivation.
The ordinary native funding/payment, replay, dispute and durable operation owners
must produce and verify these facts before a production adapter can exist.
"""
from __future__ import annotations

import copy
import json

from contract_wire import H, canonical, unique
from strict_signature import verify

ACCOUNTS = ('service', 'evaluation', 'availability', 'improvement')
ROLES = ('native', 'delivery', 'audit', 'evaluation', 'availability', 'adoption', 'dispute')
ORIGINS = ('external-attested', 'project-budget', 'self-or-related', 'unknown')
U64 = (1 << 64) - 1
SCHEMA = 'pon-demand-evidence-v1'
CONTRACT_FIELDS = {
    'context', 'request', 'requester', 'provider', 'parent', 'inputs', 'output_spec',
    'qualified_work', 'evaluation_protocol', 'fee_schedule', 'dispute_policy',
    'deadline', 'dispute_end', 'retention_until', 'fees', 'fixed_net_fees', 'beneficiaries',
}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def digest(value):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), 'DEMAND_DIGEST')
    return value


def units(value):
    require(type(value) is int and 0 <= value <= U64, 'DEMAND_UNITS')
    return value


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'DEMAND_FIELDS')


def commitment(kind, value):
    return H('demand-' + kind + '-v1', canonical(value)).hex()


def signed_record(key, *, context, kind, contract, payload):
    """Owner/test tooling only. This helper does not create an owner capability."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    signer = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    body = dict(schema=SCHEMA, context=context, kind=kind, contract=contract,
                signer=signer, payload=copy.deepcopy(payload))
    return dict(body=body, signature=key.sign(H('demand-owner-statement-v1', canonical(body))).hex())


def validate_contract(value):
    fields(value, CONTRACT_FIELDS)
    for key in CONTRACT_FIELDS - {'deadline', 'dispute_end', 'retention_until', 'fees', 'fixed_net_fees', 'beneficiaries'}:
        digest(value[key])
    for key in ('deadline', 'dispute_end', 'retention_until'):
        units(value[key])
    require(value['deadline'] < value['dispute_end'] <= value['retention_until'], 'DEMAND_WINDOWS')
    fields(value['fees'], ACCOUNTS)
    fields(value['fixed_net_fees'], ACCOUNTS[:-1])
    fields(value['beneficiaries'], ACCOUNTS)
    for account in ACCOUNTS:
        units(value['fees'][account]); digest(value['beneficiaries'][account])
        if account != 'improvement':
            require(units(value['fixed_net_fees'][account]) <= value['fees'][account], 'DEMAND_FIXED_NET_FEE')
    require(value['fees']['service'] > 0 and value['fees']['evaluation'] > 0, 'DEMAND_SERVICE_BUDGET')
    require(value['beneficiaries']['service'] == value['provider'], 'DEMAND_PROVIDER')
    require(value['beneficiaries']['improvement'] == value['provider'], 'DEMAND_IMPROVEMENT_BENEFICIARY')
    units(sum(value['fees'].values()))
    return commitment('contract', value)


class DemandEvidenceBook:
    """Append-only finite observation, not another economic or model ledger.

    Rejected bundles make no changes. Exact replay is idempotent. A new snapshot
    of a contract requires a separate owner reconciliation protocol, so this V1
    intentionally records each contract once, after all intended receipts exist.
    The existing operation/outbox owner must persist identities across restart,
    reorg and epochs. Reconstructing this Python object is NOT anti-rollback.
    """

    def __init__(self, *, context, owner_keys, registry_root, bonus_cap, max_records=4096):
        self.context = digest(context)
        fields(owner_keys, ROLES)
        self._keys = {role: digest(key) for role, key in owner_keys.items()}
        self._registry = digest(registry_root)
        self._cap = units(bonus_cap)
        require(type(max_records) is int and 1 <= max_records <= 4096, 'DEMAND_LIMIT')
        self._limit = max_records
        self._records = {}
        self._sources = set()
        self._operations = set()
        self._bonus_outputs = set()
        self._bonus_candidates = set()
        self._bonus_receipts = set()
        self._security = {}
        self._bonus_paid = 0

    def _statement(self, record, *, kind, contract, role=None, signer=None):
        fields(record, ('body', 'signature'))
        body = record['body']
        fields(body, ('schema', 'context', 'kind', 'contract', 'signer', 'payload'))
        require(body['schema'] == SCHEMA and body['context'] == self.context and
                body['kind'] == kind and body['contract'] == contract, 'DEMAND_STATEMENT_BINDING')
        expected = self._keys[role] if role else signer
        require(body['signer'] == digest(expected), 'DEMAND_AUTHORITY')
        signature = record['signature']
        require(type(signature) is str and len(signature) == 128 and
                all(c in '0123456789abcdef' for c in signature), 'DEMAND_SIGNATURE')
        verify(bytes.fromhex(expected), bytes.fromhex(signature),
               H('demand-owner-statement-v1', canonical(body)))
        require(type(body['payload']) is dict, 'DEMAND_PAYLOAD')
        return copy.deepcopy(body['payload'])

    def _origin(self, record, contract, terms, now, since):
        if record is None:
            return 'unknown', False, None
        data = self._statement(record, kind='provenance', contract=contract, role='audit')
        fields(data, ('registry', 'valid_from', 'valid_until', 'classification',
                      'control_groups', 'evidence', 'status'))
        require(data['registry'] == self._registry, 'DEMAND_REGISTRY')
        require(units(data['valid_from']) <= since <= now <= units(data['valid_until']), 'DEMAND_PROVENANCE_WINDOW')
        require(data['classification'] in ORIGINS and data['status'] in
                ('complete', 'unknown', 'revoked', 'conflicted'), 'DEMAND_PROVENANCE')
        digest(data['evidence'])
        groups = data['control_groups']
        fields(groups, ('requester', 'provider', 'evaluator', 'auditor', 'adopter'))
        for value in groups.values():
            if value is not None:
                digest(value)
        # A signed map is an external attestation, not proof of beneficial ownership.
        known = data['status'] == 'complete' and all(v is not None for v in groups.values())
        related = terms['requester'] == terms['provider'] or (
            groups['requester'] is not None and groups['requester'] == groups['provider'])
        origin = data['classification']
        if related:
            origin = 'self-or-related'
        else:
            audit_clear = (known and groups['auditor'] not in {groups['requester'], groups['provider']} and
                           self._keys['audit'] not in {terms['requester'], terms['provider']})
            if origin == 'external-attested' and not audit_clear:
                origin = 'unknown'
        # A customer may itself use its purchase. Adoption must be independent
        # of the producer, not artificially a different sixth economic actor.
        independent = (known and origin == 'external-attested' and groups['evaluator'] not in
            {groups['requester'], groups['provider'], groups['auditor']} and
            groups['adopter'] not in {groups['provider'], groups['auditor']} and
            len({terms['requester'], terms['provider'], self._keys['evaluation'], self._keys['audit']}) == 4 and
            self._keys['adoption'] not in {terms['provider'], self._keys['audit']})
        return origin, independent, data['valid_until']

    def observe(self, raw, *, expected_contract, expected_anchor, height):
        """Verify one frozen evidence bundle and retain its conditional accounting.

        The expected contract/anchor and installed keys come from the accepting
        owner, not from the untrusted bundle. Units are native development units;
        no conversion into fiat revenue or proof of market demand is implied.
        """
        digest(expected_contract); digest(expected_anchor); units(height)
        require(type(raw) is bytes and 0 < len(raw) <= 262144, 'DEMAND_BUNDLE_LIMIT')
        bundle = json.loads(raw, object_pairs_hook=unique)
        fields(bundle, ('contract', 'request', 'funding', 'provenance', 'delivery', 'acceptance',
                        'dispute', 'evaluation', 'availability', 'adoption', 'payments'))
        require(canonical(bundle) == raw, 'DEMAND_CANONICAL')
        terms = bundle['contract']
        require(validate_contract(terms) == expected_contract and terms['context'] == self.context,
                'DEMAND_CONTRACT_BINDING')
        identity = commitment('bundle', bundle)
        previous = self._records.get(expected_contract)
        if previous is not None:
            require(previous['bundle'] == identity and previous['anchor'] == expected_anchor and
                    previous['observed_height'] == height, 'DEMAND_REPLAY_CONFLICT')
            return copy.deepcopy(previous)
        require(len(self._records) + len(self._security) < self._limit, 'DEMAND_LIMIT')
        request = self._statement(bundle['request'], kind='request', contract=expected_contract,
                                  signer=terms['requester'])
        require(request == {'terms': expected_contract}, 'DEMAND_REQUEST')
        funding = self._statement(bundle['funding'], kind='funding', contract=expected_contract, role='native')
        fields(funding, ('anchor', 'observed_at', 'valid_until', 'locked_at', 'sources'))
        require(funding['anchor'] == expected_anchor and units(funding['locked_at']) <= terms['deadline'] and
                funding['locked_at'] <= units(funding['observed_at']) <= height <= units(funding['valid_until']),
                'DEMAND_FUNDING_WINDOW')
        fields(funding['sources'], ACCOUNTS)
        sources = set()
        for account, source in funding['sources'].items():
            if terms['fees'][account] == 0:
                require(source is None, 'DEMAND_ZERO_SOURCE')
                continue
            fields(source, ('source', 'payer', 'beneficiary', 'units', 'state'))
            digest(source['source'])
            require(source['source'] not in sources | self._sources, 'DEMAND_SOURCE_REUSE')
            sources.add(source['source'])
            require(source['payer'] == terms['requester'] and
                    source['beneficiary'] == terms['beneficiaries'][account] and
                    units(source['units']) == terms['fees'][account] and
                    source['state'] in ('locked', 'settled'), 'DEMAND_FUNDED_TERMS')
        origin, independent, provenance_valid_until = self._origin(
            bundle['provenance'], expected_contract, terms, height, funding['locked_at'])
        due = dict.fromkeys(ACCOUNTS, False)
        delivered = False
        output = None
        output_key = None
        if bundle['delivery'] is not None:
            delivery = self._statement(bundle['delivery'], kind='delivery', contract=expected_contract, role='delivery')
            fields(delivery, ('output', 'completed_at', 'complete', 'correct', 'verification'))
            digest(delivery['output']); digest(delivery['verification'])
            require(type(delivery['complete']) is bool and type(delivery['correct']) is bool, 'DEMAND_DELIVERY')
            require(funding['locked_at'] <= units(delivery['completed_at']) <= height, 'DEMAND_CHRONOLOGY')
            output = delivery['output']
            delivered = (delivery['complete'] and delivery['correct'] and
                         delivery['completed_at'] <= terms['deadline'])
            output_key = commitment('unique-result', {k: terms[k] for k in
                ('context', 'parent', 'inputs', 'output_spec')} | {'output': output})
        accepted = False
        if bundle['acceptance'] is not None:
            acceptance = self._statement(bundle['acceptance'], kind='acceptance', contract=expected_contract,
                                         signer=terms['requester'])
            fields(acceptance, ('output', 'accepted_at'))
            require(delivered and acceptance['output'] == output and
                    delivery['completed_at'] <= units(acceptance['accepted_at']) <= height,
                    'DEMAND_ACCEPTANCE')
            accepted = True
        resolution = 'none'
        if bundle['dispute'] is not None:
            dispute = self._statement(bundle['dispute'], kind='dispute', contract=expected_contract, role='dispute')
            fields(dispute, ('policy', 'output', 'verdict', 'resolved_at', 'evidence'))
            require(dispute['policy'] == terms['dispute_policy'] and dispute['output'] == output,
                    'DEMAND_DISPUTE_BINDING')
            require(dispute['verdict'] in ('pay-service', 'refund', 'unresolved'), 'DEMAND_DISPUTE')
            require(dispute['verdict'] != 'pay-service' or delivered, 'DEMAND_DISPUTE_DELIVERY')
            earliest_resolution = delivery['completed_at'] if output is not None else funding['locked_at']
            require(earliest_resolution <= units(dispute['resolved_at']) <= min(height, terms['dispute_end']),
                    'DEMAND_DISPUTE_WINDOW')
            digest(dispute['evidence'])
            resolution = dispute['verdict']
        due['service'] = delivered and (accepted if resolution == 'none' else resolution == 'pay-service')
        outcome = 'unobserved'
        evaluation_id = None
        if bundle['evaluation'] is not None:
            evaluation = self._statement(bundle['evaluation'], kind='evaluation', contract=expected_contract,
                                         signer=terms['beneficiaries']['evaluation'])
            require(terms['beneficiaries']['evaluation'] == self._keys['evaluation'], 'DEMAND_EVALUATOR_PIN')
            fields(evaluation, ('protocol', 'output', 'completed_at', 'fulfilled', 'outcome', 'result'))
            require(delivered and evaluation['protocol'] == terms['evaluation_protocol'] and
                    evaluation['output'] == output and type(evaluation['fulfilled']) is bool,
                    'DEMAND_EVALUATION_BINDING')
            require(delivery['completed_at'] <= units(evaluation['completed_at']) <= height,
                    'DEMAND_CHRONOLOGY')
            require(evaluation['outcome'] in ('positive-net', 'no-gain', 'inconclusive'), 'DEMAND_EVALUATION')
            digest(evaluation['result'])
            due['evaluation'] = evaluation['fulfilled']
            outcome = evaluation['outcome']
            evaluation_id = commitment('evaluation', bundle['evaluation'])
        if bundle['availability'] is not None:
            availability = self._statement(bundle['availability'], kind='availability', contract=expected_contract,
                                           role='availability')
            fields(availability, ('output', 'retained_from', 'retained_until', 'complete', 'evidence'))
            require(delivered and availability['output'] == output and type(availability['complete']) is bool and
                    units(availability['retained_from']) <= delivery['completed_at'] and
                    terms['retention_until'] <= units(availability['retained_until']) <= height,
                    'DEMAND_AVAILABILITY')
            digest(availability['evidence'])
            due['availability'] = availability['complete']
        adoption_id = None
        if bundle['adoption'] is not None:
            adoption = self._statement(bundle['adoption'], kind='adoption', contract=expected_contract, role='adoption')
            fields(adoption, ('parent', 'candidate', 'evaluation', 'receipt', 'observed_at', 'status', 'evidence'))
            require(adoption['parent'] == terms['parent'] and adoption['candidate'] == output and
                    adoption['evaluation'] == evaluation_id and evaluation_id is not None,
                    'DEMAND_ADOPTION_BINDING')
            require(evaluation['completed_at'] <= units(adoption['observed_at']) <= height and
                    adoption['status'] in ('adopted', 'rolled-back', 'unknown'), 'DEMAND_ADOPTION')
            digest(adoption['receipt']); digest(adoption['evidence'])
            adoption_id = adoption['receipt']
            due['improvement'] = (due['service'] and due['evaluation'] and independent and output != terms['parent'] and
                origin == 'external-attested' and outcome == 'positive-net' and adoption['status'] == 'adopted' and
                (terms['fees']['availability'] == 0 or due['availability']))
        require(type(bundle['payments']) is list and len(bundle['payments']) <= len(ACCOUNTS), 'DEMAND_PAYMENTS')
        paid = dict.fromkeys(ACCOUNTS, 0)
        gross = dict.fromkeys(ACCOUNTS, 0)
        operations = set()
        for receipt in bundle['payments']:
            payment = self._statement(receipt, kind='payment', contract=expected_contract, role='native')
            fields(payment, ('account', 'source', 'operation', 'beneficiary', 'output', 'anchor',
                             'gross_units', 'net_units', 'settled_at'))
            account = payment['account']
            require(type(account) is str and account in ACCOUNTS and gross[account] == 0 and
                    due[account] and terms['fees'][account] > 0, 'DEMAND_INELIGIBLE_PAYMENT')
            require(payment['source'] == funding['sources'][account]['source'] and
                    funding['sources'][account]['state'] == 'settled' and
                    payment['beneficiary'] == terms['beneficiaries'][account] and payment['output'] == output and
                    payment['anchor'] == expected_anchor, 'DEMAND_PAYMENT_BINDING')
            digest(payment['operation'])
            require(payment['operation'] not in operations | self._operations, 'DEMAND_PAYMENT_REPLAY')
            operations.add(payment['operation'])
            amount = units(payment['gross_units']); net = units(payment['net_units'])
            earliest = delivery['completed_at']
            if account == 'service':
                earliest = dispute['resolved_at'] if resolution == 'pay-service' else acceptance['accepted_at']
            elif account == 'evaluation':
                earliest = evaluation['completed_at']
            elif account == 'availability':
                earliest = availability['retained_until']
            elif account == 'improvement':
                earliest = max(adoption['observed_at'], acceptance['accepted_at'] if resolution == 'none'
                               else dispute['resolved_at'],
                               availability['retained_until'] if terms['fees']['availability'] else 0)
            require(0 < amount <= terms['fees'][account] and net <= amount and
                    earliest <= units(payment['settled_at']) <= height, 'DEMAND_PAYMENT_AMOUNT')
            # Fixed contracted service/evaluation/DA fees cannot depend on a positive vote.
            require(account == 'improvement' or amount == terms['fees'][account], 'DEMAND_FIXED_FEE')
            require(account == 'improvement' or net == terms['fixed_net_fees'][account], 'DEMAND_FIXED_NET_FEE')
            gross[account] = amount; paid[account] = net
        if gross['improvement']:
            require(output_key not in self._bonus_outputs and output not in self._bonus_candidates and
                    adoption_id not in self._bonus_receipts,
                    'DEMAND_DUPLICATE_IMPROVEMENT')
            require(self._bonus_paid + gross['improvement'] <= self._cap, 'DEMAND_GLOBAL_BONUS_CAP')
        for account in ACCOUNTS:
            units(sum(r['paid'][account] for r in self._records.values()) + paid[account])
            units(sum(r['gross'][account] for r in self._records.values()) + gross[account])
        observation = dict(schema='pon-demand-composition-observation-v2', contract=expected_contract,
            bundle=identity, anchor=expected_anchor, observed_height=height,
            origin=origin, independence_attested=independent, delivered=delivered, output_key=output_key,
            delivery_observed=bundle['delivery'] is not None,
            evaluation_outcome=outcome, dispute=resolution, conditional_fee_due=due,
            paid=paid, gross=gross, deadline=terms['deadline'], qualified_work=terms['qualified_work'],
            funding_valid_until=funding['valid_until'],
            provenance_valid_until=provenance_valid_until,
            funding_available=all(s is None or s['state'] == 'locked' for s in funding['sources'].values()),
            status=('NoUpdate' if not due['improvement'] else 'conditional-adoption-observed'),
            native_adapter_verified=False, independent_demand_proven=False,
            payment_authorized=False, dispatch_authorized=False, production_activation=False)
        # All validation completes before any bounded observation state changes.
        self._records[expected_contract] = observation
        self._sources.update(sources); self._operations.update(operations)
        self._bonus_paid += gross['improvement']
        if gross['improvement']:
            self._bonus_outputs.add(output_key); self._bonus_receipts.add(adoption_id)
            self._bonus_candidates.add(output)
        return copy.deepcopy(observation)

    def record_security(self, record):
        data = self._statement(record, kind='security-reward', contract=self.context, role='native')
        fields(data, ('reward', 'operation', 'beneficiary', 'gross_units', 'net_units', 'anchor'))
        for key in ('reward', 'operation', 'beneficiary', 'anchor'):
            digest(data[key])
        require(units(data['net_units']) <= units(data['gross_units']), 'DEMAND_PAYMENT_AMOUNT')
        previous = self._security.get(data['reward'])
        if previous is not None:
            require(previous == data, 'DEMAND_REPLAY_CONFLICT')
            return
        require(len(self._records) + len(self._security) < self._limit, 'DEMAND_LIMIT')
        require(data['operation'] not in self._operations, 'DEMAND_PAYMENT_REPLAY')
        units(sum(x['gross_units'] for x in self._security.values()) + data['gross_units'])
        self._security[data['reward']] = data
        self._operations.add(data['operation'])

    def queue_observation(self, *, height, expected_anchor):
        """Classify only this finite supplied inventory; not global queue discovery."""
        units(height); digest(expected_anchor)
        eligible = [r for r in self._records.values() if not r['delivery_observed'] and
                    r['dispute'] == 'none' and r['funding_available'] and
                    r['observed_height'] <= height <= min(r['deadline'], r['funding_valid_until']) and
                    (r['provenance_valid_until'] is None or height <= r['provenance_valid_until']) and
                    r['anchor'] == expected_anchor]
        priority = {'external-attested': 0, 'project-budget': 1, 'self-or-related': 2, 'unknown': 3}
        eligible.sort(key=lambda r: (priority[r['origin']], r['deadline'], r['contract']))
        if eligible:
            r = eligible[0]
            return dict(mode='funded-' + r['origin'], contract=r['contract'],
                        qualified_work=r['qualified_work'], dispatch_authorized=False)
        return dict(mode='existing-native-maintenance', useful_output_credit=0,
                    production_activation=False, dispatch_authorized=False)

    def snapshot(self):
        records = list(self._records.values())
        outputs = {r['output_key'] for r in records if r['delivered']}
        external = {r['output_key'] for r in records if r['delivered'] and r['origin'] == 'external-attested'}
        return dict(schema='pon-demand-book-observation-v1', contracts=len(records),
            accounts={'security': sum(r['net_units'] for r in self._security.values())} |
                     {a: sum(r['paid'][a] for r in records) for a in ACCOUNTS},
            service_receipts_by_origin={o: sum(r['paid']['service'] for r in records if r['origin'] == o)
                                        for o in ORIGINS},
            complete_unique_outputs=len(outputs), external_attested_unique_outputs=len(external),
            improvement_gross_observed=self._bonus_paid, improvement_cap=self._cap,
            repeated_complete_outputs=sum(r['delivered'] for r in records) - len(outputs),
            business_work_reuse_ratio=None, reuse_ratio_reason='requires-complete-owner-work-and-cost-denominator',
            native_adapter_verified=False, independent_demand_proven=False,
            payment_authorized=False, production_activation=False)
