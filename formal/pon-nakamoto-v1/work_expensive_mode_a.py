"""Offline Mode-A chronology and unique-work accounting experiment.

This is NOT a new consensus profile, authenticated beacon, wall-clock service,
Sybil defence, cost lower bound or durable rollback owner. The caller supplies
observed times and an externally checked challenge-owner receipt. A non-rewinding
external checkpoint is mandatory when restoring a saved journal. A local hash
chain alone cannot detect rollback or dishonest omitted work.

The frozen contract commits complete task/model/input/routing/shape/numeric/state
identities. ``reveal`` returns a ``seed`` bound to the entire frozen candidate set
and its parent/branch/round; pass this seed to the existing shared-material native
runner. ``challenge`` uses that runner's exact challenge domain. Only the full
existing scalar W1 oracle can produce a relation-qualified observation here.
Grouping correctness, task eligibility and actual Node admission are not implied.

The configured cycle count and attempt cap are frozen before reveal. Each
registration records cycles in order, with consecutive nonces, stopping at its
first reported target hit or at exhaustion. Closing an incomplete search records
the missing cycles explicitly. This checks the disclosed controlled run only;
neither that census nor a target-hit claim proves absence of secret attempts.
"""
from __future__ import annotations

from copy import deepcopy
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile

from contract_wire import H, canonical, unique
from work_oracle import CELLS, PROOF_BYTES, field_bytes, verify

SCHEMA = 'pon-work-expensive-mode-a-research-v2'
PROFILE = 'pon-matmul-transcript-64-v1'
SEARCH_STOP_RULE = 'first-target-hit-or-exhaustion-v1'
CONTRACT_FIELDS = frozenset((
    'profile', 'task', 'model', 'cell', 'generation', 'state_before',
    'transition', 'input_commitment', 'request_commitment', 'route_commitment',
    'shape', 'numeric_contract', 'output_contract',
))
HASH_FIELDS = CONTRACT_FIELDS - {'profile', 'generation', 'shape'}
ZERO = '00' * 32
MAX_EVENTS = 32768
MAX_EVENT_BYTES = 256 * 1024
MAX_JOURNAL_BYTES = 128 * 1024 * 1024
MAX_IDEAL_ENVELOPE_EXACT_BITS = 1_048_576


def require(condition, code):
    if not condition:
        raise ValueError(code)


def integer(value, code='INTEGER', minimum=0, maximum=(1 << 64) - 1):
    require(type(value) is int and minimum <= value <= maximum, code)
    return value


def digest(value, code='HASH'):
    require(type(value) is str and len(value) == 64 and
            all(c in '0123456789abcdef' for c in value), code)
    return bytes.fromhex(value)


def label(value, code='LABEL'):
    require(type(value) is str and 1 <= len(value) <= 96 and
            all(c.isascii() and (c.isalnum() or c in '-_/.:') for c in value), code)
    return value


def contract_bytes(value):
    require(type(value) is dict and set(value) == CONTRACT_FIELDS, 'CONTRACT_FIELDS')
    require(value['profile'] == PROFILE, 'RELATION_PROFILE_NOT_IMPLEMENTED')
    for key in HASH_FIELDS:
        digest(value[key], 'CONTRACT_' + key.upper())
    integer(value['generation'], 'GENERATION')
    shape = value['shape']
    require(type(shape) is list and 2 <= len(shape) <= 8, 'SHAPE')
    for n in shape:
        integer(n, 'SHAPE', 1, 4096)
    return canonical(value)


def family_id(contract):
    """No parent, lottery nonce, serialization or proof randomness in a family."""
    return H('pon-work-expensive-family-v1', contract_bytes(contract)).hex()


def _scope(branch, parent):
    return label(branch, 'BRANCH') + '@' + digest(parent, 'PARENT').hex()


def ideal_selection_envelope(target_hex, seed_choices, candidate_count):
    """Explicit independent-uniform model, never an observed/hardness bound.

    This displays why an authenticated hash commitment alone is insufficient if
    a source can pick a seed or a miner precommits many eligible candidates.
    Correlated actual tickets can invalidate this model entirely.
    Exact exponentiation is bounded before it runs by the unreduced power's
    denominator bit estimate; this is an arithmetic bound, not an RSS quota.
    """
    target = int.from_bytes(digest(target_hex, 'TARGET'), 'big')
    integer(seed_choices, 'SEED_CHOICES', 1, 4096)
    integer(candidate_count, 'CANDIDATE_COUNT', 1, 4096)
    p = Fraction(target + 1, 1 << 256)
    miss = 1 - p
    exponent = seed_choices * candidate_count
    require(exponent * miss.denominator.bit_length() <= MAX_IDEAL_ENVELOPE_EXACT_BITS,
            'IDEAL_ENVELOPE_EXACT_BUDGET')
    chance = 1 - miss ** exponent
    return {'assumption': 'independent uniform tickets; not a security bound',
            'seed_choices': seed_choices, 'candidate_count': candidate_count,
            'numerator': chance.numerator, 'denominator': chance.denominator}


class ModeAResearch:
    """Single-writer bounded journal. Refused API calls are retained as events.

    No disk write occurs implicitly. ``save`` fsyncs a snapshot and returns its
    checkpoint; its external non-rewinding custody is an explicit obligation.
    Events contain completed-attempt observations, not a proof that all work was
    disclosed. A complete experiment must separately bind the native raw log.
    The caller must provision enough journal capacity for its recorded plan;
    exhausting that separate cap explicitly refuses further events and leaves
    the uncompleted declared search census visible in ``summary``.
    """
    def __init__(self, *, max_candidates=8, max_per_actor=4, max_events=4096,
                 target_hex='7f' + 'ff' * 31, challenge_owner='external-owner',
                 allowed_cycles=1, attempts_per_cycle=4096):
        integer(max_candidates, 'MAX_CANDIDATES', 1, 256)
        integer(max_per_actor, 'MAX_PER_ACTOR', 1, max_candidates)
        integer(max_events, 'MAX_EVENTS', 1, MAX_EVENTS)
        integer(allowed_cycles, 'ALLOWED_CYCLES', 1, 64)
        integer(attempts_per_cycle, 'ATTEMPTS_PER_CYCLE', 1, 4096)
        require(digest(target_hex, 'TARGET') != bytes(32), 'TARGET')
        label(challenge_owner, 'CHALLENGE_OWNER')
        self._config = dict(max_candidates=max_candidates, max_per_actor=max_per_actor,
                           max_events=max_events, target_hex=target_hex,
                           challenge_owner=challenge_owner, allowed_cycles=allowed_cycles,
                           attempts_per_cycle=attempts_per_cycle)
        self.events = []
        self._rounds = {}
        self._active = None
        self._last_round = -1
        self._last_time = 0
        self._last_owner_sequence = 0
        self._receipts = set()
        self._external_seeds = set()
        self._accepted_work = set()
        self._application_outcomes = set()
        self._scope_weights = {}
        self._selected_scope = None
        self._journal_hash = H('pon-work-expensive-journal-v2', canonical(self._config),
                               SEARCH_STOP_RULE.encode()).hex()

    @property
    def config(self):
        """Detached inspection only; no API changes a configured search plan."""
        return deepcopy(self._config)

    def configuration_commitment(self):
        return H('pon-work-expensive-configuration-v2', canonical(self._config),
                 SEARCH_STOP_RULE.encode()).hex()

    def _run(self, action, payload, apply):
        require(len(self.events) < self._config['max_events'], 'JOURNAL_EVENT_LIMIT')
        payload = deepcopy(payload)
        require(len(canonical(payload)) <= MAX_EVENT_BYTES, 'EVENT_BYTE_LIMIT')
        try:
            result = apply()
            outcome = {'ok': True, 'result': deepcopy(result)}
        except ValueError as error:
            outcome = {'ok': False, 'error': str(error)}
        event = {'sequence': len(self.events), 'action': action,
                 'payload': payload, 'outcome': outcome, 'previous': self._journal_hash}
        event['digest'] = H('pon-work-expensive-event-v2', canonical(event)).hex()
        self.events.append(event)
        self._journal_hash = event['digest']
        now = payload.get('now_ns')
        if type(now) is int and self._last_time <= now < (1 << 64):
            self._last_time = now
        if not outcome['ok']:
            raise ValueError(outcome['error'])
        return deepcopy(outcome['result'])

    def _clock(self, now_ns):
        integer(now_ns, 'CLOCK')
        require(now_ns >= self._last_time, 'CLOCK_REWIND')

    def _round(self, phase=None):
        require(self._active is not None, 'NO_ACTIVE_ROUND')
        current = self._rounds[self._active]
        if phase is not None:
            require(current['phase'] == phase, 'PHASE_' + phase.upper())
        return current

    def open_round(self, round_id, parent_hex, branch, now_ns, cutoff_ns, expiry_ns):
        args = dict(round_id=round_id, parent_hex=parent_hex, branch=branch,
                    now_ns=now_ns, cutoff_ns=cutoff_ns, expiry_ns=expiry_ns)
        def apply():
            self._clock(now_ns)
            integer(round_id, 'ROUND')
            require(round_id > self._last_round, 'ROUND_REWIND')
            require(self._active is None or self._round()['phase'] == 'closed', 'ROUND_ACTIVE')
            scope = _scope(branch, parent_hex)
            integer(cutoff_ns, 'CUTOFF'); integer(expiry_ns, 'EXPIRY')
            require(now_ns < cutoff_ns < expiry_ns, 'ROUND_WINDOW')
            self._rounds[round_id] = dict(round_id=round_id, parent=parent_hex,
                branch=branch, scope=scope, opened_at_ns=now_ns, cutoff_ns=cutoff_ns,
                expiry_ns=expiry_ns, phase='open', registrations={}, attempts={},
                searches={}, accepted=[], seed=None, freeze=None)
            self._active = round_id
            self._last_round = round_id
            return {'round_id': round_id, 'scope': scope}
        return self._run('open_round', args, apply)

    def register(self, actor, contract, now_ns, preparation_cpu_ns=0, preparation_wall_ns=0):
        args = dict(actor=actor, contract=contract, now_ns=now_ns,
                    preparation_cpu_ns=preparation_cpu_ns, preparation_wall_ns=preparation_wall_ns)
        def apply():
            self._clock(now_ns)
            label(actor, 'ACTOR')
            integer(preparation_cpu_ns, 'PREPARATION_CPU'); integer(preparation_wall_ns, 'PREPARATION_WALL')
            current = self._round('open')
            require(now_ns < current['cutoff_ns'], 'REGISTRATION_CUTOFF')
            family = family_id(contract)
            registrations = current['registrations']
            require(len(registrations) < self._config['max_candidates'], 'CANDIDATE_LIMIT')
            require(sum(r['actor'] == actor for r in registrations.values()) <
                    self._config['max_per_actor'], 'ACTOR_LIMIT_NOT_SYBIL_DEFENCE')
            require(all(r['family_id'] != family for r in registrations.values()), 'DUPLICATE_FAMILY')
            reg = H('pon-work-expensive-registration-v1', struct.pack('<Q', current['round_id']),
                    digest(current['parent']), current['branch'].encode(), digest(family)).hex()
            registrations[reg] = dict(registration_id=reg, actor=actor,
                contract=deepcopy(contract), family_id=family, registered_at_ns=now_ns,
                preparation_cpu_ns=preparation_cpu_ns, preparation_wall_ns=preparation_wall_ns)
            current['searches'][reg] = [dict(status='not-started', attempts=0, hit_nonce=None)
                                       for _ in range(self._config['allowed_cycles'])]
            return reg
        return self._run('register', args, apply)

    def freeze(self, now_ns):
        def apply():
            self._clock(now_ns)
            current = self._round('open')
            require(now_ns <= current['cutoff_ns'], 'FREEZE_LATE')
            require(current['registrations'], 'EMPTY_CANDIDATE_SET')
            rows = [current['registrations'][k] for k in sorted(current['registrations'])]
            root = H('pon-work-expensive-candidate-root-v1', canonical(rows)).hex()
            frozen = dict(round_id=current['round_id'], parent=current['parent'],
                branch=current['branch'], candidate_root=root, candidate_count=len(rows),
                configuration_commitment=self.configuration_commitment(),
                target=self._config['target_hex'], challenge_owner=self._config['challenge_owner'],
                allowed_cycles=self._config['allowed_cycles'],
                attempts_per_cycle=self._config['attempts_per_cycle'], search_stop_rule=SEARCH_STOP_RULE,
                frozen_at_ns=now_ns, cutoff_ns=current['cutoff_ns'], expiry_ns=current['expiry_ns'])
            current['freeze'] = frozen
            current['phase'] = 'frozen'
            return frozen
        return self._run('freeze', {'now_ns': now_ns}, apply)

    def reveal(self, seed_hex, owner_receipt_hex, now_ns, owner_sequence=1, owner=None):
        """Observe one externally checked owner receipt after freeze and cutoff.

        Caller authentication and unpredictability are assumptions, not supplied
        by this method. The receipt digest is a binding observation, no signature.
        """
        owner = self._config['challenge_owner'] if owner is None else owner
        args = dict(seed_hex=seed_hex, owner_receipt_hex=owner_receipt_hex,
                    now_ns=now_ns, owner_sequence=owner_sequence, owner=owner)
        def apply():
            self._clock(now_ns)
            current = self._round('frozen')
            seed = digest(seed_hex, 'EXTERNAL_SEED'); digest(owner_receipt_hex, 'OWNER_RECEIPT')
            integer(owner_sequence, 'OWNER_SEQUENCE', 1)
            require(owner == self._config['challenge_owner'], 'OWNER_MISMATCH')
            require(owner_sequence > self._last_owner_sequence, 'OWNER_SEQUENCE_REWIND')
            require(current['cutoff_ns'] <= now_ns < current['expiry_ns'], 'REVEAL_WINDOW')
            require(owner_receipt_hex not in self._receipts, 'OWNER_RECEIPT_REPLAY')
            require(seed_hex not in self._external_seeds, 'EXTERNAL_SEED_REUSE')
            frozen = current['freeze']
            derived = H('pon-work-expensive-mode-a-seed-v2', seed, canonical(frozen)).hex()
            observed = dict(frozen, external_seed=seed_hex, seed=derived,
                owner=owner, owner_receipt=owner_receipt_hex, owner_sequence=owner_sequence,
                observed_at_ns=now_ns, waiting_wall_ns=now_ns-frozen['frozen_at_ns'])
            current['seed'] = derived
            current['reveal'] = observed
            current['phase'] = 'challenged'
            self._receipts.add(owner_receipt_hex); self._external_seeds.add(seed_hex)
            self._last_owner_sequence = owner_sequence
            return observed
        return self._run('reveal', args, apply)

    def contract(self, registration_id):
        current = self._round()
        require(registration_id in current['registrations'], 'REGISTRATION')
        return deepcopy(current['registrations'][registration_id]['contract'])

    def check_frozen(self, registration_id, contract):
        current = self._round()
        require(current['phase'] in ('frozen', 'challenged', 'closed'), 'NOT_FROZEN')
        require(contract_bytes(self.contract(registration_id)) == contract_bytes(contract),
                'FROZEN_CONTRACT_CHANGED')
        return True

    def challenge(self, registration_id, cycle, nonce):
        current = self._round('challenged')
        contract = self.contract(registration_id)
        integer(cycle, 'CYCLE', 0, self._config['allowed_cycles'] - 1)
        integer(nonce, 'NONCE', 0, self._config['attempts_per_cycle'] - 1)
        # Exactly matches pon_shared_material_v1, with the root-bound seed above.
        return H('pon-shared-material-challenge-v1', digest(contract['task']),
                 digest(self._config['target_hex']), digest(current['seed']),
                 struct.pack('<Q', cycle), struct.pack('<Q', nonce)).hex()

    def record_attempt(self, registration_id, cycle, nonce, trace_hex, now_ns,
                       producer_cpu_ns, producer_wall_ns):
        args = dict(registration_id=registration_id, cycle=cycle, nonce=nonce, trace_hex=trace_hex,
                    now_ns=now_ns, producer_cpu_ns=producer_cpu_ns, producer_wall_ns=producer_wall_ns)
        def apply():
            self._clock(now_ns)
            current = self._round('challenged')
            require(now_ns < current['expiry_ns'], 'ATTEMPT_EXPIRED')
            integer(producer_cpu_ns, 'PRODUCER_CPU'); integer(producer_wall_ns, 'PRODUCER_WALL')
            challenge = self.challenge(registration_id, cycle, nonce)
            trace = digest(trace_hex, 'TRACE')
            trials = current['attempts']
            key = registration_id + ':' + str(cycle) + ':' + str(nonce)
            require(key not in trials, 'DUPLICATE_ATTEMPT')
            searches = current['searches'][registration_id]
            require(all(s['status'] in ('target-hit', 'exhausted') for s in searches[:cycle]),
                    'PREVIOUS_CYCLE_INCOMPLETE')
            search = searches[cycle]
            require(search['status'] not in ('target-hit', 'exhausted'), 'CYCLE_ALREADY_TERMINAL')
            require(nonce == search['attempts'], 'MISSING_COMPLETED_ATTEMPTS')
            ticket = H('ticket', digest(challenge), trace).hex()
            hit = digest(ticket) <= digest(self._config['target_hex'])
            trial = dict(registration_id=registration_id, cycle=cycle, nonce=nonce,
                challenge=challenge, trace=trace_hex, ticket=ticket, target_hit=hit,
                producer_cpu_ns=producer_cpu_ns, producer_wall_ns=producer_wall_ns,
                completed_at_ns=now_ns, submitted=False)
            trials[key] = trial
            search['attempts'] += 1
            search['status'] = ('target-hit' if hit else 'exhausted' if
                               search['attempts'] == self._config['attempts_per_cycle'] else 'searching')
            search['hit_nonce'] = nonce if hit else None
            return deepcopy(trial)
        return self._run('record_attempt', args, apply)

    def submit(self, registration_id, cycle, nonce, proof_hex, parent_hex, branch, now_ns):
        """Full scalar W1 verification; no Node/work-profile qualification follows."""
        args = dict(registration_id=registration_id, cycle=cycle, nonce=nonce,
                    proof_hex=proof_hex, parent_hex=parent_hex, branch=branch, now_ns=now_ns)
        def apply():
            self._clock(now_ns)
            current = self._round('challenged')
            require(now_ns < current['expiry_ns'], 'SUBMISSION_EXPIRED')
            require((parent_hex, branch) == (current['parent'], current['branch']), 'PARENT_BRANCH_REPLAY')
            self.challenge(registration_id, cycle, nonce)
            key = registration_id + ':' + str(cycle) + ':' + str(nonce)
            require(key in current['attempts'], 'UNRECORDED_ATTEMPT')
            trial = current['attempts'][key]
            require(trial['target_hit'], 'LOSING_TICKET')
            contract = self.contract(registration_id)
            work = H('pon-work-expensive-work-id-v1', PROFILE.encode(),
                     digest(contract['task']), digest(trial['challenge'])).hex()
            require(work not in self._accepted_work, 'DUPLICATE_WORK')
            require(type(proof_hex) is str and len(proof_hex) == 2 * PROOF_BYTES and
                    all(c in '0123456789abcdef' for c in proof_hex), 'PROOF_ENCODING')
            proof = bytes.fromhex(proof_hex)
            require(proof[-32:].hex() == trial['trace'], 'ATTEMPT_TRACE_MISMATCH')
            ticket, product = verify(digest(trial['challenge']), digest(contract['task']),
                                     digest(self._config['target_hex']), proof)
            require(ticket.hex() == trial['ticket'] and len(product) == CELLS, 'VERIFIER_BINDING')
            family = current['registrations'][registration_id]['family_id']
            application = H('pon-work-expensive-application-id-v1', digest(family), field_bytes(product)).hex()
            new_application = application not in self._application_outcomes
            weight = (1 << 256) // (int(self._config['target_hex'], 16) + 1)
            # This is the explicit target-based research convention, not new DAA.
            observed = dict(work_id=work, family_id=family, application_outcome_id=application,
                application_first_observation=new_application, target_weight=weight,
                scope=current['scope'], challenge=trial['challenge'], ticket=trial['ticket'],
                proof_sha256=hashlib.sha256(proof).hexdigest(), scalar_w1_verified=True,
                native_node_accepted=False)
            self._accepted_work.add(work); self._application_outcomes.add(application)
            self._scope_weights[current['scope']] = self._scope_weights.get(current['scope'], 0) + weight
            trial['submitted'] = True
            current['accepted'].append(observed)
            return observed
        return self._run('submit', args, apply)

    def _search_census(self, current):
        rows = [dict(registration_id=reg, cycle=cycle, **search)
                for reg in sorted(current['searches'])
                for cycle, search in enumerate(current['searches'][reg])]
        unfinished = [row for row in rows if row['status'] not in ('target-hit', 'exhausted')]
        return dict(declared_searches=len(rows), terminal_searches=len(rows)-len(unfinished),
                    declared_searches_complete=bool(rows) and not unfinished,
                    unfinished_searches=unfinished,
                    search_results=rows)

    def close(self, now_ns):
        def apply():
            self._clock(now_ns)
            current = self._round()
            require(current['phase'] in ('frozen', 'challenged'), 'CLOSE_PHASE')
            submitted = {v['registration_id'] for v in current['attempts'].values() if v['submitted']}
            abandoned = sorted(set(current['registrations']) - submitted)
            current['phase'] = 'closed'
            current['closed_at_ns'] = now_ns
            current['unsubmitted_candidates'] = abandoned
            return dict(round_id=current['round_id'], unsubmitted_candidates=abandoned,
                        completed_attempts=len(current['attempts']), qualified_observations=len(current['accepted']),
                        **self._search_census(current))
        return self._run('close', {'now_ns': now_ns}, apply)

    def select_scope(self, parent_hex, branch, now_ns):
        """Observe reorg choice without rewinding application history or costs.

        Parent ancestry/fork choice is deliberately external. Different parent
        scopes are NEVER summed here, even when a caller gives them one branch
        label. A real cumulative chain requires the existing Node's ancestry.
        """
        def apply():
            self._clock(now_ns)
            scope = _scope(branch, parent_hex)
            require(any(r['scope'] == scope for r in self._rounds.values()), 'UNKNOWN_SCOPE')
            self._selected_scope = scope
            return dict(scope=scope, qualified_target_weight=self._scope_weights.get(scope, 0))
        return self._run('select_scope', dict(parent_hex=parent_hex, branch=branch, now_ns=now_ns), apply)

    def checkpoint(self):
        return dict(schema=SCHEMA, event_count=len(self.events), journal_sha256=self._journal_hash)

    def summary(self):
        trials = [t for r in self._rounds.values() for t in r['attempts'].values()]
        registrations = [v for r in self._rounds.values() for v in r['registrations'].values()]
        charged_registrations = [e['payload'] for e in self.events if e['action'] == 'register']
        prep_cpu = sum(p['preparation_cpu_ns'] for p in charged_registrations if type(p.get('preparation_cpu_ns')) is int and p['preparation_cpu_ns'] >= 0)
        prep_wall = sum(p['preparation_wall_ns'] for p in charged_registrations if type(p.get('preparation_wall_ns')) is int and p['preparation_wall_ns'] >= 0)
        return dict(schema=SCHEMA, checkpoint=self.checkpoint(),
            successful_registrations=len(registrations), registration_calls=len(charged_registrations),
            refused_events=sum(not e['outcome']['ok'] for e in self.events),
            completed_attempts=len(trials), losing_attempts=sum(not t['target_hit'] for t in trials),
            hit_unsubmitted_attempts=sum(t['target_hit'] and not t['submitted'] for t in trials),
            qualified_unique_work=len(self._accepted_work), unique_application_outcomes=len(self._application_outcomes),
            preparation_cpu_ns=prep_cpu, preparation_wall_ns=prep_wall,
            producer_cpu_ns=sum(t['producer_cpu_ns'] for t in trials),
            producer_wall_ns=sum(t['producer_wall_ns'] for t in trials),
            cost_scope='reported registration preparation (campaign: contract construction) and accepted-schedule attempt components only; excludes native setup, search/attempt-retention overhead, verification, journal/fsync and whole-process costs; never a total budget B',
            waiting_wall_ns=sum(r.get('reveal', {}).get('waiting_wall_ns', 0) for r in self._rounds.values()),
            scope_target_weights=deepcopy(self._scope_weights), selected_scope=self._selected_scope,
            selected_scope_weight=self._scope_weights.get(self._selected_scope, 0),
            unsubmitted_candidates={str(k): r.get('unsubmitted_candidates') for k, r in self._rounds.items()},
            search_plan=dict(allowed_cycles=self._config['allowed_cycles'],
                             attempts_per_cycle=self._config['attempts_per_cycle'], stop_rule=SEARCH_STOP_RULE),
            round_search_census={str(k): self._search_census(r) for k, r in self._rounds.items()},
            configuration_commitment=self.configuration_commitment(),
            journal_capacity_remaining=self._config['max_events']-len(self.events),
            production_activation=False, native_node_admission_verified=False,
            entropy_unpredictability_verified=False, owner_authentication_verified=False,
            caller_clock_authenticated=False, undisclosed_work_excluded=False,
            parent_ancestry_verified=False, sybil_resistance_verified=False,
            preparation_costs_are_caller_observations=True,
            verifier_time_included_in_producer=False,
            universal_cost_lower_bound=False)

    def save(self, path):
        path = Path(path)
        raw = canonical(dict(schema=SCHEMA, config=self._config, events=self.events,
                             checkpoint=self.checkpoint())) + b'\n'
        require(len(raw) <= MAX_JOURNAL_BYTES, 'JOURNAL_BYTE_LIMIT')
        fd, name = tempfile.mkstemp(prefix=path.name + '.', suffix='.tmp', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(raw); out.flush(); os.fsync(out.fileno())
            os.replace(name, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(name):
                os.unlink(name)
        return self.checkpoint()

    @classmethod
    def restore(cls, path, expected_checkpoint):
        require(type(expected_checkpoint) is dict and set(expected_checkpoint) ==
                {'schema', 'event_count', 'journal_sha256'}, 'EXTERNAL_CHECKPOINT_REQUIRED')
        require(expected_checkpoint['schema'] == SCHEMA, 'CHECKPOINT_SCHEMA')
        integer(expected_checkpoint['event_count'], 'CHECKPOINT_COUNT', 0, MAX_EVENTS)
        digest(expected_checkpoint['journal_sha256'], 'CHECKPOINT_HASH')
        with Path(path).open('rb') as source:
            raw = source.read(MAX_JOURNAL_BYTES + 1)
        require(len(raw) <= MAX_JOURNAL_BYTES and raw.endswith(b'\n'), 'JOURNAL_BYTES')
        def reject_number(_):
            raise ValueError('NONINTEGER_JSON_NUMBER')
        value = json.loads(raw, object_pairs_hook=unique, parse_float=reject_number, parse_constant=reject_number)
        require(type(value) is dict and set(value) == {'schema', 'config', 'events', 'checkpoint'} and
                value['schema'] == SCHEMA and value['checkpoint'] == expected_checkpoint, 'CHECKPOINT_MISMATCH')
        require(type(value['events']) is list and len(value['events']) == expected_checkpoint['event_count'], 'JOURNAL_TRUNCATED')
        result = cls(**value['config'])
        allowed = {'open_round', 'register', 'freeze', 'reveal', 'record_attempt', 'submit', 'close', 'select_scope'}
        for event in value['events']:
            require(type(event) is dict and set(event) == {'sequence', 'action', 'payload', 'outcome', 'previous', 'digest'}, 'EVENT_FIELDS')
            require(event['action'] in allowed and type(event['payload']) is dict, 'EVENT_ACTION')
            require(type(event['sequence']) is int and event['sequence'] == len(result.events) and
                    event['previous'] == result._journal_hash, 'EVENT_ORDER')
            body = {k: v for k, v in event.items() if k != 'digest'}
            require(event['digest'] == H('pon-work-expensive-event-v2', canonical(body)).hex(), 'EVENT_DIGEST')
            try:
                getattr(result, event['action'])(**event['payload'])
            except ValueError:
                pass
            except TypeError as error:
                raise ValueError('EVENT_ARGUMENTS') from error
            require(result.events and result.events[-1] == event, 'EVENT_REPLAY_MISMATCH')
        require(result.checkpoint() == expected_checkpoint, 'CHECKPOINT_MISMATCH')
        return result
