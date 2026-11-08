"""Bounded evidence contract for the existing grouped security-seal research.

The denomination is a classical *seal step-oracle query*, not a fresh neural
contraction, a physical resource unit or actual chainwork. This inspector checks
externally pinned declarations against supplied observations, reconstructs exact
native step inputs, reconciles attempts and costs, and exposes missing evidence.
It does not authenticate an issuer, a meter, demand, operator independence or a
complete public coalition transcript. A pin prevents substitution only relative
to its independently supplied value; a caller can still pin its own fixture.

``assess(evidence, expected_policy=policy, expected_policy_sha256=pin)`` accepts
plain JSON objects. ``parse_json`` rejects duplicate keys, floats and booleans.
All observation clocks are supplied ordering coordinates, not trusted wall time;
expiry and deadline bounds are exclusive, as in the native grouped admission.
Exact event replays are deduplicated by their immutable IDs, excluding only the
carrier digest. Fresh executions of one oracle input remain separate costs but
do not create new distinct queries. Cost ``included_in`` edges identify diagnostic
subsets in an explicit containment forest. Sibling coverage must be disjoint;
overlapping diagnostics require explicit nesting. Descendant recorded minima
must fit every enclosing amount or upper bound. Only root scopes are summed,
separately for each unit. Known payer and beneficiary identities must agree
throughout each ancestor path; an unknown intermediate cannot hide a conflict
or acquire an identity from a surrounding record.

The result is a qualification HOLD with a useful structural assessment, never a
registration/activation API. The native seal has no conversion to VerifiedWork.
The mathematical expected-query bounds remain in fresh_work_query_floor_v0; an
observed winning transcript is not a pathwise test of an expectation theorem.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re


POLICY_SCHEMA = 'pon-grouped-work-profile-policy-v1'
EVIDENCE_SCHEMA = 'pon-grouped-work-profile-evidence-v1'
REPORT_SCHEMA = 'pon-grouped-work-profile-assessment-v1'
PROFILE = 'pon-grouped-int257-sealed-research-v0'
DENOMINATION = 'classical-seal-step-oracle-query'
STEPS = 64
MAX_RECORDS = 16_384
MAX_BYTES = 16 * 1024 * 1024
MAX_JSON_VALUES = 1024 * 1024
MAX_UINT = (1 << 64) - 1
ROLES = frozenset(('producer', 'preprocessing', 'delegate', 'verifier',
                   'receiver', 'consumer', 'helper'))
UNITS = frozenset(('step_query', 'seed_hash', 'business_mac', 'cpu_ns', 'gpu_ns',
                   'wall_ns', 'read_bytes', 'write_bytes', 'network_tx_bytes',
                   'network_rx_bytes', 'energy_nj', 'funding_units'))
OUTCOMES = frozenset(('completed', 'rejected', 'canceled', 'unknown'))
EXTERNAL_OBLIGATIONS = (
    'AUTHENTICATED_POLICY_TASK_AND_TARGET_ISSUERS',
    'TRUSTED_PREQUERY_ORDER_AND_UNOMITTED_PREPROCESSING',
    'COMPLETE_PUBLIC_COALITION_AND_ASSISTING_QUERY_COVERAGE',
    'INDEPENDENT_TASK_SUPPLY_AND_UNBIASED_ASSIGNMENT',
    'CURRENT_TARGET_TASK_AND_CONSUMER_STATE_AT_USE',
    'GENUINE_DEMAND_CURRENT_CONSUMER_USE_AND_SETTLEMENT',
    'AUTHENTICATED_METERS_AND_COMPLETE_RESOURCE_TRANSFER',
    'CHEAPEST_LEGAL_IMPLEMENTATION_AND_PHYSICAL_COST_TRANSFER',
    'EXISTING_NATIVE_CONSENSUS_PROFILE_REGISTRATION',
)


def require(ok, code):
    if not ok:
        raise ValueError(code)


def _uint(value, code):
    require(type(value) is int and 0 <= value <= MAX_UINT, code)
    return value


def _digest(value, code='DIGEST'):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, code)
    return value


def _name(value, code):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}', value) is not None, code)
    return value


def _member(value, values, code):
    require(type(value) is str and value in values, code)
    return value


def _keys(value, names, code):
    require(type(value) is dict and set(value) == set(names.split()), code)


def canonical_bytes(value):
    """Exact bounded JSON subset used for the new evidence and policy pins."""
    state = {'values': 0, 'bytes': 0}
    containers = set()
    def budget(size):
        state['bytes'] += size
        require(state['bytes'] <= MAX_BYTES, 'JSON_BYTES')
    def visit(item, depth=0):
        state['values'] += 1
        require(state['values'] <= MAX_JSON_VALUES, 'JSON_WORK')
        require(depth <= 16, 'JSON_DEPTH')
        if item is None:
            budget(4)
            return
        if type(item) is int:
            _uint(item, 'JSON_INTEGER')
            budget(len(str(item)))
        elif type(item) is str:
            require(len(item) <= 4096, 'JSON_STRING')
            budget(len(json.dumps(item, ensure_ascii=True)))
        elif type(item) is list:
            require(len(item) <= MAX_RECORDS, 'JSON_LIST')
            require(id(item) not in containers, 'JSON_CONTAINER_ALIAS_OR_CYCLE')
            containers.add(id(item))
            budget(2 + max(0, len(item) - 1))
            for child in item:
                visit(child, depth + 1)
        elif type(item) is dict:
            require(len(item) <= MAX_RECORDS and all(type(k) is str for k in item), 'JSON_OBJECT')
            require(id(item) not in containers, 'JSON_CONTAINER_ALIAS_OR_CYCLE')
            containers.add(id(item))
            budget(2 + max(0, len(item) - 1) + len(item))
            for key, child in item.items():
                visit(key, depth + 1)
                visit(child, depth + 1)
        else:
            raise ValueError('JSON_TYPE')
    visit(value)
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode()
    require(len(raw) <= MAX_BYTES, 'JSON_BYTES')
    return raw


def parse_json(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'JSON_BYTES')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'DUPLICATE_JSON_KEY')
            result[key] = value
        return result
    def no_number(_):
        raise ValueError('JSON_NONINTEGER')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique,
                           parse_float=no_number, parse_constant=no_number)
    except (RecursionError, UnicodeError) as failure:
        raise ValueError('JSON_DEPTH_OR_ENCODING') from failure
    canonical_bytes(value)
    return value


def policy_digest(policy):
    return hashlib.sha256(b'TRNM-GROUPED-WORK-PROFILE-POLICY1\0' +
                          canonical_bytes(policy)).hexdigest()


def _index(rows, fields, label, *, carriers=False):
    require(type(rows) is list and len(rows) <= MAX_RECORDS, label + '_ROWS')
    result, replays = {}, 0
    for row in rows:
        _keys(row, fields, label + '_FIELDS')
        identity = _digest(row['id'], label + '_ID')
        if carriers:
            _digest(row['carrier_sha256'], 'CARRIER_DIGEST')
        body = {k: v for k, v in row.items() if not carriers or k != 'carrier_sha256'}
        if identity in result:
            require(carriers and result[identity] == body, label + '_ID_REBINDING')
            replays += 1
        else:
            result[identity] = body
    return result, replays


def _names_list(value, allowed, code):
    require(type(value) is list and len(value) <= MAX_RECORDS, code)
    require(all(type(x) is str and x in allowed for x in value), code)
    require(len(value) == len(set(value)), code + '_DUPLICATE')


def _policy(policy):
    _keys(policy, 'schema campaign profile denomination actors candidates demands operations', 'POLICY_FIELDS')
    require(policy['schema'] == POLICY_SCHEMA and policy['profile'] == PROFILE and
            policy['denomination'] == DENOMINATION, 'POLICY_PROFILE')
    _digest(policy['campaign'], 'CAMPAIGN')
    require(type(policy['actors']) is list and 1 <= len(policy['actors']) <= 256, 'ACTORS')
    actors = {}
    for row in policy['actors']:
        _keys(row, 'id control_group', 'ACTOR_FIELDS')
        identity = _name(row['id'], 'ACTOR_ID')
        _name(row['control_group'], 'CONTROL_GROUP')
        require(identity not in actors, 'ACTOR_REBINDING')
        actors[identity] = row
    candidates, _ = _index(policy['candidates'],
        'id task material challenge statement target task_authority target_authority authorized_at expires_at', 'CANDIDATE')
    require(0 < len(candidates) <= 64, 'CANDIDATE_LIMIT')
    challenges = set()
    for row in candidates.values():
        for field in ('task', 'material', 'challenge', 'statement', 'target'):
            _digest(row[field], 'CANDIDATE_' + field.upper())
        require(int(row['target'], 16) > 0, 'TARGET_ZERO')
        require(row['challenge'] not in challenges, 'CHALLENGE_ALIAS')
        challenges.add(row['challenge'])
        _member(row['task_authority'], actors, 'AUTHORITY_NOT_PINNED')
        _member(row['target_authority'], actors, 'AUTHORITY_NOT_PINNED')
        require(_uint(row['authorized_at'], 'AUTHORIZED_AT') <
                _uint(row['expires_at'], 'EXPIRES_AT'), 'AUTHORIZATION_WINDOW')
    demands, _ = _index(policy['demands'],
        'id task material requester consumer authorized_at expires_at', 'DEMAND')
    for row in demands.values():
        _digest(row['task'], 'DEMAND_TASK'); _digest(row['material'], 'DEMAND_MATERIAL')
        _member(row['requester'], actors, 'DEMAND_ACTOR')
        _member(row['consumer'], actors, 'DEMAND_ACTOR')
        require(_uint(row['authorized_at'], 'DEMAND_AUTHORIZED_AT') <
                _uint(row['expires_at'], 'DEMAND_EXPIRES_AT'), 'DEMAND_WINDOW')
    operations, _ = _index(policy['operations'],
        'id actor role candidates authorized_at deadline required_costs', 'OPERATION')
    require(operations, 'EMPTY_OPERATION_PLAN')
    for row in operations.values():
        _member(row['actor'], actors, 'OPERATION_OWNER')
        _member(row['role'], ROLES, 'OPERATION_OWNER')
        _names_list(row['candidates'], candidates, 'OPERATION_CANDIDATES')
        require(_uint(row['authorized_at'], 'OPERATION_AUTHORIZED_AT') <
                _uint(row['deadline'], 'OPERATION_DEADLINE'), 'OPERATION_WINDOW')
        require(type(row['required_costs']) is list and 1 <= len(row['required_costs']) <= 64, 'REQUIRED_COSTS')
        seen = set()
        for cost in row['required_costs']:
            _keys(cost, 'stage unit', 'REQUIRED_COST_FIELDS')
            pair = (_name(cost['stage'], 'COST_STAGE'),
                    _member(cost['unit'], UNITS, 'REQUIRED_COST_UNIT_OR_DUPLICATE'))
            require(pair not in seen, 'REQUIRED_COST_UNIT_OR_DUPLICATE')
            seen.add(pair)
    return actors, candidates, demands, operations


def _frame(tag, *parts):
    # Independent reader of the fixed native seal domain, not a new wire format.
    return (b'TRNM-GROUPED-FRESH-SEAL0\0' + len(tag).to_bytes(2, 'big') + tag +
            b''.join(len(p).to_bytes(4, 'big') + p for p in parts))


_PROFILE_HASH = hashlib.sha256(_frame(b'profile', PROFILE.encode(),
    b'pon-routed-int257-grouped-research-v0',
    b'signed-i32-coeff-i64-accum-bias8-lowest-argmax', b'\0@', b'\0\x10')).digest()


def _seed(candidate):
    return hashlib.sha256(_frame(b'seed', _PROFILE_HASH,
        bytes.fromhex(candidate['challenge']), bytes.fromhex(candidate['statement']))).digest()


def _step_input(candidate, index, predecessor):
    return _frame(b'step', _PROFILE_HASH, bytes.fromhex(candidate['challenge']),
                  index.to_bytes(2, 'big'), predecessor)


def _operation(identity, operations):
    require(type(identity) is str and identity in operations, 'UNPLANNED_OPERATION')
    return operations[identity]


def _candidate(identity, operation, candidates):
    require(type(identity) is str and identity in candidates and
            identity in operation['candidates'], 'UNAUTHORIZED_CANDIDATE')
    return candidates[identity]


def assess(evidence, *, expected_policy, expected_policy_sha256):
    """Inspect supplied evidence; external facts cannot be granted by JSON flags.

    Missing/unknown observations produce explicit local issues and retain all
    known costs. Structural contradictions, changed identities, late binding
    and duplicate charges raise ValueError rather than producing an assessment.
    No result asserts that all actual calls or physical resource scopes were
    disclosed. ``actual_chainwork`` is always zero for this unregistered profile.
    """
    _digest(expected_policy_sha256, 'EXPECTED_POLICY_PIN')
    policy_raw = canonical_bytes(expected_policy)
    require(hashlib.sha256(b'TRNM-GROUPED-WORK-PROFILE-POLICY1\0' + policy_raw).hexdigest() ==
            expected_policy_sha256, 'EXPECTED_POLICY_PIN')
    # Subsequent logic uses only the exact snapshot whose pin was checked.
    policy = parse_json(policy_raw)
    evidence = parse_json(canonical_bytes(evidence))
    actors, candidates, demands, operations = _policy(policy)
    _keys(evidence, 'schema policy_sha256 queries terminals uses costs', 'EVIDENCE_FIELDS')
    require(evidence['schema'] == EVIDENCE_SCHEMA, 'EVIDENCE_SCHEMA')
    require(evidence['policy_sha256'] == expected_policy_sha256, 'EVIDENCE_POLICY_SUBSTITUTION')
    issues = set()
    queries, query_replays = _index(evidence['queries'],
        'id operation candidate at index predecessor answer carrier_sha256', 'QUERY', carriers=True)
    terminals, terminal_replays = _index(evidence['terminals'],
        'id at outcome receipt_sha256 carrier_sha256', 'TERMINAL', carriers=True)
    uses, use_replays = _index(evidence['uses'],
        'id operation candidate demand at output_sha256 receipt_sha256 carrier_sha256', 'USE', carriers=True)
    costs, cost_replays = _index(evidence['costs'],
        'id operation stage unit amount upper_bound meter payer beneficiary receipt_sha256 coverage included_in carrier_sha256',
        'COST', carriers=True)

    table, counts_by_role, operation_queries, ordering = {}, Counter(), Counter(), set()
    for row in queries.values():
        op = _operation(row['operation'], operations)
        c = _candidate(row['candidate'], op, candidates)
        at = _uint(row['at'], 'QUERY_ORDER')
        require(at not in ordering, 'AMBIGUOUS_QUERY_ORDER')
        ordering.add(at)
        # Includes speculative final-step probes; no later declaration can bind T.
        require(max(c['authorized_at'], op['authorized_at']) < at, 'AUTHORIZATION_AFTER_QUERY')
        if at >= min(c['expires_at'], op['deadline']):
            issues.add('QUERY_OUTSIDE_WINDOW:' + row['id'])
        index = _uint(row['index'], 'QUERY_INDEX')
        require(1 <= index <= STEPS, 'QUERY_INDEX')
        predecessor = bytes.fromhex(_digest(row['predecessor'], 'QUERY_PREDECESSOR'))
        answer = bytes.fromhex(_digest(row['answer'], 'QUERY_ANSWER'))
        raw = _step_input(c, index, predecessor)
        require(hashlib.sha256(raw).digest() == answer, 'QUERY_HASH_MISMATCH')
        # Exact native preimage bytes, not wrapper or a claimed candidate digest.
        table[raw] = answer
        counts_by_role[op['role']] += 1
        operation_queries[row['operation']] += 1
    completed = []
    for identity, candidate in sorted(candidates.items()):
        state = _seed(candidate)
        for index in range(1, STEPS + 1):
            state = table.get(_step_input(candidate, index, state))
            if state is None:
                break
        if state is not None:
            completed.append(dict(candidate=identity, endpoint=state.hex(),
                target_hit=state <= bytes.fromhex(candidate['target']),
                hypothetical_award_per_hit=str(STEPS * ((1 << 256) // (int(candidate['target'], 16) + 1)))))

    outcomes, latest_query = Counter(), defaultdict(int)
    for row in queries.values():
        latest_query[row['operation']] = max(latest_query[row['operation']], row['at'])
    for identity, row in terminals.items():
        op = _operation(identity, operations)
        _member(row['outcome'], OUTCOMES, 'TERMINAL_OUTCOME')
        at = _uint(row['at'], 'TERMINAL_ORDER')
        require(at >= max(op['authorized_at'], latest_query[identity]), 'TERMINAL_BEFORE_EXECUTION')
        if row['receipt_sha256'] is not None:
            _digest(row['receipt_sha256'], 'TERMINAL_RECEIPT')
        else:
            issues.add('TERMINAL_RECEIPT_MISSING:' + identity)
        if row['outcome'] == 'unknown':
            issues.add('OPERATION_TERMINAL_UNKNOWN:' + identity)
        if at >= op['deadline']:
            issues.add('OPERATION_TERMINAL_LATE:' + identity)
        outcomes[row['outcome']] += 1
    for identity in operations.keys() - terminals.keys():
        issues.add('OPERATION_TERMINAL_MISSING:' + identity)

    demand_ids, materials, consumer_operations, operation_replays = set(), set(), {}, 0
    for row in uses.values():
        op = _operation(row['operation'], operations)
        c = _candidate(row['candidate'], op, candidates)
        require(type(row['demand']) is str and row['demand'] in demands, 'UNPINNED_DEMAND')
        d = demands[row['demand']]
        require(op['role'] == 'consumer' and op['actor'] == d['consumer'], 'CONSUMER_OWNER')
        require((d['task'], d['material']) == (c['task'], c['material']), 'DEMAND_CONTENT_BINDING')
        at = _uint(row['at'], 'USE_ORDER')
        require(at > max(d['authorized_at'], op['authorized_at'], c['authorized_at']), 'USE_BEFORE_AUTHORIZATION')
        if at >= min(d['expires_at'], op['deadline'], c['expires_at']):
            issues.add('USE_OUTSIDE_WINDOW:' + row['id'])
        if row['operation'] in terminals:
            require(at <= terminals[row['operation']]['at'], 'USE_AFTER_TERMINAL')
        _digest(row['output_sha256'], 'CONSUMER_OUTPUT')
        _digest(row['receipt_sha256'], 'CONSUMER_RECEIPT')
        binding = {key: value for key, value in row.items() if key != 'id'}
        previous = consumer_operations.get(row['operation'])
        if previous is not None:
            require(previous == binding, 'CONSUMER_OPERATION_REBINDING')
            operation_replays += 1
        else:
            consumer_operations[row['operation']] = binding
        demand_ids.add(row['demand']); materials.add(d['material'])
    for identity in demands.keys() - demand_ids:
        issues.add('DEMAND_USE_MISSING:' + identity)

    required, seen_costs, roots, covered, atoms = set(), set(), [], {}, {}
    for identity, op in operations.items():
        required.update((identity, row['stage'], row['unit']) for row in op['required_costs'])
    for row in costs.values():
        _operation(row['operation'], operations)
        _name(row['stage'], 'COST_STAGE')
        _member(row['unit'], UNITS, 'COST_UNIT')
        for field in ('amount', 'upper_bound'):
            if row[field] is not None:
                _uint(row[field], 'COST_' + field.upper())
        require(row['amount'] is None or row['upper_bound'] is None or
                row['amount'] <= row['upper_bound'], 'COST_EXCEEDS_UPPER_BOUND')
        if row['amount'] is None:
            issues.add('COST_AMOUNT_UNKNOWN:' + row['id'])
        for field in ('meter', 'payer', 'beneficiary'):
            if row[field] is None:
                issues.add('COST_' + field.upper() + '_UNKNOWN:' + row['id'])
            else:
                require(type(row[field]) is str and row[field] in actors, 'COST_TRANSFER_ACTOR')
        if row['receipt_sha256'] is None:
            issues.add('COST_RECEIPT_MISSING:' + row['id'])
        else:
            _digest(row['receipt_sha256'], 'COST_RECEIPT')
        coverage = row['coverage']
        require(type(coverage) is list and 1 <= len(coverage) <= MAX_RECORDS, 'COST_COVERAGE')
        for atom in coverage:
            _digest(atom, 'COST_COVERAGE_ATOM')
        require(len(set(coverage)) == len(coverage), 'COST_COVERAGE_DUPLICATE')
        atoms[row['id']] = set(coverage)
        seen_costs.add((row['operation'], row['stage'], row['unit']))
        require(row['included_in'] is None or type(row['included_in']) is str, 'COST_PARENT_MISSING')
    # Validate links only after every scalar and coverage set has been checked.
    for row in costs.values():
        parent = row['included_in']
        if parent is None:
            roots.append(row)
            for atom in atoms[row['id']]:
                key = (row['unit'], atom)
                require(key not in covered, 'OVERLAPPING_RESOURCE_CHARGE')
                covered[key] = row['id']
        else:
            require(type(parent) is str and parent in costs, 'COST_PARENT_MISSING')
            p = costs[parent]
            require(p['unit'] == row['unit'] and atoms[row['id']] <= atoms[parent], 'COST_SUBSET_BINDING')
            if p['amount'] is not None and row['amount'] is not None:
                require(row['amount'] <= p['amount'], 'COST_SUBSET_EXCEEDS_PARENT')
            for field in ('payer', 'beneficiary'):
                require(p[field] is None or row[field] is None or p[field] == row[field], 'COST_SUBSET_TRANSFER_CONFLICT')
    # Memoize roots to keep long inclusion chains linear in their link count.
    resolved_roots = {}
    for row in costs.values():
        lineage, current = [], row['id']
        active = set()
        while current not in resolved_roots:
            require(current not in active, 'COST_CYCLE')
            active.add(current); lineage.append(current)
            parent = costs[current]['included_in']
            if parent is None:
                resolved_roots[current] = current
                break
            current = parent
        root = resolved_roots[current]
        for identity in lineage:
            resolved_roots[identity] = root
    children = defaultdict(list)
    for row in costs.values():
        if row['included_in'] is not None:
            children[row['included_in']].append(row['id'])
    for sibling_ids in children.values():
        sibling_atoms = set()
        for identity in sibling_ids:
            require(not (sibling_atoms & atoms[identity]), 'COST_AMBIGUOUS_SUBSET_OVERLAP')
            sibling_atoms.update(atoms[identity])
    # Check the entire path, not only adjacent rows. Unknown intermediate
    # identities do not erase a known ancestor's binding. Carry immutable
    # bindings separately for each child so unrelated branches remain distinct;
    # never fill an unknown observation with an inferred payer or beneficiary.
    transfer_stack = [(row['id'], (None, None)) for row in roots]
    while transfer_stack:
        identity, inherited = transfer_stack.pop()
        declared = tuple(costs[identity][field] for field in ('payer', 'beneficiary'))
        require(all(prior is None or current is None or prior == current
                    for prior, current in zip(inherited, declared)),
                'COST_SUBSET_TRANSFER_CONFLICT')
        bindings = tuple(current if current is not None else prior
                         for prior, current in zip(inherited, declared))
        transfer_stack.extend((child, bindings) for child in children[identity])
    # Every disjoint descendant charge is a recorded lower amount for each
    # ancestor, even through an unknown intermediate. This is arithmetic
    # consistency of supplied counters, not a physical resource lower bound.
    minima, stack = {}, [(row['id'], False) for row in roots]
    while stack:
        identity, exiting = stack.pop()
        row = costs[identity]
        if not exiting:
            stack.append((identity, True))
            stack.extend((child, False) for child in children[identity])
            continue
        minimum = max(row['amount'] or 0, sum(minima[child] for child in children[identity]))
        cap = row['amount'] if row['amount'] is not None else row['upper_bound']
        require(cap is None or minimum <= cap, 'COST_DESCENDANTS_EXCEED_BOUND')
        minima[identity] = minimum
    for operation, stage, unit in sorted(required - seen_costs):
        issues.add('COST_REQUIRED_MISSING:' + operation + ':' + stage + ':' + unit)

    totals, transfer = {}, []
    missing_costs = required - seen_costs
    for unit in sorted({row['unit'] for row in roots} | {item[2] for item in required}):
        selected = [row for row in roots if row['unit'] == unit]
        unknown = [row for row in selected if row['amount'] is None]
        missing = sum(item[2] == unit for item in missing_costs)
        known = sum(minima[row['id']] for row in selected)
        upper = None if missing or any(row['upper_bound'] is None for row in unknown) else sum(
            row['amount'] if row['amount'] is not None else row['upper_bound'] for row in selected)
        totals[unit] = dict(known=known, total=None if unknown or missing else known,
            upper_bound=upper, unknown_records=len(unknown), missing_required_records=missing)
    for row in roots:
        op = operations[row['operation']]
        transfer.append(dict(cost=row['id'], executor=op['actor'], role=op['role'],
            meter=row['meter'], payer=row['payer'], beneficiary=row['beneficiary'],
            unit=row['unit'], amount=row['amount'], upper_bound=row['upper_bound'],
            recorded_minimum=minima[row['id']]))
    operation_step_totals, selected_by_operation = {}, defaultdict(list)
    # Each node is visited twice. This avoids quadratic ancestor walks in a
    # long aggregate/subset chain supplied by an untrusted report.
    stack = [(row['id'], False) for row in roots if row['unit'] == 'step_query']
    active_operations = Counter()
    while stack:
        cost_id, exiting = stack.pop()
        row = costs[cost_id]
        op_id = row['operation']
        if exiting:
            active_operations[op_id] -= 1
            continue
        if active_operations[op_id] == 0:
            selected_by_operation[op_id].append(row)
        active_operations[op_id] += 1
        stack.append((cost_id, True))
        stack.extend((child, False) for child in children[cost_id])
    for identity in operations:
        # A local operation may be a subset of an enclosing process aggregate.
        # Use its highest counters only, and never mask its missing charge with
        # a different operation's (possibly honest verifier's) counter.
        selected = selected_by_operation[identity]
        if not selected:
            if operation_queries[identity]:
                issues.add('QUERY_COST_MISSING:' + identity)
            continue
        seen_atoms = set()
        for row in selected:
            require(not (seen_atoms & atoms[row['id']]), 'OVERLAPPING_OPERATION_STEP_COVERAGE')
            seen_atoms.update(atoms[row['id']])
        unknown = [r for r in selected if r['amount'] is None]
        known = sum(minima[r['id']] for r in selected)
        upper = None if any(r['upper_bound'] is None for r in unknown) else sum(
            r['amount'] if r['amount'] is not None else r['upper_bound'] for r in selected)
        total = None if unknown else known
        operation_step_totals[identity] = dict(known=known, total=total, upper_bound=upper,
            unknown_records=len(unknown), traced_execution_events=operation_queries[identity])
        require(upper is None or operation_queries[identity] <= upper, 'OPERATION_QUERY_COUNT_EXCEEDS_REPORTED_COST')
        if total != operation_queries[identity]:
            issues.add('OPERATION_STEP_COUNTERS_WITHOUT_EXACT_TRACE:' + identity)
    # Do not sum a callback's step count and its aggregate again. Counter-only
    # receipts never become synthetic observed query transcripts.
    step_totals = totals.get('step_query')
    if step_totals is not None:
        require(step_totals['upper_bound'] is None or
                len(queries) <= step_totals['upper_bound'], 'QUERY_COUNT_EXCEEDS_REPORTED_COST')
        if step_totals['total'] != len(queries):
            issues.add('STEP_COUNTERS_WITHOUT_EXACT_QUERY_TRACE_COVERAGE')

    return dict(schema=REPORT_SCHEMA, policy_sha256=expected_policy_sha256,
        evidence_sha256=hashlib.sha256(canonical_bytes(evidence)).hexdigest(),
        qualification='HOLD', observation_status='COMPLETE_DECLARED_PLAN' if not issues else 'INCOMPLETE',
        profile=PROFILE, denomination=DENOMINATION, seal_steps=STEPS,
        source_of_authority='independently supplied expected pin; issuer authenticity not established',
        declared_actor_count=len(actors),
        declared_control_group_count=len({row['control_group'] for row in actors.values()}),
        queries=dict(observed_execution_events=len(queries), distinct_native_inputs=len(table),
            repeated_input_executions=len(queries) - len(table), carrier_replays=query_replays,
            events_by_declared_role=dict(sorted(counts_by_role.items())), complete_seal_traces=completed,
            public_query_total=None, coalition_query_total=None,
            complete_trace_does_not_verify_useful_relation=True,
            inspection_hash_replays_excluded_from_original_observations=True),
        attempts=dict(planned=len(operations), observed_terminals=len(terminals),
            missing_terminals=len(operations) - len(terminals), outcomes=dict(sorted(outcomes.items())),
            terminal_carrier_replays=terminal_replays),
        demand=dict(planned=len(demands), observed_consumer_operation_references=len(consumer_operations),
            observed_consumer_receipt_rows=len(uses),
            distinct_observed_demand_references=len(demand_ids), distinct_used_materials=len(materials),
            distinct_consumer_operations=len(consumer_operations),
            operation_identity_replays=operation_replays,
            repeated_demand_uses=len(consumer_operations) - len(demand_ids), carrier_replays=use_replays,
            genuine_independent_demand_established=False),
        resources=dict(totals_by_unit=totals, included_subset_records=len(costs) - len(roots),
            carrier_replays=cost_replays, transfers=transfer,
            step_counters_by_operation=operation_step_totals,
            scope='disjoint declared root atoms; units are never added or converted across dimensions'),
        local_issues=sorted(issues), unresolved_predicates=list(EXTERNAL_OBLIGATIONS),
        actual_chainwork=0, consensus_weight_eligible=False, production_activation=False,
        physical_resource_lower_bound_proved=False, fresh_neural_mac_floor_proved=False,
        quantum_security_proved=False)


def main(argv=None):
    """Read-only CLI: HOLD is a valid assessment; malformed input exits nonzero."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--expected-policy', required=True)
    parser.add_argument('--expected-policy-sha256', required=True)
    args = parser.parse_args(argv)
    def read(path):
        with open(path, 'rb') as stream:
            return parse_json(stream.read(MAX_BYTES + 1))
    try:
        report = assess(read(args.evidence), expected_policy=read(args.expected_policy),
                        expected_policy_sha256=args.expected_policy_sha256)
    except (OSError, ValueError) as failure:
        print(json.dumps({'schema': REPORT_SCHEMA, 'status': 'REJECTED',
                          'error': str(failure)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
