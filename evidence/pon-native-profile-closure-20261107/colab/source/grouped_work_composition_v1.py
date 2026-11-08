"""Compose separately pinned grouped-work observations without inventing owners.

Each input carries the ORIGINAL policy and evidence accepted by
``grouped_work_profile_v1``. An independently supplied manifest binds every
expected source, its reporting-owner namespace, its policy digest, the mapping
from that policy's short actor labels to participant namespaces, and all expected
owner/operation identities. A manifest pin detects substitution relative to its
supplied value; it is not a signature or proof of real control, independence,
prequery authorization, current consumer use, or public-query completeness.

Native queries are composed by their FULL preimage bytes. Separate owner/event
identities retain their execution observations even when they evaluate one input.
An owner/event identity, owner/operation, terminal receipt, demand or cost cannot
be rebound by another source. Repeated carriers retain one observation. A shared
native challenge has one frozen statement, target, task and material binding;
changing its local candidate ID cannot create another seal opportunity.

Ordering coordinates are checked inside each original policy. This module does
not manufacture a total order between independent owners. It therefore cannot
turn observed query counts into the expectation in the oracle-query theorem.
Missing expected sources, operations and records remain explicit. In particular,
an omitted offline/preprocessing owner is not proved absent by a complete set of
the sources that a caller chose to declare.

Resource observations are retained with immutable owner namespaces and checked
for inconsistent containment and per-operation step undercharging. Distinct
namespace labels do not prove disjoint physical measurements. Consequently no
cross-owner additive physical-resource total is returned. Receipt digests may
name a bundle containing several operations or dimensions: a digest alone is
not an operation identity or a new payment.

This is a bounded, read-only composition contract. Qualification is always HOLD,
actual chainwork is zero, and fresh per-ticket producer business contractions
can still be zero under the admitted cached-product implementation.
"""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re

import grouped_work_profile_v1 as profile


MANIFEST_SCHEMA = 'pon-grouped-work-composition-manifest-v1'
EVIDENCE_SCHEMA = 'pon-grouped-work-composition-evidence-v1'
REPORT_SCHEMA = 'pon-grouped-work-composition-assessment-v1'
MAX_SOURCES = 32
MAX_PARTICIPANTS = 256
MAX_TOTAL_RECORDS = profile.MAX_RECORDS
MAX_BYTES = profile.MAX_BYTES
_MANIFEST_DOMAIN = b'TRNM-GROUPED-WORK-COMPOSITION-MANIFEST1\0'
_UNION_DOMAIN = b'TRNM-GROUPED-WORK-COMPOSITION-INPUTS1\0'


def require(condition, code):
    if not condition:
        raise ValueError(code)


def _keys(value, fields, code):
    require(type(value) is dict and set(value) == set(fields.split()), code)


def _digest(value, code):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, code)
    return value


def _rows(value, code, *, minimum=0, maximum=MAX_TOTAL_RECORDS):
    require(type(value) is list and minimum <= len(value) <= maximum, code)
    return value


def _ref(key):
    return dict(owner=key[0], id=key[1])


def _key(ref):
    return ref['owner'], ref['id']


def _put(table, key, body, code):
    previous = table.get(key)
    if previous is not None:
        require(previous == body, code)
        return False
    table[key] = body
    return True


def manifest_digest(manifest):
    """Domain-separated canonical pin, not the hash of arbitrary file bytes."""
    return hashlib.sha256(_MANIFEST_DOMAIN + profile.canonical_bytes(manifest)).hexdigest()


def _manifest(value):
    _keys(value, 'schema campaign profile denomination participants operations sources',
          'MANIFEST_FIELDS')
    require(value['schema'] == MANIFEST_SCHEMA and value['profile'] == profile.PROFILE
            and value['denomination'] == profile.DENOMINATION, 'MANIFEST_PROFILE')
    _digest(value['campaign'], 'MANIFEST_CAMPAIGN')
    participants = set()
    for identity in _rows(value['participants'], 'PARTICIPANTS', minimum=1,
                          maximum=MAX_PARTICIPANTS):
        _digest(identity, 'PARTICIPANT_ID')
        require(identity not in participants, 'PARTICIPANT_DUPLICATE')
        participants.add(identity)
    operations = set()
    for row in _rows(value['operations'], 'EXPECTED_OPERATIONS', minimum=1):
        _keys(row, 'owner id', 'EXPECTED_OPERATION_FIELDS')
        _digest(row['owner'], 'EXPECTED_OPERATION_OWNER')
        require(row['owner'] in participants, 'EXPECTED_OPERATION_OWNER')
        _digest(row['id'], 'EXPECTED_OPERATION_ID')
        key = _key(row)
        require(key not in operations, 'EXPECTED_OPERATION_DUPLICATE')
        operations.add(key)
    sources = {}
    for row in _rows(value['sources'], 'EXPECTED_SOURCES', minimum=1, maximum=MAX_SOURCES):
        _keys(row, 'id owner policy_sha256 actor_owners', 'EXPECTED_SOURCE_FIELDS')
        identity = _digest(row['id'], 'EXPECTED_SOURCE_ID')
        require(identity not in sources, 'EXPECTED_SOURCE_DUPLICATE')
        _digest(row['owner'], 'EXPECTED_SOURCE_OWNER')
        require(row['owner'] in participants, 'EXPECTED_SOURCE_OWNER')
        _digest(row['policy_sha256'], 'EXPECTED_POLICY_PIN')
        aliases = {}
        for binding in _rows(row['actor_owners'], 'ACTOR_OWNER_BINDINGS', minimum=1,
                             maximum=MAX_PARTICIPANTS):
            _keys(binding, 'actor owner', 'ACTOR_OWNER_FIELDS')
            actor = binding['actor']
            require(type(actor) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,128}', actor)
                    is not None, 'ACTOR_OWNER_ACTOR')
            _digest(binding['owner'], 'ACTOR_OWNER_REBINDING')
            require(actor not in aliases and binding['owner'] in participants,
                    'ACTOR_OWNER_REBINDING')
            aliases[actor] = binding['owner']
        sources[identity] = dict(owner=row['owner'], pin=row['policy_sha256'], aliases=aliases)
    return participants, operations, sources


def _cost_composition(costs, operation_queries, issues):
    """Check the union of immutable observations, not their meter authenticity."""
    roots, children, atoms = [], defaultdict(list), {}
    for key, row in costs.items():
        atoms[key] = set(row['coverage'])
        if row['included_in'] is None:
            roots.append(key)
        else:
            parent = _key(row['included_in'])
            require(parent in costs, 'COMPOSED_COST_PARENT_MISSING')
            children[parent].append(key)
    for key, row in costs.items():
        if row['included_in'] is not None:
            parent_key = _key(row['included_in'])
            parent = costs[parent_key]
            require(row['unit'] == parent['unit'] and atoms[key] <= atoms[parent_key],
                    'COMPOSED_COST_SUBSET_BINDING')
    for sibling_ids in children.values():
        covered_siblings = set()
        for key in sibling_ids:
            require(not covered_siblings.intersection(atoms[key]),
                    'COMPOSED_COST_SIBLING_OVERLAP')
            covered_siblings.update(atoms[key])

    # New sources can disclose another branch of an already observed tree.
    # Check every ancestor, not just each source's individually valid subtree.
    minima, visited, seen_scopes, active_scopes = {}, set(), set(), Counter()
    stack = [(key, False, None, None) for key in roots]
    while stack:
        key, exiting, payer, beneficiary = stack.pop()
        row = costs[key]
        if not exiting:
            require(key not in visited, 'COMPOSED_COST_CYCLE')
            visited.add(key)
            # A declared owner/atom cannot appear in separate branches, even
            # when one occurrence is a child of ANOTHER owner's aggregate.
            # Repeated coverage is diagnostic only along one ancestor path.
            # Different namespace labels still do not prove physical separation.
            for atom in atoms[key]:
                scope = row['owner'], row['unit'], atom
                require(scope not in seen_scopes or active_scopes[scope] > 0,
                        'COMPOSED_OWNER_RESOURCE_OVERLAP')
                seen_scopes.add(scope)
                active_scopes[scope] += 1
            for name, inherited in (('payer', payer), ('beneficiary', beneficiary)):
                require(row[name] is None or inherited is None or row[name] == inherited,
                        'COMPOSED_COST_TRANSFER_CONFLICT')
            payer = row['payer'] if row['payer'] is not None else payer
            beneficiary = row['beneficiary'] if row['beneficiary'] is not None else beneficiary
            stack.append((key, True, payer, beneficiary))
            stack.extend((child, False, payer, beneficiary) for child in children[key])
            continue
        minimum = max(row['amount'] or 0, sum(minima[child] for child in children[key]))
        cap = row['amount'] if row['amount'] is not None else row['upper_bound']
        require(cap is None or minimum <= cap, 'COMPOSED_COST_DESCENDANTS_EXCEED_BOUND')
        minima[key] = minimum
        for atom in atoms[key]:
            active_scopes[(row['owner'], row['unit'], atom)] -= 1
    require(len(visited) == len(costs), 'COMPOSED_COST_CYCLE')

    selected, active = defaultdict(list), Counter()
    stack = [(key, False) for key in roots if costs[key]['unit'] == 'step_query']
    while stack:
        key, exiting = stack.pop()
        row = costs[key]
        operation = _key(row['operation'])
        if exiting:
            active[operation] -= 1
            continue
        if active[operation] == 0:
            selected[operation].append(key)
        active[operation] += 1
        stack.append((key, True))
        stack.extend((child, False) for child in children[key])
    counters = []
    for operation in sorted(set(selected) | set(operation_queries)):
        keys = selected[operation]
        count = operation_queries[operation]
        if not keys:
            issues.add('COMPOSED_QUERY_COST_MISSING:' + ':'.join(operation))
            continue
        seen = set()
        for key in keys:
            require(not seen.intersection(atoms[key]), 'COMPOSED_OPERATION_STEP_OVERLAP')
            seen.update(atoms[key])
        unknown = [costs[key] for key in keys if costs[key]['amount'] is None]
        known = sum(minima[key] for key in keys)
        upper = None if any(row['upper_bound'] is None for row in unknown) else sum(
            costs[key]['amount'] if costs[key]['amount'] is not None
            else costs[key]['upper_bound'] for key in keys)
        total = None if unknown else known
        require(upper is None or count <= upper, 'COMPOSED_OPERATION_QUERY_UNDERCHARGE')
        if total != count:
            issues.add('COMPOSED_STEP_COUNTER_WITHOUT_EXACT_TRACE:' + ':'.join(operation))
        counters.append(dict(operation=_ref(operation), observed_execution_events=count,
                             known=known, total=total, upper_bound=upper,
                             unknown_records=len(unknown)))
    return dict(
        unique_cost_observations=len(costs),
        observations=[costs[key] for key in sorted(costs)],
        declared_root_observations=[dict(cost=_ref(key), recorded_minimum=minima[key])
                                    for key in sorted(roots)],
        step_counters_by_operation=counters,
        cross_owner_additive_physical_totals=None,
        scope='immutable owner/record observations; different owner namespaces do not prove physical disjointness')


def compose(evidence, *, expected_manifest, expected_manifest_sha256):
    """Compose supplied records; missing declared coverage remains incomplete.

    The byte and record ceilings apply to the ENTIRE collection before invoking
    the per-source reader. They cannot be multiplied by the number of sources.
    Original evidence is required; precomputed assessment summaries are refused.
    """
    _digest(expected_manifest_sha256, 'EXPECTED_MANIFEST_PIN')
    manifest_raw = profile.canonical_bytes(expected_manifest)
    require(hashlib.sha256(_MANIFEST_DOMAIN + manifest_raw).hexdigest() ==
            expected_manifest_sha256, 'EXPECTED_MANIFEST_PIN')
    evidence_raw = profile.canonical_bytes(evidence)
    require(len(manifest_raw) + len(evidence_raw) <= MAX_BYTES, 'COMPOSITION_BYTES')
    manifest = profile.parse_json(manifest_raw)
    evidence = profile.parse_json(evidence_raw)
    participants, expected_operations, expected_sources = _manifest(manifest)
    _keys(evidence, 'schema manifest_sha256 sources', 'COMPOSITION_FIELDS')
    require(evidence['schema'] == EVIDENCE_SCHEMA, 'COMPOSITION_SCHEMA')
    require(evidence['manifest_sha256'] == expected_manifest_sha256,
            'COMPOSITION_MANIFEST_SUBSTITUTION')
    rows = _rows(evidence['sources'], 'SOURCE_ROWS', maximum=MAX_SOURCES)
    records = (len(manifest['operations']) + len(manifest['participants']) +
               len(manifest['sources']) + sum(len(row['actor_owners']) for row in manifest['sources']))
    require(records <= MAX_TOTAL_RECORDS, 'COMPOSITION_RECORDS')
    for row in rows:
        _keys(row, 'id policy evidence carrier_sha256', 'SOURCE_FIELDS')
        _digest(row['id'], 'SOURCE_ID')
        _digest(row['carrier_sha256'], 'SOURCE_CARRIER')
        require(row['id'] in expected_sources, 'UNEXPECTED_SOURCE')
        require(type(row['policy']) is dict and type(row['evidence']) is dict,
                'SOURCE_ORIGINALS_REQUIRED')
        for collection, names in ((row['policy'], ('actors', 'candidates', 'demands', 'operations')),
                                  (row['evidence'], ('queries', 'terminals', 'uses', 'costs'))):
            for name in names:
                records += len(_rows(collection.get(name), 'SOURCE_ORIGINALS_REQUIRED'))
                require(records <= MAX_TOTAL_RECORDS, 'COMPOSITION_RECORDS')
        for operation in row['policy']['operations']:
            require(type(operation) is dict, 'SOURCE_ORIGINALS_REQUIRED')
            records += len(_rows(operation.get('required_costs'), 'SOURCE_ORIGINALS_REQUIRED'))
            require(records <= MAX_TOTAL_RECORDS, 'COMPOSITION_RECORDS')

    inputs, source_replays, checked = {}, 0, []
    for row in rows:
        source_id = row['id']
        body = dict(policy=row['policy'], evidence=row['evidence'])
        if not _put(inputs, source_id, body, 'SOURCE_ID_REBINDING'):
            source_replays += 1
            continue
        expected = expected_sources[source_id]
        policy, observed = row['policy'], row['evidence']
        result = profile.assess(observed, expected_policy=policy,
                                expected_policy_sha256=expected['pin'])
        require(policy['campaign'] == manifest['campaign'], 'SOURCE_CAMPAIGN')
        require(set(expected['aliases']) == {actor['id'] for actor in policy['actors']},
                'SOURCE_ACTOR_NAMESPACE_COVERAGE')
        checked.append((source_id, expected, policy, observed, result))

    issues = set()
    missing_sources = sorted(set(expected_sources) - inputs.keys())
    for source_id in missing_sources:
        issues.add('EXPECTED_SOURCE_MISSING:' + source_id)
    expected_reporters = {row['owner'] for row in expected_sources.values()}
    observed_reporters = {expected_sources[source_id]['owner'] for source_id in inputs}
    missing_reporters = sorted(expected_reporters - observed_reporters)
    for owner in missing_reporters:
        issues.add('EXPECTED_OWNER_SOURCE_MISSING:' + owner)

    candidates, operations, demands = {}, {}, {}
    queries, terminals, uses, use_events, costs = {}, {}, {}, {}, {}
    query_coordinates, source_summaries = {}, []
    query_replays = terminal_replays = use_replays = cost_replays = 0
    complete_occurrences = Counter()
    for source_id, expected, policy, observed, result in checked:
        aliases = expected['aliases']
        for issue in result['local_issues']:
            issues.add('SOURCE:' + source_id + ':' + issue)
        source_summaries.append(dict(id=source_id, reporting_owner=expected['owner'],
            policy_sha256=expected['pin'], evidence_sha256=result['evidence_sha256'],
            observation_status=result['observation_status'], local_issues=result['local_issues']))
        local_candidates = {}
        for candidate in policy['candidates']:
            local_candidates[candidate['id']] = candidate['challenge']
            frozen = dict(candidate, id=candidate['challenge'],
                          task_authority=aliases[candidate['task_authority']],
                          target_authority=aliases[candidate['target_authority']])
            _put(candidates, candidate['challenge'], frozen, 'NATIVE_CHALLENGE_REBINDING')
        for trace in result['queries']['complete_seal_traces']:
            complete_occurrences[local_candidates[trace['candidate']]] += 1
        local_operations = {}
        for operation in policy['operations']:
            owner = aliases[operation['actor']]
            key = owner, operation['id']
            require(key in expected_operations, 'UNEXPECTED_OWNER_OPERATION')
            local_operations[operation['id']] = key
            body = dict(owner=owner, id=operation['id'], role=operation['role'],
                candidates=sorted(local_candidates[c] for c in operation['candidates']),
                authorized_at=operation['authorized_at'], deadline=operation['deadline'],
                required_costs=sorted(operation['required_costs'], key=lambda x: (x['stage'], x['unit'])))
            _put(operations, key, body, 'OWNER_OPERATION_REBINDING')
        local_demands = {}
        for demand in policy['demands']:
            owner = aliases[demand['requester']]
            key = owner, demand['id']
            local_demands[demand['id']] = key
            body = dict(demand, owner=owner, requester=owner, consumer=aliases[demand['consumer']])
            _put(demands, key, body, 'OWNER_DEMAND_REBINDING')

        for row in observed['queries']:
            operation = local_operations[row['operation']]
            key = operation[0], row['id']
            body = dict(owner=key[0], id=key[1], operation=_ref(operation),
                candidate=local_candidates[row['candidate']],
                **{field: row[field] for field in ('at', 'index', 'predecessor', 'answer')})
            if _put(queries, key, body, 'OWNER_QUERY_EVENT_REBINDING'):
                coordinate = operation, row['at']
                require(coordinate not in query_coordinates, 'OWNER_QUERY_COORDINATE_ALIAS')
                query_coordinates[coordinate] = key
            else:
                query_replays += 1
        for row in observed['terminals']:
            operation = local_operations[row['id']]
            body = dict(owner=operation[0], id=operation[1],
                        **{field: row[field] for field in ('at', 'outcome', 'receipt_sha256')})
            if not _put(terminals, operation, body, 'OWNER_TERMINAL_RECEIPT_REBINDING'):
                terminal_replays += 1
        for row in observed['uses']:
            operation = local_operations[row['operation']]
            body = dict(operation=_ref(operation), candidate=local_candidates[row['candidate']],
                demand=_ref(local_demands[row['demand']]),
                **{field: row[field] for field in ('at', 'output_sha256', 'receipt_sha256')})
            _put(use_events, (operation[0], row['id']), body, 'OWNER_USE_EVENT_REBINDING')
            if not _put(uses, operation, body, 'OWNER_CONSUMER_OPERATION_REBINDING'):
                use_replays += 1

        local_costs = {row['id']: (local_operations[row['operation']][0], row['id'])
                       for row in observed['costs']}
        for row in observed['costs']:
            operation = local_operations[row['operation']]
            key = operation[0], row['id']
            body = dict(owner=key[0], id=key[1], operation=_ref(operation),
                **{field: row[field] for field in ('stage', 'unit', 'amount', 'upper_bound', 'receipt_sha256')},
                **{field: None if row[field] is None else aliases[row[field]]
                   for field in ('meter', 'payer', 'beneficiary')},
                coverage=sorted(row['coverage']),
                included_in=None if row['included_in'] is None else _ref(local_costs[row['included_in']]))
            if not _put(costs, key, body, 'OWNER_COST_RECEIPT_REBINDING'):
                cost_replays += 1

    missing_operations = sorted(expected_operations - operations.keys())
    for key in missing_operations:
        issues.add('EXPECTED_OPERATION_MISSING:' + ':'.join(key))
    for key in operations.keys() - terminals.keys():
        issues.add('COMPOSED_OPERATION_TERMINAL_MISSING:' + ':'.join(key))
    operation_queries, counts_by_role = Counter(), Counter()
    table = {}
    for key, row in queries.items():
        operation = _key(row['operation'])
        operation_queries[operation] += 1
        counts_by_role[operations[operation]['role']] += 1
        terminal = terminals.get(operation)
        require(terminal is None or row['at'] <= terminal['at'],
                'COMPOSED_QUERY_AFTER_TERMINAL')
        candidate = candidates[row['candidate']]
        raw = profile._step_input(candidate, row['index'], bytes.fromhex(row['predecessor']))
        # Each ORIGINAL source has already checked the actual SHA-256 answer.
        # This table is keyed by bytes, not an answer, carrier, or claimed ID.
        entry = table.setdefault(raw, dict(answer=bytes.fromhex(row['answer']), events=set()))
        require(entry['answer'].hex() == row['answer'], 'COMPOSED_ORACLE_CONFLICT')
        entry['events'].add(key)
    for operation, use in uses.items():
        terminal = terminals.get(operation)
        require(terminal is None or use['at'] <= terminal['at'], 'COMPOSED_USE_AFTER_TERMINAL')

    resource_report = _cost_composition(costs, operation_queries, issues)
    resource_report['record_carrier_replays'] = cost_replays
    completed = []
    for challenge, candidate in sorted(candidates.items()):
        state = profile._seed(candidate)
        owners = set()
        for index in range(1, profile.STEPS + 1):
            entry = table.get(profile._step_input(candidate, index, state))
            if entry is None:
                state = None
                break
            state = entry['answer']
            owners.update(event[0] for event in entry['events'])
        if state is not None:
            completed.append(dict(challenge=challenge, statement=candidate['statement'],
                target=candidate['target'], endpoint=state.hex(),
                target_hit=state <= bytes.fromhex(candidate['target']),
                contributing_owner_namespaces=sorted(owners),
                source_complete_trace_occurrences=complete_occurrences[challenge],
                hypothetical_award_per_hit=str(profile.STEPS *
                    ((1 << 256) // (int(candidate['target'], 16) + 1)))))
    union = hashlib.sha256(_UNION_DOMAIN)
    owner_distribution = Counter()
    for raw in sorted(table):
        union.update(len(raw).to_bytes(4, 'big')); union.update(raw)
        owner_distribution[len({key[0] for key in table[raw]['events']})] += 1

    return dict(schema=REPORT_SCHEMA, manifest_sha256=expected_manifest_sha256,
        evidence_sha256=hashlib.sha256(evidence_raw).hexdigest(),
        profile=profile.PROFILE, denomination=profile.DENOMINATION,
        qualification='HOLD',
        observation_status='COMPLETE_DECLARED_COMPOSITION' if not issues else 'INCOMPLETE',
        coverage=dict(expected_sources=len(expected_sources), observed_sources=len(inputs),
            source_carrier_replays=source_replays, missing_sources=missing_sources,
            expected_reporting_owner_namespaces=len(expected_reporters),
            observed_reporting_owner_namespaces=len(observed_reporters),
            missing_reporting_owners=missing_reporters,
            declared_participant_namespaces=len(participants),
            expected_operations=len(expected_operations), observed_operation_declarations=len(operations),
            missing_operations=[_ref(key) for key in missing_operations],
            public_query_total=None, coalition_query_total=None,
            public_coverage_complete=False, actual_control_relationships_authenticated=False,
            independent_owner_control_established=False,
            global_inter_owner_order_established=False,
            undeclared_owner_or_role_absence_established=False),
        sources=source_summaries,
        queries=dict(unique_declared_execution_events=len(queries),
            distinct_native_inputs=len(table), repeated_input_executions=len(queries) - len(table),
            event_carrier_replays=query_replays,
            events_by_declared_role=dict(sorted(counts_by_role.items())),
            native_input_union_sha256=union.hexdigest(),
            identity_uses_full_native_preimage_bytes=True,
            native_inputs_by_declared_owner_count={str(n): count for n, count in sorted(owner_distribution.items())},
            complete_seal_traces=completed, distinct_complete_trace_opportunities=len(completed),
            source_complete_trace_occurrences=sum(complete_occurrences.values()),
            complete_trace_does_not_verify_useful_relation=True,
            observed_counts_are_not_expected_query_costs=True),
        attempts=dict(unique_owner_operations=len(operations), observed_terminals=len(terminals),
            terminal_carrier_replays=terminal_replays,
            outcomes=dict(sorted(Counter(row['outcome'] for row in terminals.values()).items()))),
        demand=dict(unique_owner_demand_references=len(demands),
            unique_consumer_operations=len(uses), observed_use_event_identities=len(use_events),
            operation_replays=use_replays, genuine_independent_demand_established=False),
        resources=resource_report, local_issues=sorted(issues),
        unresolved_predicates=list(profile.EXTERNAL_OBLIGATIONS),
        source_authority='independently supplied namespace/policy pins; real owner control and receipts are not authenticated',
        receipt_digest_alone_is_not_operation_identity=True,
        actual_chainwork=0, consensus_weight_eligible=False, production_activation=False,
        physical_resource_lower_bound_proved=False, fresh_neural_mac_floor_proved=False,
        quantum_security_proved=False)


def main(argv=None):
    """Read-only CLI. A valid HOLD returns zero; inconsistent input returns two."""
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--expected-manifest', required=True)
    parser.add_argument('--expected-manifest-sha256', required=True)
    args = parser.parse_args(argv)
    def read(path):
        with open(path, 'rb') as stream:
            return profile.parse_json(stream.read(MAX_BYTES + 1))
    try:
        report = compose(read(args.evidence), expected_manifest=read(args.expected_manifest),
                         expected_manifest_sha256=args.expected_manifest_sha256)
    except (OSError, ValueError) as failure:
        print(json.dumps(dict(schema=REPORT_SCHEMA, status='REJECTED', error=str(failure)),
                         sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, separators=(',', ':'), allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
