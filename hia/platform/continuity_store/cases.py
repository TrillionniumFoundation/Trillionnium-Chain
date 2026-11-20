"""Actual native/original differential corpus for the complete finite relation."""
from __future__ import annotations

from dataclasses import dataclass, replace
import copy
import random

from hia.platform.typed_store.cases import Case as TypedCase, kv, delta, MAX
from hia.platform.continuity_store.reference import MAINTENANCE, canonical, configuration, relation, root_grammar
from hia.tests.test_state_root import reference as root_reference

@dataclass(frozen=True)
class Case(TypedCase):
    variant: int = 0
    height: int = 0
    continuity_code: int = 0
    capacity: dict | None = None

    def corpus(self):
        result = super().corpus()
        result.update(variant=self.variant, height=self.height)
        return result

    def progress(self):
        events = TypedCase.progress(replace(self, cancel=None))
        if self.fail_delta is None and self.fail_row is None and self.continuity_code == 0:
            events.append([len(events) + 1, 8, len(self.result)])
        if self.cancel is not None:
            if not 1 <= self.cancel <= len(events):
                raise ValueError('Cancellation outside actual callback relation')
            events = events[:self.cancel]
        return events

def material(state, variant=0, maintenance=True):
    values = copy.deepcopy(state)
    if maintenance and MAINTENANCE not in values:
        values[MAINTENANCE] = copy.deepcopy(configuration(variant)['record'])
    return tuple((key.encode(), canonical(value)) for key, value in sorted(values.items()))

def make(name, state, *, variant=0, height=0, root=False, maintenance=True):
    rows = material(state, variant, maintenance)
    code, capacity = relation(rows, height, variant)
    expected_code = code
    if not code and root:
        expected_code = root_grammar(rows)
    return Case(name=name, before=rows, changes=(), result=rows, code=expected_code,
        variant=variant, height=height, root=root, profile=variant >> 1,
        continuity_code=code, capacity=capacity)

def rewards(height, owners=None):
    owners = owners or ['0' * 64]
    return {'reward:' + f'{index:02}': {'maturity': height + 20 - index, 'amount': index,
        'owner': owners[index % len(owners)]} for index in range(min(height, 20))}

def cases():
    result = []
    def add(name, state, **options):
        case = make(name, state, **options)
        result.append(case)
        return case
    owner = '0' * 64
    owners = [f'{index:064x}' for index in range(17)]
    for variant in range(4):
        add(f'bootstrap-{variant}', {}, variant=variant, root=variant < 2)
        add(f'maintenance-missing-{variant}', {}, variant=variant, maintenance=False)
        for other in range(4):
            if variant != other:
                add(f'maintenance-other-context-{variant}-{other}',
                    {MAINTENANCE: configuration(other)['record']}, variant=variant)
        for field in configuration(variant)['record']:
            record = copy.deepcopy(configuration(variant)['record'])
            del record[field]
            add(f'maintenance-missing-{variant}-{field}', {MAINTENANCE: record}, variant=variant)
        for name, replacement in [('null', None), ('array', []), ('false', False), ('number', 0), ('string', 'x')]:
            add(f'maintenance-type-{variant}-{name}', {MAINTENANCE: replacement}, variant=variant)
        for name, value in [('floating-zero', 0.0), ('negative-zero', -0.0), ('false', False), ('string', '0'), ('one', 1)]:
            record = copy.deepcopy(configuration(variant)['record'])
            record['useful_output_credit'] = value
            add(f'maintenance-credit-{variant}-{name}', {MAINTENANCE: record}, variant=variant)
        record = copy.deepcopy(configuration(variant)['record'])
        record['extra'] = None
        add(f'maintenance-extra-{variant}', {MAINTENANCE: record}, variant=variant)
        for height in (0, 1, 2, 19, 20, 21, 127, MAX - 20):
            state = rewards(height, owners)
            state['account:' + owners[0]] = None
            add(f'queue-complete-{variant}-{height}', state, variant=variant, height=height)
        for suffix in ('', '\0', ':', 'é', '😀', 'x' * 141, 'x' * 147):
            name = suffix.encode().hex()[:18] or 'empty'
            add(f'archive-missing-{variant}-{name}-{len(suffix)}', {'contribution:' + suffix: None}, variant=variant)
            if len(('evaluation-archive:' + suffix).encode()) <= 160:
                add(f'archive-present-{variant}-{name}-{len(suffix)}',
                    {'contribution:' + suffix: [], 'evaluation-archive:' + suffix: None}, variant=variant)
        state = rewards(1, [owner])
        state.update({'quota:': {'remaining': 1, 'owner': owner}, 'release:\0': {'remaining': MAX, 'owner': owner},
            'task:é': {'remaining': 1, 'owner': owner}, 'account:opaque': None, 'contribution:': False})
        add(f'recipient-exact-dedup-{variant}', state, variant=variant, height=1)
        state['account:' + owner] = None
        add(f'existing-null-account-{variant}', state, variant=variant, height=1)
    invalid_numbers = [('null', None), ('false', False), ('true', True), ('negative', -1), ('float', 1.0),
        ('string', '1'), ('array', []), ('object', {}), ('missing', None)]
    for prefix in ('quota:', 'release:', 'task:'):
        for name, value in invalid_numbers:
            body = {'remaining': value, 'owner': owner}
            if name == 'missing':
                del body['remaining']
            add(f'{prefix[:-1]}-remaining-{name}', {prefix: body})
        for name, value in [('zero', 0), ('one', 1), ('max', MAX)]:
            add(f'{prefix[:-1]}-remaining-{name}', {prefix: {'remaining': value, 'owner': owner}})
        for name, value in [('null', None), ('false', False), ('number', 0), ('array', []), ('object', {}),
                ('short', '0' * 63), ('long', '0' * 65), ('upper', 'A' * 64), ('unicode', 'é' * 32),
                ('nul', '0' * 63 + '\0'), ('punctuation', 'g' * 64), ('missing', None)]:
            body = {'remaining': 1, 'owner': value}
            if name == 'missing':
                del body['owner']
            add(f'{prefix[:-1]}-owner-{name}', {prefix: body})
            body['remaining'] = 0
            add(f'{prefix[:-1]}-zero-ignores-owner-{name}', {prefix: body})
    for field in ('maturity', 'amount'):
        for name, value in invalid_numbers:
            body = {'maturity': 21, 'amount': 0, 'owner': owner}
            body[field] = value
            if name == 'missing':
                del body[field]
            add(f'reward-{field}-{name}', {'reward:': body}, height=1)
    for height in (0, 1, 19, 20, 21, MAX - 20, MAX - 19, MAX - 1, MAX):
        add(f'queue-empty-height-{height}', {}, height=height)
        for due in sorted({0, height, min(MAX, height + 1), min(MAX, height + 20), MAX}):
            add(f'queue-due-{height}-{due}', {'reward:': {'maturity': due, 'amount': 0, 'owner': owner}}, height=height)
    add('reward-duplicate-precedes-bad-amount', {'reward:a': {'maturity': 21, 'amount': 0, 'owner': owner},
        'reward:b': {'maturity': 21, 'amount': False, 'owner': None}}, height=1)
    add('quota-error-precedes-reward-queue', {'quota:': {'remaining': False},
        'reward:': {'maturity': 0, 'amount': False, 'owner': None}}, height=1)
    add('release-error-precedes-reward-queue', {'release:': {'remaining': False},
        'reward:': {'maturity': 0, 'amount': False, 'owner': None}}, height=1)
    add('reward-queue-precedes-task-error', {'task:': {'remaining': False},
        'reward:': {'maturity': 0, 'amount': False, 'owner': None}}, height=1)
    add('maintenance-error-precedes-quota', {MAINTENANCE: None, 'quota:': {'remaining': False}})
    for name in ('quota', 'quota;', 'release', 'release;', 'reward', 'reward;', 'task', 'task;',
            'contribution', 'contribution;', 'account', 'account;', 'quotaé', 'task😀', 'zz:'):
        add('prefix-neighbor-' + name.encode().hex(), {name: None}, variant=1)
    for name, value in [('floating', 1.25), ('unicode', 'é'), ('nested-unicode', {'é': '😀'})]:
        add('root-after-continuity-' + name, {'zz:': value}, root=True)
        add('continuity-before-root-' + name, {'quota:': None, 'zz:': value}, root=True)
    # A real, sorted, typed Delta repairs or invalidates the maintenance relation.
    base = material({MAINTENANCE: None})
    repaired = material({})
    result.append(Case(name='delta-repairs-maintenance', before=base,
        changes=((MAINTENANCE.encode(), b'null', canonical(configuration(0)['record'])),), result=repaired,
        root=True, continuity_code=0, capacity=relation(repaired, 0, 0)[1]))
    result.append(Case(name='delta-invalidates-maintenance', before=repaired,
        changes=((MAINTENANCE.encode(), canonical(configuration(0)['record']), b'null'),), result=base,
        code=91, root=True, continuity_code=91))
    result.append(Case(name='detach-restores-maintenance', before=base,
        changes=((MAINTENANCE.encode(), canonical(configuration(0)['record']), b'null'),), result=repaired,
        detach=True, root=True, continuity_code=0, capacity=relation(repaired, 0, 0)[1]))
    # Full ordered State scan crosses original row callback boundaries.
    for count in (255, 256, 257, 512, 513):
        add('full-state-progress-' + str(count), {f'zz:{index:05}': None for index in range(count - 1)})
    for selected in list(result[:4]) + [next(case for case in result if case.name == 'delta-repairs-maintenance'),
            next(case for case in result if case.name == 'quota-error-precedes-reward-queue'),
            next(case for case in result if case.name == 'full-state-progress-257')]:
        for point in range(1, len(selected.progress()) + 1):
            result.append(replace(selected, name=selected.name + '-cancel-' + str(point), code=80, cancel=point))
    # Deterministic complete maps exercise identity sorting independently of key order.
    rng = random.Random(0xC071A117)
    for index in range(80):
        variant = index % 4
        height = rng.choice((0, 1, 2, 19, 20, 21, 37))
        state = rewards(height, owners)
        for row in range(rng.randrange(1, 32)):
            prefix = rng.choice(('quota:', 'release:', 'task:'))
            chosen = rng.choice(owners)
            state[prefix + f'{row:04}'] = {'remaining': rng.choice((0, 1, 2, MAX)), 'owner': chosen}
            if rng.randrange(5) == 0:
                state['account:' + chosen] = rng.choice((None, False, {}, []))
            if rng.randrange(3) == 0:
                state['contribution:' + f'{row:04}'] = None
            if rng.randrange(5) == 0:
                state['evaluation-archive:' + f'{row:04}'] = False
        if index % 7 == 0:
            state['quota:bad'] = {'remaining': False}
        add('random-complete-state-' + str(index), state, variant=variant, height=height)
    # The new owner must retain original apply/complete-State errors before its
    # private continuity phase, even when maintenance is independently invalid.
    raw_bad = (
        ('late-json', b'zz:bad', b'{', 83),
        ('late-empty-value', b'zz:bad', b'', 83),
        ('late-whitespace', b'zz:bad', b' null', 84),
        ('late-duplicate-member', b'zz:bad', b'{"a":0,"a":1}', 84),
        ('late-object-order', b'zz:bad', b'{"z":0,"a":1}', 84),
        ('late-number-spelling', b'zz:bad', b'1.00', 84),
        ('late-value-over', b'zz:bad', b'"' + b'a' * 4095 + b'"', 84),
        ('late-key-over', b'z' * 161, b'null', 84),
        ('early-empty-key', b'', b'null', 83),
    )
    for name, key, value, code in raw_bad:
        rows = tuple(sorted(((MAINTENANCE.encode(), b'null'), (key, value))))
        index = next(i for i, row in enumerate(rows) if row[0] == key)
        result.append(Case(name='state-before-continuity-' + name, before=rows, changes=(), result=rows,
            code=code, fail_row=index, root=True, continuity_code=91))
    invalid = material({MAINTENANCE: None, 'zz:': None})
    result.append(Case(name='delta-mismatch-before-continuity', before=invalid,
        changes=((b'zz:', b'false', b'true'),), result=invalid, code=81, fail_delta=0,
        root=True, continuity_code=91))
    absent = material({MAINTENANCE: None})
    result.append(Case(name='delta-absent-before-continuity', before=absent,
        changes=((b'zz:', b'null', None),), result=absent, code=81, fail_delta=0,
        root=True, continuity_code=91))
    selected = make('final-state-cancel-before-maintenance', {MAINTENANCE: None})
    result.append(replace(selected, code=80, cancel=len(selected.progress())))
    names = [case.name for case in result]
    if len(names) != len(set(names)):
        raise ValueError('Duplicate semantic corpus name')
    return result

def capacity_cases():
    for variant in range(4):
        for count in (65516, 65517):
            state = {f'zz:{index:05}': None for index in range(count - 1)}
            yield make(f'working-capacity-{variant}-{count}', state, variant=variant)
        state = {f'zz:{index:05}': None for index in range(65516)}
        state[MAINTENANCE] = None
        yield make(f'capacity-maintenance-before-limit-{variant}', state, variant=variant)
        del state[MAINTENANCE]
        del state['zz:00000']
        state['quota:'] = None
        yield make(f'capacity-state-error-before-limit-{variant}', state, variant=variant)
    owner = '0' * 64
    for variant in (0, 1):
        state = {f'zz:{index:05}': None for index in range(65514)}
        state['quota:'] = {'remaining': 1, 'owner': owner}
        yield make(f'capacity-owner-reserve-{variant}', state, variant=variant)
        del state['zz:00000']
        state['account:' + owner] = None
        yield make(f'capacity-existing-owner-{variant}', state, variant=variant)
    state = {f'zz:{index:05}': None for index in range(65514)}
    state['contribution:'] = None
    yield make('capacity-archive-reserve', state, variant=1)
    del state['zz:00000']
    state['evaluation-archive:'] = None
    yield make('capacity-existing-archive', state, variant=1)
    for variant in (2, 3):
        state = {f'zz:{index:05}': None for index in range(65515)}
        state['account:opaque'] = None
        yield make(f'growth-split-not-total-capacity-{variant}', state, variant=variant)
