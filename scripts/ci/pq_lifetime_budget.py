#!/usr/bin/env python3
"""Conservative PQ128 lifetime budget arithmetic; never a security attestation.

Input contract and the arithmetic example are described by
``docs/security/PQ128_LIFETIME_BUDGET_V1.md``. A theorem reference, signed log,
source hash, or successful invocation cannot establish that a cryptographic
reduction applies. All numeric outputs are arithmetic on declared inputs.
``actual_lifetime_failure_bound`` remains null and qualification remains false.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_source_reader import SourceReadError, read_regular

SCHEMA = 'trnm-pq128-lifetime-budget-v1'
DEFAULT_MANIFEST = 'config/pon/pq128-lifetime-budget-v1.json'
SOURCE_LOCK_SCHEMA = 'trnm-pq128-source-lock-v1'
DEFAULT_SOURCE_LOCK = 'config/pon/pq128-source-lock-v1.json'
EVENT_IDS = frozenset({'signature', 'commitment', 'proof', 'ledger', 'transport',
                       'recovery', 'release', 'application'})
QUERY_COVERAGE = frozenset({'online', 'offline', 'preprocessing', 'failed',
                           'unpublished', 'recursive', 'shared-primitive'})
MODEL = 'quantum-adaptive-lifetime'
MAX_BYTES = 1024 * 1024
MAX_ROWS = 128
MAX_DIGITS = 1233  # <4096 bits, below Python's ordinary decimal conversion cap.
MAX_ARITHMETIC_BITS = 4096  # Bound every exact result; do not round an overflow.


class BudgetError(ValueError):
    """An ambiguous or malformed budget contract must be refused."""


def require(ok, message):
    if not ok:
        raise BudgetError(message)


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names.split()),
            'unexpected or missing fields: ' + where)


def string(value, where):
    require(type(value) is str and 0 < len(value) <= 8192 and value.strip() == value,
            'invalid string: ' + where)
    try:
        value.encode('utf-8')
    except UnicodeError as error:
        raise BudgetError('invalid Unicode string: ' + where) from error
    return value


def sequence(value, where, nonempty=False):
    require(type(value) is list and int(nonempty) <= len(value) <= MAX_ROWS,
            'invalid list: ' + where)
    return value


def strings(value, where, nonempty=False):
    sequence(value, where, nonempty)
    for item in value:
        string(item, where)
    require(len(set(value)) == len(value), 'duplicate list member: ' + where)
    return value


def natural(value, where, positive=False):
    require(type(value) is str and len(value) <= MAX_DIGITS
            and re.fullmatch(r'0|[1-9][0-9]*', value) is not None,
            'integer must be a canonical decimal string: ' + where)
    try:
        result = int(value)
    except ValueError as error:
        raise BudgetError('integer exceeds runtime parsing limit: ' + where) from error
    require(result > 0 if positive else result >= 0, 'invalid integer: ' + where)
    return result


def probability(value, where, positive=False):
    fields(value, 'numerator denominator', where)
    result = Fraction(natural(value['numerator'], where + '.numerator'),
                      natural(value['denominator'], where + '.denominator', True))
    require(0 < result <= 1 if positive else 0 <= result <= 1,
            'probability outside range: ' + where)
    return result


def bounded_fraction(value, where):
    require(value.numerator.bit_length() <= MAX_ARITHMETIC_BITS
            and value.denominator.bit_length() <= MAX_ARITHMETIC_BITS,
            'exact arithmetic limit exceeded: ' + where)
    return value


def bounded_sum(values, where):
    result = Fraction()
    for value in values:
        result = bounded_fraction(result + value, where)
    return result


def rational(value):
    if value is None:
        return None
    bounded_fraction(value, 'rational output')
    try:
        return {'numerator': str(value.numerator), 'denominator': str(value.denominator)}
    except ValueError as error:
        raise BudgetError('rational exceeds runtime serialization limit') from error


def relative_path(value, where):
    string(value, where)
    require(not value.startswith('/') and '\\' not in value and '\x00' not in value
            and not any(part in ('', '.', '..') for part in value.split('/')),
            'unsafe source path: ' + where)
    return value


def strict_json(raw):
    """Decode a bounded UTF-8 JSON object, rejecting duplicate/numeric ambiguity."""
    require(type(raw) in (str, bytes), 'JSON input must be text or bytes')
    try:
        encoded = raw.encode('utf-8') if type(raw) is str else raw
        require(len(encoded) <= MAX_BYTES, 'oversize JSON input')
        raw = encoded.decode('utf-8')
    except UnicodeError as error:
        raise BudgetError('budget JSON must be valid UTF-8') from error

    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON field: ' + key)
            out[key] = value
        return out

    def integer(text):
        require(len(text) <= 18, 'oversize JSON integer; use canonical decimal strings')
        return int(text)

    def unsupported(text):
        raise BudgetError('floating-point/nonfinite JSON number refused: ' + text)

    try:
        parsed = json.loads(raw, object_pairs_hook=unique, parse_int=integer,
                            parse_float=unsupported, parse_constant=unsupported)
        # JSON permits escaped lone surrogates. They are not valid UTF-8 paths
        # or source text, even when the byte encoding of the escape was valid.
        pending = [parsed]
        while pending:
            value = pending.pop()
            if type(value) is str:
                value.encode('utf-8')
            elif type(value) is dict:
                pending.extend(value)
                pending.extend(value.values())
            elif type(value) is list:
                pending.extend(value)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise BudgetError('invalid budget JSON: ' + str(error)) from error
    require(type(parsed) is dict, 'budget JSON must be an object')
    return parsed


def evaluate(data):
    """Validate the declared model and perform exact, explicitly conditional sums."""
    fields(data, 'schema purpose target_bits experiment assumptions primitives events terms',
           'manifest')
    require(data['schema'] == SCHEMA, 'unsupported budget schema')
    require(data['purpose'] in ('research-model', 'arithmetic-example'), 'unknown purpose')
    require(type(data['target_bits']) is int and data['target_bits'] == 128,
            'this schema fixes the target at 128 bits')
    target = Fraction(1, 1 << 128)
    exp = data['experiment']
    fields(exp, 'id profile model horizon source_revision', 'experiment')
    for key, value in exp.items():
        string(value, 'experiment.' + key)
    require(exp['model'] == MODEL, 'unsupported adversary model')
    require(re.fullmatch(r'[0-9a-f]{40}', exp['source_revision']) is not None
            or (data['purpose'] == 'arithmetic-example'
                and exp['source_revision'] == 'illustrative'),
            'source revision must be a full lowercase commit ID, or illustrative in an arithmetic example')

    assumptions = {}
    for row in sequence(data['assumptions'], 'assumptions'):
        fields(row, 'id statement status', 'assumption')
        for key in ('id', 'statement'):
            string(row[key], 'assumption.' + key)
        require(row['id'] not in assumptions, 'duplicate assumption ID')
        require(row['status'] in ('assumed', 'unmet'), 'invalid assumption status')
        assumptions[row['id']] = row

    primitives = {}
    public_parameters = set()
    for row in sequence(data['primitives'], 'primitives'):
        fields(row, 'id construction public_parameter_id fixed_across_epochs reset_at_epoch query_budget',
               'primitive')
        for key in ('id', 'construction', 'public_parameter_id'):
            string(row[key], 'primitive.' + key)
        require(row['id'] not in primitives, 'duplicate primitive ID')
        # The parameter identity is global. Renaming a construction is not a
        # new public oracle and must not split one preprocessing/query scope.
        identity = row['public_parameter_id']
        require(identity not in public_parameters,
                'shared public primitive duplicated; canonicalize its lifetime budget')
        public_parameters.add(identity)
        # v1 has no theorem proving that a changed label resets oracle advice.
        require(row['fixed_across_epochs'] is True and row['reset_at_epoch'] is False,
                'epoch/key rotation cannot reset this fixed public primitive budget')
        query = row['query_budget']
        fields(query, 'basis maximum coverage assumption_id', 'query_budget')
        strings(query['coverage'], 'query coverage')
        require(set(query['coverage']) == QUERY_COVERAGE,
                'query coverage must include offline, preprocessing, failures, unpublished searches and shared uses')
        require(query['basis'] in ('external-adversary-assumption', 'unknown'),
                'node telemetry cannot bound adversary quantum queries')
        if query['basis'] == 'unknown':
            require(query['maximum'] is None and query['assumption_id'] is None,
                    'unknown query limit cannot contain a numeric cap')
        else:
            # Zero is permitted only as a declared external model assumption;
            # this checker never attests that an attacker made zero queries.
            natural(query['maximum'], 'query maximum')
            string(query['assumption_id'], 'query assumption_id')
            require(query['assumption_id'] in assumptions,
                    'query maximum must name its external adversary assumption')
        primitives[row['id']] = row

    allocations = {}
    source_paths = set()
    for row in sequence(data['events'], 'events', True):
        fields(row, 'id definition source_paths allocation', 'event')
        string(row['id'], 'event.id')
        string(row['definition'], 'event.definition')
        require(row['id'] in EVENT_IDS and row['id'] not in allocations,
                'unknown or duplicate event ID')
        for path in strings(row['source_paths'], 'event source_paths', True):
            source_paths.add(relative_path(path, 'event source_path'))
        allocations[row['id']] = probability(row['allocation'], 'event allocation', True)
    require(set(allocations) == EVENT_IDS, 'missing required event category')
    allocated = bounded_sum(allocations.values(), 'allocation sum')
    require(allocated <= target, 'planned allocations exceed the target')

    term_ids, covered, losses = set(), set(), set()
    results, unknown, obligations = [], [], []
    partial = Fraction()
    all_assumed = all(row['status'] == 'assumed' for row in assumptions.values())
    for row in sequence(data['terms'], 'terms', True):
        fields(row, 'id covers experiment_id profile model status bound scope opportunities theorem loss_ids primitive_ids assumption_ids obligations',
               'term')
        term_id = string(row['id'], 'term.id')
        require(term_id not in term_ids, 'duplicate term ID')
        term_ids.add(term_id)
        covers = strings(row['covers'], 'term coverage', True)
        require(set(covers) <= EVENT_IDS, 'unknown covered event')
        require(not covered.intersection(covers),
                'duplicate event coverage; use one joint theorem term')
        covered.update(covers)
        require(row['experiment_id'] == exp['id'] and row['profile'] == exp['profile']
                and row['model'] == exp['model'], 'experiment/profile/model mismatch')
        require(row['scope'] in ('per-invocation', 'multi-instance', 'whole-lifetime'),
                'unsupported bound scope')
        scope = row['scope']
        opportunities = row['opportunities']
        multiplier = 1
        if scope == 'per-invocation':
            fields(opportunities, 'maximum cap_kind conditioning', 'opportunities')
            multiplier = natural(opportunities['maximum'], 'opportunity maximum', True)
            require(opportunities['cap_kind'] == 'almost-sure',
                    'expected or observed opportunities do not give an almost-sure cap')
            require(opportunities['conditioning'] in ('uniform-adaptive-history', 'first-bad-joint'),
                    'marginal bounds cannot be reused across adaptive histories')
        else:
            require(opportunities is None,
                    'multi-instance/whole-lifetime bounds must not be multiplied again')
        strings(row['loss_ids'], 'loss IDs')
        require(not losses.intersection(row['loss_ids']),
                'duplicate loss ID requires an explicit deduplicated theorem mapping')
        losses.update(row['loss_ids'])
        for key, known in (('primitive_ids', primitives), ('assumption_ids', assumptions)):
            strings(row[key], key)
            require(set(row[key]) <= set(known), 'unknown reference: ' + key)
        strings(row['obligations'], 'obligations')
        obligations.extend({'term_id': term_id, 'obligation': value}
                           for value in row['obligations'])
        status = row['status']
        require(status in ('unknown', 'declared-model-bound', 'illustrative'),
                'unsupported bound status; self-certification is refused')
        if status == 'unknown':
            require(row['bound'] is None and row['theorem'] is None and row['obligations'],
                    'unknown term requires null bound/theorem and explicit obligations')
            value = None
            unknown.append(term_id)
        else:
            require(status != 'illustrative' or data['purpose'] == 'arithmetic-example',
                    'illustrative values cannot enter the research model')
            theorem = row['theorem']
            fields(theorem, 'reference locator applicability', 'theorem')
            for key, content in theorem.items():
                string(content, 'theorem.' + key)
            value = bounded_fraction(probability(row['bound'], 'declared term bound')
                                     * multiplier, 'lifetime term')
            partial = bounded_fraction(partial + value, 'partial arithmetic sum')
        allocation = bounded_sum((allocations[event] for event in covers),
                                 'joint allocation sum')
        results.append({'id': term_id, 'covers': covers, 'scope': scope,
                        'input_status': status, 'multiplier': str(multiplier),
                        'allocation': rational(allocation),
                        'declared_lifetime_term': rational(value),
                        'within_allocation': None if value is None else value <= allocation,
                        'theorem': row['theorem'], 'proof_verified': False})
    require(covered == EVENT_IDS, 'every required event must have one term, including unknowns')

    query_unknown = [key for key, row in primitives.items()
                     if row['query_budget']['basis'] == 'unknown']
    # Even a full table does not establish a complete event reduction or verify
    # theorem instantiations. The three values below deliberately differ.
    model_sum = None if unknown else partial
    return {
        'schema': 'trnm-pq128-lifetime-budget-result-v1', 'status': 'HOLD',
        'purpose': data['purpose'], 'target': rational(target),
        'allocated_sum': rational(allocated), 'partial_arithmetic_sum': rational(partial),
        'model_arithmetic_sum': rational(model_sum),
        'target_met_under_declared_bounds': None if model_sum is None else model_sum <= target,
        'all_declared_assumptions_assumed': all_assumed,
        'actual_lifetime_failure_bound': None,
        'whole_chain_pq_qualified': False, 'pq_128_qualified': False,
        'production_activation': False, 'composition_coverage_proved': False,
        'theorem_applicability_verified': False,
        # evaluate() has no source access. Only inspect() can establish
        # consistency with the separately reviewed declared-path source lock.
        'source_revision_bound': False, 'source_binding_scope': 'unbound',
        'source_lock_sha256': None,
        'experiment': exp, 'assumptions': data['assumptions'],
        'unknown_terms': unknown, 'unknown_query_budgets': query_unknown,
        'term_results': results, 'source_paths': sorted(source_paths),
        'obligations': [
            {'term_id': None, 'obligation': 'Prove the complete whole-chain bad-event reduction, including shared-model replacement/hybrid errors; the eight audit categories alone do not establish coverage.'},
            {'term_id': None, 'obligation': 'Independently establish applicability of each theorem to the pinned implementation and the common adaptive quantum experiment, including legal auxiliary quantum states and preprocessing.'},
            {'term_id': None, 'obligation': 'Discharge external assumptions; unmodeled implementation failures and simultaneous custodian compromise have no invented probability.'},
        ] + obligations,
        'note': 'Exact arithmetic over declared inputs only. References, source hashes and node logs do not prove a PQ128 security claim; no unconditional bound or activation is produced.',
    }


def inspect(root, manifest_path=DEFAULT_MANIFEST):
    """Bind research paths to a reviewed lock, without authenticating its origin.

    The lock is checked-in review material so this check also works in shallow
    CI checkouts. It is not a signature, a Git history check, an immutable
    checkout snapshot, or evidence of complete dependency/theorem coverage.
    Arithmetic examples never acquire a revision binding from this lock.
    """
    root = Path(root)
    try:
        raw = read_regular(root, relative_path(manifest_path, 'manifest'), MAX_BYTES)
        result = evaluate(strict_json(raw))
        result['manifest_sha256'] = hashlib.sha256(raw).hexdigest()
        lock_raw = None
        if result['purpose'] == 'research-model':
            lock_raw = read_regular(root, DEFAULT_SOURCE_LOCK, MAX_BYTES)
            lock = strict_json(lock_raw)
            fields(lock, 'schema source_revision files', 'source lock')
            require(lock['schema'] == SOURCE_LOCK_SCHEMA, 'unsupported source lock schema')
            require(lock['source_revision'] == result['experiment']['source_revision'],
                    'source lock revision differs from the declared experiment')
            require(type(lock['files']) is dict
                    and set(lock['files']) == set(result['source_paths']),
                    'source lock paths must exactly match the declared event paths')
            for path, digest in lock['files'].items():
                require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
                        'source lock digest must be a full lowercase SHA-256: ' + path)
        result['source_files_sha256'] = {
            path: hashlib.sha256(read_regular(root, path, MAX_BYTES)).hexdigest()
            for path in result['source_paths']
        }
        if lock_raw is not None:
            for path, digest in lock['files'].items():
                require(result['source_files_sha256'][path] == digest,
                        'source lock hash mismatch: ' + path)
            result['source_revision_bound'] = True
            result['source_binding_scope'] = 'declared-event-paths-only'
            result['source_lock_sha256'] = hashlib.sha256(lock_raw).hexdigest()
    except SourceReadError as error:
        raise BudgetError(str(error)) from error
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--manifest', default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        result = inspect(args.root, args.manifest)
    except (BudgetError, OSError) as error:
        print(json.dumps({'schema': 'trnm-pq128-lifetime-budget-result-v1',
                          'status': 'REFUSE', 'reason': str(error)}, sort_keys=True),
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
