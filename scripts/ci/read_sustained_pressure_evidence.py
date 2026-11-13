#!/usr/bin/env python3
"""Read retained sustained-report bytes without executing the native driver.

The independent projection preserves declarations and validated accounting
values. It does not establish a causal pressure experiment or a qualification.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile

from pq_source_reader import read_regular
import run_from_zero_native as driver


SCHEMA = 'trnm-sustained-pressure-evidence-projection-v1'


def _declaration(document: dict, key: str, expected: bool | int, *, count: bool = False) -> dict:
    if key not in document:
        return {'present': False, 'value': None, 'consistent_with_retained_values': None}
    value = document[key]
    valid = type(value) is int and 0 <= value < (1 << 64) if count else type(value) is bool
    if not valid:
        raise ValueError('SUSTAINED_OPTIONAL_DECLARATION_TYPE:' + key)
    return {'present': True, 'value': value,
            'consistent_with_retained_values': value == expected}


def project_report(path: Path) -> dict:
    """Read one regular bounded input; validate a private copy of those bytes."""
    path = Path(path)
    result = {
        'schema': SCHEMA,
        'status': 'REFUSED',
        'source': {'path': str(path), 'raw_bytes': None, 'sha256': None},
        'original_gate_validated': False,
        'validator_scope': None,
        'error': None,
        'declarations': None,
        'phases': [],
        'accounting_pressure_from_retained_values': None,
        'causal_pressure': {'status': 'UNKNOWN', 'demonstrated': None},
        'offered_deadline_evidence': None,
        'qualifications': {
            'causal_budget_depletion_qualified': False,
            'public_network_ready': False,
            'resource_fairness_qualified': False,
            'work_profile_qualified': False,
            'production_activation': False,
            'independent_accepted': False,
            'ordinary_hepta_entry': False,
        },
    }
    try:
        # Do not resolve the supplied path: the descriptor reader checks every
        # named ancestor and the leaf, including ordinary symlink rejection.
        raw = read_regular(path.parent, path.name, driver.REPORT_LIMIT)
        source_sha256 = hashlib.sha256(raw).hexdigest()
        result['source'].update(raw_bytes=len(raw), sha256=source_sha256)
        with tempfile.TemporaryDirectory(prefix='trnm-pressure-evidence-') as directory:
            owned = Path(directory) / 'report.json'
            owned.write_bytes(raw)
            validated = driver.validate_sustained_report(owned)
        if validated['sha256'] != source_sha256:
            raise ValueError('SUSTAINED_REPORT_COPY_IDENTITY')
        result['original_gate_validated'] = True
        result['validator_scope'] = validated['scope']
        document = driver.json_load(raw)
        phases = []
        for phase, observation in zip(document['phases'], validated['phases'], strict=True):
            reserve = phase['initial_meter']['start_reserve_ns']
            minimum = observation['minimum_sampled_stored_credit_ns']
            refusals = observation['mutation_cpu_refusals']
            below_reserve = minimum < reserve
            negative_credit = minimum < 0
            pressure = below_reserve or negative_credit or refusals > 0
            phases.append({
                'phase': observation['phase'],
                # Preserve the validator's original observation counts and scope.
                'retained_values': dict(observation, start_reserve_ns=reserve),
                'sampled_credit_below_start_reserve': below_reserve,
                'sampled_negative_credit': negative_credit,
                'accounting_pressure_from_retained_values': pressure,
                'declarations': {
                    'budget_depletion_observed': _declaration(
                        phase, 'budget_depletion_observed', pressure),
                    'mutation_cpu_refusals': _declaration(
                        phase, 'mutation_cpu_refusals', refusals, count=True),
                },
            })
        # This OR matches the original producer's document-level declaration.
        # It does not identify what caused a refusal or the sampled credit.
        pressure = any(phase['accounting_pressure_from_retained_values'] for phase in phases)
        declarations = {
            'budget_depletion_demonstrated': _declaration(
                document, 'budget_depletion_demonstrated', pressure),
        }
        result.update(status='HOLD', phases=phases, declarations=declarations,
                      accounting_pressure_from_retained_values=pressure)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', type=Path, required=True,
                        help='existing public-v3-sustained-local-from-zero-v1 JSON report')
    args = parser.parse_args(argv)
    result = project_report(args.report)
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return 0 if result['status'] == 'HOLD' else 2


if __name__ == '__main__':
    raise SystemExit(main())
