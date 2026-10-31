#!/usr/bin/env python3
"""Bounded conditional quantum-miner/DAA sensitivity, NOT a security proof.

The actual Rust W1 producer, reversible oracle, timestamps, WAN, and quantum
machine are not exercised. The reference.py functions encode the development
contract; this tool imports them rather than inventing a different retarget.
"""
from __future__ import annotations

import argparse
import json
from math import isqrt
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'formal' / 'pon-nakamoto-v1'))
from reference import retarget, timestamp_state, work  # noqa: E402

DEFAULT_CONFIG = ROOT / 'config' / 'pon' / 'devnet-v1.json'
MAX_EPOCHS = 32


class InvalidScenario(ValueError):
    pass


def checked_int(value: object, lower: int, upper: int, name: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise InvalidScenario(f'invalid {name}')
    return value


def load_profile(filename: Path) -> dict:
    """Only the existing 16-block, x4 bounded development profile is modeled."""
    def unique(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise InvalidScenario('duplicate config key: ' + key)
            record[key] = value
        return record

    try:
        config = json.loads(filename.read_text(encoding='utf-8'),
                            object_pairs_hook=unique,
                            parse_constant=lambda _: (_ for _ in ()).throw(InvalidScenario('nonfinite JSON')))
    except (OSError, ValueError, UnicodeError) as exc:
        raise InvalidScenario(f'unreadable/invalid profile: {filename}') from exc
    if type(config) is not dict or config.get('schema') != 'pon-devnet-2' or config.get('production_activation') is not False:
        raise InvalidScenario('this tool only models the disabled development profile')
    interval = checked_int(config.get('retarget_interval'), 16, 4096, 'interval')
    spacing = checked_int(config.get('target_spacing_seconds'), 1, 3600, 'spacing')
    if interval != 16 or config.get('retarget_factor') != 4 or config.get('median_time_width') != 11:
        raise InvalidScenario('DAA rules changed; revalidate against the actual consensus')
    try:
        limit = int(config['pow_limit_hex'], 16)
        initial = int(config['initial_target_hex'], 16)
    except (KeyError, ValueError, TypeError) as exc:
        raise InvalidScenario('invalid target configuration') from exc
    if not 1 <= initial <= limit < (1 << 256):
        raise InvalidScenario('invalid target bounds')
    checked_int(config.get('future_skew_seconds'), 0, 86400, 'future skew')
    checked_int(config.get('genesis_timestamp'), 1, (1 << 63) - 1, 'genesis timestamp')
    return config


def ceil_div(n: int, d: int) -> int:
    return (n + d - 1) // d


def target_search_proxies(target: int) -> dict:
    """Conditional uniform-search proxies. sqrt(N) is NOT an oracle gate count."""
    chainwork = work(target)
    expected_classical_trials = ceil_div(1 << 256, target + 1)
    sqrt_index = isqrt(expected_classical_trials)
    if sqrt_index * sqrt_index < expected_classical_trials:
        sqrt_index += 1
    return {'target_hex': f'{target:064x}', 'chainwork': chainwork,
            'expected_classical_trials_proxy': expected_classical_trials,
            'ideal_sqrt_search_index': sqrt_index}


def simulate(config: dict, epochs: int, seconds_per_header: int) -> dict:
    epochs = checked_int(epochs, 1, MAX_EPOCHS, 'epochs')
    step = checked_int(seconds_per_header, 1, 3600, 'seconds_per_header')
    interval = config['retarget_interval']
    spacing = config['target_spacing_seconds']
    initial = int(config['initial_target_hex'], 16)
    limit = int(config['pow_limit_hex'], 16)
    timestamp = config['genesis_timestamp']
    # Match ledger.py target(parent) precisely: retarget BEFORE creating block
    # 16,32,... using the PREVIOUS 16 ancestors (genesis included for 16).
    headers = [(timestamp, initial)]
    target = initial
    cumulative_chainwork = 0
    cumulative_classical_proxy = 0
    cumulative_sqrt_index = 0
    rows = []
    for height in range(1, epochs * interval + 1):
        if height % interval == 0:
            target = retarget(headers[-1][1], headers[-interval][0],
                              headers[-1][0], interval, spacing, limit)
        timestamp += step
        # Grant the header time as an assumed external clock. This checks
        # isolated median/future constraints, NOT feasible real mining time.
        if timestamp_state(timestamp, [h[0] for h in headers[-11:]],
                           timestamp, config['future_skew_seconds']) != 'admissible':
            raise InvalidScenario('timestamp fails development median/future checks')
        headers.append((timestamp, target))
        p = target_search_proxies(target)
        cumulative_chainwork += p['chainwork']
        cumulative_classical_proxy += p['expected_classical_trials_proxy']
        cumulative_sqrt_index += p['ideal_sqrt_search_index']
        if height % interval == 1:
            first_target = target
            first_timestamp = timestamp
            start_work = cumulative_chainwork - p['chainwork']
        if height % interval == 0:
            rows.append({'epoch': height // interval,
                         'block_range': [height - interval + 1, height],
                         'seconds_per_header_assumed': step,
                         'first_timestamp': first_timestamp,
                         'last_timestamp': timestamp,
                         'start_target_hex': f'{first_target:064x}',
                         'retarget_boundary_height': height,
                         'boundary_target_hex': p['target_hex'],
                         'boundary_chainwork': p['chainwork'],
                         'boundary_ideal_sqrt_search_index': p['ideal_sqrt_search_index'],
                         'epoch_chainwork': cumulative_chainwork - start_work,
                         'cumulative_chainwork': cumulative_chainwork,
                         'cumulative_classical_trials_proxy': cumulative_classical_proxy,
                         'cumulative_ideal_sqrt_search_index': cumulative_sqrt_index})
    return {'schema': 'trnm-conditional-quantum-daa-sensitivity-v1',
            'status': 'UNQUALIFIED_HYPOTHETICAL',
            'production_activation': False, 'quantum_hardness_qualified': False,
            'notes': [
                'Retarget applies at heights 16,32,... from prior 16 headers, including genesis at height 16.',
                'Real W1 full-relation oracles, reversibility, uncomputation and cost NOT measured.',
                'All timestamps use an assumed wall clock; lawful schedules are not achievable mining evidence.',
                'Ideal sqrt index is not a quantum circuit/gate estimate or hardness lower bound.',
                'No mined blocks, chains, fork-choice changes, attacks, or security qualifications are created.'
            ], 'epochs': rows}

def compare_scenarios(config: dict, epochs: int) -> dict:
    fast = simulate(config, epochs, 1)
    ordinary = simulate(config, epochs, config['target_spacing_seconds'])
    return {'schema': 'trnm-quantum-daa-comparison-v1',
            'status': 'HOLD_RESEARCH_ONLY',
            'same_wall_clock_or_mining_budget': False,
            'fast_timestamp_hypothesis': fast,
            'nominal_timestamp_reference': ordinary}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, default=DEFAULT_CONFIG)
    parser.add_argument('--epochs', type=int, default=4)
    args = parser.parse_args()
    try:
        result = compare_scenarios(load_profile(args.profile), args.epochs)
    except InvalidScenario as error:
        print(f'REFUSE: {error}', file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0


if __name__ == '__main__':
    sys.exit(main())
