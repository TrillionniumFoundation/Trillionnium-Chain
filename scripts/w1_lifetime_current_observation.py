#!/usr/bin/env python3
"""Observe explicitly reviewed current sources without changing historical V1.

The old ledger is byte-pinned and stays unchanged. Its finite accounting and
source-observation function are reused in a private function context with an
explicitly different current pin set and source label. This does not turn
source text into execution, a complete hash-use inventory or a security bound.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
from types import FunctionType, ModuleType

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = 'config/pon/w1-lifetime-current-source-v2.json'
CONTRACT_SHA256 = 'bd22f0db32c479dd7d42ae541eeed0ad0c1115d40b88b01d07acefd25930fbb7'
# Exact offline evidence fixture from 1a14f7d4; its SOURCE_BASE stays 7150d96a.
# scripts/w1_lifetime_ledger.py is the separate current successor, left unchanged.
LEGACY = 'tests/fixtures/w1-lifetime-historical-7150/ledger.py'
LEGACY_SHA256 = '7e494ba406c63442dfbd17147d006b967cb07d7f6c886ce5779a0f2f05fceef6'
CURRENT = '5c04c60e463462d9df8884786e0d5bb32af08a64'
HISTORICAL = '7150d96a2112875b4afcf3023361a5cef4a0e4b1'
CHANGED = (
    'trillionnium/crates/trnm-crypto-primitives/Cargo.toml',
    'trillionnium/Cargo.lock',
    'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs',
    'trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs',
    'trillionnium/crates/trnm-pon-node/src/store.rs',
    'trillionnium/crates/trnm-pon-node/src/consensus.rs',
    'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
    'formal/pon-nakamoto-v1/quantum_oracle_resources.py',
)
MAX_BYTES = 2 * 1024 * 1024
QUALIFICATION = {
    'production_activation': False, 'consensus_admission': False,
    'whole_chain_post_quantum_qualified': False, 'actual_lifetime_failure_bound': None,
    'coverage_exhaustiveness_proved': False, 'composition_theorem_instantiated': False,
}


class ObservationError(ValueError):
    """A current source contract differs; never a cryptographic result."""


def require(value, message):
    if not value:
        raise ObservationError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_regular(root, relative, limit=MAX_BYTES):
    root = Path(root).absolute()
    require(root == root.resolve(strict=True), 'source root/ancestor alias')
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and parts.as_posix() == relative and bool(parts.parts)
            and all(part not in ('.', '..') for part in parts.parts), 'source path syntax')
    current = root
    for part in parts.parts[:-1]:
        current /= part
        require(stat.S_ISDIR(current.lstat().st_mode), 'nonregular source ancestor: ' + relative)
    path = root / relative
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                'nonregular or oversized source: ' + relative)
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        after, visible = os.fstat(descriptor), path.lstat()
        identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                  value.st_mtime_ns, value.st_ctime_ns)
        require(identity(before) == identity(after) == identity(visible)
                and len(raw) == before.st_size, 'source changed during read: ' + relative)
        return raw
    finally:
        os.close(descriptor)


def load(root):
    raw = read_regular(root, LEGACY)
    require(sha(raw) == LEGACY_SHA256, 'historical reader bytes changed')
    legacy = ModuleType('_trnm_lifetime_historical_v1')
    legacy.__file__ = str(Path(root) / LEGACY)
    exec(compile(raw, legacy.__file__, 'exec'), legacy.__dict__)
    require(legacy.SOURCE_BASE == HISTORICAL, 'historical source identity changed')
    contract_raw = read_regular(root, CONTRACT, 128 * 1024)
    require(sha(contract_raw) == CONTRACT_SHA256, 'unreviewed current source contract')
    contract = legacy.strict_json(contract_raw)
    require(set(contract) == {'schema', 'source_base_commit', 'historical_source_base_commit',
                             'historical_reader', 'selected_source_scope', 'changed_paths',
                             'sources', 'qualification'}, 'current contract fields')
    require(contract['schema'] == 'TRNM-W1-LIFETIME-CURRENT-SOURCE-CONTRACT2'
            and contract['source_base_commit'] == CURRENT
            and contract['historical_source_base_commit'] == HISTORICAL,
            'current source namespace')
    require(contract['historical_reader'] == {'path': LEGACY, 'sha256': LEGACY_SHA256}
            and contract['changed_paths'] == list(CHANGED)
            and contract['selected_source_scope'] == '20_selected_paths_not_full_dependency_or_execution_closure',
            'current source scope')
    require(type(contract['qualification']) is dict
            and set(contract['qualification']) == set(QUALIFICATION)
            and all(contract['qualification'][key] is value for key, value in QUALIFICATION.items()),
            'unsupported qualification')
    rows = contract['sources']
    require(type(rows) is list and [row['path'] for row in rows] == list(legacy.SOURCE_PINS),
            'current selected source roster')
    sources, pins, changed = {}, {}, []
    for row in rows:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'historical_sha256', 'current_sha256'},
                'source row fields')
        name = row['path']
        require(row['historical_sha256'] == legacy.SOURCE_PINS[name], 'historical pin changed')
        require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_BYTES, 'source byte bound')
        raw = read_regular(root, name, row['bytes'])
        require(len(raw) == row['bytes'] and sha(raw) == row['current_sha256'],
                'current source identity mismatch: ' + name)
        if row['historical_sha256'] != row['current_sha256']:
            changed.append(name)
        sources[name], pins[name] = raw, row['current_sha256']
    require(tuple(changed) == CHANGED, 'unreviewed changed source set')
    return legacy, contract, sources, pins


def report(root=ROOT, raw=None):
    legacy, contract, sources, pins = load(root)
    historical_pins = dict(legacy.SOURCE_PINS)
    # Function code remains exactly the historical byte-pinned source. Its
    # explicit data context is copied, not patched into the historical module.
    current_context = dict(legacy.source_survey.__globals__)
    current_context.update(SOURCE_PINS=dict(pins), SOURCE_BASE=CURRENT)
    survey_function = FunctionType(legacy.source_survey.__code__, current_context,
                                   'current_selected_source_survey')
    survey = survey_function(sources)
    require(legacy.SOURCE_PINS == historical_pins and legacy.SOURCE_BASE == HISTORICAL,
            'historical reader context was changed')
    ledger = legacy.evaluate(legacy.template() if raw is None else raw)
    return legacy.serializable({
        'schema': 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2',
        'status': 'CURRENT_SELECTED_SOURCE_OBSERVED_SECURITY_HOLD',
        'current_source_contract': {'path': CONTRACT, 'sha256': CONTRACT_SHA256,
                                    'source_base_commit': CURRENT},
        'historical_reader': contract['historical_reader'],
        'historical_source_base_commit': HISTORICAL,
        'changed_source_paths': list(CHANGED),
        'survey_logic_scope': 'unchanged_byte_pinned_V1_function_with_explicit_private_current_pin_context',
        'historical_reader_or_pin_bytes_changed': False,
        'historical_positive_replay_established': False,
        'current_source_observation_is_historical_reproduction': False,
        'selected_source_survey': survey,
        'lifetime_ledger': ledger,
        'independent_acceptance': legacy.independent_acceptance_lines(survey),
        'counterexamples': legacy.counterexamples(),
        'qualification': dict(QUALIFICATION),
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    try:
        raw = None
        if args.input:
            legacy, _, _, _ = load(args.root)
            require(not args.input.is_symlink(), 'input symlink')
            with args.input.open('rb') as stream:
                raw = legacy.strict_json(stream.read(legacy.MAX_INPUT_BYTES + 1))
        value = report(args.root, raw)
        print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as error:
        print(json.dumps({'schema': 'TRNM-W1-LIFETIME-CURRENT-OBSERVATION2',
                          'status': 'REFUSED', 'error': str(error),
                          'qualification': QUALIFICATION}), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
