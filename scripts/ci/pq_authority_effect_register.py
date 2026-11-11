#!/usr/bin/env python3
"""Check seven curated authority/effect source records; always retain HOLD.

This is a reviewed source-consistency contract, not a call-graph analyzer,
runtime test runner, Git provenance verifier, or whole-chain PQ qualification.
The fixed lock is review material, not an independently authenticated trust root.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

from pq_lifetime_budget import BudgetError, relative_path, strict_json
from pq_source_reader import SourceReadError, read_regular

SCHEMA = 'trnm-pq-authority-effects-v1'
RESULT_SCHEMA = 'trnm-pq-authority-effects-result-v1'
DEFAULT_MANIFEST = 'config/pon/pq-authority-effects-v1.json'
# The seven route definitions and 44 source paths retain their reviewed scope.
# Prior review lineages are documented in PQ_AUTHORITY_EFFECT_REGISTER_V1.md.
SOURCE_REVISION = '8add285b6c0a91d8b7812efe2d02c9342f74c91b'
PURPOSE = 'curated-source-consistency-only'
MAX_BYTES = 1024 * 1024
# SHA-256 of canonical {"source_revision": SOURCE_REVISION, "files": ...}.
# Generated from git show at the exact revision, not from current-tree hashes.
REVIEWED_SOURCE_LOCK_SHA256 = 'da8d605dead05faa1302c96d8bba1ff4f1e07cd5423390a34679f02dc73cecb9'

CRATES = 'trillionnium/crates/'
TRANSFER = CRATES + 'trnm-types/src/transfer.rs'
MVCC = CRATES + 'trnm-mvcc-fee/'
EXECUTOR = MVCC + 'src/pon_executor.rs'
NODE = CRATES + 'trnm-pon-node/'
RESEARCH = CRATES + 'trnm-research-protocol/'
SETTLEMENT = CRATES + 'trnm-service-settlement/'
CELL = CRATES + 'trnm-data-availability/'
DISCOVERY = CELL + 'src/cell/discovery'
SOURCE_FIELDS = ('entry_sources', 'authentication_sources', 'state_or_effect_sources',
                 'profile_sources', 'negative_test_sources')
ROUTE_FIELDS = ('id', 'effect_scope', 'reachability_observation', 'profile_boundary',
                *SOURCE_FIELDS)


def route(scope, observation, boundary, entries, authentication, effects, profiles, tests):
    """Keep the small reviewed table explicit; no inference from crypto keywords."""
    return dict(zip(ROUTE_FIELDS[1:],
                    (scope, observation, boundary, entries, authentication,
                     effects, profiles, tests)))


ROUTES = {
    'compat_transfer_type_v1': route(
        'validation-result-only', 'no-in-repository-native-consumer-found',
        'classic-type-without-a-selected-node-profile',
        (TRANSFER, CRATES + 'trnm-types/src/lib.rs'), (TRANSFER,), (), (), (TRANSFER,)),
    'native_pnx1_account_transfer': route(
        'native-account-state-and-node-persistence', 'native-owner-source-connection',
        'distinct-pq-account-and-network-owner-selection',
        (CRATES + 'trnm-protocol/src/pon_wire.rs', NODE + 'src/ingress.rs', NODE + 'src/store.rs'),
        (EXECUTOR, CRATES + 'trnm-crypto-primitives/src/lib.rs'),
        (EXECUTOR, NODE + 'src/store.rs'),
        (EXECUTOR, MVCC + 'src/pon_executor/pq_accounts.rs',
         MVCC + 'src/pon_executor/pq_accounts_v2.rs', NODE + 'src/ingress.rs',
         NODE + 'src/public_submit.rs'),
        (MVCC + 'tests/pq_account_owner.rs', NODE + 'tests/pq_account_native.rs',
         MVCC + 'src/pon_executor/pq_accounts_v2/tests.rs',
         NODE + 'tests/public_submit_recovery.rs')),
    'portable_consumption_settlement_v1': route(
        'portable-settlement-store-only', 'portable-kernel-no-native-consumer-found',
        'fixed-classical-bilateral-signature-schema',
        (SETTLEMENT + 'src/store.rs',),
        (SETTLEMENT + 'src/engine.rs', SETTLEMENT + 'src/types.rs'),
        (SETTLEMENT + 'src/engine.rs', SETTLEMENT + 'src/store.rs'),
        (SETTLEMENT + 'src/types.rs',), (SETTLEMENT + 'src/tests.rs',)),
    'research_command_state_v1': route(
        'research-protocol-state-only', 'local-state-machine-no-native-consumer-found',
        'fixed-classical-research-command-schema',
        (RESEARCH + 'src/command.rs', RESEARCH + 'src/state.rs'),
        (RESEARCH + 'src/command.rs', RESEARCH + 'src/state.rs'),
        (RESEARCH + 'src/state.rs',), (RESEARCH + 'src/command.rs',),
        (RESEARCH + 'tests/protocol_v1.rs', RESEARCH + 'tests/protocol_v1/security_cases.rs')),
    'hepta_admission_compare_v1': route(
        'owner-context-comparison-only', 'comparison-result-no-final-use-consumer-found',
        'classical-v1-and-separate-pq-v2-comparators',
        (RESEARCH + 'src/hepta_handoff.rs',),
        (RESEARCH + 'src/hepta_handoff.rs', RESEARCH + 'src/state.rs'), (),
        (RESEARCH + 'src/hepta_handoff.rs', RESEARCH + 'src/hepta_handoff/pq.rs'),
        (RESEARCH + 'tests/protocol_v1.rs', RESEARCH + 'tests/hepta_handoff_pq.rs')),
    'cell_discovery_v1_fetch_cache': route(
        'provider-directory-and-content-cache-only', 'cli-transport-store-file-source-connection',
        'explicit-v1-v2-cli-wire-and-directory-selection',
        (CELL + 'src/bin/trnm-cell-discovery.rs', DISCOVERY + '/transport.rs'),
        (DISCOVERY + '.rs', CELL + 'src/types.rs'),
        (DISCOVERY + '/directory.rs', DISCOVERY + '/transport.rs',
         CELL + 'src/cell/network.rs', CELL + 'src/cell/store.rs'),
        (CELL + 'src/bin/trnm-cell-discovery.rs', CELL + 'src/bin/unix/pq.rs', DISCOVERY + '.rs',
         DISCOVERY + '/pq.rs', DISCOVERY + '/pq/directory.rs', DISCOVERY + '/pq/transport.rs'),
        (DISCOVERY + '/tests.rs', DISCOVERY + '/pq/tests.rs')),
    'reference_release_finality_v2_observer': route(
        'read-only-certificate-facts', 'reference-and-native-read-only-observation',
        'classical-reference-profile-without-activation',
        ('formal/release-finality-v2/verify_certificate.py', NODE + 'src/release_finality.rs'),
        ('formal/release-finality-v2/verify_certificate.py',
         'formal/pon-nakamoto-v1/strict_signature.py', NODE + 'src/release_finality.rs',
         CRATES + 'trnm-crypto-primitives/src/lib.rs'), (),
        ('config/release-finality-v2.json', 'formal/release-finality-v2/protocol.py'),
        (NODE + 'tests/release_finality_v2.rs',)),
}


class RegisterError(ValueError):
    """A malformed, changed, or overclaiming source record must be refused."""


def require(ok, message):
    if not ok:
        raise RegisterError(message)


def fields(value, names, where):
    require(type(value) is dict and set(value) == set(names),
            'unexpected or missing fields: ' + where)


def source_paths():
    return sorted({path for value in ROUTES.values()
                   for field in SOURCE_FIELDS for path in value[field]})


def source_lock_digest(files):
    raw = json.dumps({'source_revision': SOURCE_REVISION, 'files': files},
                     sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def validate_manifest(data):
    fields(data, ('schema', 'source_revision', 'purpose', 'coverage_complete',
                  'whole_chain_pq_qualified', 'production_activation', 'routes',
                  'source_files_sha256'), 'manifest')
    require(data['schema'] == SCHEMA and data['purpose'] == PURPOSE,
            'unsupported authority effect schema/purpose')
    require(data['source_revision'] == SOURCE_REVISION,
            'source revision differs from the fixed reviewed revision')
    for name in ('coverage_complete', 'whole_chain_pq_qualified', 'production_activation'):
        require(data[name] is False, 'source consistency cannot qualify ' + name)
    rows = data['routes']
    require(type(rows) is list and len(rows) == len(ROUTES),
            'exactly seven curated routes are required')
    seen = set()
    for row in rows:
        fields(row, ROUTE_FIELDS, 'route')
        rid = row['id']
        require(type(rid) is str and rid in ROUTES and rid not in seen,
                'unknown or duplicate route ID')
        seen.add(rid)
        expected = ROUTES[rid]
        for name in ('effect_scope', 'reachability_observation', 'profile_boundary'):
            require(type(row[name]) is str and row[name] == expected[name],
                    'unreviewed effect/context: ' + rid + '.' + name)
        for name in SOURCE_FIELDS:
            value = row[name]
            require(type(value) is list and all(type(path) is str for path in value)
                    and len(value) == len(set(value)) and set(value) == set(expected[name]),
                    'curated source set mismatch: ' + rid + '.' + name)
    files = data['source_files_sha256']
    require(type(files) is dict and set(files) == set(source_paths()),
            'source lock must cover exactly the curated source paths')
    for path, digest in files.items():
        require(type(digest) is str and re.fullmatch(r'[0-9a-f]{64}', digest) is not None,
                'source hash must be a full lowercase SHA-256: ' + path)
    require(source_lock_digest(files) == REVIEWED_SOURCE_LOCK_SHA256,
            'source hashes differ from the fixed reviewed lock')


def inspect(root: Path, manifest_path: str = DEFAULT_MANIFEST):
    """Check actual regular-file bytes against the reviewed lock, never qualify."""
    try:
        raw = read_regular(Path(root), relative_path(manifest_path, 'manifest'), MAX_BYTES)
        data = strict_json(raw)
        validate_manifest(data)
        observed = {}
        for path in source_paths():
            observed[path] = hashlib.sha256(read_regular(Path(root), path, MAX_BYTES)).hexdigest()
            require(observed[path] == data['source_files_sha256'][path],
                    'source lock hash mismatch: ' + path)
    except (SourceReadError, BudgetError) as error:
        raise RegisterError(str(error)) from error
    return {
        'schema': RESULT_SCHEMA,
        'status': 'HOLD',
        'source_consistency': 'PASS',
        'scope': PURPOSE,
        'source_revision': SOURCE_REVISION,
        'reviewed_source_lock_sha256': REVIEWED_SOURCE_LOCK_SHA256,
        'manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'source_files_sha256': observed,
        'routes': sorted(data['routes'], key=lambda row: row['id']),
        'curated_routes_checked': len(ROUTES),
        'source_revision_binding': 'fixed-reviewed-file-lock-only',
        'provenance_authenticated': False,
        'coverage_complete': False,
        'call_graph_proved': False,
        'runtime_reachability_proved': False,
        'native_tests_executed': False,
        'whole_chain_pq_qualified': False,
        'production_activation': False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--manifest', default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    try:
        result = inspect(args.root, args.manifest)
    except (RegisterError, OSError) as error:
        print(json.dumps({'schema': RESULT_SCHEMA, 'status': 'REFUSE', 'reason': str(error)},
                         sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
