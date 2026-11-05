#!/usr/bin/env python3
"""Check current navigation/profile identity, never synthesize execution evidence."""
from __future__ import annotations
import argparse
import json
import subprocess
import tomllib
from pathlib import Path
from report_module_evidence import ROOT, check_symbol, check_test_selector, validate_contract
from check_invariant_evidence import load, require, safe

REGISTRY = 'config/pon/applicability-v1.json'
CLASSES = {'source-binding', 'local-execution', 'historical-receipt',
           'hosted-head-check', 'prospective-merge-check', 'external-acceptance'}
NATIVE_STORAGE_PROFILE = 'native-authenticated-storage-v1'
NATIVE_STORAGE_ENTRY = {
    'path': 'trillionnium/crates/trnm-pon-node/src/store.rs',
    'symbol': 'Node::open_with_authenticated_state',
}
NATIVE_STORAGE_TESTS = {
    'trillionnium/crates/trnm-pon-node/src/native_authenticated_tests.rs': {
        'native_authenticated_signed_growth_branches_reopen_and_compact_queries',
        'native_authenticated_namespaces_missing_nodes_and_corrupt_records_fail_closed',
        'native_authenticated_process_exit_before_commit_cold_recovers_without_destructors',
    },
    'trillionnium/crates/trnm-pon-node/src/store/authenticated_migration_tests.rs': {
        'authenticated_migration_preserves_signed_branches_and_irreversible_local_facts',
        'authenticated_migration_retains_partial_reorganization_then_target_recovers_once',
        'authenticated_migration_rechecks_retained_authority_including_inactive_branches',
        'authenticated_migration_rejects_external_owner_journal_and_required_marker',
        'authenticated_migration_atomic_target_creation_never_overwrites_a_racing_destination',
        'authenticated_migration_last_callback_cannot_hide_raw_file_or_receipt_changes',
        'authenticated_migration_process_exit_leaves_pending_and_source_reopens',
    },
    'trillionnium/crates/trnm-pon-node/tests/authenticated_storage_cli.rs': {
        'explicit_backend_mines_and_cold_reopens_the_same_authenticated_native_state',
        'explicit_and_default_storage_namespaces_reject_each_other_without_changing_the_database',
        'invalid_backend_scope_and_external_owner_combinations_reject_before_open',
    },
    'formal/pon-nakamoto-v1/test_native_authenticated_storage_oracle.py': {
        'MigrationPreservationOracle.test_every_retained_table_is_checked_including_empty_ones',
        'MigrationPreservationOracle.test_retained_values_cannot_change_type_or_contents',
        'SignedApplicationControls.test_self_consistent_state_records_cannot_change_signed_transfer_amount',
        'SignedApplicationControls.test_native_compact_query_is_independently_checked_when_present',
    },
}


def validate_native_storage_profile(profile: dict) -> None:
    """A local storage namespace cannot acquire consensus or legacy-open authority."""
    require(all(profile[field] is None for field in (
        'configuration', 'revision_pointer', 'consensus_revision')),
        'native authenticated storage is local, not a consensus revision')
    require(profile['entrypoint'] == NATIVE_STORAGE_ENTRY,
            'native authenticated storage requires the explicit opener')
    require(profile['document'] ==
            'docs/protocol/pon-nakamoto-v1/details/NATIVE_AUTHENTICATED_STORAGE_V1.md',
            'native authenticated storage contract identity')
    require(set(profile['modules']) == {'M06', 'M07', 'M08', 'M15', 'M17'},
            'native authenticated storage responsibility coverage')
    required = {path + '::' + symbol for path, symbols in NATIVE_STORAGE_TESTS.items()
                for symbol in symbols}
    require(required <= set(profile['tests']),
            'native authenticated storage control selector coverage')


def profile_table(profiles: list[dict]) -> str:
    lines = ['| Boundary / modules | Configuration / revision | Contract | Entrypoint | Exact test selector |',
             '|---|---|---|---|---|']
    for row in profiles:
        config = row['configuration']
        configuration = (f"[{Path(config).name}](../../{config}), revision{row['consensus_revision']}"
                         if config else 'Local/research boundary; no consensus revision')
        doc = row['document']
        entry = row['entrypoint']
        lines.append('| ' + ' | '.join([row['id'] + ' / ' + ', '.join(row['modules']),
                     configuration, f'[{Path(doc).stem}](../../{doc})',
                     f"[{entry['symbol']}](../../{entry['path']})",
                     '<br>'.join(row['tests'])]) + ' |')
    return '\n'.join(lines)


def validate(root: Path = ROOT) -> dict:
    root = Path(root).resolve()
    data = load(safe(root, REGISTRY))
    require(data['schema'] == 'pon-applicability-v1', 'applicability schema')
    require(set(data['evidence_classes']) == CLASSES, 'evidence class separation')
    require(data['module_contracts'] == 'config/pon/module-contracts-v1.json' and
            data['module_maturity'] == 'config/pon/module-maturity-v1.json' and
            data['source_inventory'] == 'config/portability-inventory-v1.json',
            'canonical authority changed')
    safe(root, data['source_inventory'])
    validate_contract(root)
    contracts = load(safe(root, data['module_contracts']))['modules']
    maturity = {m['id']: m for m in load(safe(root, data['module_maturity']))['modules']}
    rows = []
    for module in contracts:
        safe(root, module['specification'])
        for procedure in maturity[module['id']]['responsibilities']:
            rows.append({'module': module['id'], 'document': module['specification'],
                         **procedure, 'evidence_class': 'source-binding'})
    profiles = data['profiles']
    require(len(profiles) == len({p['id'] for p in profiles}), 'duplicate applicability profile')
    require({p['id'] for p in profiles} == {'evaluation-v1', 'lifecycle-v2', 'lifecycle-v3',
            'lifecycle-v4', 'checkpoint-tile-v1', 'local-pool-reconciliation',
            'protected-hello-handoff', 'integer-factor-v2', 'public-intake-v3-r9',
            'continuity-v1', 'model-evidence-v3', 'w1-verifier-equivalence',
            'history-state-resource-bounds', 'internal-error-identity', 'model-composition-v4',
            'account-archive-research-v1', 'model-window-history-v1', NATIVE_STORAGE_PROFILE},
            'applicability profile coverage')
    for profile in profiles:
        require(profile['modules'] and set(profile['modules']) <= set(maturity), 'profile modules')
        require(len(profile['modules']) == len(set(profile['modules'])), 'duplicate profile module')
        if profile['id'] == NATIVE_STORAGE_PROFILE:
            validate_native_storage_profile(profile)
        safe(root, profile['document'])
        check_symbol(root, profile['entrypoint'])
        require(profile['tests'], 'missing profile tests')
        require(len(profile['tests']) == len(set(profile['tests'])), 'duplicate profile test selector')
        for selector in profile['tests']:
            check_test_selector(root, selector)
        require(profile['evidence_class'] == 'source-binding' and profile['receipt'] is None,
                'source navigation masquerades as execution receipt')
        if profile['configuration'] is not None:
            config = load(safe(root, profile['configuration']))
            value = config
            for part in profile['revision_pointer'].split('.'):
                value = value[part]
            require(type(value) is int and value == profile['consensus_revision'], 'profile revision drift')
        else:
            require(profile['consensus_revision'] is None and profile['revision_pointer'] is None,
                    'transport/local policy masquerades as consensus revision')
    authority = safe(root, 'docs/architecture/TRNM_DOCUMENTATION_AUTHORITY_V1.md').read_text()
    expected_table = '<!-- applicability-table:start -->\n' + profile_table(profiles) + '\n<!-- applicability-table:end -->'
    require(expected_table in authority, 'documentation applicability table drift')
    snapshot = load(safe(root, 'docs/development/CURRENT_SNAPSHOT_V1.json'))
    cargo = tomllib.loads(safe(root, 'trillionnium/Cargo.toml').read_text())
    require(snapshot['workspace_packages'] == len(cargo['workspace']['members']), 'snapshot package drift')
    require(snapshot['applicability_registry'] == REGISTRY, 'snapshot applicability authority')
    require(data['delivery'] == {'candidate_identity': 'derive-from-git-at-verification',
            'hosted_head_status': 'not-established-by-this-registry',
            'prospective_merge_status': 'not-established-by-this-registry',
            'production_activation': False}, 'unearned delivery status')
    return {'result': 'PASS', 'procedures': rows, 'profiles': profiles,
            'tests_executed_by_this_checker': False, 'acceptance_granted': False}


def markdown(result: dict) -> str:
    lines = ['| Module / procedure | Document | Source owners | Controlled entrypoint | Test selectors | Evidence class |',
             '|---|---|---|---|---|---|']
    for row in result['procedures']:
        refs = lambda values: '<br>'.join(v['path'] + '::' + v['symbol'] for v in values) or 'none'
        entry = row['controlled_entrypoint']
        lines.append('| ' + ' | '.join([row['operation'], row['document'], refs(row['runtime_symbols']),
                     refs([entry]) if entry else 'none', '<br>'.join(row['evidence_selectors']) or 'none',
                     row['evidence_class']]) + ' |')
    return '\n'.join(lines)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--format', choices=['json', 'markdown'], default='json')
    args = parser.parse_args()
    result = validate()
    git = lambda *args: subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()
    result['source_identity'] = {'baseline_head': git('rev-parse', 'HEAD'),
                                 'baseline_tree': git('rev-parse', 'HEAD^{tree}'),
                                 'candidate_state': 'dirty-candidate' if git('status', '--porcelain') else 'committed-clean'}
    print(markdown(result) if args.format == 'markdown' else json.dumps(result, indent=2))
