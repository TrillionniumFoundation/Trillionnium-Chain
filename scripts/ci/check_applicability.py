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


def profile_table(profiles: list[dict]) -> str:
    lines = ['| Boundary / modules | Configuration / revision | Contract | Entrypoint | Exact test selector |',
             '|---|---|---|---|---|']
    for row in profiles:
        config = row['configuration']
        configuration = (f"[{Path(config).name}](../../{config}), revision{row['consensus_revision']}"
                         if config else 'Local/transport policy; no consensus revision')
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
            'protected-hello-handoff', 'integer-factor-v2', 'public-intake-v3-r9'},
            'applicability profile coverage')
    for profile in profiles:
        require(profile['modules'] and set(profile['modules']) <= set(maturity), 'profile modules')
        safe(root, profile['document'])
        check_symbol(root, profile['entrypoint'])
        require(profile['tests'], 'missing profile tests')
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
