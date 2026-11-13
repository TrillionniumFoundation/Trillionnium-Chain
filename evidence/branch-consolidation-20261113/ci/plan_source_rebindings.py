#!/usr/bin/env python3
"""Read-only current-source pin plan. Never edits manifests or accepts evidence."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--declared-source-checkpoint', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    root = args.root.absolute()
    if root != root.resolve(strict=True):
        raise ValueError('root must be canonical')
    output_path = args.output.absolute()
    if output_path != output_path.parent.resolve(strict=True) / output_path.name:
        raise ValueError('output must not traverse symlinked directories')
    if output_path == root or root in output_path.parents:
        raise ValueError('output must be outside the repository')
    revision = args.declared_source_checkpoint
    if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise ValueError('full source checkpoint required')
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(root / 'scripts/ci'))
    from pq_source_reader import read_regular

    def module(name):
        path = root / 'scripts/ci' / (name + '.py')
        spec = importlib.util.spec_from_file_location('_rebind_plan_' + name, path)
        result = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = result
        spec.loader.exec_module(result)
        return result

    def raw(path):
        return read_regular(root, path, 4 * 1024 * 1024)

    def sha(value):
        return hashlib.sha256(value).hexdigest()

    def blob(value):
        return hashlib.sha1(b'blob ' + str(len(value)).encode() + b'\0' + value).hexdigest()

    report = {'schema': 'trnm-reviewed-source-rebinding-plan-v1',
              'declared_source_checkpoint': revision,
              'canonical_publication_verified': False,
              'source_semantics_reviewed_by_planner': False,
              'repository_files_modified': False,
              'historical_evidence_rewritten': False,
              'production_activation': False, 'plans': {}, 'errors': []}

    def load(path):
        return json.loads(raw(path))

    def record_error(path, error):
        report['errors'].append({'path': path, 'reason': str(error)})

    for name, manifest, constant, digest_fn in (
        ('pq_root_dependency_register', 'config/pon/pq-root-dependency-register-v3.json',
         'REVIEWED_SOURCE_SNAPSHOT_SHA256', 'source_snapshot_digest'),
        ('pq_authority_effect_register', 'config/pon/pq-authority-effects-v1.json',
         'REVIEWED_SOURCE_LOCK_SHA256', 'source_lock_digest'),
    ):
        data = load(manifest)
        old = data['source_files_sha256']
        new = {}
        for path in old:
            try:
                new[path] = sha(raw(path))
            except (OSError, ValueError) as error:
                record_error(path, error)
        owner = module(name)
        plan = {'source_field': 'source_files_sha256', 'changes': {
            path: {'old': old[path], 'observed': new[path]}
            for path in new if new[path] != old[path]},
            'new_semantic_routes_or_paths_added': False}
        if set(new) == set(old):
            plan['reader_constant'] = constant
            plan['candidate_reader_constant'] = getattr(owner, digest_fn)(new)
        report['plans'][manifest] = plan

    path = 'config/pon/hash-use-contract-v1.json'
    value = load(path)
    changes = {}
    observed = {}
    for name, row in value['source_files'].items():
        try:
            content = raw(name)
            observed[name] = {**row, 'bytes': len(content), 'sha256': sha(content)}
            if row != observed[name]:
                changes[name] = {'old': row, 'observed': observed[name]}
        except (OSError, ValueError) as error:
            record_error(name, error)
    owner = module('hash_use_contract')
    report['plans'][path] = {'source_field': 'source_files', 'changes': changes,
        'hash_construction_semantics_not_updated': True,
        'digest_uses_selected_reader_functions': True}
    if set(observed) == set(value['source_files']):
        report['plans'][path]['candidate_source_map_sha256'] = owner.sha(owner.canonical(observed))

    path = 'config/pon/pq-cross-branch-corpus-v1.json'
    value = load(path)
    changes = {}
    for name, old in value['pinned_blobs'].items():
        try:
            new = blob(raw(name))
            if old != new:
                changes[name] = {'old': old, 'observed_git_blob': new}
        except (OSError, ValueError) as error:
            record_error(name, error)
    report['plans'][path] = {'source_field': 'pinned_blobs', 'changes': changes,
        'new_source_census_not_inferred': True, 'upstream_heads_and_history_unchanged': True}

    path = 'config/pon/w1-lifetime-current-source-v2.json'
    value = load(path)
    rows = []
    for row in value['sources']:
        content = raw(row['path'])
        rows.append({**row, 'bytes': len(content), 'current_sha256': sha(content)})
    report['plans'][path] = {'candidate_sources': rows,
        'candidate_changed_paths': [row['path'] for row in rows
                                    if row['historical_sha256'] != row['current_sha256']],
        'historical_hashes_unchanged': True,
        'current_checkpoint_requires_publication_verification': revision}

    path = 'config/pon/w1-qrom-implementation-current-v2.json'
    value = load(path)
    fields = {}
    for key, rows in (('project_files', value['project_files']),
                      ('local_path_closure.files', value['local_path_closure']['files'])):
        observed_rows = []
        for row in rows:
            content = raw(row['path'])
            observed_rows.append({**row, 'bytes': len(content), 'sha256': sha(content)})
        fields[key] = observed_rows
    report['plans'][path] = {'candidate_current_rows': fields,
        'new_local_path_dependency_and_include_review_required': True,
        'historical_contract_helpers_assets_and_parameters_unchanged': True,
        'current_checkpoint_requires_publication_verification': revision}

    path = 'config/pon/pq128-lifetime-composition-v2.json'
    value = load(path)
    report['plans'][path] = {'input_pin_observations': {
        key: {'path': row['path'], 'old': row['sha256'],
              'observed_sha256': sha(raw(row['path']))}
        for key, row in value['input_manifests'].items()},
        'rerun_after_register_serialization': True,
        'probability_query_budget_and_unknown_fields_unchanged': True}
    with output_path.open('x') as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'result': 'PLAN_ONLY', 'output': str(output_path),
                      'errors': len(report['errors']), 'repository_files_modified': False}))
    return 0 if not report['errors'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
