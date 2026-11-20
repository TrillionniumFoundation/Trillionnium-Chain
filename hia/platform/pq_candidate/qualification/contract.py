"""Source, method and command contract for Candidate qualification only."""
from pathlib import Path
import subprocess

from hia.platform.pq_auth.qualification.contract import (
    COMPILER, ORIGINAL_ROOTS, PLATFORM_GUARD, REVISION, SHARED,
    canonical, check_platform_environment, compose, document, identity, inventory,
    need, read, regular, relative, same, sha,
)

ROOT = Path(__file__).resolve().parents[4]
PREFIX = 'hia/platform/pq_candidate/'
SCHEMA = 'trnm.hia.candidate-public-qualification.v1'
LIMITS = {'whole_chain_native': False, 'whole_crypto_crate_ported': False,
          'openssl_owned_provider_ported': False, 'tuf_ported': False,
          'constant_time_qualified': False, 'foreign_arbitrary_pointer_gate_qualified': False,
          'register_stack_secret_erasure_qualified': False, 'production_activation': False,
          'live_pointer_const_contract_required': True}
UNITS = (
    ('candidate', 'hia/src/crypto/ml_dsa_owner.hepta', 'trnm_candidate_owner_private'),
    ('gate', 'hia/src/crypto/pq_candidate_gate.hepta', 'trnm_candidate_gate_private'),
    ('owned-emitter', PREFIX + 'owned_emitter.hepta', None),
)
METHODS = ('CandidateAlgorithm.name', 'CandidateAlgorithm.public_key_bytes',
    'CandidateAlgorithm.signature_bytes', 'CandidateAlgorithm.nist_category',
    'CandidateSigningKey.from_owned_seed', 'CandidateSigningKey.algorithm',
    'CandidateSigningKey.public_key', 'CandidateSigningKey.sign',
    'CandidateVerifier.from_pinned_raw', 'CandidateVerifier.algorithm',
    'CandidateVerifier.public_key', 'CandidateVerifier.verify')
PLATFORM_FILES = ('build_owned.py', 'emit_owned.py', 'owned_emitter.hepta', 'owned.map',
    'owned_exports.json', 'pq_candidate.h', 'README.md', 'qualify.py', 'readback.py',
    'qualification/contract.py', 'qualification/cases.py', 'qualification/native_cases.py',
    'qualification/api.py', 'qualification/allocations.py', 'qualification/lifetimes.py',
    'qualification/abi_client.c', 'qualification/integrity.py')
SHARED_QUALIFICATION = ('hia/platform/pq_auth/qualification/contract.py',
    'hia/platform/pq_auth/qualification/supervision.py',
    'hia/platform/pq_auth/qualification/supervision_controls.py',
    'hia/platform/pq_auth/qualification/allocator_observer.c',
    'hia/platform/pq_auth/readback.py')
COUNTS = {'original_retained': 343, 'original_doctests': 2, 'explicit_original_methods': 12,
          'exports': 25, 'native_cases': 892, 'native_abi_calls': 14680,
          'alias_original_pairs': 2, 'native_original_pairs': 894,
          'allocation_controls': 186, 'actual_allocation_failures': 109,
          'lifetime_abi_calls': 992,
          'readonly_owner_shared_threads': 8, 'independent_post_owner_values': 132,
          'native_partitions': 3, 'real_process_controls': 8,
          'native_execution_limit_seconds': 240, 'single_cleanup_limit_seconds': 3}
PARTITION_COUNTS = {'methods': 156, 'verify-65': 324, 'verify-87': 412}


def input_map(root, *, git_original=True):
    from hia.tools.ml_dsa_original import boundary_inputs
    roots = (*ORIGINAL_ROOTS, *boundary_inputs(root))
    if git_original:
        raw = subprocess.check_output(['git', 'ls-tree', '-rz', 'HEAD', '--', *roots], cwd=root)
        names = [entry.split(b'\t', 1)[1].decode() for entry in raw.split(b'\0') if entry]
    else:
        names = []
        for prefix in roots:
            path = Path(root) / prefix
            names.extend(item.relative_to(root).as_posix() for item in path.rglob('*') if item.is_file()) if path.is_dir() else names.append(prefix)
    need(names, 'empty original source roster')
    names = set(names) | set(SHARED) | set(SHARED_QUALIFICATION) | {PREFIX + name for name in PLATFORM_FILES}
    manifest = document(read(root, 'hia/components.json'))
    need(set(manifest) == {'schema', 'includes'} and manifest['schema'] == 'trnm.hia.component-includes.v1'
         and type(manifest['includes']) is dict, 'component schema')
    # compose_source admits every manifest key before selecting this image's
    # call closure. Retain the actual files on which that admission depends,
    # including keys whose functions do not enter a Candidate image.
    for name in manifest['includes']:
        relative(name)
        need(name.startswith(('src/', 'platform/', 'storage/')) and name.endswith('.hepta'), 'component path')
        names.add('hia/' + name)

    def visit(name, ancestry=()):
        relative(name)
        need(name not in ancestry and name.startswith(('src/', 'platform/', 'storage/')) and name.endswith('.hepta'), 'component path or cycle')
        names.add('hia/' + name)
        for row in manifest['includes'].get(name, []):
            need(type(row) is dict and set(row) == {'source', 'functions'} and type(row['functions']) is list
                 and row['functions'] and len(set(row['functions'])) == len(row['functions']), 'component functions')
            visit(row['source'], (*ancestry, name))

    for _, source, _ in UNITS:
        visit(source[4:])
    return {name: sha(read(root, name)) for name in sorted(names)}


def normalize(request, result):
    # The public error-display call implements fmt::Display. The standalone
    # enum's code/fields are represented by its input, not an owned error object.
    return {'display': result['display']} if request['op'] == 'error_display' else result


def jsonl(rows):
    import json
    return b''.join((json.dumps(row, sort_keys=True) + '\n').encode() for row in rows)
