#!/usr/bin/env python3
"""Bind one research proof profile without importing another profile's budget.

This reader compares selected source bytes and declarations. It does not run a
proof verifier, establish a build closure, discharge a theorem hypothesis or
authorize admission. The native-PNW1 lifetime register remains a different
experiment; its presence cannot qualify the selected RISC Zero proof profile.
The upstream security lifecycle check is mandatory. A byte-identical historical
profile can be reproducible while its current-use eligibility is withdrawn.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sys
import tomllib
import zlib

import pq_lifetime_budget as lifetime
import w1_upstream_security as upstream
from pq_source_reader import SourceReadError, read_regular


SCHEMA = 'trnm-pq-proof-profile-binding-v1'
RESULT_SCHEMA = 'trnm-pq-proof-profile-binding-result-v2'
DEFAULT_MANIFEST = 'config/pon/pq-proof-profile-binding-v1.json'
PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'
NATIVE_PROFILE = 'pon-nakamoto-v1-pq-research-native-pnw1'
MAPPING = 'config/pon/w1-qrom-implementation-current-v2.json'
MAX_BYTES = 2 * 1024 * 1024
OBLIGATIONS = frozenset({
    'latest_theorem_version_equivalence', 'complete_relation_and_compiler',
    'all_27_recursion_program_semantics',
    'control_padding_and_recursive_trace_size_reachability',
    'relaxed_rbr_knowledge_soundness', 'committed_relation_monotonicity',
    'merkle_multi_extractability', 'sponge_and_domain_separation_mapping',
    'fiat_shamir_challenge_and_salt_mapping',
    'finite_field_sampling_and_challenge_length',
    'sequential_adaptive_composition', 'lifetime_global_quantum_budget',
    'concrete_enabled_features_and_debug_exclusion', 'quantum_work_and_chainweight',
    'pq_signature_owner_authorization',
})
EXCLUDED = {
    'TRNM-W1-FULL-PUBLIC-STARK-RESEARCH-P3-0.8.0-R1': (
        'formal/pon-nakamoto-v1/w1_public_stark_research/src/proof_config.rs',
        'RESEARCH_DOMAIN', 'poseidon2-goldilocks-p3-0.8.0',
    ),
    'TRNM-W1-P3-SHA3-512-TAGGED-R1': (
        'formal/pon-nakamoto-v1/w1_public_stark_research/src/tagged_sha3.rs',
        'PROFILE_ID', 'FIPS202/SHA3-512',
    ),
}


class ProfileError(ValueError):
    """A profile identity or scope declaration was not reproduced."""


def require(ok, message):
    if not ok:
        raise ProfileError(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()),
            'unexpected or missing fields: ' + label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pinned(root, row, observations):
    fields(row, 'path bytes sha256', 'source pin')
    path = lifetime.relative_path(row['path'], 'source pin')
    require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_BYTES,
            'invalid source byte limit')
    require(type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
            'source SHA-256 must be a full lowercase digest')
    raw = read_regular(root, path, row['bytes'])
    require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
            'source pin differs: ' + path)
    if path in observations:
        require(observations[path] == raw, 'inconsistent duplicate input: ' + path)
    observations[path] = raw
    return raw


def text_constant(raw, name, byte_literal=False):
    text = raw.decode('utf-8')
    type_pattern = r'&\[u8\]' if byte_literal else r'&str'
    prefix = 'b' if byte_literal else ''
    pattern = (r'\bconst\s+' + re.escape(name) + r'\s*:\s*' + type_pattern
               + r'\s*=\s*' + prefix + r'"([^"\n]*)"\s*;')
    values = re.findall(pattern, text)
    require(len(values) == 1, 'nonunique source constant: ' + name)
    value = values[0]
    # The two existing byte IDs use ASCII and at most a terminal NUL. No
    # general Rust parser or preprocessing/feature equivalence is claimed.
    if byte_literal and value.endswith(r'\0'):
        value = value[:-2]
    require('\\' not in value and value.isascii(), 'unsupported source literal: ' + name)
    return value


def upstream_parameters(raw, expected_commit):
    """Read the pinned source declaration, without executing upstream code."""
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
            decoded = stream.read(lifetime.MAX_BYTES + 1)
    except (OSError, EOFError, zlib.error) as error:
        raise ProfileError('invalid or truncated upstream snapshot') from error
    snapshot = lifetime.strict_json(decoded)
    require(snapshot.get('schema') == 'TRNM-W1-UPSTREAM-SOURCE-SNAPSHOT1'
            and snapshot.get('repository') == 'risc0/risc0'
            and snapshot.get('commit') == expected_commit, 'upstream snapshot identity differs')
    rows = snapshot.get('files')
    require(type(rows) is list and len(rows) == 24, 'upstream selected source roster differs')
    sources = {}
    for row in rows:
        name, content = row['path'], row['content']
        require(name not in sources and type(content) is str, 'duplicate or invalid upstream source')
        encoded = content.encode('utf-8')
        require(type(row['bytes']) is int and len(encoded) == row['bytes']
                and sha(encoded) == row['sha256'], 'upstream selected source bytes differ')
        sources[name] = content

    def number(text, name):
        matches = re.findall(r'\bconst\s+' + re.escape(name)
                             + r'\s*:\s*usize\s*=\s*([0-9]+)\s*;', text)
        require(len(matches) == 1, 'nonunique upstream numeric constant: ' + name)
        return int(matches[0])

    field = sources['risc0/core/src/field/baby_bear.rs']
    require(re.search(r'pub\s+const\s+P:\s*u32\s*=\s*15\s*\*\s*\(1\s*<<\s*27\)\s*\+\s*1\s*;',
                      field) is not None
            and re.search(r'const\s+BETA:\s*Elem\s*=\s*Elem::new\(11\)\s*;', field) is not None,
            'upstream field construction differs')
    stark = sources['risc0/zkp/src/lib.rs']
    extension = number(field, 'EXT_SIZE')
    queries, inverse_rate = number(stark, 'QUERIES'), number(stark, 'INV_RATE')
    fold_po2, final_degree = number(stark, 'FRI_FOLD_PO2'), number(stark, 'FRI_MIN_DEGREE')
    require((extension, queries, inverse_rate, fold_po2, final_degree) == (4, 50, 4, 4, 256),
            'selected field/FRI parameters differ')
    return {
        'field': {'base_modulus': str(15 * 2**27 + 1),
                  'extension_degree': extension,
                  'extension_polynomial': 'X^4 + 11'},
        'fri': {'queries': queries, 'inverse_rate': inverse_rate,
                'folding_factor': 2 ** fold_po2, 'final_min_degree': final_degree},
    }


def validate_declarations(binding, mapping, system):
    """Compare scopes without treating self-declared bounds as proved values."""
    fields(binding, 'schema scope selected_profile_id mapping_contract system_lifetime_register '
           'expected_identity excluded_profile_sources theorem_reference', 'binding')
    require(binding['schema'] == SCHEMA
            and binding['scope'] == 'selected-source-binding-only', 'unsupported binding scope')
    require(binding['selected_profile_id'] == PROFILE, 'unsupported selected proof profile')
    require(binding['mapping_contract']['path'] == MAPPING, 'wrong selected mapping source')
    require(mapping.get('schema') == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2'
            and mapping.get('profile_id') == PROFILE, 'selected mapping profile mismatch')
    obligations = mapping.get('proof_obligations')
    require(type(obligations) is list and len(obligations) == len(OBLIGATIONS)
            and set(obligations) == OBLIGATIONS, 'selected proof obligations differ')
    flags = mapping.get('qualification')
    fields(flags, 'post_quantum_soundness_qualified complete_w1_soundness_qualified '
           'quantum_work_qualified pq_signature_qualification_inferred production_qualified '
           'consensus_admission security_bits_quantum', 'mapping qualification')
    require(flags['security_bits_quantum'] is None
            and all(value is False for key, value in flags.items() if key != 'security_bits_quantum'),
            'mapping qualification escalation')
    budget = mapping.get('lifetime_budget')
    fields(budget, 'quantum_queries_lifetime accepted_statements_lifetime '
           'max_recursive_nodes_per_statement max_fs_rounds_per_reduction '
           'target_total_failure_probability rrbr_knowledge_error '
           'concrete_hash_to_ideal_oracle_error hash_output_sigma_bits '
           'min_verifier_randomness_bits adaptive_composition_bound policy_adopted',
           'selected lifetime budget')
    require(budget['policy_adopted'] is False
            and all(value is None for key, value in budget.items() if key != 'policy_adopted'),
            'selected lifetime budget requires a separately reviewed promotion schema')

    register = binding['system_lifetime_register']
    fields(register, 'path profile_id relationship', 'system lifetime register')
    require(register == {
        'path': lifetime.DEFAULT_MANIFEST, 'profile_id': NATIVE_PROFILE,
        'relationship': 'separate-native-system-experiment',
    }, 'native register cannot supply the selected proof budget')
    require(system.get('purpose') == 'research-model', 'arithmetic example is not the system register')
    system_result = lifetime.evaluate(system)
    require(system['experiment']['profile'] == NATIVE_PROFILE,
            'system lifetime experiment profile mismatch')
    require(all(row['profile'] == NATIVE_PROFILE for row in system['terms']),
            'system lifetime term profile mismatch')
    require(system_result['actual_lifetime_failure_bound'] is None
            and system_result['composition_coverage_proved'] is False,
            'system register qualification escalation')
    # Primitive names alone do not establish a common experiment or a resource
    # reduction. This list is only an inventory discrepancy, not a coverage test.
    registered = {row['public_parameter_id'] for row in system['primitives']}
    selected_primitives = {'FIPS180-4/SHA-256', 'risc0-3.0.6/Poseidon2/BabyBear'}
    return system_result, sorted(selected_primitives - registered)


def inspect(root, manifest=DEFAULT_MANIFEST, expected_profile_descriptor_sha256=None):
    if expected_profile_descriptor_sha256 is not None:
        require(type(expected_profile_descriptor_sha256) is str
                and re.fullmatch(r'[0-9a-f]{64}', expected_profile_descriptor_sha256),
                'expected profile descriptor must be a full lowercase SHA-256')
    root = Path(root)
    observations = {}
    raw = read_regular(root, lifetime.relative_path(manifest, 'binding manifest'), lifetime.MAX_BYTES)
    observations[manifest] = raw
    binding = lifetime.strict_json(raw)
    # Validate the outer structure before following any declared file path.
    fields(binding, 'schema scope selected_profile_id mapping_contract system_lifetime_register '
           'expected_identity excluded_profile_sources theorem_reference', 'binding')
    contract_raw = pinned(root, binding['mapping_contract'], observations)
    mapping = lifetime.strict_json(contract_raw)
    system_path = lifetime.DEFAULT_MANIFEST
    system_raw = read_regular(root, system_path, lifetime.MAX_BYTES)
    observations[system_path] = system_raw
    system = lifetime.strict_json(system_raw)
    system_result, missing_primitives = validate_declarations(binding, mapping, system)

    inputs = {}
    for group in ('project_files', 'saved_v2_files'):
        rows = mapping.get(group)
        require(type(rows) is list and 0 < len(rows) <= lifetime.MAX_ROWS,
                'invalid selected input roster')
        for row in rows:
            require(row['path'] not in inputs, 'duplicate selected input path')
            inputs[row['path']] = pinned(root, row, observations)
    upstream_raw = pinned(root, mapping['upstream_snapshot'], observations)
    entry = 'formal/pon-nakamoto-v1/w1_v2_verifier/src/main.rs'
    image_path = 'formal/pon-nakamoto-v1/w1_v2_verifier/src/image.rs'
    profile_path = 'formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs'
    require(text_constant(inputs[entry], 'PROFILE_ID') == PROFILE, 'entry profile mismatch')
    image_matches = re.findall(r'IMAGE_ID:\s*\[u32;\s*8\]\s*=\s*\[([^]]+)\]',
                               inputs[image_path].decode('utf-8'))
    require(len(image_matches) == 1, 'nonunique guest image constant')
    image = [int(word.strip()) for word in image_matches[0].split(',') if word.strip()]
    require(len(image) == 8 and all(0 <= word < 2**32 for word in image), 'invalid guest image')
    lock_path = 'formal/pon-nakamoto-v1/w1_v2_verifier/Cargo.lock'
    packages = tomllib.loads(inputs[lock_path].decode('utf-8'))['package']
    versions = [row['version'] for row in packages if row['name'] == 'risc0-zkvm']
    require(versions == ['3.0.6'], 'selected SDK lock differs')
    identity = {
        'sdk': versions[0], 'image_id': image,
        'hash_suite': text_constant(inputs[profile_path], 'HASH_SUITE'),
        'final_control_id': text_constant(inputs[profile_path], 'CONTROL_ID'),
        'verifier_parameters_digest': text_constant(inputs[profile_path], 'PARAMETERS'),
    }
    identity.update(upstream_parameters(upstream_raw, mapping['upstream_commit']))
    require(identity == binding['expected_identity'], 'selected proof parameters differ')

    exclusions = binding['excluded_profile_sources']
    require(type(exclusions) is list and len(exclusions) == len(EXCLUDED),
            'excluded profile roster differs')
    seen = set()
    excluded_reports = []
    for row in exclusions:
        fields(row, 'profile_id source', 'excluded profile')
        profile_id = row['profile_id']
        require(profile_id in EXCLUDED and profile_id not in seen,
                'unknown or duplicate excluded profile')
        seen.add(profile_id)
        path, symbol, primitive = EXCLUDED[profile_id]
        require(row['source']['path'] == path, 'excluded source path differs')
        excluded_raw = pinned(root, row['source'], observations)
        require(text_constant(excluded_raw, symbol, True) == profile_id,
                'excluded profile source identity differs')
        excluded_reports.append({'profile_id': profile_id, 'source_sha256': sha(excluded_raw),
                                 'shared_primitive_identity': primitive,
                                 'parameters_or_bound_imported': False})

    theorem = binding['theorem_reference']
    fields(theorem, 'evaluator_source evaluator_revision official_url '
           'official_latest_revision_observed observation_date '
           'latest_full_text_obtained version_equivalence_verified', 'theorem reference')
    require(theorem['evaluator_source']['path'] == 'scripts/w1_qrom_composition_budget.py'
            and theorem['evaluator_revision'] == '2026-01-01'
            and theorem['official_url'] == 'https://eprint.iacr.org/2025/2166'
            and theorem['official_latest_revision_observed'] == '2026-03-02'
            and theorem['observation_date'] == '2026-11-09'
            and theorem['latest_full_text_obtained'] is False
            and theorem['version_equivalence_verified'] is False,
            'unreviewed theorem revision promotion')
    evaluator = pinned(root, theorem['evaluator_source'], observations)
    require(b"'manuscript_date': '2026-01-01'" in evaluator,
            'evaluator theorem revision differs')

    upstream_security = upstream.inspect(root)
    upstream_identity = upstream_security['selected_identity']
    require(upstream_identity['profile_id'] == PROFILE
            and upstream_identity['hash_suite'] == identity['hash_suite']
            and upstream_identity['final_control_id'] == identity['final_control_id']
            and upstream_identity['verifier_parameters_digest'] == identity['verifier_parameters_digest']
            and upstream_identity['guest_image_id'] == identity['image_id'],
            'upstream security inspection refers to a different proof identity')
    # Reconcile the two real read scopes. Neither an independently correct
    # report for another source nor a changed policy file can fill this slot.
    for path, digest in upstream_security['source_files_sha256'].items():
        if path not in observations:
            observations[path] = read_regular(root, path, MAX_BYTES)
        require(sha(observations[path]) == digest,
                'upstream security source differs from profile observation: ' + path)
    for path, before in observations.items():
        require(read_regular(root, path, len(before)) == before,
                'selected input changed between observations: ' + path)
    descriptor = {
        'profile_id': PROFILE, 'mapping_contract_sha256': sha(contract_raw),
        'identity': identity,
        'source_inputs': {path: sha(data) for path, data in sorted(inputs.items())},
        'upstream_snapshot_sha256': mapping['upstream_snapshot']['sha256'],
    }
    profile_digest = sha(json.dumps(descriptor, sort_keys=True, separators=(',', ':')).encode('utf-8'))
    if expected_profile_descriptor_sha256 is not None:
        require(profile_digest == expected_profile_descriptor_sha256,
                'candidate proof profile descriptor mismatch')
    status = ('PROFILE_BOUND_UPSTREAM_REVOKED_HOLD'
              if upstream_security['status'] == 'KNOWN_AFFECTED_SELECTED_PROFILE'
              else 'PROFILE_BOUND_MIGRATION_UNREVIEWED_HOLD')
    return {
        'schema': RESULT_SCHEMA, 'status': status,
        'selected_profile_id': PROFILE, 'selected_profile_descriptor_sha256': profile_digest,
        'candidate_profile_identity_matched': expected_profile_descriptor_sha256 is not None,
        'selected_identity': identity, 'binding_manifest_sha256': sha(raw),
        'source_binding_scope': 'selected-project-and-fixture-files-only',
        'selected_input_observation_count': len(observations),
        'selected_inputs_before_after_equal': True,
        'source_files_sha256': {path: sha(data) for path, data in sorted(observations.items())},
        'complete_dependency_closure_verified': False,
        'compiled_or_loaded_identity_verified': False,
        'native_proof_verification_performed': False,
        'independent_source_authentication': False,
        'upstream_security': upstream_security,
        'current_proof_use_eligible': False,
        'system_lifetime_register': {
            'profile_id': NATIVE_PROFILE,
            'source_revision': system['experiment']['source_revision'],
            'manifest_sha256': sha(system_raw),
            'source_revision_bound': False,
            'relationship': 'separate-native-system-experiment',
            'selected_proof_profile_covered': False,
            'arithmetic_imported': False,
            'unknown_term_count': len(system_result['unknown_terms']),
        },
        'unregistered_selected_primitive_identities': missing_primitives,
        'excluded_proof_profiles': excluded_reports,
        'selected_lifetime_budget': mapping['lifetime_budget'],
        'open_obligations': [{'id': item, 'state': 'UNRESOLVED'}
                             for item in mapping['proof_obligations']],
        'theorem_version': theorem,
        'actual_lifetime_failure_bound': None,
        'composition_coverage_proved': False,
        'whole_chain_hash_query_scope_closed': False,
        'whole_chain_pq_qualified': False,
        'production_activation': False,
        'note': 'A source/profile binding is not a security theorem. The native-PNW1 register '
                'and both P3 candidates supply no selected-profile failure bound; byte pins '
                'and endpoint equality do not authenticate a deployed implementation. '
                'The mandatory upstream lifecycle result separately withdraws the affected '
                'historical profile from current use; historical replay cannot reinstate it.',
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--manifest', default=DEFAULT_MANIFEST)
    parser.add_argument('--expected-profile-descriptor-sha256')
    parser.add_argument('--require-current', action='store_true',
                        help='refuse current use of a withdrawn or unreviewed proof profile')
    args = parser.parse_args(argv)
    try:
        result = inspect(args.root, args.manifest, args.expected_profile_descriptor_sha256)
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        if args.require_current:
            upstream.require_current(result['upstream_security'])
    except (ProfileError, lifetime.BudgetError, SourceReadError, OSError,
            KeyError, TypeError, ValueError, RecursionError) as error:
        print(json.dumps({'schema': RESULT_SCHEMA, 'status': 'REFUSE', 'reason': str(error),
                          'actual_lifetime_failure_bound': None,
                          'current_proof_use_eligible': False,
                          'whole_chain_pq_qualified': False, 'production_activation': False},
                         sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
