#!/usr/bin/env python3
"""Withdraw current-use eligibility from an upstream-affected W1 proof profile.

This offline reader binds the selected mapping, actual Cargo declarations and
retained proof identities. It does not load a verifier, authenticate installed
crate bytes, reproduce an exploit, or approve a migration. The advisory policy
is a reviewed snapshot, not a live vulnerability feed. Historical evidence can
remain reproducible after the implementation it records is withdrawn.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

import pq_lifetime_budget as lifetime
from pq_source_reader import SourceReadError, read_regular


SCHEMA = 'trnm-w1-upstream-security-v1'
RESULT_SCHEMA = 'trnm-w1-upstream-security-result-v1'
DEFAULT_MANIFEST = 'config/pon/w1-upstream-security-v1.json'
MAPPING = 'config/pon/w1-qrom-implementation-current-v2.json'
PREFIX = 'formal/pon-nakamoto-v1/'
BACKENDS = {
    'v2_verifier': PREFIX + 'w1_v2_verifier',
    'hardened_verifier': PREFIX + 'w1_hardened_verifier',
    'guest_v2': PREFIX + 'w1_zkvm/methods/guest-v2',
}
REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index'
MAX_BYTES = 2 * 1024 * 1024
RELEASE = {
    'url': 'https://github.com/risc0/risc0/releases/tag/v3.1.0',
    'tag': 'v3.1.0', 'release_id': 441049704, 'published_at': '2026-11-10T23:26:01Z',
    'affected_receipt_formats': ['composite', 'succinct', 'Groth16', 'on-chain'],
    'regeneration_required': True,
}
ADVISORIES = [
    {
        'id': 'GHSA-g6qg-9j8p-7j87',
        'url': 'https://github.com/risc0/risc0/security/advisories/GHSA-g6qg-9j8p-7j87',
        'affected_before': {
            'risc0-zkvm': '3.1.0', 'risc0-circuit-recursion': '4.1.0',
            'risc0-groth16': '3.0.6',
        },
    },
    {
        'id': 'GHSA-qvmf-qrrq-p2w4',
        'url': 'https://github.com/risc0/zirgen/security/advisories/GHSA-qvmf-qrrq-p2w4',
        'fixed_generator_release': 'v3.1.0',
        'regenerate': ['circuits', 'recursion-programs', 'control-roots', 'Groth16-setups'],
    },
]
# These are the exact release-family versions, not open-ended safe ranges.
# rv32im and zkp are also named in the release's circuit/hash repairs. Presence
# of a Groth16 package in a lock does not establish use of that receipt format.
PATCH_RELEASE = {
    'risc0-zkvm': '3.1.0', 'risc0-circuit-recursion': '4.1.0',
    'risc0-circuit-rv32im': '4.1.0', 'risc0-zkp': '3.0.6',
    'risc0-groth16': '3.0.6',
}
HISTORICAL_PROFILE = 'trnm-w1-risc0-3.0.6-poseidon2-join-v2'
HISTORICAL_CONTROL = '7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e'
HISTORICAL_PARAMETERS = 'ece5e9b8ae2cd6ea6b1827b464ff0348f9a7f4decd269c0087fdfd75098da013'
HISTORICAL_IMAGE = [1958252411, 3287394615, 1805488136, 1516578702,
                    78549041, 790278610, 301018785, 4279049364]
HISTORICAL_RECEIPT = '6c72828c9d05a62175e08fa3e7e1d0d5e85e785ad96b5beb5ec7a2e2490c26ee'
RECEIPT = 'evidence/pon-w1-full-v2-20261105/succinct.bin'
GUEST_ELF = 'evidence/pon-w1-full-v2-20261105/guest.bin'
PROOF_RESULT = 'evidence/pon-w1-full-v2-20261105/proof-result.json'


class UpstreamSecurityError(ValueError):
    """Invalid source evidence or unsupported current-use eligibility."""


def require(condition, message):
    if not condition:
        raise UpstreamSecurityError(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names.split()),
            'unexpected or missing fields: ' + label)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(root, row, observations):
    fields(row, 'path bytes sha256', 'source pin')
    path = lifetime.relative_path(row['path'], 'source pin')
    require(type(row['bytes']) is int and 0 < row['bytes'] <= MAX_BYTES,
            'invalid source byte count')
    require(type(row['sha256']) is str and re.fullmatch(r'[0-9a-f]{64}', row['sha256']),
            'invalid source SHA-256')
    require(path not in observations, 'duplicate selected source: ' + path)
    raw = read_regular(root, path, row['bytes'])
    require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
            'source pin differs: ' + path)
    observations[path] = raw
    return raw


def stable_version(value):
    if type(value) is not str or not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value):
        return None
    require(len(value) <= 32, 'unsupported version size')
    return tuple(map(int, value.split('.')))


def package_status(name, package):
    """Classify a declared locked package; this does not verify installed code."""
    version = package.get('version')
    parsed = stable_version(version)
    patched = stable_version(PATCH_RELEASE[name])
    source = package.get('source')
    checksum = package.get('checksum')
    registry_identity = (source == REGISTRY and type(checksum) is str
                         and re.fullmatch(r'[0-9a-f]{64}', checksum) is not None)
    if not registry_identity:
        status = 'UNREVIEWED_PACKAGE_SOURCE'
    elif parsed is None:
        status = 'UNREVIEWED_PRERELEASE_OR_VERSION'
    elif parsed < patched:
        status = 'KNOWN_AFFECTED_UPSTREAM_RELEASE'
    elif parsed == patched:
        status = 'PUBLISHED_PATCH_VERSION_MIGRATION_UNREVIEWED'
    else:
        status = 'UNREVIEWED_LATER_VERSION'
    return {
        'name': name, 'locked_version': version, 'locked_source': source,
        'declared_checksum': checksum, 'published_patch_version': PATCH_RELEASE[name],
        'assessment': status, 'installed_package_bytes_verified': False,
        'advisory_ids': ([ADVISORIES[0]['id']]
                         if name in ADVISORIES[0]['affected_before'] else []),
        'release_reference': RELEASE['url'],
    }


def backend(name, path, sources):
    manifest = tomllib.loads(sources[path + '/Cargo.toml'].decode('utf-8'))
    lock = tomllib.loads(sources[path + '/Cargo.lock'].decode('utf-8'))
    declared = manifest.get('dependencies', {}).get('risc0-zkvm')
    require(type(declared) is dict and type(declared.get('version')) is str,
            name + ': missing explicit SDK dependency declaration')
    requirement = declared['version']
    require(requirement.startswith('=') and requirement[1:],
            name + ': SDK declaration must be an exact version')
    packages = lock.get('package')
    require(type(packages) is list and all(type(row) is dict for row in packages),
            name + ': malformed Cargo package list')
    rows = []
    for crate in PATCH_RELEASE:
        selected = [row for row in packages if row.get('name') == crate]
        require(len(selected) == 1, name + ': missing or ambiguous locked crate: ' + crate)
        rows.append(package_status(crate, selected[0]))
    sdk = next(row for row in rows if row['name'] == 'risc0-zkvm')
    require(requirement[1:] == sdk['locked_version'],
            name + ': manifest SDK differs from the actual selected lock')
    return {'id': name, 'manifest_path': path + '/Cargo.toml',
            'lock_path': path + '/Cargo.lock', 'sdk_requirement': requirement,
            'manifest_and_lock_sdk_match': True, 'packages': rows,
            'cargo_resolution_executed': False, 'build_or_loaded_identity_verified': False}


def constant(raw, name):
    matches = re.findall(r'\bconst\s+' + re.escape(name)
                         + r'\s*:\s*&str\s*=\s*"([^"\\\n]*)"\s*;', raw.decode('utf-8'))
    require(len(matches) == 1, 'ambiguous source constant: ' + name)
    return matches[0]


def inspect(root, manifest=DEFAULT_MANIFEST):
    root = Path(root)
    observations = {}
    raw = read_regular(root, lifetime.relative_path(manifest, 'security register'), MAX_BYTES)
    observations[manifest] = raw
    register = lifetime.strict_json(raw)
    fields(register, 'schema scope observed_on release advisories selected_profile_id '
           'mapping_contract approved_current_profile_ids', 'security register')
    require(register['schema'] == SCHEMA
            and register['scope'] == 'selected-source-upstream-withdrawal-only',
            'unsupported security register scope')
    require(register['observed_on'] == '2026-11-11'
            and json.dumps(register['release'], sort_keys=True) == json.dumps(RELEASE, sort_keys=True)
            and json.dumps(register['advisories'], sort_keys=True) == json.dumps(ADVISORIES, sort_keys=True),
            'unreviewed upstream policy or omitted advisory')
    require(register['approved_current_profile_ids'] == [],
            'this policy has no approved migrated profile; self-promotion refused')
    require(register['mapping_contract']['path'] == MAPPING, 'wrong selected mapping')
    mapping_raw = pin(root, register['mapping_contract'], observations)
    mapping = lifetime.strict_json(mapping_raw)
    require(mapping.get('schema') == 'TRNM-W1-QROM-IMPLEMENTATION-CONTRACT2',
            'unsupported selected mapping schema')
    require(mapping.get('profile_id') == register['selected_profile_id'],
            'selected profile differs from mapping')
    selected = {}
    for group in ('project_files', 'saved_v2_files'):
        roster = mapping.get(group)
        require(type(roster) is list and 0 < len(roster) <= 128, 'invalid selected source roster')
        for row in roster:
            selected[row['path']] = pin(root, row, observations)
    upstream = pin(root, mapping['upstream_snapshot'], observations)
    required = {path + suffix for path in BACKENDS.values()
                for suffix in ('/Cargo.toml', '/Cargo.lock')}
    entry = BACKENDS['v2_verifier'] + '/src/main.rs'
    profile = BACKENDS['hardened_verifier'] + '/src/profile.rs'
    image = BACKENDS['v2_verifier'] + '/src/image.rs'
    required.update((entry, profile, image, RECEIPT, GUEST_ELF, PROOF_RESULT))
    require(required <= set(selected), 'selected mapping omits required backend/proof identity')
    backends = [backend(name, path, selected) for name, path in BACKENDS.items()]
    profile_id = constant(selected[entry], 'PROFILE_ID')
    require(profile_id == mapping['profile_id'], 'entry profile differs from selected mapping')
    image_match = re.findall(r'\bIMAGE_ID\s*:\s*\[u32;\s*8\]\s*=\s*\[([0-9,\s]+)\]',
                             selected[image].decode('utf-8'))
    require(len(image_match) == 1, 'ambiguous image source')
    image_words = [int(word.strip()) for word in image_match[0].split(',') if word.strip()]
    require(len(image_words) == 8 and all(0 <= word < 2**32 for word in image_words),
            'invalid image ID')
    identity = {
        'profile_id': profile_id, 'hash_suite': constant(selected[profile], 'HASH_SUITE'),
        'final_control_id': constant(selected[profile], 'CONTROL_ID'),
        'verifier_parameters_digest': constant(selected[profile], 'PARAMETERS'),
        'guest_image_id': image_words, 'saved_receipt_sha256': sha(selected[RECEIPT]),
        'saved_guest_elf_sha256': sha(selected[GUEST_ELF]),
        'saved_proof_result_sha256': sha(selected[PROOF_RESULT]),
        'upstream_snapshot_sha256': sha(upstream),
    }
    retained = []
    for key, old in (('profile_id', HISTORICAL_PROFILE), ('final_control_id', HISTORICAL_CONTROL),
                     ('verifier_parameters_digest', HISTORICAL_PARAMETERS),
                     ('guest_image_id', HISTORICAL_IMAGE), ('saved_receipt_sha256', HISTORICAL_RECEIPT)):
        if identity[key] == old:
            retained.append(key)
    affected = [{'backend': item['id'], 'crate': row['name'], 'version': row['locked_version']}
                for item in backends for row in item['packages']
                if row['assessment'] == 'KNOWN_AFFECTED_UPSTREAM_RELEASE']
    unreviewed = [{'backend': item['id'], 'crate': row['name'], 'assessment': row['assessment']}
                  for item in backends for row in item['packages']
                  if row['assessment'].startswith('UNREVIEWED_')]
    blockers = ['NO_REVIEWED_MIGRATED_PROFILE', 'REGENERATED_PROOF_AND_VERIFIER_BINDING_REQUIRED']
    if affected:
        blockers.insert(0, 'UPSTREAM_AFFECTED_LOCKED_PACKAGES')
    if unreviewed:
        blockers.append('UNREVIEWED_PACKAGE_VERSION_OR_SOURCE')
    if any(len({row['assessment'] for row in item['packages']}) > 1 for item in backends):
        blockers.append('MIXED_OR_UNREVIEWED_PATCH_RELEASE_FAMILY')
    if retained:
        blockers.append('HISTORICAL_IDENTITY_REQUIRES_MIGRATION_REVIEW')
    for path, value in observations.items():
        require(read_regular(root, path, len(value)) == value,
                'selected source changed between observations: ' + path)
    return {
        'schema': RESULT_SCHEMA,
        'status': 'KNOWN_AFFECTED_SELECTED_PROFILE' if affected else 'UNREVIEWED_MIGRATION',
        'observation_date': register['observed_on'], 'release': register['release'],
        'advisory_ids': [row['id'] for row in register['advisories']],
        'selected_identity': identity, 'backend_observations': backends,
        'affected_locked_packages': affected, 'unreviewed_locked_packages': unreviewed,
        'retained_historical_identity_fields': retained, 'blockers': blockers,
        'historical_replay_scope': 'diagnostic-only; historical acceptance is not current proof eligibility',
        'historical_artifacts_modified': False, 'fresh_verification_performed': False,
        'current_proof_use_eligible': False, 'migration_approved': False,
        'actual_w1_exploit_reproduced': False, 'groth16_use_inferred_from_lock_presence': False,
        'source_binding_scope': 'selected-declarations-and-artifact-bytes-not-a-loaded-build',
        'selected_inputs_before_after_equal': True,
        'source_files_sha256': {path: sha(value) for path, value in sorted(observations.items())},
        'required_migration_evidence': [
            'Reviewed coherent patched manifests, locks, source closure, features and exact prover/r0vm toolchain.',
            'Regenerated circuits/recursion programs, control root and verifier-parameter digest.',
            'Rebuild/review the guest image identity; it need not change if the reviewed rebuild preserves it. Regenerate complete W1 receipts for the original inputs.',
            'New versioned proof-profile namespace and exact old-receipt refusal/new-receipt verification.',
            'Independent full-relation, negative, recursive and native-admission/recovery validation.',
            'Separate concrete soundness/QROM, lifetime composition and quantum-work qualification.',
        ],
        'security_bits_quantum': None, 'actual_lifetime_failure_bound': None,
        'whole_chain_pq_qualified': False, 'production_activation': False,
        'note': 'The release withdraws earlier receipt families, including succinct receipts. '
                'The advisory\'s most severe demonstrated claim substitution targets Groth16; '
                'this read does not reproduce that attack against W1. A patched version label '
                'alone establishes neither regenerated identities nor project security.',
    }


def require_current(report):
    require(type(report) is dict and report.get('schema') == RESULT_SCHEMA,
            'unsupported current-use report')
    # A caller can edit a report DTO. This reviewed policy has no current-use
    # approval route at all; a boolean cannot invent an approved migration.
    raise UpstreamSecurityError('selected proof profile is not eligible for current use')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--manifest', default=DEFAULT_MANIFEST)
    parser.add_argument('--require-current', action='store_true')
    args = parser.parse_args(argv)
    try:
        report = inspect(args.root, args.manifest)
        print(json.dumps(report, sort_keys=True, allow_nan=False))
        if args.require_current:
            require_current(report)
    except (UpstreamSecurityError, lifetime.BudgetError, SourceReadError, OSError,
            KeyError, TypeError, ValueError, RecursionError) as error:
        print(json.dumps({'schema': RESULT_SCHEMA, 'status': 'REFUSE', 'reason': str(error),
                          'current_proof_use_eligible': False,
                          'whole_chain_pq_qualified': False}, sort_keys=True), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
