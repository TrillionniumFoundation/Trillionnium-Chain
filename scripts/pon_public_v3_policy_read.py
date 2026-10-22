#!/usr/bin/env python3
"""Exact signed-policy identifiers, not signature/host/native execution evidence.

Retained observation schemas do not imply a resource revision. In particular,
r11, r12 and r13 all use the paid-envelope v3 observer. Missing policy stays unknown.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import struct

CONFIG = Path(__file__).resolve().parents[1] / 'config/pon/public-resource-profile-vectors-v1.json'
OBSERVATION_SCHEMA = 'public-protected-resource-policy-observation-v1'
ARITHMETIC_PROFILE = 'arithmetic-facts-v1'
ARITHMETIC_REVISION = 'r13-arithmetic-facts-v1'


def require(value, message):
    if not value:
        raise ValueError(message)


def domain_hash(domain, parts):
    tag = domain.encode('ascii')
    h = hashlib.sha256(b'TRNM-PON1\0' + struct.pack('<H', len(tag)) + tag)
    for part in parts:
        h.update(struct.pack('<I', len(part)))
        h.update(part)
    return h.hexdigest()


def policy_id(config, revision, ticket_bits, lifetime_ms):
    require(type(ticket_bits) is int and 8 <= ticket_bits <= 20
            and type(lifetime_ms) is int and 100 <= lifetime_ms <= 2000,
            'exact public policy parameters required')
    require(revision in config['revisions'], 'unknown public resource revision')
    parts = [config['transport_profile'].encode('ascii'),
             config['revisions'][revision]['resource_contract'].encode('ascii'),
             bytes([ticket_bits]), struct.pack('<Q', lifetime_ms),
             *(struct.pack('<Q', config[key]) for key in
               ('burst_ns', 'refill_ns_per_second', 'start_reserve_ns')),
             struct.pack('<I', config['worker_limit'])]
    return domain_hash(config['hash_domain'], parts)


def arithmetic_policy_id(config, ticket_bits, lifetime_ms):
    entry = config['arithmetic_profile']
    return domain_hash(entry['hash_domain'], [
        bytes.fromhex(policy_id(config, entry['base_revision'], ticket_bits, lifetime_ms)),
        entry['resource_contract'].encode('ascii'), struct.pack('<Q', entry['slots']),
        struct.pack('<Q', entry['maximum_software_bytes'])])


def load_profiles(path=CONFIG):
    raw = path.read_bytes()
    require(len(raw) <= 64 * 1024, 'finite public policy vector file required')

    def unique(rows):
        value = {}
        for key, item in rows:
            require(key not in value, 'duplicate public policy vector key')
            value[key] = item
        return value

    config = json.loads(raw, object_pairs_hook=unique)
    require(config['schema'] == 'pon-public-resource-profile-vectors-v1'
            and config['current_revision'] == 'r13'
            and config['transport_profile'] == 'public-protected-development-v3'
            and config['hash_domain'] == 'public-protected-profile-v3'
            and [config[key] for key in ('burst_ns', 'refill_ns_per_second',
                                        'start_reserve_ns', 'worker_limit')]
                == [2_000_000_000, 250_000_000, 100_000_000, 2]
            and set(config['revisions']) == {'r10', 'r11', 'r12', 'r13'}
            and config['source_vectors_are_native_acceptance'] is False,
            'original resource numbers and explicit profile history required')
    for revision, entry in config['revisions'].items():
        require(entry['resource_contract'].startswith('resource-revision-' + revision + '/')
                and [(row['ticket_bits'], row['lifetime_ms']) for row in entry['vectors']]
                    == [(8, 2000), (12, 2000), (16, 2000)],
                'complete exact public policy vectors required')
        for row in entry['vectors']:
            require(policy_id(config, revision, row['ticket_bits'], row['lifetime_ms'])
                    == row['policy_id'], 'public policy vector hash mismatch')
    entry = config['arithmetic_profile']
    require(set(entry) == {'work_profile', 'resource_revision', 'base_revision', 'hash_domain',
            'source', 'resource_contract', 'slots', 'maximum_software_bytes', 'vectors'}
            and entry['work_profile'] == ARITHMETIC_PROFILE
            and entry['resource_revision'] == ARITHMETIC_REVISION
            and entry['base_revision'] == 'r13'
            and entry['hash_domain'] == 'public-protected-profile-v3-arithmetic-facts-v1'
            and entry['source'] == 'trillionnium/crates/trnm-pon-node/src/ingress/public_v3/work_arithmetic.rs'
            and type(entry['slots']) is int and entry['slots'] == 64
            and type(entry['maximum_software_bytes']) is int
            and entry['maximum_software_bytes'] == 4 * 1024 * 1024
            and [(row['ticket_bits'], row['lifetime_ms']) for row in entry['vectors']]
                == [(8, 2000), (12, 2000), (16, 2000)],
            'explicit separate arithmetic profile and original r13 bounds required')
    for row in entry['vectors']:
        require(arithmetic_policy_id(config, row['ticket_bits'], row['lifetime_ms']) == row['policy_id'],
                'arithmetic policy vector hash mismatch')
    return config


def identify_observation(value):
    require(type(value) is dict and set(value) == {'schema', 'transport_profile',
            'policy_id', 'ticket_bits', 'lifetime_ms'}, 'exact public policy observation required')
    config = load_profiles()
    require(value['schema'] == OBSERVATION_SCHEMA
            and value['transport_profile'] == config['transport_profile']
            and type(value['policy_id']) is str
            and re.fullmatch('[0-9a-f]{64}', value['policy_id']),
            'canonical public policy observation required')
    matches = [revision for revision in config['revisions']
               if policy_id(config, revision, value['ticket_bits'], value['lifetime_ms'])
                   == value['policy_id']]
    if arithmetic_policy_id(config, value['ticket_bits'], value['lifetime_ms']) == value['policy_id']:
        require(not matches, 'ambiguous public policy identifier')
        return {**value, 'resource_revision': ARITHMETIC_REVISION,
                'base_resource_revision': 'r13', 'work_profile': ARITHMETIC_PROFILE}
    require(len(matches) == 1, 'unrecognized or mismatched public policy identifier')
    return {**value, 'resource_revision': matches[0]}
