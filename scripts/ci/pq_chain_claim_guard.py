#!/usr/bin/env python3
"""Reject unsupported *whole-chain* post-quantum promotion claims.

A passing invocation means only that the checked-out research candidate still
advertises HOLD; it is NOT a PQ-128 attestation, authorization or consensus gate.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import stat
import sys

CONFIG = 'config/pon/post-quantum-transition-v1.json'
CORPUS = 'config/pon/pq-cross-branch-corpus-v1.json'
CONSENSUS = 'config/consensus-mainline.json'
DEVNET = 'config/pon/devnet-v1.json'
BOUNDARY = 'PROJECT_BOUNDARY.json'
PROOF_MANIFEST = 'trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0/backend-manifest.json'

# One failure cannot be compensated by successes in other security domains.
REQUIRED_ASSERTIONS = frozenset({
    'production_activation', 'independent_accepted', 'native_pq_node_integrated',
    'quantum_pon_hardness_qualified', 'physical_rollback_resistant',
    'hepta_final_use_integrated', 'public_wan_accepted', 'allow_legacy_fallback',
})
GATES = {
    'authorization': (
        'trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs',
        'trillionnium/crates/trnm-pon-node/src/ingress.rs',
        'trillionnium/crates/trnm-research-protocol/src/hepta_handoff.rs',
        'trillionnium/crates/trnm-research-protocol/src/hepta_handoff/pq.rs',
        'trillionnium/crates/trnm-data-availability/src/cell/discovery/pq.rs',
        'scripts/ci/pq_authority_surface_scan.py',
        'scripts/ci/test_pq_authority_surface_scan.py',
        'docs/security/PQ_AUTHORITY_SURFACE_AUDIT_20261031.md',
    ),
    'proof_pq128': (
        'trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs',
        'docs/security/POST_QUANTUM_TRANSITION_V1.md',
    ),
    'quantum_mining_fork_choice': (
        'config/pon/devnet-v1.json',
        'docs/protocol/pon-nakamoto-v1/details/WORK_COST_DAA_BOUNDARIES.md',
        'scripts/ci/pq_quantum_daa_scenarios.py',
        'scripts/ci/test_pq_quantum_daa_scenarios.py',
        'docs/security/PQ_QUANTUM_DAA_SENSITIVITY_20261031.md',
    ),
    'migration_and_rollback': (
        'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/migration.rs',
        'trillionnium/crates/trnm-data-availability/src/cell/discovery/pq/directory.rs',
        'scripts/ci/pq_external_rollback_oracle.py',
        'scripts/ci/test_pq_external_rollback_oracle.py',
        'docs/security/PQ_EXTERNAL_ROLLBACK_WITNESS_REFERENCE_20261031.md',
    ),
    'capacity_and_invalid_input': (
        'trillionnium/crates/trnm-protocol/src/pq_frame.rs',
        'config/pon/post-quantum-transition-v1.json',
    ),
    'independent_end_to_end': (
        'docs/security/PQ_APPLICATION_AUTHORIZATION_V6.md',
        'config/pon/pq-cross-branch-corpus-v1.json',
    ),
}

class UnsafePromotion(ValueError):
    pass


def require(ok: bool, msg: str) -> None:
    if not ok:
        raise UnsafePromotion(msg)


def safe_file(root: Path, relative: str) -> bytes:
    require(not Path(relative).is_absolute() and '..' not in Path(relative).parts,
            'unsafe source path: ' + relative)
    path = root
    for component in Path(relative).parts:
        path = path / component
        require(not path.is_symlink(), 'symlink source: ' + relative)
    try:
        metadata = path.stat()
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_size <= 1024 * 1024,
                'oversized/nonregular source: ' + relative)
        data = path.read_bytes()
        require(len(data) == metadata.st_size, 'changing source: ' + relative)
        return data
    except OSError as error:
        raise UnsafePromotion('missing or unreadable source: ' + relative) from error


def strict_json(root: Path, relative: str) -> dict:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, 'duplicate JSON field: ' + relative + ':' + key)
            value[key] = item
        return value
    def finite_float(value: str) -> float:
        parsed = float(value)
        require(math.isfinite(parsed), 'nonfinite JSON number: ' + relative)
        return parsed

    def reject_nonstandard_constant(value: str) -> float:
        raise UnsafePromotion('nonstandard JSON constant: ' + relative + ':' + value)

    try:
        data = json.loads(safe_file(root, relative), object_pairs_hook=unique,
                          parse_float=finite_float,
                          parse_constant=reject_nonstandard_constant)
    except (ValueError, UnicodeError) as error:
        raise UnsafePromotion('invalid JSON: ' + relative) from error
    require(type(data) is dict, 'non-object JSON: ' + relative)
    return data


def false_field(data: dict, name: str, context: str) -> None:
    require(data.get(name) is False, 'unsupported PQ promotion: ' + context + '.' + name)


def inspect(root: Path) -> dict:
    p = strict_json(root, CONFIG)
    c = strict_json(root, CORPUS)
    main = strict_json(root, CONSENSUS)
    dev = strict_json(root, DEVNET)
    boundary = strict_json(root, BOUNDARY)
    require(p.get('schema') == 'trnm-pon-post-quantum-transition-v1' and
            p.get('status') == 'research-only-no-activation' and
            p.get('changes_existing_consensus') is False,
            'PQ research profile changed')
    for obj, names, label in (
        (p, ('production_activation', 'allow_classical_fallback'), CONFIG),
        (main, ('runtime_implemented', 'work_profile_qualified', 'production_candidate',
                'production_consensus_activation', 'public_testnet_ready', 'release_ready'), CONSENSUS),
        (dev, ('production_activation',), DEVNET),
        (boundary.get('consensus', {}), ('production_candidate',
                'production_consensus_activation'), BOUNDARY),
    ):
        require(type(obj) is dict, 'missing security profile: ' + label)
        for name in names:
            false_field(obj, name, label)
    require(main.get('active_consensus_implementation') is None and
            boundary['consensus'].get('active_implementation') is None,
            'nonempty production consensus implementation')
    a = c.get('assertions')
    require(type(a) is dict and set(a) == REQUIRED_ASSERTIONS,
            'missing research-only negative assertion')
    for name in sorted(REQUIRED_ASSERTIONS):
        false_field(a, name, CORPUS)
    r = p.get('reference_signature')
    k = p.get('reference_key_exchange')
    limits = p.get('existing_devnet_limits')
    candidate = p.get('candidate_limits_for_analysis_only')
    conf = p.get('conformance')
    require(all(type(x) is dict for x in (r, k, limits, candidate, conf)),
            'missing typed PQ security limits')
    require(r.get('algorithm') == 'ML-DSA-65' and r.get('signature_bytes') == 3309 and
            r.get('public_key_bytes') == 1952 and
            r.get('signed_envelope_bytes') == 3487,
            'unknown PQ authentication envelope')
    for obj, names, label in (
        (r, ('native_account_migration_integrated',), 'signature'),
        (k, ('tls_authenticated_deployed',), 'transport'),
        (limits, ('post_quantum_transaction_wire_compatible',), 'legacy limits'),
        (candidate, ('evaluated_for_network_or_security',), 'candidate limits'),
        (conf, ('tests_are_product_activation', 'independent_accepted',
                'native_node_integrated'), 'conformance'),
    ):
        for name in names:
            false_field(obj, name, label)
    require(limits.get('max_transaction_bytes') == 2048 and
            limits.get('max_block_bytes') == 1048576 and
            dev.get('max_transaction_bytes') == limits['max_transaction_bytes'] and
            dev.get('max_block_bytes') == limits['max_block_bytes'],
            'actual devnet resource ceiling changed without qualification')
    for paths in GATES.values():
        for path in paths:
            safe_file(root, path)
    # The formerly researched guest may be absent from the current candidate.
    # If reintroduced, its own qualification flag cannot override whole-chain HOLD.
    if (root / PROOF_MANIFEST).exists() or (root / PROOF_MANIFEST).is_symlink():
        manifest = strict_json(root, PROOF_MANIFEST)
        false_field(manifest, 'pq_128_security_qualified', PROOF_MANIFEST)
        false_field(manifest, 'production_consensus_activation', PROOF_MANIFEST)
    return {
        'schema': 'trnm-whole-chain-pq-claim-guard-v1',
        'status': 'HOLD', 'whole_chain_pq_qualified': False,
        'pq_128_qualified': False, 'production_activation': False,
        'gates': {gate: {'status': 'UNQUALIFIED', 'source_paths': list(paths)}
                  for gate, paths in GATES.items()},
        'note': 'Source/flag refusal only; no independent crypto, quantum cost, WAN, rollback or production evidence.',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args()
    try:
        result = inspect(args.root)
    except UnsafePromotion as error:
        print(json.dumps({'schema': 'trnm-whole-chain-pq-claim-guard-v1',
                          'status': 'REFUSE', 'reason': str(error)}, sort_keys=True), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
