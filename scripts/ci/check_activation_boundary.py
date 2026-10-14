#!/usr/bin/env python3
"""Reject activation declarations in an experimental checkout; not runtime authority."""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Required bindings live in code so editing the policy cannot remove an obligation.
BINDINGS = {
    'config/consensus-mainline.json': (
        'runtime_implemented', 'work_profile_qualified', 'production_candidate',
        'production_consensus_activation', 'public_testnet_ready', 'release_ready',
    ),
    'config/pon-nakamoto-v1.json': (
        'production_candidate', 'production_consensus_activation',
        'public_testnet_ready', 'release_ready', 'automatic_bft_fallback',
        'automatic_hash_only_fallback', 'implementation.runtime_implemented',
        'implementation.work_profile_qualified',
        'implementation.public_model_efficacy_measured',
        'implementation.public_model_product_loop_accepted',
        'implementation.reorg_external_effects_qualified',
        'implementation.independent_security_accepted',
        'implementation.independent_economics_accepted',
        'work_profile.cost_hardness_accepted', 'work_profile.independent_verifier',
    ),
    'config/pon/work-profile-v1.json': (
        'production_eligible', 'external_hardness_acceptance',
    ),
}
EVIDENCE = (
    'deterministic_finality', 'artifact_availability', 'independent_evaluator',
    'three_real_predecessor_future_window_generations',
    'wan_partition_power_loss_deep_reorg_validation',
)


class ActivationError(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ActivationError('duplicate key: ' + key)
        result[key] = value
    return result


def load(path):
    return json.loads(path.read_text(), object_pairs_hook=unique)


def check(root=ROOT):
    policy = load(root / 'config/activation-policy-v1.json')
    expected = {
        'schema': 'trnm-activation-policy-v1',
        'mode': 'experimental-deny-by-default',
        'promotion_allowlist': [],
        'required_false_bindings': {path: list(keys) for path, keys in BINDINGS.items()},
        'required_evidence_before_promotion': list(EVIDENCE),
    }
    if policy != expected:
        raise ActivationError('activation policy differs from mandatory frozen obligations')
    for path, keys in BINDINGS.items():
        data = load(root / path)
        for key in keys:
            value = data
            for component in key.split('.'):
                if not isinstance(value, dict) or component not in value:
                    raise ActivationError(f'missing activation binding: {path}:{key}')
                value = value[component]
            if value is not False:
                raise ActivationError(f'unsupported activation: {path}:{key}')
    truth = load(root / 'config/consensus-mainline.json')
    if truth.get('active_consensus_implementation', 'missing') is not None:
        raise ActivationError('active consensus implementation must remain null')
    pon = load(root / 'config/pon-nakamoto-v1.json')
    if pon.get('work_profile', {}).get('status') != 'implemented-experimental-not-security-qualified':
        raise ActivationError('work profile must remain experimental')
    return {'result': 'PASS', 'activation': False, 'scope': 'declaration-consistency-only'}


if __name__ == '__main__':
    try:
        print(json.dumps(check(), sort_keys=True))
    except (ActivationError, OSError, ValueError, TypeError) as error:
        raise SystemExit('Activation boundary failed: ' + str(error))
