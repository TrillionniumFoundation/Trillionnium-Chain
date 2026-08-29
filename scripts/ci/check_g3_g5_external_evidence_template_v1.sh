#!/usr/bin/env bash
set -euo pipefail
root=$(git rev-parse --show-toplevel); cd "$root"

python3 - <<'PY'
import json
from pathlib import Path

path = Path('docs/evidence/g3-g5/EXTERNAL_EVIDENCE_CAMPAIGN_TEMPLATE_V1.json')
runbook = Path('docs/runbooks/TRNM_EXTERNAL_EVIDENCE_CAMPAIGN_V1.md')
value = json.loads(path.read_text(encoding='utf-8'))
assert value['schema'] == 'trnm-external-evidence-campaign-v1'
assert value['classification'] == 'candidate-non-normative'
assert value['campaign_id'] == 'UNASSIGNED'
assert value['status'] == 'NOT_STARTED'
assert runbook.is_file()

source = value['source']
for key in (
    'release_commit', 'release_tree', 'binary_sha256', 'sbom_sha256',
    'genesis_sha256', 'configuration_root', 'toolchain_identity'
):
    assert source[key] is None, key

independence = value['independence']
for key in (
    'package_author', 'campaign_operator', 'reviewer', 'auditor_organization',
    'operator_is_package_author', 'reviewer_is_package_author',
    'independence_declaration_sha256'
):
    assert independence[key] is None, key

for key, enabled in value['prerequisites'].items():
    assert enabled is False, key

for key in ('validator_processes', 'physical_hosts', 'operators', 'regions', 'custody_domains'):
    assert value['topology'][key] == 0, key
for key in ('host_inventory_sha256', 'operator_identity_root', 'custody_identity_root', 'network_topology_root'):
    assert value['topology'][key] is None, key

hsm = value['external_anchor_hsm']
for key in ('non_exportable_key', 'quorum_custody', 'monotonic_authority_external_to_node_namespace'):
    assert hsm[key] is False, key
for key, field in hsm.items():
    if key not in {'non_exportable_key', 'quorum_custody', 'monotonic_authority_external_to_node_namespace'}:
        assert field is None, key

faults = value['physical_faults']
for key in (
    'power_loss_executed', 'host_reboot_executed', 'controller_cache_loss_executed',
    'disk_full_executed', 'torn_write_executed', 'independent_recovery_process'
):
    assert faults[key] is False, key
for key in ('fault_schedule_root', 'raw_trace_root', 'recovery_or_quarantine_decision_root'):
    assert faults[key] is None, key

network = value['network_campaign']
for key in (
    'four_validator_run', 'seven_validator_run', 'partition_3_1', 'partition_2_2',
    'partition_5_2', 'weighted_partition_4_3', 'offline_rejoin',
    'leader_crash_timeout_certificate', 'restart_catchup', 'state_sync',
    'epoch_rotation', 'signer_rotation', 'signer_outage'
):
    assert network[key] is False, key
for key in (
    'conflicting_finality_observed', 'double_sign_observed',
    'state_root_divergence_observed', 'signed_raw_trace_root', 'result_root'
):
    assert network[key] is None, key

benchmark = value['benchmark']
assert benchmark['repetition_roots'] == []
for key, field in benchmark.items():
    if key == 'repetition_roots':
        continue
    if key in {'same_hardware', 'same_workload'}:
        assert field is False, key
    else:
        assert field is None, key

security = value['security_review']
for key in ('consensus_audit_complete', 'cryptography_audit_complete', 'economic_review_complete', 'red_team_complete'):
    assert security[key] is False, key
for key, field in security.items():
    if key not in {'consensus_audit_complete', 'cryptography_audit_complete', 'economic_review_complete', 'red_team_complete'}:
        assert field is None, key

operations = value['operations']
for key in ('incident_drill', 'restore_drill', 'key_rotation_drill', 'state_sync_drill', 'observability_drill'):
    assert operations[key] is False, key
for key, field in operations.items():
    if key not in {'incident_drill', 'restore_drill', 'key_rotation_drill', 'state_sync_drill', 'observability_drill'}:
        assert field is None, key

governance = value['governance']
assert governance['authorized'] is False
for key, field in governance.items():
    if key != 'authorized':
        assert field is None, key

for key, enabled in value['claims'].items():
    assert enabled is False, key
assert value['signatures'] == []
assert len(value['notes']) >= 4
print('G3-G5 empty external-evidence campaign template: fail-closed contract ok')
PY

git diff --check
