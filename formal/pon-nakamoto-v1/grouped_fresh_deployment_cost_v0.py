"""Read-only accounting for a controlled grouped-work fanout experiment.

This module grants no demand, funding, admission, FinalUse or chainwork authority.
Material equality is not customer independence or proof of actual consumption.
The concrete source catalogue below identifies existing owners and the missing
composition; it does not replace a call to any of those owners.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from contract_wire import canonical
from grouped_work_lottery_v0 import request_precommitment
from experiments.grouped_cell_operator_v0 import model_commitment


SCHEMA = 'pon-grouped-fresh-deployment-cost-v0'
CASES = ('valid', 'carrier_replay', 'forged_endpoint', 'truncated_cancel',
         'discarded_response', 'after_local_cap')
LOCAL_CAP = 256
DEMAND_COMPONENTS = (
    {
        'owner': 'M06 native task lifecycle',
        'path': 'trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2/tasks_v5.rs',
        'mechanism': 'Native requester/source authorization, lease currentness, immutable model/input/task/meter bindings and recorded output.',
        'boundary': 'Existing PQ5/W1 matrix relation; not grouped-fresh-profile eligibility or evidence of independent operators.',
    },
    {
        'owner': 'Native Node funding snapshot',
        'path': 'trillionnium/crates/trnm-pon-node/src/store/funding.rs',
        'mechanism': 'Reads active anchor and the requested native monetary row from an owner snapshot.',
        'boundary': 'A supplied JSON observation or caller-implemented owner trait is not an authenticated chain.',
    },
    {
        'owner': 'Native Node payment observation',
        'path': 'trillionnium/crates/trnm-pon-node/src/store/funding/payment.rs',
        'mechanism': 'Reexecutes the exact ordinary native transition and checks source, subject, beneficiary and gross/net debit/credit.',
        'boundary': 'Historical/current-chain payment is distinct from irreversible finality, real customer need and fresh grouped work.',
    },
    {
        'owner': 'M12 local resource/effect journal',
        'path': 'trillionnium/crates/trnm-service-settlement/src/native_budget.rs',
        'mechanism': 'Rechecks native funding; durably binds operation/effect and retains unknown costs and prior payment observations.',
        'boundary': 'Local reserve/begin_effect alone is not request-specific serving consent; full database rollback and external effects need other owners.',
    },
    {
        'owner': 'Offline consumer context supplement',
        'path': 'formal/pon-nakamoto-v1/model_consumer_context.py',
        'mechanism': 'Checks complete V2 relations plus separately pinned signatures and declared causal use order.',
        'boundary': 'It explicitly does not establish installation, independently controlled operators, current FinalUse or new consumer benefit.',
    },
    {
        'owner': 'Grouped fresh research admission',
        'path': 'trillionnium/crates/trnm-pon-node/src/grouped_fresh_admission_v0.rs',
        'mechanism': 'Native parent/target and signed canonical capsule; one-policy local verification journal.',
        'boundary': 'Public controlled fixture keys and historical corpus; no authentic external demand or monetary settlement bridge.',
    },
)


def material_identity(init, requests, product):
    """Content identity excludes lottery context, not an economic demand ID.

    Two independent customers can legitimately request identical content. Thus
    this identifier can only count reused material within a declared experiment;
    it must never be a general customer deduplication or payment policy.
    """
    value = {'model_commitment': model_commitment(init),
             'request_precommitment': request_precommitment(init, requests),
             'product_sha256': hashlib.sha256(canonical(product)).hexdigest()}
    raw = b'TRNM-GROUPED-MATERIAL-ACCOUNTING-V0\0' + canonical(value)
    return dict(value, material_content_id=hashlib.sha256(raw).hexdigest(),
                economic_demand_authenticated=False, actual_consumption_proved=False)


def demand_bridge_audit(root):
    """Inventory actual source bytes without upgrading them to runtime evidence."""
    root = Path(root)
    components = []
    for component in DEMAND_COMPONENTS:
        item = dict(component)
        try:
            raw = (root / item['path']).read_bytes()
        except OSError as failure:
            item.update(source_status='unavailable', source_sha256=None,
                        source_bytes=None, error_type=type(failure).__name__)
        else:
            item.update(source_status='present', source_sha256=hashlib.sha256(raw).hexdigest(),
                        source_bytes=len(raw))
        item['owner_operation_executed_by_this_audit'] = False
        components.append(item)
    return {
        'schema': 'pon-grouped-fresh-demand-bridge-audit-v0',
        'scope': 'source-owner inventory and explicit missing composition, no authority grant',
        'components': components,
        'missing_composition': [
            'An actual independently authorized task and its original source/consumer are not established by this campaign.',
            'No actual Node-funded service subject is joined to this grouped profile, request and delivered output.',
            'No ordinary consumer owner grants current FinalUse or proves one actual externally used result.',
            'No ordinary native payment for this grouped output is observed or settled.',
            'A demand/consumer receipt is not reusable security-ticket credit or evidence of a physical work floor.',
        ],
        'external_demand_authenticated': False,
        'independent_operators': False,
        'actual_consumer_uses_observed': 0,
        'native_payment_for_grouped_output_observed': False,
        'production_activation': False,
        'chainwork_awarded': 0,
    }


def topology_accounting(planned_receivers, workers):
    """Check all precommitted slots; partial/failed workers stay in the denominator.

    CPU in wait4 includes each reaped receiver and its waited native child on
    Linux. Native-only CPU and per-stage timings are subsets, never extra charges.
    Caller must independently bind these local observations to retained bytes.
    """
    if type(planned_receivers) is not int or planned_receivers not in (1, 2, 4):
        raise ValueError('FANOUT_TOPOLOGY')
    if type(workers) is not list:
        raise ValueError('FANOUT_WORKERS')
    issues, ids, attempts, permits, cell_calls, macs = [], set(), 0, 0, 0, 0
    verified, rejected, cancelled, discarded = 0, 0, 0, 0
    cpu, native_cpu, known_wait4, cpu_complete = 0.0, 0.0, 0, True
    tx, rx, ack_kernel, content_ids, work_ids = 0, 0, 0, set(), set()
    if len(workers) != planned_receivers:
        issues.append('RECEIVER_DENOMINATOR')
    for index, observed in enumerate(workers):
        label = f'receiver-{index}'
        if type(observed) is not dict:
            issues.append(label + ':MALFORMED')
            continue
        identity = observed.get('receiver_id')
        if type(identity) is not str or not identity or identity in ids:
            issues.append(label + ':DUPLICATE_OR_MISSING_ID')
        ids.add(identity)
        wait4 = observed.get('wait4')
        if isinstance(wait4, dict):
            user, system = wait4.get('user_seconds'), wait4.get('system_seconds')
            if all(type(v) in (int, float) and 0 <= v < float('inf') for v in (user, system)):
                cpu += user + system
                known_wait4 += 1
            else:
                issues.append(label + ':CPU_RANGE')
            if wait4.get('exit_code') != 0:
                issues.append(label + ':EXIT')
                cpu_complete = False
        else:
            issues.append(label + ':CPU_UNKNOWN')
            cpu_complete = False
        report = observed.get('worker_report')
        if not isinstance(report, dict):
            issues.append(label + ':REPORT_UNAVAILABLE')
            continue
        if report.get('status') != 'PASS':
            issues.append(label + ':WORKER_NOT_PASS')
        if not report.get('source_bytes_stable') or not report.get('runner_bytes_stable'):
            issues.append(label + ':SOURCE_OR_RUNNER_CHANGED')
        if report.get('chainwork_awarded') != 0 or report.get('external_demand_authenticated') is not False:
            issues.append(label + ':QUALIFICATION_OVERCLAIM')
        content_ids.add(report.get('material_content_id'))
        records = report.get('transport_records', [])
        if type(records) is not list or [r.get('case') for r in records] != list(CASES):
            issues.append(label + ':ATTEMPT_DENOMINATOR')
            continue
        for row in records:
            if row.get('status') in ('not_started', 'started'):
                issues.append(label + ':UNFINISHED_ATTEMPT')
            else:
                attempts += 1
            response = row.get('verification') or {}
            case = row['case']
            if case in ('valid', 'carrier_replay', 'discarded_response'):
                if response.get('status') != 'verified':
                    issues.append(label + ':' + case + ':NOT_VERIFIED')
                else:
                    verified += 1
                    work_ids.add(response.get('work_id'))
            elif case == 'forged_endpoint':
                if response.get('status') != 'rejected' or response.get('error') != 'NATIVE_Seal(Endpoint)':
                    issues.append(label + ':FORGED_ENDPOINT')
                rejected += int(response.get('status') == 'rejected')
            elif case == 'truncated_cancel':
                if row.get('transport_error') != 'TCP_TRUNCATED_FRAME' or row.get('complete_verifier_called'):
                    issues.append(label + ':CANCELLATION')
                cancelled += int(row.get('transport_error') == 'TCP_TRUNCATED_FRAME')
            elif case == 'after_local_cap':
                if response.get('status') != 'rejected' or response.get('error') != 'NATIVE_VerificationBudget':
                    issues.append(label + ':CAP_NOT_ENFORCED')
                if 'independent_full_cell' in response.get('stages', {}):
                    issues.append(label + ':CAP_REJECTED_AFTER_CELL')
                rejected += int(response.get('status') == 'rejected')
            if 'independent_full_cell' in response.get('stages', {}):
                cell_calls += 1
                if response.get('reference_macs') != 37008:
                    issues.append(label + ':CELL_MAC_COUNT')
                macs += response['reference_macs']
            if case == 'discarded_response':
                client = row.get('client') or {}
                if client.get('status') != 'response_intentionally_discarded' or client.get('received_bytes') != 0:
                    issues.append(label + ':DISCARD_CONTROL')
                discarded += int(client.get('status') == 'response_intentionally_discarded')
            tx += row.get('received_frame_bytes', 0)
            ack_kernel += row.get('ack_kernel_accepted_bytes', 0)
            rx += (row.get('client') or {}).get('received_bytes', 0)
        budget = (report.get('final_ledger') or {}).get('verification_budget', {})
        if (budget.get('fixed_limit'), budget.get('reserved'), budget.get('remaining')) != (LOCAL_CAP, LOCAL_CAP, 0):
            issues.append(label + ':LOCAL_BUDGET')
        permits += budget.get('reserved', 0)
        native = report.get('native_exit') or {}
        native_times = [native.get('native_child_user_seconds'), native.get('native_child_system_seconds')]
        if native.get('exit_code') != 0 or not all(
                type(v) in (int, float) and 0 <= v < float('inf') for v in native_times):
            issues.append(label + ':NATIVE_CPU_OR_EXIT_UNKNOWN')
            cpu_complete = False
        else:
            native_cpu += sum(native_times)
    if None in content_ids or len(content_ids) != 1:
        issues.append('MATERIAL_CONTENT_CHANGED_OR_UNKNOWN')
    return dict(schema=SCHEMA, status='PASS' if not issues else 'FAIL', issues=issues,
                planned_receivers=planned_receivers, observed_receiver_slots=len(workers),
                planned_transport_attempts=planned_receivers * len(CASES),
                completed_transport_attempts=attempts, verified_receptions=verified,
                rejected_verifications=rejected, truncated_sender_cancellations=cancelled,
                intentionally_discarded_client_responses=discarded,
                distinct_verified_work_ids=len(work_ids - {None}),
                distinct_material_content_ids=len(content_ids - {None}),
                observed_local_reservations=permits,
                configured_sum_of_local_caps=LOCAL_CAP * planned_receivers,
                independent_full_cell_calls=cell_calls, independent_full_cell_macs=macs,
                receiver_wait4_cpu_seconds=cpu if known_wait4 == planned_receivers and cpu_complete else None,
                observed_wait4_cpu_seconds_partial=cpu,
                native_cpu_seconds_subset=native_cpu,
                native_cpu_is_subset_not_additional=True,
                tcp_application_received_by_receivers_bytes=tx,
                tcp_application_received_by_clients_bytes=rx,
                tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read=ack_kernel,
                global_verification_cap_enforced=False,
                actual_consumer_uses_observed=0, external_demand_authenticated=False,
                independent_operators=False, production_activation=False, chainwork_awarded=0)
