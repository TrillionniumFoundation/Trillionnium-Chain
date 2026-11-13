"""Read-only accounting for a controlled grouped-work fanout experiment.

This module grants no demand, funding, admission, FinalUse or chainwork authority.
Material equality is not customer independence or proof of actual consumption.
The concrete source catalogue below identifies existing owners and the missing
composition; it does not replace a call to any of those owners.

The emitted accounting report uses the fresh v1 namespace for fixed-packet
identity binding. Historical worker observations and the original work profile
retain their meanings; no stored v0 report is rewritten.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path

from contract_wire import canonical
from grouped_work_lottery_v0 import request_precommitment
from experiments.grouped_cell_operator_v0 import model_commitment


SCHEMA = 'pon-grouped-fresh-deployment-cost-v1'
CASES = ('valid', 'carrier_replay', 'forged_endpoint', 'truncated_cancel',
         'discarded_response', 'after_local_cap')
LOCAL_CAP = 256
FIXED_PACKET_NONCES = ('1', '2')
FIXED_PACKET_BY_CASE = {'valid': '1', 'carrier_replay': '1', 'discarded_response': '2'}
_EXPECTATIONS_UNSUPPLIED = object()
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


def _counter(value):
    return type(value) is int and 0 <= value < 1 << 64


def _identity(value):
    # These labels are observations, not authenticated identities. Preserve the
    # existing opaque-label fixtures while refusing missing/unhashable aliases.
    return type(value) is str and 0 < len(value) <= 512 and value.strip() == value


def _work_id_map(value):
    return (type(value) is dict and set(value) == set(FIXED_PACKET_NONCES)
            and all(_identity(value[nonce]) for nonce in FIXED_PACKET_NONCES)
            and value['1'] != value['2'])


def produced_work_ids(produced):
    """Bind the original two nonce slots; labels alone do not authenticate work.

    The campaign obtains these IDs from its original native freeze before any
    receiver is started. Offline readback uses the unchanged pinned producer
    table, not a receiver's chosen IDs or an old aggregate count.
    """
    if (type(produced) is not list or len(produced) != len(FIXED_PACKET_NONCES)
            or any(type(row) is not dict or type(row.get('nonce')) is not int
                   or row['nonce'] != int(nonce)
                   for row, nonce in zip(produced, FIXED_PACKET_NONCES))):
        raise ValueError('FIXED_PACKET_PRODUCER_ROSTER')
    identities = {str(row['nonce']): row.get('work_id') for row in produced}
    if not _work_id_map(identities):
        raise ValueError('FIXED_PACKET_PRODUCER_WORK_IDS')
    return identities


def _seconds(value):
    if type(value) not in (int, float):
        return None
    try:
        value = float(value)
    except (OverflowError, ValueError):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def _sum_seconds(values):
    try:
        total = math.fsum(values)
    except OverflowError:
        return None
    return total if math.isfinite(total) else None


def topology_accounting(planned_receivers, workers, *, expected_work_ids=_EXPECTATIONS_UNSUPPLIED):
    """Check all precommitted slots; partial/failed workers stay in the denominator.

    CPU in wait4 includes each reaped receiver and its waited native child on
    Linux. Native-only CPU and per-stage timings are subsets, never extra charges.
    Missing or malformed observations make complete totals null. Named partial
    sums retain usable measurements without asserting coverage of omitted work.
    Caller must independently bind these local observations to retained bytes.
    Each fixed packet has one work identity across carrier replays and receivers.
    The two fixed nonce slots have distinct work identities. Production-table
    expectations, when supplied, bind every response to the original slot; an
    omitted expectation is only an unanchored structural observation. Passing
    an explicit malformed expectation never falls back to unanchored inspection.
    """
    if type(planned_receivers) is not int or planned_receivers not in (1, 2, 4):
        raise ValueError('FANOUT_TOPOLOGY')
    if type(workers) is not list:
        raise ValueError('FANOUT_WORKERS')
    issues, ids, attempts, permits, cell_calls, macs = [], set(), 0, 0, 0, 0
    verified, rejected, cancelled, discarded = 0, 0, 0, 0
    cpu_parts, native_parts, content_ids, work_ids = [], [], set(), set()
    known_wait4 = known_native = known_permits = known_material = 0
    cpu_complete = native_complete = cells_complete = work_complete = True
    slots_complete = records_complete = len(workers) == planned_receivers
    byte_parts = dict(receiver=0, client=0, ack_kernel=0)
    byte_known = dict.fromkeys(byte_parts, 0)
    byte_complete = dict.fromkeys(byte_parts, True)
    expected_attempts = planned_receivers * len(CASES)
    packet_work_ids = {nonce: set() for nonce in FIXED_PACKET_NONCES}
    expected = None
    expectation_supplied = expected_work_ids is not _EXPECTATIONS_UNSUPPLIED
    if expectation_supplied:
        if _work_id_map(expected_work_ids):
            expected = dict(expected_work_ids)
        else:
            issues.append('FIXED_PACKET_EXPECTATIONS_MALFORMED')
            work_complete = False
    if not slots_complete:
        issues.append('RECEIVER_DENOMINATOR')

    def mapping(value, code):
        if type(value) is not dict:
            issues.append(code)
            return {}
        return value

    def record_bytes(kind, value, code, terminal):
        if not _counter(value):
            issues.append(code)
            byte_complete[kind] = False
        else:
            byte_parts[kind] += value
            byte_known[kind] += 1
        if not terminal:
            byte_complete[kind] = False

    for index, observed in enumerate(workers):
        label = f'receiver-{index}'
        if type(observed) is not dict:
            issues.append(label + ':MALFORMED')
            slots_complete = False
            continue
        identity = observed.get('receiver_id')
        if not _identity(identity) or identity in ids:
            issues.append(label + ':DUPLICATE_OR_MISSING_ID')
            slots_complete = False
        else:
            ids.add(identity)
        wait4 = mapping(observed.get('wait4'), label + ':CPU_UNKNOWN')
        wait_times = [_seconds(wait4.get(key)) for key in ('user_seconds', 'system_seconds')]
        cpu_parts.extend(v for v in wait_times if v is not None)
        receiver_cpu = _sum_seconds(wait_times) if None not in wait_times else None
        if receiver_cpu is None:
            issues.append(label + ':CPU_RANGE')
            cpu_complete = False
        else:
            known_wait4 += 1
        if type(wait4.get('exit_code')) is not int or wait4['exit_code'] != 0:
            issues.append(label + ':EXIT')
            cpu_complete = False
        report = observed.get('worker_report')
        if type(report) is not dict:
            issues.append(label + ':REPORT_UNAVAILABLE')
            records_complete = cpu_complete = False
            continue
        if report.get('status') != 'PASS':
            issues.append(label + ':WORKER_NOT_PASS')
        if report.get('source_bytes_stable') is not True or report.get('runner_bytes_stable') is not True:
            issues.append(label + ':SOURCE_OR_RUNNER_CHANGED')
        if (type(report.get('chainwork_awarded')) is not int or report['chainwork_awarded'] != 0
                or report.get('external_demand_authenticated') is not False
                or any(key in report and report[key] is not False
                       for key in ('production_activation', 'independent_operators'))):
            issues.append(label + ':QUALIFICATION_OVERCLAIM')
        material = report.get('material_content_id')
        if _identity(material):
            content_ids.add(material)
            known_material += 1
        else:
            issues.append(label + ':MATERIAL_ID_UNKNOWN')

        # Cost observations survive malformed/missing transport records. These
        # independent fields must not be skipped by an early records refusal.
        ledger = mapping(report.get('final_ledger'), label + ':LEDGER_MALFORMED')
        budget = mapping(ledger.get('verification_budget'), label + ':BUDGET_MALFORMED')
        budget_values = [budget.get(k) for k in ('fixed_limit', 'reserved', 'remaining')]
        if (not all(_counter(v) for v in budget_values)
                or tuple(budget_values) != (LOCAL_CAP, LOCAL_CAP, 0)):
            issues.append(label + ':LOCAL_BUDGET')
        if _counter(budget.get('reserved')):
            permits += budget['reserved']
            known_permits += 1
        if 'spent' in budget and (not _counter(budget['spent'])
                or not _counter(budget.get('reserved')) or budget['spent'] > budget['reserved']):
            issues.append(label + ':LOCAL_BUDGET_SPENT')
        native = mapping(report.get('native_exit'), label + ':NATIVE_EXIT_MALFORMED')
        native_times = [_seconds(native.get(k)) for k in
                        ('native_child_user_seconds', 'native_child_system_seconds')]
        native_parts.extend(v for v in native_times if v is not None)
        child_cpu = _sum_seconds(native_times) if None not in native_times else None
        if child_cpu is None:
            issues.append(label + ':NATIVE_CPU_OR_EXIT_UNKNOWN')
            cpu_complete = native_complete = False
        else:
            known_native += 1
        if type(native.get('exit_code')) is not int or native['exit_code'] != 0:
            issues.append(label + ':NATIVE_CPU_OR_EXIT_UNKNOWN')
            cpu_complete = native_complete = False
        # wait4 values have microsecond resolution. Allow only one microsecond
        # for conversion/subtraction rounding, not a proportional cost subsidy.
        if (receiver_cpu is not None and child_cpu is not None
                and child_cpu - receiver_cpu > 0.000001):
            issues.append(label + ':NATIVE_CPU_EXCEEDS_RECEIVER')
            cpu_complete = native_complete = False

        records = report.get('transport_records')
        if (type(records) is not list or len(records) != len(CASES)
                or any(type(r) is not dict or r.get('case') != case
                       for r, case in zip(records, CASES))):
            issues.append(label + ':ATTEMPT_DENOMINATOR')
            records_complete = False
        if type(records) is not list:
            continue
        for ordinal, row in enumerate(records):
            entry = f'{label}:attempt-{ordinal}'
            if type(row) is not dict:
                issues.append(entry + ':MALFORMED')
                continue
            terminal = row.get('status') == 'observed'
            if not terminal:
                issues.append(entry + ':UNFINISHED_OR_UNKNOWN_ATTEMPT')
                work_complete = cells_complete = False
            else:
                attempts += 1
            if type(row.get('ordinal')) is not int or row['ordinal'] != ordinal:
                issues.append(entry + ':ORDINAL')
                records_complete = False
            case = row.get('case')
            if type(case) is not str or case not in CASES:
                issues.append(entry + ':CASE')
                records_complete = False
            if type(row.get('complete_verifier_called')) is not bool:
                issues.append(entry + ':VERIFIER_CALL_UNKNOWN')
                cells_complete = False
            response_value = row.get('verification')
            if case == 'truncated_cancel' and response_value is None:
                response, stages = {}, {}
            else:
                response = mapping(response_value, entry + ':VERIFICATION_MALFORMED')
                stages = mapping(response.get('stages'), entry + ':STAGES_MALFORMED')
            if (('chainwork_awarded' in response and
                    (type(response['chainwork_awarded']) is not int or response['chainwork_awarded'] != 0))
                    or any(key in response and response[key] is not False
                           for key in ('production_activation', 'external_demand_authenticated'))):
                issues.append(entry + ':QUALIFICATION_OVERCLAIM')
            full_cell = 'independent_full_cell' in stages
            expected_cell = case in ('valid', 'carrier_replay', 'forged_endpoint', 'discarded_response')
            if expected_cell and (not full_cell or row.get('complete_verifier_called') is not True):
                issues.append(entry + ':FULL_CELL_OBSERVATION_MISSING')
                cells_complete = False
            if case in ('valid', 'carrier_replay', 'discarded_response'):
                if response.get('status') != 'verified':
                    issues.append(entry + ':NOT_VERIFIED')
                    work_complete = False
                else:
                    verified += 1
                    work_id = response.get('work_id')
                    if not _identity(work_id):
                        issues.append(entry + ':WORK_ID_UNKNOWN')
                        work_complete = False
                    else:
                        work_ids.add(work_id)
                        nonce = FIXED_PACKET_BY_CASE[case]
                        packet_work_ids[nonce].add(work_id)
                        if expected is not None and work_id != expected[nonce]:
                            issues.append(entry + ':WORK_ID_NOT_FIXED_PACKET')
                            work_complete = False
            elif case == 'forged_endpoint':
                if response.get('status') != 'rejected' or response.get('error') != 'NATIVE_Seal(Endpoint)':
                    issues.append(entry + ':FORGED_ENDPOINT')
                rejected += int(response.get('status') == 'rejected')
            elif case == 'truncated_cancel':
                if (row.get('transport_error') != 'TCP_TRUNCATED_FRAME'
                        or row.get('complete_verifier_called') is not False or response_value is not None):
                    issues.append(entry + ':CANCELLATION')
                    cells_complete = False
                cancelled += int(row.get('transport_error') == 'TCP_TRUNCATED_FRAME')
            elif case == 'after_local_cap':
                if (response.get('status') != 'rejected' or response.get('error') != 'NATIVE_VerificationBudget'
                        or row.get('complete_verifier_called') is not True):
                    issues.append(entry + ':CAP_NOT_ENFORCED')
                if full_cell:
                    issues.append(entry + ':CAP_REJECTED_AFTER_CELL')
                    cells_complete = False
                rejected += int(response.get('status') == 'rejected')
            if full_cell:
                if type(stages['independent_full_cell']) is not dict:
                    issues.append(entry + ':CELL_STAGE_MALFORMED')
                    cells_complete = False
                else:
                    cell_calls += 1
                count = response.get('reference_macs')
                if not _counter(count) or count != 37008:
                    issues.append(entry + ':CELL_MAC_COUNT')
                    cells_complete = False
                if _counter(count):
                    macs += count
            client = mapping(row.get('client'), entry + ':CLIENT_MALFORMED')
            client_status = client.get('status')
            client_terminal = client_status in ('response_observed', 'response_intentionally_discarded', 'failed')
            if case == 'discarded_response':
                if (client_status != 'response_intentionally_discarded'
                        or type(client.get('received_bytes')) is not int or client['received_bytes'] != 0):
                    issues.append(entry + ':DISCARD_CONTROL')
                discarded += int(client_status == 'response_intentionally_discarded')
            elif client_status != 'response_observed':
                issues.append(entry + ':CLIENT_NOT_OBSERVED')
            record_bytes('receiver', row.get('received_frame_bytes'), entry + ':RECEIVER_BYTES_UNKNOWN', terminal)
            record_bytes('ack_kernel', row.get('ack_kernel_accepted_bytes'), entry + ':ACK_BYTES_UNKNOWN', terminal)
            record_bytes('client', client.get('received_bytes'), entry + ':CLIENT_BYTES_UNKNOWN', client_terminal)
            if (_counter(client.get('received_bytes')) and _counter(row.get('ack_kernel_accepted_bytes'))
                    and client['received_bytes'] > row['ack_kernel_accepted_bytes']):
                issues.append(entry + ':CLIENT_BYTES_EXCEED_ACK')
                byte_complete['client'] = byte_complete['ack_kernel'] = False
    for nonce, identities in packet_work_ids.items():
        if len(identities) > 1:
            issues.append('FIXED_PACKET_WORK_ID_REBINDING:' + nonce)
            work_complete = False
    if packet_work_ids['1'] & packet_work_ids['2']:
        issues.append('DISTINCT_FIXED_PACKETS_ALIAS_WORK_ID')
        work_complete = False
    if known_material != planned_receivers or len(content_ids) != 1:
        issues.append('MATERIAL_CONTENT_CHANGED_OR_UNKNOWN')
    cpu, native_cpu = _sum_seconds(cpu_parts), _sum_seconds(native_parts)
    if cpu is None:
        issues.append('CPU_SUM_RANGE')
    if native_cpu is None:
        issues.append('NATIVE_CPU_SUM_RANGE')
    coverage = slots_complete and records_complete
    byte_totals = {k: byte_parts[k] if coverage and byte_complete[k]
                   and byte_known[k] == expected_attempts else None for k in byte_parts}
    return dict(schema=SCHEMA, status='PASS' if not issues else 'FAIL', issues=issues,
                planned_receivers=planned_receivers, observed_receiver_slots=len(workers),
                planned_transport_attempts=expected_attempts,
                completed_transport_attempts=attempts, verified_receptions=verified,
                rejected_verifications=rejected, truncated_sender_cancellations=cancelled,
                intentionally_discarded_client_responses=discarded,
                distinct_verified_work_ids=len(work_ids) if coverage and work_complete else None,
                observed_distinct_verified_work_ids_partial=len(work_ids),
                observed_work_ids_by_fixed_packet={nonce: sorted(identities)
                    for nonce, identities in packet_work_ids.items()},
                producer_work_id_expectations_supplied=expectation_supplied,
                producer_work_ids_bound=expected is not None and coverage and work_complete,
                distinct_material_content_ids=len(content_ids) if slots_complete
                    and known_material == planned_receivers else None,
                observed_distinct_material_content_ids_partial=len(content_ids),
                observed_local_reservations=permits if slots_complete and known_permits == planned_receivers else None,
                observed_local_reservations_partial=permits,
                configured_sum_of_local_caps=LOCAL_CAP * planned_receivers,
                independent_full_cell_calls=cell_calls if coverage and cells_complete else None,
                independent_full_cell_macs=macs if coverage and cells_complete else None,
                observed_independent_full_cell_calls_partial=cell_calls,
                observed_independent_full_cell_macs_partial=macs,
                receiver_wait4_cpu_seconds=cpu if slots_complete and known_wait4 == planned_receivers
                    and cpu_complete else None,
                observed_wait4_cpu_seconds_partial=cpu, known_wait4_receivers=known_wait4,
                native_cpu_seconds_subset=native_cpu if slots_complete and known_native == planned_receivers
                    and native_complete else None,
                observed_native_cpu_seconds_partial=native_cpu, known_native_cpu_receivers=known_native,
                native_cpu_is_subset_not_additional=True,
                tcp_application_received_by_receivers_bytes=byte_totals['receiver'],
                tcp_application_received_by_clients_bytes=byte_totals['client'],
                tcp_ack_kernel_accepted_bytes_not_proof_of_peer_read=byte_totals['ack_kernel'],
                observed_transport_bytes_partial=byte_parts, transport_byte_observation_counts=byte_known,
                global_verification_cap_enforced=False,
                actual_consumer_uses_observed=0, external_demand_authenticated=False,
                independent_operators=False, production_activation=False, chainwork_awarded=0)
