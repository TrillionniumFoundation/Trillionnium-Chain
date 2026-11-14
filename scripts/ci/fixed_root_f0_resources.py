#!/usr/bin/env python3
"""Strict R11 reader for actual, whole-controller-cgroup boundary observations.

This parser executes no kernel read. Passing synthetic controls is not evidence
that a Host, controller, workload, memory peak, or service ran successfully.
"""
from __future__ import annotations

import re

from fixed_root_f0_ownership import require
from run_fixed_root_phase_host import validate_identity_shape

SCHEMA = 'fixed-host-root-controller-resources-v1'
SAMPLE_SCHEMA = 'fixed-host-root-controller-resource-sample-v1'
SCOPE = ('whole original controller cgroup and all descendants; includes controller, broker, '
         'launcher and external producer processes; excludes separately systemd-owned public phase; '
         'not per-actor RSS')
CPU_SCOPE = ('before phase launcher spawn through actual actor reaping and phase exit; '
             'excludes earlier honest-miner preparation')
PEAK_SCOPE = ('whole original controller service lifetime, including earlier preparation and '
              'previous phases; never a memory delta or per-actor peak')
STAGES = ('before_launch', 'actors_ready', 'after_reap')
MEMORY_CEILING = 17_179_869_184


def u64(value, code='RESOURCE_U64_REQUIRED'):
    require(type(value) is int and 0 <= value < 2**64, code)
    return value


def ok(value, code):
    require(type(value) is dict and set(value) == {'Ok'}, code)
    return value['Ok']


def text_integer(raw):
    require(type(raw) is str and raw.isascii()
            and re.fullmatch('[0-9]+', raw.strip()) is not None,
            'RESOURCE_UNSIGNED_TEXT_REQUIRED')
    return u64(int(raw.strip()))


def parse_counters(reads):
    require(type(reads) is dict and set(reads) == {'cpu_stat', 'memory_current', 'memory_peak'},
            'ALL_THREE_CONTROLLER_COUNTER_READS_REQUIRED')
    cpu, current, peak = (ok(reads[name], 'ACTUAL_CONTROLLER_RAW_READ_REQUIRED:' + name)
                          for name in ('cpu_stat', 'memory_current', 'memory_peak'))
    require(type(cpu) is str and cpu.isascii() and len(cpu) <= 2048
            and type(current) is str and len(current) <= 128
            and type(peak) is str and len(peak) <= 128,
            'BOUNDED_ACTUAL_CONTROLLER_COUNTERS')
    fields = {}
    for line in cpu.splitlines():
        parts = line.split()
        require(len(parts) == 2 and parts[0] not in fields, 'UNIQUE_COMPLETE_CPU_STAT_FIELDS')
        fields[parts[0]] = text_integer(parts[1])
    require('usage_usec' in fields, 'ACTUAL_USAGE_USEC_REQUIRED')
    usage, current, peak = fields['usage_usec'], text_integer(current), text_integer(peak)
    require(usage > 0 and 0 < current <= peak <= MEMORY_CEILING,
            'ACTIVE_CONTROLLER_COUNTER_GEOMETRY')
    return {'cpu_usage_usec': usage, 'memory_current_bytes': current,
            'memory_peak_lifetime_bytes': peak}


def validate_actor(process, controller):
    validate_identity_shape({'process': process, 'cgroup': controller['cgroup']})
    parent = controller['process']
    require(process['parent_pid'] == parent['pid']
            and all(process[key] == parent[key] for key in ('cgroup', 'boot_id', 'executable')),
            'RESOURCE_ACTOR_CONTROLLER_BINDING')


def check_sample(sample, controller, stage, expected):
    require(type(sample) is dict and sample.get('schema') == SAMPLE_SCHEMA
            and sample.get('scope') == SCOPE and sample.get('stage') == stage
            and sample.get('complete') is True
            and sample.get('validation') == {'Ok': None},
            'KNOWN_ACTUAL_CONTROLLER_SAMPLE_REQUIRED')
    require(sample['controller_identity'] == controller,
            'RESOURCE_EXPECTED_CONTROLLER_CHANGED')
    for field in ('controller_before', 'controller_after'):
        actual = ok(sample[field], 'ACTUAL_CONTROLLER_IDENTITY_REQUIRED')
        validate_identity_shape(actual)
        require(actual == controller, 'RESOURCE_CONTROLLER_IDENTITY_CHANGED')
    count = u64(sample['expected_live_actors'])
    require(count == len(expected), 'COMPLETE_CONTROLLER_RESOURCE_ACTORS')
    begin, end = u64(sample['started_monotonic_ns']), u64(sample['ended_monotonic_ns'])
    require(0 < begin <= end, 'ORDERED_CONTROLLER_RESOURCE_CLOCKS')
    for field in ('actors_before', 'actors_after'):
        rows = sample[field]
        require(type(rows) is list and len(rows) == count, 'ALL_RESOURCE_ACTORS_REQUIRED')
        seen = set()
        for ordinal, (row, spawned) in enumerate(zip(rows, expected)):
            require(type(row) is dict and set(row) == {'ordinal', 'pid', 'identity'},
                    'EXACT_RESOURCE_ACTOR_OBSERVATION')
            pid = u64(row['pid'])
            require(pid > 1 and pid not in seen and u64(row['ordinal']) == ordinal,
                    'DISTINCT_RESOURCE_ACTOR_PIDS_REQUIRED')
            process = ok(row['identity'], 'ACTUAL_RESOURCE_ACTOR_IDENTITY_REQUIRED')
            validate_actor(process, controller)
            require(pid == process['pid'] == spawned['pid'] and process == spawned['identity'],
                    'RESOURCE_ACTOR_BIRTH_OR_EXECUTABLE_CHANGED')
            seen.add(pid)
    require(sample['actors_before'] == sample['actors_after'], 'RESOURCE_ACTOR_IDENTITY_CHANGED')
    counters = parse_counters(sample['reads'])
    observed = ok(sample['counters'], 'ACTUAL_PARSED_CONTROLLER_COUNTERS_REQUIRED')
    require(type(observed) is dict and set(observed) == set(counters),
            'EXACT_PARSED_CONTROLLER_COUNTERS_REQUIRED')
    require(all(u64(observed[key]) == value for key, value in counters.items()),
            'RAW_AND_PARSED_CONTROLLER_COUNTERS_MUST_AGREE')
    return {'stage': stage, 'started_monotonic_ns': begin, 'ended_monotonic_ns': end,
            'live_actors': count, **counters}


def check_controller_resources(value, cgroup):
    require(type(value) is dict and value.get('controller_resource_schema') == SCHEMA
            and value.get('controller_resources_complete') is True,
            'COMPLETE_CONTROLLER_RESOURCE_COVERAGE_REQUIRED')
    controller = value['controller_identity_before']
    validate_identity_shape(controller)
    require(controller['process']['cgroup'] == cgroup
            and value['controller_identity_after'] == {'Ok': controller},
            'EXACT_CAMPAIGN_RESOURCE_CONTROLLER_REQUIRED')
    phases = value['phases']
    require(type(phases) is list and len(phases) == 2, 'BOTH_CONTROLLER_RESOURCE_PHASES_REQUIRED')
    summaries, previous = [], None
    for index, (phase, name) in enumerate(zip(phases, ('baseline', 'valid-work-root'))):
        require(type(phase) is dict, 'ACTUAL_CONTROLLER_RESOURCE_PHASE_REQUIRED')
        expected_count = 0 if index == 0 else 24
        resource = phase.get('external_controller_resources')
        require(type(resource) is dict and resource.get('schema') == SCHEMA
                and resource.get('phase') == phase['mode'] == name
                and resource.get('scope') == SCOPE and resource.get('complete') is True
                and resource.get('per_actor_rss_qualified') is False
                and resource.get('old_public_rss_diagnostics_preserved') is True
                and resource.get('cpu_interval_scope') == CPU_SCOPE
                and resource.get('memory_peak_scope') == PEAK_SCOPE,
                'COMPLETE_EXPLICIT_CONTROLLER_GROUP_RESOURCE_REQUIRED')
        require(resource['controller_identity'] == controller
                and u64(resource['expected_phase_actors']) == expected_count,
                'RESOURCE_PHASE_CONTROLLER_OR_COUNT_CHANGED')
        owner = phase['external_controller_observation']
        require(owner['controller_identity'] == controller
                and u64(owner['launched']) == u64(owner['reaped']) == expected_count,
                'ALL_ACTUAL_CHILDREN_MUST_BE_REAPED')
        spawned = resource['actor_manifest']
        require(type(spawned) is list and len(spawned) == expected_count
                and spawned == owner['actual_attack_process_contexts'],
                'EXACT_ORIGINAL_CHILD_MANIFEST_REQUIRED')
        pids = []
        for ordinal, actor in enumerate(spawned):
            pid = u64(actor['pid'])
            require(pid > 1 and pid not in pids and u64(actor['ordinal']) == ordinal
                    and actor['actual_cgroup'] == '0::' + cgroup,
                    'DISTINCT_ACTUAL_CHILD_HANDLES_REQUIRED')
            validate_actor(actor['identity'], controller)
            require(actor['identity']['pid'] == pid, 'ACTUAL_CHILD_PID_BINDING')
            pids.append(pid)
        reaped = resource['reaped_actor_pids']
        require(type(reaped) is list and len(reaped) == expected_count
                and [u64(pid) for pid in reaped] == pids
                and [u64(child['pid']) for child in phase['children']] == pids,
                'EXACT_ORIGINAL_REAPED_CHILDREN_REQUIRED')
        require(phase['controller_resource_ready'] == resource['actors_ready'],
                'PUBLIC_PHASE_RESOURCE_BOUNDARY_MUST_AGREE')
        observed = []
        for stage in STAGES:
            snapshot = check_sample(resource[stage], controller, stage,
                                    spawned if stage == 'actors_ready' else [])
            if previous is not None:
                require(previous['ended_monotonic_ns'] <= snapshot['started_monotonic_ns'],
                        'CAMPAIGN_RESOURCE_CLOCK_REWIND')
                require(previous['cpu_usage_usec'] <= snapshot['cpu_usage_usec']
                        and previous['memory_peak_lifetime_bytes'] <= snapshot['memory_peak_lifetime_bytes'],
                        'CAMPAIGN_CONTROLLER_COUNTER_REWIND')
            previous = snapshot
            observed.append(snapshot)
        delta = observed[-1]['cpu_usage_usec'] - observed[0]['cpu_usage_usec']
        require(delta > 0 and u64(resource['cpu_usage_delta_usec']) == delta
                and u64(ok(resource['validation'], 'VALIDATED_CONTROLLER_INTERVAL_REQUIRED')) == delta,
                'ACTUAL_CONTROLLER_CPU_INTERVAL_REQUIRED')
        summaries.append({'phase': name, 'expected_phase_actors': expected_count,
                          'cpu_usage_delta_usec': delta, 'observations': observed})
    return {'schema': SCHEMA, 'complete': True, 'planned_phases': 2,
            'planned_boundary_samples': 6, 'observed_boundary_samples': 6,
            'per_actor_rss_qualified': False, 'scope': SCOPE, 'phases': summaries}
