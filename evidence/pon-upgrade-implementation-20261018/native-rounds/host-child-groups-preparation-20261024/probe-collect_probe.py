"""Read-only bounded diagnostic export; never a capability or terminal proof."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

LIMIT = 1024 * 1024
OUTPUT_LIMIT = 12 * LIMIT
HEAD = '03b67a955b8fcb6b6c920be584eaad5c0a71d34d'
SOURCE_SHA = 'eed36395892893ff43e07c5012d0876b8743b5251e0f7c15ab3065a2b8822894'
LEAF_PROFILE = 'FRESH_U_LEAF_ONLY_V1'
CHILD_PROFILE = 'FRESH_U_CHILD_GROUPS_ONLY_V1'
NAMES = (
    '00-source-preflight.json',
    '01-preparation-owner-retained.json',
    '01-preparation-rejected-no-scope.json',
    '01-original-owner-before-request.json',
    '02-native-namespace-observation.json',
    '02-original-attempt-unknown-retained.json',
    '03-evidence-window.json',
    '04-ordinary-exit-intent.json',
)
RAW_FIELDS = frozenset(('cgroup.type', 'cgroup.procs', 'cgroup.events', 'cgroup.stat',
    'cgroup.subtree_control', 'cgroup.max.depth', 'cgroup.max.descendants',
    'memory.max', 'memory.current', 'memory.peak', 'memory.swap.max',
    'memory.swap.current', 'cpu.max', 'cpu.max.burst', 'cpu.stat',
    'pids.max', 'pids.current'))


def field_values(raw):
    result = {}
    rows = raw.splitlines()
    if not 0 < len(rows) <= 64:
        raise ValueError('bounded raw fields required')
    for row in rows:
        parts = row.split()
        if (len(parts) != 2 or parts[0] in result or
            re.fullmatch(r'[a-z_]+|core_sched\.force_idle_usec', parts[0]) is None or
            re.fullmatch(r'0|[1-9][0-9]{0,19}', parts[1]) is None or int(parts[1]) >= 2**64):
            raise ValueError('raw fields malformed')
        result[parts[0]] = int(parts[1])
    return result


def leaf_raw_consistent(role, raw, pid):
    # Diagnostic consistency with the pinned fresh profile, never admission.
    if raw['cgroup.type'] != 'domain\n':
        return False
    expected_procs = str(pid)+'\n' if role == 'observer' else ''
    if raw['cgroup.procs'] != expected_procs:
        return False
    tree = field_values(raw['cgroup.stat'])
    if (tree.get('nr_descendants') != {'scope': 3, 'host': 2}.get(role, 0) or
        tree.get('nr_dying_descendants') != 0 or
        any(value != 0 for key, value in tree.items() if key.startswith('nr_dying_'))):
        return False
    controllers = raw['cgroup.subtree_control'].split()
    expected = frozenset() if role == 'observer' else frozenset(('cpu', 'memory', 'pids'))
    if len(controllers) != len(expected) or frozenset(controllers) != expected:
        return False
    if role == 'operation':
        # Preserve the original seven pristine predicates, without subtracting a baseline.
        if (any(raw[key] != '0\n' for key in
                ('pids.current', 'memory.current', 'memory.swap.current', 'memory.peak')) or
            field_values(raw['cgroup.events']).get('populated') != 0 or
            field_values(raw['cpu.stat']).get('usage_usec') != 0):
            return False
    return True


def namespace_disposition(parsed, files, directory_error=None):
    """Conservative namespace evidence only; never classify the whole probe PASS."""
    unknown = []
    incomplete = []
    for name in ('01-preparation-owner-retained.json',
                 '01-preparation-rejected-no-scope.json',
                 '02-original-attempt-unknown-retained.json'):
        if name in files and files[name].get('status') != 'NOT_PRESENT':
            unknown.append('FAILURE_OR_UNKNOWN_RECORD_PRESENT:'+name)
    for name, value in parsed.items():
        if value.get('status') == 'UNKNOWN_RETAINED' or 'UNKNOWN' in str(value.get('outcome', '')):
            unknown.append('UNKNOWN_DOMINATES:'+name)
        if 'window_record_error' in value:
            unknown.append('EVIDENCE_IO_FAILURE_RECORDED:'+name)
        if any(value.get(flag) is True for flag in
               ('whole_u_terminal', 'resource_return_proven', 'money_return',
                'probe_completed_successfully', 'c_or_a_born', 'funded_reservation',
                'model_installed', 'activation', 'qualified', 'final_use_authority')):
            unknown.append('CONFLICTING_UNPROVEN_CLAIM:'+name)
    required = ('00-source-preflight.json', '01-original-owner-before-request.json',
                '02-native-namespace-observation.json', '03-evidence-window.json',
                '04-ordinary-exit-intent.json')
    if directory_error:
        incomplete.append('DIRECTORY_UNAVAILABLE')
    for name in required:
        if name not in parsed:
            incomplete.append('MISSING_OR_INCOMPLETE:'+name)
    if not incomplete:
        before, original, observed, window, ending = (parsed[name] for name in required)
        pid = before.get('pid')
        unit = original.get('unit')
        if (any(value.get('source') != HEAD or value.get('pid') != pid or
                value.get('preparation_profile') != LEAF_PROFILE
                for value in (before, original, observed, window, ending)) or
            type(pid) is not int or not 0 < pid < 2**31 or
            before.get('source_subset_sha256') != SOURCE_SHA or
            before.get('factory_called') is not False or before.get('admit_called') is not False or
            type(unit) is not str or re.fullmatch(r'trnm-host-[0-9a-f]{32}\.scope', unit) is None or
            observed.get('unit') != unit or type(original.get('starttime')) is not int or
            original['starttime'] <= 0):
            unknown.append('CONFLICTING_SOURCE_OR_ORIGINAL_IDENTITY')
        if (observed.get('status') != 'FRESH_LEAF_CONSUMED_ONLY' or
            observed.get('record_role') != 'PROVISIONAL_FRESH_LEAF_CONSUMED_OBSERVATION' or
            window.get('outcome') != 'FRESH_LEAF_CONSUMED_ONLY' or
            ending.get('outcome') != 'FRESH_LEAF_CONSUMED_ONLY' or
            ending.get('status') != 'FRESH_LEAF_EXPERIMENT_ENDING_NO_TERMINAL_FACT' or
            original.get('fresh_leaf_phase') != 'PREPARED' or
            observed.get('phase_before_raw') != 'FRESH_U_LEAF' or
            any(value.get('fresh_leaf_phase') != 'LEAF_PROOF_CONSUMED'
                for value in (observed, window, ending))):
            unknown.append('CONFLICTING_STAGE_DISPOSITION')
        if any(value.get('actual_exit_status') != 'UNKNOWN' or
               value.get('probe_completed_successfully') is not False
               for value in (observed, window, ending)):
            unknown.append('CONFLICTING_EXIT_OR_PROBE_COMPLETION_CLAIM')
        groups = observed.get('groups')
        expected_groups = {'scope', 'host', 'observer', 'operation'}
        if type(groups) is not dict:
            incomplete.append('INCOMPLETE_NAMESPACE_GROUPS')
        elif set(groups) != expected_groups:
            (unknown if set(groups)-expected_groups else incomplete).append('CONFLICTING_FRESH_LEAF_GROUPS')
        else:
            for role, group in groups.items():
                if type(group) is not dict:
                    incomplete.append('INCOMPLETE_GROUP:'+role)
                    continue
                identity, raw = group.get('held_identity'), group.get('raw')
                if (type(group.get('name')) is not str or type(identity) is not list or
                    len(identity) != 3 or any(type(item) is not int for item in identity) or
                    type(raw) is not dict or set(raw) != RAW_FIELDS or
                    any(type(item) is not str or len(item) > 65536 for item in raw.values())):
                    incomplete.append('INCOMPLETE_GROUP_FIELDS:'+role)
                    continue
                try:
                    if not leaf_raw_consistent(role, raw, pid):
                        unknown.append('CONFLICTING_FRESH_LEAF_RAW:'+role)
                except (KeyError, TypeError, ValueError):
                    incomplete.append('INCOMPLETE_FRESH_LEAF_RAW:'+role)
            operation = original.get('operation')
            if (type(operation) is not str or re.fullmatch(r'operation-[0-9a-f]{32}', operation) is None or
                any(type(groups[role]) is not dict for role in expected_groups) or
                any(groups[role].get('name') != name for role, name in
                    (('host', 'host'), ('observer', 'observer'), ('operation', operation)))):
                unknown.append('CONFLICTING_FRESH_LEAF_NAMES')
        invocation = observed.get('invocation')
        if (type(invocation) is not list or len(invocation) != 16 or
            any(type(item) is not int or not 0 <= item <= 255 for item in invocation) or not any(invocation)):
            incomplete.append('INCOMPLETE_INVOCATION')
    disposition = 'UNKNOWN' if unknown else 'INCOMPLETE' if incomplete else 'FRESH_LEAF_OBSERVED_ONLY'
    return {'namespace_observation': disposition, 'reasons': (unknown+incomplete)[:32],
            'actual_exit_status': 'UNKNOWN', 'probe_completion': 'NOT_PROVEN',
            'evidence_durability': 'NOT_PROVEN', 'whole_u_terminal': False,
            'resource_return_proven': False, 'money_return': False}


def bounded_read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid():
            raise ValueError('owned regular diagnostic file required')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit+1)
        after = os.fstat(fd)
        signature = lambda value: (value.st_dev, value.st_ino, value.st_mode,
            value.st_uid, value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if len(data) > limit or signature(before) != signature(after):
            raise ValueError('diagnostic file oversized or changing')
        return data
    finally:
        os.close(fd)


def child_raw_consistent(role, raw, pid):
    budgets = {'scope': (17*1024**3, 500000, 272), 'host': (17*1024**3, 500000, 272),
        'observer': (1024**3, 100000, 16), 'operation': (16*1024**3, 400000, 256),
        'controller': (128*1024**2, 100000, 16), 'aggregate': (8*1024**3, 300000, 240)}
    memory, cpu, pids = budgets[role]
    expected = {'cgroup.type': 'domain\n',
        'cgroup.procs': str(pid)+'\n' if role == 'observer' else '',
        'memory.max': str(memory)+'\n', 'memory.swap.max': '0\n',
        'cpu.max': str(cpu)+' 100000\n', 'cpu.max.burst': '0\n', 'pids.max': str(pids)+'\n'}
    if role != 'scope':
        depth, descendants = {'host': (2, 4), 'operation': (1, 2)}.get(role, (0, 0))
        expected.update({'cgroup.max.depth': str(depth)+'\n',
                         'cgroup.max.descendants': str(descendants)+'\n'})
    if any(raw[key] != value for key, value in expected.items()):
        return False
    tree = field_values(raw['cgroup.stat'])
    if (tree.get('nr_descendants') != {'scope': 5, 'host': 4, 'operation': 2}.get(role, 0)
        or tree.get('nr_dying_descendants') != 0
        or any(value != 0 for key, value in tree.items() if key.startswith('nr_dying_'))):
        return False
    active = frozenset(('cpu', 'memory', 'pids')) if role in ('scope', 'host', 'operation') else frozenset()
    controllers = raw['cgroup.subtree_control'].split()
    if len(controllers) != len(active) or frozenset(controllers) != active:
        return False
    events = field_values(raw['memory.events'])
    if not {'low', 'high', 'max', 'oom', 'oom_kill'} <= set(events):
        return False
    if role in ('operation', 'controller', 'aggregate'):
        def counter(key):
            value = raw[key]
            if re.fullmatch(r'(0|[1-9][0-9]{0,19})\n', value) is None or int(value) >= 2**64:
                raise ValueError('bounded raw counter required')
            return int(value)
        if (not 0 <= counter('memory.current') <= counter('memory.peak') <= memory or
            any(raw[key] != '0\n' for key in ('pids.current', 'memory.swap.current')) or
            field_values(raw['cgroup.events']).get('populated') != 0 or
            field_values(raw['cpu.stat']).get('usage_usec') != 0 or any(events.values())):
            return False
        if role != 'operation' and any(raw[key] != '0\n' for key in ('memory.current', 'memory.peak')):
            return False
    return True


def child_namespace_disposition(parsed, files, directory_error=None):
    # Reuse the original leaf/first-failure checks on the pre-C/A read. This
    # diagnostic normalization never alters stored evidence or mints authority.
    normalized = {name: dict(value) for name, value in parsed.items()}
    reasons = []
    for name in ('00-source-preflight.json', '01-original-owner-before-request.json',
                 '02-native-namespace-observation.json', '03-evidence-window.json',
                 '04-ordinary-exit-intent.json'):
        value = normalized.get(name)
        if value is None or value.get('preparation_profile') != CHILD_PROFILE:
            reasons.append('MISSING_OR_CONFLICTING_CHILD_PROFILE:'+name)
            continue
        value['preparation_profile'] = LEAF_PROFILE
        if name in ('03-evidence-window.json', '04-ordinary-exit-intent.json'):
            if value.get('outcome') != 'CHILD_GROUPS_PREPARED_ONLY' or value.get('fresh_leaf_phase') != 'CHILD_GROUPS_PREPARED':
                reasons.append('CONFLICTING_CHILD_ENDING:'+name)
            value.update(outcome='FRESH_LEAF_CONSUMED_ONLY', fresh_leaf_phase='LEAF_PROOF_CONSUMED')
    observed = parsed.get('02-native-namespace-observation.json', {})
    if (observed.get('status') != 'CHILD_GROUPS_PREPARED_ONLY' or
        observed.get('record_role') != 'PROVISIONAL_CHILD_GROUPS_PREPARED_OBSERVATION' or
        observed.get('fresh_leaf_phase') != 'CHILD_GROUPS_PREPARED' or
        observed.get('child_groups_created') is not True or
        any(observed.get(key) is not False for key in
            ('native_process_born', 'ready', 'qualified', 'final_use_authority'))):
        reasons.append('CONFLICTING_CHILD_PREPARATION')
    leaf = observed.get('fresh_leaf_groups')
    if '02-native-namespace-observation.json' in normalized:
        normalized['02-native-namespace-observation.json'].update(
            status='FRESH_LEAF_CONSUMED_ONLY', record_role='PROVISIONAL_FRESH_LEAF_CONSUMED_OBSERVATION',
            fresh_leaf_phase='LEAF_PROOF_CONSUMED', groups=leaf)
    result = namespace_disposition(normalized, files, directory_error)
    if result['namespace_observation'] != 'FRESH_LEAF_OBSERVED_ONLY':
        reasons.extend(result['reasons'])
    groups = observed.get('groups')
    if type(groups) is not dict or set(groups) != {'scope', 'host', 'observer', 'operation', 'controller', 'aggregate'}:
        reasons.append('CONFLICTING_PREPARED_CHILD_GROUPS')
    else:
        for role, group in groups.items():
            try:
                identity, raw = group['held_identity'], group['raw']
                if (type(identity) is not list or len(identity) != 3 or
                    any(type(item) is not int for item in identity) or
                    type(raw) is not dict or set(raw) != RAW_FIELDS | {'memory.events'} or
                    any(type(item) is not str or len(item) > 65536 for item in raw.values()) or
                    not child_raw_consistent(role, raw, observed['pid']) or
                    (role in ('controller', 'aggregate') and group.get('name') != role) or
                    (role in ('scope', 'host', 'observer', 'operation') and
                     (type(leaf) is not dict or group['name'] != leaf[role]['name'] or
                      identity != leaf[role]['held_identity']))):
                    reasons.append('CONFLICTING_PREPARED_CHILD_RAW:'+role)
            except (KeyError, TypeError, ValueError):
                reasons.append('INCOMPLETE_PREPARED_CHILD_RAW:'+role)
    result['namespace_observation'] = 'UNKNOWN' if reasons else 'CHILD_GROUPS_OBSERVED_ONLY'
    result['reasons'] = reasons[:32]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--prepared-children', action='store_true')
    args = parser.parse_args()
    if not args.output.is_absolute():
        parser.error('absolute evidence directory required')
    report = {'schema': 'namespace-probe-readonly-export-v2',
              'utc_epoch_seconds': time.time(), 'diagnostic_only': True,
              'whole_u_terminal': False, 'money_return': False, 'files': {}}
    parsed = {}
    try:
        directory = args.output.stat(follow_symlinks=False)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.geteuid():
            raise ValueError('owned evidence directory required')
        for name in NAMES:
            try:
                raw = bounded_read(args.output/name, LIMIT)
                report['files'][name] = {'bytes': len(raw),
                    'sha256': hashlib.sha256(raw).hexdigest(),
                    'raw_base64': base64.b64encode(raw).decode('ascii')}
                value = json.loads(raw)
                if type(value) is not dict:
                    raise ValueError('diagnostic JSON object required')
                parsed[name] = value
            except FileNotFoundError:
                report['files'][name] = {'status': 'NOT_PRESENT'}
            except Exception as error:
                report['files'].setdefault(name, {}).update({
                    'status': 'UNREADABLE_OR_INCOMPLETE',
                    'error': type(error).__name__+':'+str(error)[:4096]})
        origin = parsed.get('01-original-owner-before-request.json',
                            parsed.get('00-source-preflight.json', {}))
        pid = origin.get('pid')
        if type(pid) is int and 0 < pid < 2**31:
            process = {'pid': pid, 'original_owner_authority': False,
                       'expected_starttime': origin.get('starttime')}
            for name in ('stat', 'cgroup'):
                try:
                    process[name] = bounded_read(Path('/proc')/str(pid)/name, 65536).decode('utf-8')
                except Exception as error:
                    process[name] = {'error': type(error).__name__+':'+str(error)[:4096]}
            report['process_diagnostic'] = process
    except Exception as error:
        report['directory_status'] = type(error).__name__+':'+str(error)[:4096]
    classify = child_namespace_disposition if args.prepared_children else namespace_disposition
    report['disposition'] = classify(parsed, report['files'], report.get('directory_status'))
    raw = (json.dumps(report, sort_keys=True)+'\n').encode()
    if len(raw) > OUTPUT_LIMIT:
        raise ValueError('bounded export required')
    sys.stdout.buffer.write(raw)  # One finite snapshot, no live-tail loop.
    sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
