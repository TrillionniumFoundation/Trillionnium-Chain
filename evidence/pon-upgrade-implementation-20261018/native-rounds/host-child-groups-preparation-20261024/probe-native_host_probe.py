"""Single fresh U-leaf preparation; default is source/environment preflight only.

No execution authorization is encoded here. Root must explicitly authorize the
admit-once invocation after reviewing this driver. The same original owner stays
alive through a finite evidence window on either native result or uncertainty.
Its ordinary exit deliberately loses the owner, without resource-return proof.
JSON is diagnostic, never terminal/use authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

HEAD = '03b67a955b8fcb6b6c920be584eaad5c0a71d34d'
MANIFEST_SHA256 = 'eed36395892893ff43e07c5012d0876b8743b5251e0f7c15ab3065a2b8822894'
OWNER = None
FIRST_FAILURE = None
LIMIT = 1024 * 1024
EXPORT_WINDOW_SECONDS = 60
LEAF_PROFILE = 'FRESH_U_LEAF_ONLY_V1'
CHILD_PROFILE = 'FRESH_U_CHILD_GROUPS_ONLY_V1'


def stable_file_signature(value):
    # A successful read can update atime; that is not source replacement.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def source_preflight(root, manifest):
    with manifest.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != MANIFEST_SHA256:
        raise ValueError('probe source manifest changed')
    data = json.loads(raw)
    if data['sourceCommit'] != HEAD or len(data['files']) != 8:
        raise ValueError('probe source identity')
    for row in data['files']:
        path = Path(row['path'])
        if path.is_absolute() or '..' in path.parts or path.parts[0] != 'scripts':
            raise ValueError('probe source path')
        target = root/path
        before = target.stat(follow_symlinks=False)
        with target.open('rb') as stream:
            content = stream.read(row['bytes']+1)
        after = target.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or stable_file_signature(before) != stable_file_signature(after) or len(content) != row['bytes'] or hashlib.sha256(content).hexdigest() != row['sha256']:
            raise ValueError('probe source bytes')
    if sys.implementation.name != 'cpython' or sys.version_info[:3] != (3, 12, 3) or os.uname().sysname != 'Linux':
        raise ValueError('probe supported Python/Linux required')
    return {'source': HEAD, 'source_subset_sha256': MANIFEST_SHA256,
            'pid': os.getpid(), 'python': sys.version.split()[0],
            'membership': Path('/proc/self/cgroup').read_text(),
            'preflight_only': True, 'factory_called': False, 'admit_called': False,
            'preparation_profile': LEAF_PROFILE}


def record(output, name, data):
    raw = (json.dumps(data, sort_keys=True, indent=2)+'\n').encode()
    if len(raw) > LIMIT:
        raise ValueError('bounded probe evidence required')
    fd = os.open(output/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def error_text(error):
    try:
        return str(error)[:4096]
    except BaseException:
        return '<exception message unavailable>'


def stored_integer(value):
    if type(value) is not int or value.bit_length() > 64:
        raise ValueError('stored integer type/range')
    return value


def stored_string(value, limit=8192):
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError('stored string type')
    if len(value) > limit:
        return {'prefix': value[:limit], 'truncated': True}
    return value


def stored_signature(value):
    if value is None:
        return None
    if type(value) not in (tuple, list) or len(value) != 3:
        raise ValueError('stored signature shape')
    return [stored_integer(item) for item in value]


def stored_flag(value):
    if type(value) is not bool:
        raise ValueError('stored flag type')
    return value


def stored_invocation(value):
    if value is None:
        return None
    if type(value) not in (tuple, list) or len(value) != 16:
        raise ValueError('stored invocation shape')
    return [stored_integer(item) for item in value]


def stored_slot(value):
    if len(value) != 4:
        raise ValueError('stored slot shape')
    return [stored_integer(value[part]) for part in range(4)]


def captured(function):
    try:
        return {'value': function()}
    except BaseException as error:
        return {'unavailable': type(error).__name__, 'error': error_text(error)[:256]}


def stored_leaf_phase(cap):
    # Stored diagnostic only. Never inspect, stringify or export _leaf_fact.
    try:
        values = object.__getattribute__(cap, '__dict__')
        return stored_string(values.get('_leaf_phase'), 64)
    except BaseException:
        return None


def stored_owner_diagnostics(cap):
    """Bounded known fields only: no verify, fstat, manager or cgroup reads."""
    result = {'same_global_owner': cap is OWNER, 'stored_values_only': True,
              'new_kernel_or_manager_reads': False, 'capability_authority': False,
              'fields': {}, 'groups': [], 'owned_fd_slots': []}
    try:
        values = object.__getattribute__(cap, '__dict__')
        if type(values) is not dict:
            raise ValueError('owner storage unavailable')
    except BaseException as error:
        result['owner_storage_error'] = type(error).__name__+':'+error_text(error)[:256]
        return result
    converters = {'_pid': stored_integer, '_start': stored_integer,
        '_unit': lambda value: stored_string(value, 128),
        '_operation_name': lambda value: stored_string(value, 128),
        '_original_membership': stored_string,
        '_job': lambda value: stored_string(value, 512),
        '_unit_path': lambda value: stored_string(value, 512),
        '_invocation': stored_invocation, '_started': stored_flag,
        '_ready': stored_flag, '_failed': stored_flag,
        '_leaf_phase': lambda value: stored_string(value, 64)}
    for name, convert in converters.items():
        result['fields'][name] = captured(lambda name=name, convert=convert: convert(values[name]))
    groups = values.get('_groups')
    if type(groups) is dict:
        result['group_count_known'] = len(groups)
        result['groups_truncated'] = len(groups) > 6
        for index, (role, entry) in enumerate(groups.items()):
            if index == 6:
                break
            row = {'role': captured(lambda: stored_string(role, 64))}
            if type(entry) in (tuple, list) and len(entry) == 4:
                row['parent_fd'] = captured(lambda: None if entry[0] is None else stored_integer(entry[0]))
                row['name'] = captured(lambda: stored_string(entry[1]))
                row['fd'] = captured(lambda: stored_integer(entry[2]))
                row['stored_identity'] = captured(lambda: stored_signature(entry[3]))
            else:
                row['entry_error'] = 'stored group shape'
            result['groups'].append(row)
    else:
        result['groups_error'] = 'stored groups absent or invalid'
    entries = values.get('_fds')
    if type(entries) is list:
        result['owned_fd_count_known'] = len(entries)
        result['owned_fd_slots_truncated'] = len(entries) > 64
        for index, entry in enumerate(entries[:64]):
            row = {'index': index}
            if type(entry) in (tuple, list) and len(entry) == 2:
                row['slot'] = captured(lambda: stored_slot(entry[0]))
                row['stored_signature'] = captured(lambda: stored_signature(entry[1]))
            else:
                row['entry_error'] = 'stored owned-fd entry shape'
            result['owned_fd_slots'].append(row)
    else:
        result['owned_fd_slots_error'] = 'stored slots absent or invalid'
    return result


def unknown_payload(cap, error, phase):
    global FIRST_FAILURE
    current = {'driver_phase': phase, 'error_type': type(error).__name__,
               'message': error_text(error)}
    if FIRST_FAILURE is None:
        FIRST_FAILURE = current
    return {'status': 'UNKNOWN_RETAINED', 'source': HEAD, 'pid': os.getpid(),
        'preparation_profile': LEAF_PROFILE, 'fresh_leaf_phase': stored_leaf_phase(cap),
        'record_role': 'FAILURE_DOMINATES_ANY_PROVISIONAL_OBSERVATION',
        'first_failure': FIRST_FAILURE, 'current_failure': current,
        'original_owner_diagnostic': stored_owner_diagnostics(cap),
        'no_retry': True, 'actual_exit_status': 'UNKNOWN',
        'probe_completed_successfully': False, 'whole_u_terminal': False,
        'resource_return_proven': False, 'money_return': False}


def finish_namespace_experiment(output, outcome, exit_code):
    # The original PID/thread retains strong OWNER throughout this window.
    # This is a cooperative observation window, not a timeout for manager/FS
    # calls and not the original runtime's eight-second terminal deadline.
    deadline = time.monotonic() + EXPORT_WINDOW_SECONDS
    note = {'source': HEAD, 'pid': os.getpid(), 'outcome': outcome,
            'preparation_profile': LEAF_PROFILE, 'fresh_leaf_phase': stored_leaf_phase(OWNER),
            'export_window_seconds': EXPORT_WINDOW_SECONDS,
            'original_owner_retained_during_window': OWNER is not None,
            'whole_u_terminal': False, 'resource_return_proven': False,
            'money_return': False, 'old_unit_must_never_be_reused': True,
            'ordinary_exit_will_lose_owner': True,
            'actual_exit_status': 'UNKNOWN', 'probe_completed_successfully': False,
            'no_stop_delete_reset_retry_or_explicit_fd_retirement': True}
    try:
        record(output, '03-evidence-window.json', note)
    except BaseException as error:
        # If evidence storage itself fails, never convert that to success.
        note['window_record_error'] = type(error).__name__ + ':' + error_text(error)
        failure = unknown_payload(OWNER, error, 'RECORD_EVIDENCE_WINDOW')
        note['first_failure'] = failure['first_failure']
        note['original_owner_diagnostic'] = failure['original_owner_diagnostic']
        try:
            record(output, '02-original-attempt-unknown-retained.json', failure)
        except BaseException as publish_error:
            # O_EXCL retains any earlier failure. A fixed best-effort evidence
            # write is not a new request, cap or observation window.
            note['failure_record_error'] = type(publish_error).__name__+':'+error_text(publish_error)
        exit_code = 74
    while True:
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(remaining, 5))
    note['status'] = 'FRESH_LEAF_EXPERIMENT_ENDING_NO_TERMINAL_FACT'
    note['owner_present_before_ordinary_return'] = OWNER is not None
    note['planned_process_exit_code'] = exit_code
    try:
        record(output, '04-ordinary-exit-intent.json', note)
    except BaseException as error:
        try:
            record(output, '02-original-attempt-unknown-retained.json',
                   unknown_payload(OWNER, error, 'RECORD_ORDINARY_EXIT_INTENT'))
        except BaseException:
            pass  # Keep previous failures; actual exit status stays UNKNOWN.
        exit_code = 74
    # No stop/delete/reset/retirement/settlement. Returning ends this standalone
    # namespace experiment. OS FD closure on exit is not a terminal/use proof.
    return exit_code


def raw_namespace(cap, kernel):
    if tuple(cap._groups) != ('scope', 'host', 'observer', 'operation'):
        raise ValueError('fresh leaf requires exactly S/H/observer/U; no C/A groups')
    fields = ('cgroup.type', 'cgroup.procs', 'cgroup.events', 'cgroup.stat',
        'cgroup.subtree_control', 'cgroup.max.depth', 'cgroup.max.descendants',
        'memory.max', 'memory.current', 'memory.peak', 'memory.swap.max',
        'memory.swap.current', 'cpu.max', 'cpu.max.burst', 'cpu.stat',
        'pids.max', 'pids.current')
    rows = {}
    for role, (_, name, fd, identity) in cap._groups.items():
        rows[role] = {'name': name, 'held_identity': identity,
                      'raw': {key: kernel._text(fd, key) for key in fields}}
    return rows


def raw_child_namespace(cap, kernel):
    if tuple(cap._groups) != ('scope', 'host', 'observer', 'operation',
                              'controller', 'aggregate'):
        raise ValueError('same original S/H/observer/U/C/A groups required')
    fields = ('cgroup.type', 'cgroup.procs', 'cgroup.events', 'cgroup.stat',
        'cgroup.subtree_control', 'cgroup.max.depth', 'cgroup.max.descendants',
        'memory.max', 'memory.current', 'memory.peak', 'memory.swap.max',
        'memory.swap.current', 'cpu.max', 'cpu.max.burst', 'cpu.stat',
        'pids.max', 'pids.current', 'memory.events')
    rows = {}
    for role, (_, name, fd, identity) in cap._groups.items():
        rows[role] = {'name': name, 'held_identity': identity,
                      'raw': {key: kernel._text(fd, key) for key in fields}}
    return rows


def observe_once(cap, kernel, output, *, child_groups=False):
    """One request; any failure preserves its phase and original stored bindings."""
    phase = 'RECORD_ORIGINAL_OWNER_BEFORE_REQUEST'
    try:
        if cap is not OWNER or stored_leaf_phase(cap) != 'PREPARED':
            raise ValueError('same original fresh-leaf owner required')
        record(output, '01-original-owner-before-request.json',
            {'source': HEAD, 'pid': os.getpid(), 'starttime': cap._start,
             'unit': cap._unit, 'operation': cap._operation_name,
             'original_membership': cap._original_membership,
             'scope_request_not_yet_called': True, 'preparation_profile': LEAF_PROFILE,
             'fresh_leaf_phase': 'PREPARED'})
        phase = 'ADMIT_FRESH_LEAF_ONCE'
        fact = cap.admit_fresh_leaf()  # Original private fact, one local strong reference.
        if stored_leaf_phase(cap) != 'FRESH_U_LEAF':
            raise ValueError('fresh-leaf admission phase required')
        phase = 'READ_RAW_NAMESPACE'
        observed = raw_namespace(cap, kernel)
        phase = 'CONSUME_FRESH_LEAF_ONCE'
        consumed = cap.consume_fresh_leaf(fact)  # Exact same fact; never copied/serialized/replayed.
        if consumed is not None or stored_leaf_phase(cap) != 'LEAF_PROOF_CONSUMED':
            raise ValueError('fresh-leaf consume returns no operation grant')
        children = None
        if child_groups:
            if LEAF_PROFILE != CHILD_PROFILE:
                raise ValueError('explicit child-group preparation profile required')
            phase = 'PREPARE_FRESH_CHILD_GROUPS_ONCE'
            if cap.prepare_fresh_child_groups() is not None:
                raise ValueError('child-group preparation returns no grant')
            phase = 'VERIFY_ORIGINAL_CHILD_PREPARATION'
            if cap.verify_child_preparation() is not None or stored_leaf_phase(cap) != 'CHILD_GROUPS_PREPARED':
                raise ValueError('original child preparation remains unqualified')
            if cap._ready is not False or cap._failed is not False:
                raise ValueError('child preparation cannot be ready or failed')
            phase = 'READ_RAW_CHILD_NAMESPACE'
            children = raw_child_namespace(cap, kernel)
        phase = 'RECORD_PROVISIONAL_NAMESPACE_OBSERVATION'
        result = {'status': 'FRESH_LEAF_CONSUMED_ONLY', 'source': HEAD,
            'record_role': 'PROVISIONAL_FRESH_LEAF_CONSUMED_OBSERVATION',
            'preparation_profile': LEAF_PROFILE,
            'phase_before_raw': 'FRESH_U_LEAF', 'fresh_leaf_phase': 'LEAF_PROOF_CONSUMED',
            'pid': os.getpid(), 'unit': cap._unit, 'invocation': cap._invocation,
            'groups': observed, 'original_owner_held': True,
            'actual_exit_status': 'UNKNOWN', 'probe_completed_successfully': False,
            'whole_u_terminal': False, 'c_or_a_born': False, 'funded_reservation': False,
            'money_return': False, 'model_installed': False, 'activation': False}
        if child_groups:
            result.update(status='CHILD_GROUPS_PREPARED_ONLY',
                record_role='PROVISIONAL_CHILD_GROUPS_PREPARED_OBSERVATION',
                fresh_leaf_phase='CHILD_GROUPS_PREPARED',
                fresh_leaf_groups=observed, groups=children,
                child_groups_created=True, native_process_born=False,
                ready=False, qualified=False, final_use_authority=False)
        record(output, '02-native-namespace-observation.json', result)
    except BaseException as error:
        # The provisional file can already exist if either fsync failed. Keep
        # every file and let UNKNOWN dominate; never delete or call verify again.
        try:
            record(output, '02-original-attempt-unknown-retained.json',
                   unknown_payload(cap, error, phase))
        except BaseException:
            return 'ORIGINAL_ATTEMPT_UNKNOWN_EVIDENCE_ERROR', 74
        return 'ORIGINAL_ATTEMPT_UNKNOWN_RETAINED', 30
    return ('CHILD_GROUPS_PREPARED_ONLY', 21) if child_groups else ('FRESH_LEAF_CONSUMED_ONLY', 20)


def main():
    global OWNER, LEAF_PROFILE
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', required=True, type=Path)
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--admit-once', action='store_true')
    parser.add_argument('--prepare-child-groups', action='store_true')
    args = parser.parse_args()
    if args.prepare_child_groups:
        LEAF_PROFILE = CHILD_PROFILE
    if not args.source_root.is_absolute() or not args.manifest.is_absolute():
        parser.error('absolute pinned source paths required')
    before = source_preflight(args.source_root, args.manifest)
    if not args.admit_once:
        print(json.dumps(before, sort_keys=True))
        return
    if args.output is None or not args.output.is_absolute():
        parser.error('fresh absolute output directory required for native attempt')
    os.mkdir(args.output, 0o700)  # EEXIST refuses a replay, including failed runs.
    record(args.output, '00-source-preflight.json', before)
    # Dedicated original O survives SSH transport hangup. Its result is followed
    # by the finite cooperative export window above. This is not a service.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGPIPE, signal.SIG_IGN)
    sys.path.insert(0, str(args.source_root/'scripts'))
    import llm_runtime_host_scope as host
    import llm_runtime_kernel_owned as kernel
    try:
        OWNER = host.prepare_fresh_host_leaf()  # Fresh profile, original close helper; no C/A birth.
    except kernel.KernelOwnedCloseRequired as error:
        OWNER = error.capability
        try:
            data = unknown_payload(OWNER, error, 'PREPARE_ORIGINAL_OWNER')
            data['native_admission'] = False
            record(args.output, '01-preparation-owner-retained.json', data)
        except BaseException:
            return finish_namespace_experiment(args.output, 'PREPARATION_UNKNOWN_EVIDENCE_ERROR', 74)
        return finish_namespace_experiment(args.output, 'PREPARATION_UNKNOWN_RETAINED', 30)
    except BaseException as error:
        # The factory's ordinary failure path completed its own before-effect
        # cleanup. An uncertain close instead uses the retained-owner case above.
        record(args.output, '01-preparation-rejected-no-scope.json',
            {'status': 'PREPARATION_REJECTED_NO_SCOPE_REQUEST', 'source': HEAD,
             'pid': os.getpid(), 'error_type': type(error).__name__,
             'error': str(error)[:4096], 'native_admission': False,
             'whole_u_terminal': False, 'money_return': False})
        return 31
    cap = OWNER  # Keep the original strong owner before a possible manager effect.
    outcome, exit_code = observe_once(cap, kernel, args.output,
                                    child_groups=args.prepare_child_groups)
    return finish_namespace_experiment(args.output, outcome, exit_code)


if __name__ == '__main__':
    raise SystemExit(main())
