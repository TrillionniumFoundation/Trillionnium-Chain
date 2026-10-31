#!/usr/bin/env python3
"""Owned Python/FD mechanisms ONLY: no W1, Cargo, native ELF or qualification run."""
from pathlib import Path
import argparse
import ast
import errno
import hashlib
import importlib.util
import io
import json
import os
import resource
import signal
import stat
import sys
import time

MIB = 1024 * 1024


def pin(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def event(path, value):
    raw = (json.dumps(value, sort_keys=True) + '\n').encode()
    with path.open('ab') as stream:
        assert stream.tell() + len(raw) <= MIB
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def no_child(pid):
    try:
        result = os.waitpid(pid, os.WNOHANG)
        return {'ECHILD': False, 'waitpid': list(result)}
    except ChildProcessError as error:
        return {'ECHILD': error.errno == errno.ECHILD, 'errno': error.errno}


def new_actor(module, root, name, source):
    directory = root / name
    directory.mkdir()
    log = (directory / 'parent-events.jsonl').open('xb')
    owned = []
    actor = module.Actor(name, [sys.executable, '-c', source], directory, module.PROFILE,
                         time.monotonic() + 12, log, owned)
    assert owned == [actor]
    return actor, log, directory


def held_stdout(actor):
    reader = os.dup(actor.process.stdout.fileno())
    os.set_blocking(reader, False)
    actual = os.fstat(reader)
    assert stat.S_ISFIFO(actual.st_mode)
    procpath = f'/proc/{actor.process.pid}/fd/1'
    # Intentional fixture-only traversal of the real child's kernel proc-fd link.
    # NO O_NOFOLLOW: this is not a production arbitrary-path open capability.
    writer = os.open(procpath, os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    duplicate = os.fstat(writer)
    assert (actual.st_dev, actual.st_ino) == (duplicate.st_dev, duplicate.st_ino)
    assert module_birth(actor.process.pid) == actor.original_birth
    return reader, writer, {'source': procpath, 'intentional_proc_fd_fixture_link': True,
                            'reader_dev': actual.st_dev, 'reader_ino': actual.st_ino,
                            'writer_dev': duplicate.st_dev, 'writer_ino': duplicate.st_ino,
                            'pid': actor.process.pid, 'birth': actor.original_birth,
                            'writer_flags': 'O_WRONLY|O_NONBLOCK|O_CLOEXEC'}


def module_birth(pid):
    return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[19]


def read_state(fd):
    try:
        raw = os.read(fd, 1)
        return {'EOF': raw == b'', 'bytes': raw.hex()}
    except BlockingIOError:
        return {'EOF': False, 'EAGAIN': True}


def eof_case(module, root):
    actor, log, directory = new_actor(module, root, 'PY01-real-held-pipe', 'import time;time.sleep(60)')
    reader = writer = None
    try:
        reader, writer, binding = held_stdout(actor)
        assert read_state(reader).get('EAGAIN') is True
        result = actor.abort()
        after = read_state(reader)
        # A still-held REAL writer prevents EOF even though leader was SIGKILLed/reaped.
        assert after.get('EAGAIN') is True
        reaped = no_child(actor.process.pid)
        assert reaped['ECHILD'] is True
        os.close(writer)
        writer = None
        eof = read_state(reader)
        assert eof['EOF'] is True
        return {'fixture': binding, 'abort': result, 'after_abort_real_pipe': after,
                'after_fixture_writer_close': eof, 'final_wait': reaped,
                'bug_observed': result.get('streams_complete') is True,
                'fixed_safety_observed': result.get('streams_complete') is not True}
    finally:
        if writer is not None:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        if actor.wait is None:
            actor.abort()
        log.close()


def rpc_source(profile):
    return ("import sys,json; r=json.loads(sys.stdin.readline());"
            f"print(json.dumps({{'schema':{profile!r},"
            "'sequence':0,'kind':'response','id':r['id'],'op':r['op'],'data':{}}),flush=True)")


def logger_case(module, root):
    actor, log, directory = new_actor(module, root, 'R3-real-RPC-injected-logger', rpc_source(module.PROFILE))
    original = actor.log
    def slow(value):
        if value['kind'] == 'response_received':
            time.sleep(2.01)
        original(value)
    actor.log = slow
    started = time.monotonic()
    error = None
    returned = False
    try:
        try:
            actor.rpc(1, 'search')
            returned = True
        except Exception as failure:
            error = type(failure).__name__ + ':' + str(failure)
        elapsed = time.monotonic() - started
        if returned:
            actor.finish()
        else:
            actor.abort()
        assert no_child(actor.process.pid)['ECHILD'] is True
        return {'injected_parent_logger_sleep_seconds': 2.01, 'rpc_returned': returned,
                'actual_release_to_return_or_error_seconds': elapsed, 'error': error,
                'actual_wait4': actor.wait, 'historical_IO_cause_proven': False,
                'bug_observed': returned and elapsed > 2,
                'fixed_safety_observed': not returned and elapsed > 2}
    finally:
        if actor.wait is None:
            actor.abort()
        log.close()


def finish_case(module, root):
    actor, log, directory = new_actor(module, root, 'R3-real-finish-injected-fsync', rpc_source(module.PROFILE))
    actor.rpc(1, 'search')
    original = actor.close_files
    def slow():
        original()
        time.sleep(2.01)
    actor.close_files = slow
    error = None
    returned = False
    started = time.monotonic()
    try:
        try:
            actor.finish()
            returned = True
        except Exception as failure:
            error = type(failure).__name__ + ':' + str(failure)
        elapsed = time.monotonic() - started
        actor.close_files = original
        assert no_child(actor.process.pid)['ECHILD'] is True
        return {'injected_close_fsync_delay_seconds': 2.01, 'finish_returned': returned,
                'actual_elapsed_seconds': elapsed, 'error': error, 'actual_wait4': actor.wait,
                'historical_IO_cause_proven': False, 'bug_observed': returned and elapsed > 2,
                'fixed_safety_observed': not returned and elapsed > 2}
    finally:
        actor.close_files = original
        if actor.wait is None:
            actor.abort()
        log.close()


def stale_group_case(module, root):
    actor, log, directory = new_actor(module, root, 'R5-real-exit-held-pipe', 'import time;time.sleep(0.10)')
    reader = writer = None
    original_signal = module.os.killpg
    would_signal = []
    try:
        reader, writer, binding = held_stdout(actor)
        end = time.monotonic() + 2
        while actor.wait is None and time.monotonic() < end:
            actor.consume(0.01)
        assert actor.wait is not None and actor.wait['reaped'] is True
        assert no_child(actor.process.pid)['ECHILD'] is True
        assert read_state(reader).get('EAGAIN') is True
        def forbid_after_reap(pgid, sig):
            nonlocal writer
            assert actor.wait is not None
            would_signal.append({'pgid': pgid, 'signal': int(sig), 'leader_already_reaped': True,
                                 'actual_signal_executed': False})
            # This observation is deliberately NOT an actual stale-PGID signal.
            if writer is not None:
                os.close(writer)
                writer = None
        module.os.killpg = forbid_after_reap
        result = actor.abort()
        return {'fixture': binding, 'real_natural_exit_and_wait4': actor.wait,
                'signal_call_observations': would_signal, 'abort': result,
                'PID_reuse_or_dangerous_signal_executed': False,
                'bug_observed': bool(would_signal), 'fixed_safety_observed': not would_signal}
    finally:
        module.os.killpg = original_signal
        if writer is not None:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        if actor.wait is None:
            actor.abort()
        log.close()


def aggregate_case(module, root):
    rows = []
    for kind in ('bytes', 'files'):
        path = root / ('PY02-final-' + kind)
        path.mkdir()
        if kind == 'bytes':
            for name, size in [('first.bin', 16 * MIB), ('second.bin', 16 * MIB - 256)]:
                with (path / name).open('xb') as stream:
                    stream.truncate(size)
        else:
            for index in range(127):
                (path / f'fixture-{index:03d}').touch(exist_ok=False)
        result = {'schema': 'negative-mechanism-fixture-only', 'component_execution_complete': False,
                  'qualifying_execution_receipt': False, 'whole_work_hardness_qualified': False,
                  'padding': 'x' * 256}
        blocked = False
        error = None
        if hasattr(module, 'seal_outputs'):
            try:
                module.seal_outputs(path, result, time.monotonic(), time.monotonic() + 2)
            except Exception as failure:
                blocked = True
                error = str(failure)
        else:
            # Exact original partial function sequence, NOT a native/profile receipt.
            module.inventory(path)
            module.write_new(path / 'owner-result.json', result)
            module.write_new(path / 'post-write-terminal.json', result)
        actual = [p for p in path.iterdir() if p.is_file()]
        total = sum(p.stat().st_size for p in actual)
        rows.append({'kind': kind, 'actual_files': len(actual), 'actual_logical_bytes': total,
                     'sparse_fixture_physical_bytes': sum(p.stat().st_blocks * 512 for p in actual),
                     'blocked_before_final_overcap_write': blocked, 'error': error,
                     'bug_observed': not blocked and (len(actual) > 128 or total > 32 * MIB),
                     'fixed_safety_observed': blocked and len(actual) <= 128 and total <= 32 * MIB,
                     'fixture_is_not_W1_or_qualified_receipt': True})
    return {'cases': rows, 'bug_observed': all(r['bug_observed'] for r in rows),
            'fixed_safety_observed': all(r['fixed_safety_observed'] for r in rows)}


def numeric_case(module, reader, original):
    import copy
    cases = []
    for expected, value in ((1, True), (1, 1.0), (0, False), (0, 0.0)):
        observations = {}
        for name, target in [('frozen_original', original), ('revision002', reader)]:
            old_stdin = target.sys.stdin
            fake = io.TextIOWrapper(io.BytesIO((json.dumps({'id': value, 'op': 'search'}) + '\n').encode()))
            accepted = True
            try:
                target.sys.stdin = fake
                try:
                    target.request(expected, 'search')
                except ValueError:
                    accepted = False
            finally:
                target.sys.stdin = old_stdin
                fake.close()
            observations[name] = accepted
        cases.append({'expected_id': expected, 'JSON_id_repr': repr(value), **observations})
    assert all(c['frozen_original'] and not c['revision002'] for c in cases)
    rejects = {}
    for name, target in [('owner', module), ('reader', reader)]:
        rejected = []
        for value in (False, True, 0.0, 1.0, -1, 1 << 64):
            try:
                target.uint(value, 'fixture')
            except ValueError:
                rejected.append(repr(value))
        assert len(rejected) == 6
        for value in (0, 1, 64, 4096, (1 << 64) - 1):
            assert target.uint(value, 'fixture') == value
        rejects[name] = rejected
    bases = [
        {'sequence':0,'kind':'initialized','owner_pid':123,'owner_birth':'10',
         'limits':{'as_soft':512*MIB,'as_hard':512*MIB,'fsize_soft':8*MIB,'fsize_hard':8*MIB},
         'selected_setup':{'attempts':1,'supported':1,'cpu_ns':1,'wall_ns':1},'production_template_make_calls':2},
        {'sequence':0,'kind':'trial_started','search':0,'ordinal':0},
        {'sequence':0,'kind':'trial_completed','search':0,'ordinal':0,'nonce':1_000_000,'target_hit':True},
        {'sequence':0,'kind':'response','id':0,'op':'initialize','operation_wall_ns':1,'operation_cpu_ns':1,
         'data':{'owner_pid':123,'owner_birth':'10','initialized':True}},
        {'sequence':0,'kind':'response','id':1,'op':'search','operation_wall_ns':1,'operation_cpu_ns':1,
         'data':{'search':0,'first':1_000_000,'count_limit':4096,'attempts':1,'setup_attempts':1,
                 'supported_setups':1,'producer_acquisition':{'cpu_ns':1,'wall_ns':1}}},
        {'sequence':0,'kind':'response','id':65,'op':'seal','operation_wall_ns':1,'operation_cpu_ns':1,
         'data':{'searches':64,'same_selected_setup_attempts':1}},
    ]
    def integer_paths(value, prefix=()):
        for key, child in value.items():
            if type(child) is int:
                yield prefix+(key,),child
            elif type(child) is dict:
                yield from integer_paths(child,prefix+(key,))
    mutants = 0
    for frame in bases:
        reader.native_numbers(frame)
        for path, initial in integer_paths(frame):
            for invalid in (True, False, float(initial)):
                changed = copy.deepcopy(frame)
                target = changed
                for key in path[:-1]: target=target[key]
                target[path[-1]]=invalid
                try:
                    reader.native_numbers(changed)
                except ValueError:
                    mutants += 1
                else:
                    raise AssertionError(('integer-alias-not-rejected',frame['kind'],path,repr(invalid)))
    for hit in (False, True):
        frame=copy.deepcopy(bases[2]);frame['target_hit']=hit;reader.native_numbers(frame)
    frame=copy.deepcopy(bases[2]);frame['target_hit']=1
    try:
        reader.native_numbers(frame)
    except ValueError:
        pass
    else:
        raise AssertionError('numeric-one-was-accepted-as-bool-hit')
    return {'request_partial_predicates':cases,'strict_u64_rejections':rejects,
            'strict_declared_integer_alias_mutants_rejected':mutants,
            'real_boolean_hits_retained':True,'bug_observed':False,'fixed_safety_observed':True,
            'partial_schema_predicates_only_not_native_payment_or_qualification':True}


def final_inventory_case(module, root):
    result={'schema':'negative-mechanism-fixture-only','component_execution_complete':False,
            'qualifying_execution_receipt':False,'whole_work_hardness_qualified':False}
    path=root/'PY02-actual-post-write-verification';path.mkdir()
    real_inventory=module.inventory;calls=[]
    def observe(output,*args,**kwargs):
        calls.append({'actual_final_names':sorted(p.name for p in output.iterdir()),
                      'reserve_bytes':kwargs.get('reserve_bytes',0),'reserve_files':kwargs.get('reserve_files',0)})
        return real_inventory(output,*args,**kwargs)
    module.inventory=observe
    try:
        rc=module.seal_outputs(path,result,time.monotonic(),time.monotonic()+2)
    finally:
        module.inventory=real_inventory
    assert rc==1 and calls[-1]['actual_final_names']==['owner-result.json','post-write-terminal.json']
    path2=root/'PY02-post-write-new-file-interference';path2.mkdir()
    real_write=module.write_new
    def interfere(file,value):
        real_write(file,value)
        if file.name=='post-write-terminal.json':
            for index in range(127): (path2/f'late-fixture-{index:03d}').touch(exist_ok=False)
    module.write_new=interfere;rejected=False
    try:
        try:
            module.seal_outputs(path2,result,time.monotonic(),time.monotonic()+2)
        except ValueError:
            rejected=True
    finally:
        module.write_new=real_write
    assert rejected
    return {'actual_inventory_calls':calls,'upstream_failed_fixture_exit':rc,
            'post_write_129_file_interference_rejected':rejected,
            'all_fixture_receipts_qualified_false':True,'fixed_safety_observed':True,'bug_observed':False,
            'scope':'actual-Python-files-no-native-profile-or-successful-qualified-receipt'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--owned-source', type=Path, required=True)
    parser.add_argument('--version', choices=('v2',), required=True)
    parser.add_argument('--original-candidate', type=Path, required=True)
    parser.add_argument('--remaining-suite-seconds', type=float, required=True)
    args = parser.parse_args()
    assert 0 < args.remaining_suite_seconds <= 15
    def deadline_expired(*unused):
        raise TimeoutError('shared-original-fifteen-second-mechanism-suite-budget')
    signal.signal(signal.SIGALRM, deadline_expired)
    signal.signal(signal.SIGTERM, deadline_expired)
    signal.setitimer(signal.ITIMER_REAL, args.remaining_suite_seconds)
    started = time.monotonic()
    os.nice(19 - os.getpriority(os.PRIO_PROCESS, 0))
    resource.setrlimit(resource.RLIMIT_AS, (1024 * MIB, 1024 * MIB))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16 * MIB, 16 * MIB))
    args.output.mkdir(exist_ok=False)
    event(args.output / 'events.jsonl', {'kind': 'started', 'pid': os.getpid(), 'birth': module_birth(os.getpid()),
          'nice': os.getpriority(os.PRIO_PROCESS, 0), 'AS': resource.getrlimit(resource.RLIMIT_AS),
          'scope': 'owned-Python-FD-mechanisms-only-no-native-W1'})
    sys.path.insert(0, str(args.owned_source / 'scripts'))
    owner_path = args.candidate / 'scripts/run_pon_w1_real_header_reuse_v1.py'
    reader_path = args.candidate / 'scripts/ci/check_pon_w1_real_header_reuse_v1.py'
    owner = load('mechanism_owner_' + args.version, owner_path)
    reader = load('mechanism_reader_' + args.version, reader_path)
    original = load('frozen_original_request_predicate', args.original_candidate / 'scripts/ci/check_pon_w1_real_header_reuse_v1.py')
    cases = {}
    for name, action in [('PY01', lambda: eof_case(owner, args.output)),
                         ('R3_RPC', lambda: logger_case(owner, args.output)),
                         ('R3_FINISH', lambda: finish_case(owner, args.output)),
                         ('R5', lambda: stale_group_case(owner, args.output)),
                         ('PY02', lambda: aggregate_case(owner, args.output)),
                         ('R4', lambda: numeric_case(owner, reader, original)),
                         ('PY02_POSTWRITE', lambda: final_inventory_case(owner, args.output))]:
        before = time.monotonic()
        cases[name] = action()
        cases[name]['case_elapsed_seconds'] = time.monotonic() - before
        event(args.output / 'events.jsonl', {'kind': 'case_completed', 'name': name, 'result': cases[name]})
    expected = 'bug_observed' if args.version == 'v1' else 'fixed_safety_observed'
    result = {'schema': 'pn1-python-fd-mechanism-control-only-v1', 'version': args.version,
              'actual_elapsed_seconds': time.monotonic() - started,
              'source_pins': [pin(owner_path), pin(reader_path)], 'cases': cases,
              'all_expected_mechanisms_observed': all(c[expected] for c in cases.values()),
              'actual_W1_or_native64_or_oracle_or_paid_identity_run': False,
              'source_binary_attestation': False, 'all_owned_descendants_terminal': 'UNKNOWN-not-a-whole-tree-census',
              'qualifying_execution_receipt': False, 'merge_ready': False}
    raw = json.dumps(result, indent=2, sort_keys=True).encode() + b'\n'
    with (args.output / 'result.json').open('xb') as stream:
        assert len(raw) <= MIB
        stream.write(raw)
    print(json.dumps({'version': args.version, 'all_expected_mechanisms_observed': result['all_expected_mechanisms_observed'],
                      'elapsed_seconds': result['actual_elapsed_seconds'], 'result': str(args.output / 'result.json')}))
    return 0 if result['all_expected_mechanisms_observed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
