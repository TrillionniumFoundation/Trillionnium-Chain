"""Actual process/pipe observations for the private whole-block development owner."""
from __future__ import annotations
from pathlib import Path
import fcntl, hashlib, json, os, selectors, signal, struct, subprocess, time, traceback

U64 = (1 << 64) - 1

def identity(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

def need(ok, message):
    if not ok:
        raise ValueError(message)

def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')

def parse(raw, *, height, workers, count, sequence):
    need(len(raw) >= 256 and raw[:8] == b'BFOUT001', 'Whole block result header')
    h = struct.unpack('<32Q', raw[:256])
    need(h[1] == sequence and h[6:9] == (height, count, workers), 'Actual context in result')
    need(raw[216:256] == bytes(40) and h[2] in (1, 2, 3, 4), 'Reserved/result classification')
    context_n, parent_n, state_n, receipts_n = h[25], h[20], h[19], h[18]
    need(len(raw) == 256 + context_n + parent_n + state_n + receipts_n, 'Full output extent')
    at = 256
    context = raw[at:at + context_n]; at += context_n
    parent = raw[at:at + parent_n]; at += parent_n
    state = raw[at:at + state_n]; at += state_n
    need(len(context) >= 576 and context[:4] == b'SDO1', 'Internal Settings constructor record')
    need(struct.unpack_from('<I', context, 4)[0] == context_n, 'Full constructor record')
    need(context[8:16] == bytes(8) and context[468:480] == bytes(12), 'Constructor reserved')
    ec, sc, pl, ml, sl = struct.unpack_from('<5I', context, 448)
    need((ec, sc) == (3, 7) and 576 + pl + ml + sl == context_n, 'Constructor variable fields')
    receipts = []
    for _ in range(h[17]):
        need(at + 8 <= len(raw), 'Receipt length word')
        n = struct.unpack_from('<Q', raw, at)[0]; at += 8
        need(n <= len(raw) - at, 'Complete receipt bytes')
        receipts.append(raw[at:at + n].hex()); at += n
    need(at == len(raw), 'No trailing receipt data')
    if h[2] != 1:
        need(not state and not receipts and raw[168:200] == bytes(32), 'No partial successor on rejection')
    return {'header': list(h), 'context_hex': context.hex(), 'parent_hex': parent.hex(),
            'state_hex': state.hex(), 'receipts': receipts, 'root_hex': raw[168:200].hex()}

def execute(directory, elf, state, transactions, *, workers, height=10, sequence=91,
            miner=bytes([1])*32, parent_id=bytes([2])*32, gate=None, barrier=False):
    directory.mkdir(mode=0o700)
    started = time.monotonic_ns()
    streams = {name: bytearray() for name in ('stdin', 'stdout', 'stderr', 'progress', 'replies')}
    intended = b''; pending = bytearray(); events = []; barrier_events = []; task_records = []
    child = None; poller = None; handles = []; complete = set(); sequences = {}
    failure = None; cleanup = []; result = None; released = False; image = None
    count = min(workers, len(transactions)) if workers in (1, 2, 4, 8) else 0
    try:
        image = os.memfd_create('hia-private-whole-batch', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        handles.append(image)
        at = 0
        while at < len(elf):
            n = os.write(image, elf[at:]); need(n > 0, 'ELF write'); at += n
        os.fchmod(image, 0o500); fcntl.fcntl(image, getattr(fcntl, 'F_ADD_SEALS', 1033), 15)
        progress_reader = reply_writer = None
        if gate is not None or barrier:
            progress_reader, gw = os.pipe(); handles.extend((progress_reader, gw)); gr, reply_writer = os.pipe()
            handles.extend((gr, reply_writer)); passed = (image, gw, gr)
        else:
            gw = gr = U64; passed = (image,)
        frame = b'BPEXEC01' + struct.pack('<7Q', height, workers, len(transactions), sequence, gw, gr, len(state))
        frame += miner + parent_id + state + b''.join(struct.pack('<Q', len(tx)) + tx for tx in transactions)
        intended = struct.pack('<Q', len(frame)) + frame
        child = subprocess.Popen(['/proc/self/fd/' + str(image)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=passed, close_fds=True,
            env={'PATH': ''}, start_new_session=True)
        for fd in passed:
            if fd != image:
                os.close(fd); handles.remove(fd)
        poller = selectors.DefaultSelector()
        for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
            os.set_blocking(stream.fileno(), False); poller.register(stream, selectors.EVENT_READ, name)
        if progress_reader is not None:
            os.set_blocking(progress_reader, False); poller.register(progress_reader, selectors.EVENT_READ, 'progress')
            os.set_blocking(reply_writer, False)
        deadline = time.monotonic() + 240
        os.set_blocking(child.stdin.fileno(), False)
        with selectors.DefaultSelector() as writer:
            writer.register(child.stdin, selectors.EVENT_WRITE)
            at = 0
            while at < len(intended):
                need(time.monotonic() < deadline, 'Native input deadline')
                try:
                    n = os.write(child.stdin.fileno(), intended[at:])
                except BlockingIOError:
                    writer.select(.02); continue
                need(n > 0, 'Input write')
                streams['stdin'].extend(intended[at:at + n]); at += n
        child.stdin.close()

        def reply(event):
            classification, token, seq_delta = (0, 0, 0) if gate is None else gate(event)
            answer = b'BPGO0001' + struct.pack('<5Q', sequence, event['worker'],
                event['sequence'] + seq_delta, classification, token)
            at = 0
            while at < len(answer):
                need(time.monotonic() < deadline, 'Actual reply deadline')
                try:
                    n = os.write(reply_writer, answer[at:])
                except BlockingIOError:
                    time.sleep(.005); continue
                need(n > 0, 'Reply write')
                streams['replies'].extend(answer[at:at + n]); at += n
            event['reply_hex'] = answer.hex()

        while child.poll() is None or 'stdout' not in complete or 'stderr' not in complete:
            need(time.monotonic() < deadline, 'Native child exceeded original 240-second budget')
            for key, _ in poller.select(.05):
                try:
                    raw = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not raw:
                    complete.add(key.data); poller.unregister(key.fileobj); continue
                streams[key.data].extend(raw)
                if key.data != 'progress':
                    continue
                pending.extend(raw)
                while len(pending) >= 64:
                    record = bytes(pending[:64]); del pending[:64]
                    p = struct.unpack('<8Q', record)
                    need(record[:8] == b'BPPROG01' and p[1] == sequence and p[6] == height and p[7] == 0, 'Progress identity')
                    need(p[3] == sequences.get(p[2], 0) + 1, 'Per-owner callback order')
                    sequences[p[2]] = p[3]
                    main = p[2] == 8
                    if main:
                        need(p[4] in range(10, 18), 'Canonical callback kind')
                    else:
                        need(p[2] < count and p[4] in (1, 2) and p[5] % count == p[2], 'Actual scoped-worker stride')
                    event = {'worker': p[2], 'sequence': p[3], 'kind': p[4], 'index': p[5], 'raw_hex': record.hex()}
                    events.append(event)
                    if barrier and not main and not released:
                        need(p[3] == 1 and p[4] == 1, 'One first pending slot per worker')
                        barrier_events.append(event)
                        if len(barrier_events) == count:
                            path = Path('/proc') / str(child.pid) / 'task'
                            for task in sorted(path.iterdir(), key=lambda item: int(item.name)):
                                row = {'tid': int(task.name)}
                                for name in ('stat', 'status', 'wchan'):
                                    row[name] = (task / name).read_text()
                                task_records.append(row)
                            need(len(task_records) == (count + 1 if count > 1 else 1), 'Real kernel thread count at first barrier')
                            for item in reversed(barrier_events):
                                reply(item)
                            released = True
                    else:
                        reply(event)
        child.wait(timeout=3)
        need(not pending, 'No truncated progress')
        if child.returncode == 0:
            need(not streams['stderr'], 'No native error diagnostics on normal Result')
            result = parse(bytes(streams['stdout']), height=height, workers=workers,
                           count=len(transactions), sequence=sequence)
            if result['parent_hex']:
                need(result['parent_hex'] == state.hex(), 'Original parent State changed')
        else:
            need(child.returncode == 78 and not streams['stdout'] and not streams['stderr'], 'Actual process failed')
    except BaseException as error:
        failure = {'error': repr(error), 'traceback': traceback.format_exc()}
    finally:
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=3)
            except BaseException as error:
                cleanup.append(repr(error))
        if child is not None:
            for name, stream in (('stdout', child.stdout), ('stderr', child.stderr)):
                if stream is None or stream.closed:
                    continue
                try:
                    os.set_blocking(stream.fileno(), False)
                    while True:
                        try:
                            raw = os.read(stream.fileno(), 65536)
                        except BlockingIOError:
                            break
                        if not raw:
                            break
                        streams[name].extend(raw)
                except BaseException as error:
                    cleanup.append(repr(error))
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except BaseException as error:
                        cleanup.append(repr(error))
        if poller is not None:
            poller.close()
        for fd in handles:
            try:
                os.close(fd)
            except BaseException as error:
                cleanup.append(repr(error))
        for name, raw in streams.items():
            (directory / (name + '.raw')).write_bytes(raw)
        (directory / 'intended-input.raw').write_bytes(intended)
        report = {'status': 'PASS' if failure is None and not cleanup else 'FAIL',
            'pid': None if child is None else child.pid, 'exit_code': None if child is None else child.returncode,
            'elapsed_ns': time.monotonic_ns() - started, 'wall_limit_seconds': 240, 'cleanup_limit_seconds': 3, 'input': identity(intended),
            'streams': {name: identity(raw) for name, raw in streams.items()}, 'executable': identity(elf),
            'events': events, 'barrier_kernel_tasks': task_records, 'result': result,
            'primary_error': failure, 'cleanup_errors': cleanup}
        write_json(directory / 'report.json', report)
    return report
