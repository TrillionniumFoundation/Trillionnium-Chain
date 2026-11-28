"""Physical qualification for the fresh native Host checkpoint candidate.

Every owner case executes the sealed native HIA image against real private
files. Fixture observations carry no production fixed-parent authority.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from hia.platform.host_checkpoint.build import Build, new_output, sha256, write_json
from hia.platform.build import sealed_executable

MAGIC = int.from_bytes(b'HIAHK002', 'little')
FIELDS = ('magic','fixture','error','sequence','full_checks','opens','reads','read_bytes',
          'EINTR','close_errors','TID','thread_CPU_ns','wall_ns','state_capacity',
          'boot_trimmed_bytes','positive_short_reads')
LIMITS = {'cpu.max': b'25000 100000\n', 'cpu.max.burst': b'0\n',
          'memory.max': b'2147483648\n', 'memory.swap.max': b'0\n', 'pids.max': b'256\n'}
PARENT = Path('sys/fs/cgroup/trnmponpublic.slice')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def provision(root: Path) -> Path:
    parent = root / PARENT
    parent.mkdir(parents=True, mode=0o700)
    (root/'controllers').write_bytes(b'cpu memory pids\n')
    (root/'boot').write_bytes(b'boot-identity\n')
    (root/'membership').write_bytes(b'0::/trnmponpublic.slice\n')
    for name, value in LIMITS.items():
        (parent/name).write_bytes(value)
    return parent


class Session:
    def __init__(self, image: bytes, directory: Path, *, address_limit=None):
        self.directory = directory
        self.image_sha256 = sha256(image)
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.stdin = bytearray()
        self.receipts = []
        self.descriptor_observations = []
        fd = sealed_executable(image, 'hia-host-qualified')
        try:
            def child_limit():
                resource.setrlimit(resource.RLIMIT_AS,(address_limit,address_limit))
            self.process = subprocess.Popen(['/proc/self/fd/' + str(fd)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=directory, env={'PATH':''}, pass_fds=(fd,), start_new_session=True,
                preexec_fn=child_limit if address_limit is not None else None)
        finally:
            os.close(fd)
        self.started_ns = time.monotonic_ns()

    def read_exact(self, stream, size: int, *, timeout: float = 15) -> bytes:
        end = time.monotonic() + timeout
        output = bytearray()
        while len(output) < size:
            remaining = end-time.monotonic()
            require(remaining > 0, 'Native observation timed out')
            ready, _, _ = select.select([stream], [], [], remaining)
            require(bool(ready), 'Native observation timed out')
            data = os.read(stream.fileno(), size-len(output))
            require(bool(data), 'Native process ended before complete observation')
            output.extend(data)
        if stream is self.process.stdout:
            self.stdout.extend(output)
        else:
            self.stderr.extend(output)
        return bytes(output)

    def receipt(self, error: int = 0) -> dict:
        raw = self.read_exact(self.process.stdout, 128)
        row = dict(zip(FIELDS, struct.unpack('<16Q', raw)))
        require(row['magic'] == MAGIC and row['fixture'] == 1, 'Wrong native fixture receipt')
        require(row['error'] == error, f'Expected error {error}, observed {row["error"]}')
        if not error:
            require(row['TID'] == self.process.pid, 'Receipt must name actual native calling TID')
            self.observe_closed_resources()
        self.receipts.append(row)
        return row

    def observe_closed_resources(self) -> None:
        links = {}
        for fd in Path(f'/proc/{self.process.pid}/fd').iterdir():
            try:
                links[fd.name] = os.readlink(fd)
            except FileNotFoundError:
                continue
        leaks = [value for value in links.values() if value.startswith(str(self.directory))]
        require(not leaks, 'Resource file descriptor survived a native receipt')
        self.descriptor_observations.append(links)

    def write(self, data: bytes) -> None:
        self.stdin.extend(data)
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def request(self, count: int = 1, gate: int = 0, chunk: int = 4096) -> None:
        self.write(struct.pack('<QQQ', count, gate, chunk))

    def gate(self, number: int) -> None:
        require(self.read_exact(self.process.stderr, 8) == struct.pack('<Q', number),
                'Actual native fixture gate was not reached')

    def finish(self, error: int = 0) -> dict:
        self.process.stdin.close()
        self.process.stdin = None
        try:
            out, err = self.process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(self.process.pid, signal.SIGKILL)
            out, err = self.process.communicate(timeout=3)
            self.stdout.extend(out);self.stderr.extend(err)
            self.save('FAIL', 'Native completion timeout')
            raise
        self.stdout.extend(out);self.stderr.extend(err)
        require(not out and not err, 'Unexpected extra native output')
        require(self.process.returncode == (64+error if error else 0), 'Unexpected native exit')
        return self.save('PASS')

    def save(self, status: str, error: str | None = None) -> dict:
        row = {'schema':'trnm.hia.host-physical-case.v2','status':status,'error':error,
               'executable_sha256':self.image_sha256,'pid':self.process.pid,
               'exit_code':self.process.returncode,'receipts':self.receipts,
               'stdin_sha256':sha256(self.stdin),'stdout_sha256':sha256(self.stdout),
               'stderr_sha256':sha256(self.stderr),'descriptor_observations':self.descriptor_observations,
               'elapsed_wall_ns':time.monotonic_ns()-self.started_ns,
               'fixture_production_authority':False}
        for name, data in (('stdin.raw',self.stdin),('stdout.raw',self.stdout),('stderr.raw',self.stderr)):
            (self.directory/name).write_bytes(data)
        write_json(self.directory/'observation.json',row)
        return row

    def abort(self, reason: str) -> None:
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
        try:
            out, err = self.process.communicate(timeout=3)
            self.stdout.extend(out);self.stderr.extend(err)
        finally:
            self.save('FAIL',reason)


class Corpus:
    def __init__(self, image: bytes, output: Path):
        self.image = image
        self.output = output
        output.mkdir()
        self.rows = []

    def case(self, name, *, before=None, after=None, initial_error=0,
             expected=0, count=1, chunk=4096, gate=0, mutation=None,
             second_error=None):
        directory = self.output/name
        directory.mkdir()
        parent = provision(directory)
        session = None
        try:
            if before:
                before(directory,parent)
            session = Session(self.image,directory)
            initial = session.receipt(initial_error)
            if initial_error:
                row = session.finish(initial_error)
            else:
                if after:
                    after(directory,parent)
                session.request(count,gate,chunk)
                if gate:
                    session.gate(gate)
                    if mutation:
                        mutation(directory,parent)
                    session.write(b'\x01')
                final = session.receipt(expected)
                if not expected:
                    require(final['full_checks'] == initial['full_checks']+count,
                            'Full fresh checkpoint count differs')
                    require(final['thread_CPU_ns'] > 0 and final['wall_ns'] > 0,
                            'Actual clocks must measure successful requests')
                if second_error is not None:
                    session.request()
                    session.receipt(second_error)
                    expected = second_error
                row = session.finish(expected)
            row['name'] = name
            row['expected_error'] = initial_error or expected
            self.rows.append(row)
            return row
        except BaseException as error:
            if session:
                session.abort(type(error).__name__+': '+str(error))
            self.rows.append({'name':name,'status':'FAIL','error':type(error).__name__+': '+str(error)})
            raise


def changed_file(name, data):
    return lambda directory,parent: (parent/name).write_bytes(data)


def replace_parent(directory, parent):
    old = parent.with_name(parent.name+'.old')
    parent.rename(old)
    shutil.copytree(old,parent)
    parent.chmod(0o700)


def physical_cases(corpus: Corpus) -> None:
    first = corpus.case('fresh-every-call',count=3)
    before,after = first['receipts']
    require(after['opens']-before['opens'] == 24 and after['reads']-before['reads'] == 42,
            'Normal checks must freshly open eight streams/directories and read seven streams to EOF')
    corpus.case('repeat-original-seven-proof-check-count',count=7693)
    for chunk in (1,2,3,7,31,128,129,255,256,257,4096):
        corpus.case(f'chunk-{chunk}',chunk=chunk)
    for size in (0,1,255,256,257,4095,4096,4097,65537,131073):
        corpus.case(f'boot-size-{size}',before=lambda d,p,n=size:(d/'boot').write_bytes(b'x'*n))
    corpus.case('boot-trim-equivalent',after=lambda d,p:(d/'boot').write_bytes('\u2007\u0085boot-identity\u3000\n'.encode()))
    corpus.case('boot-long-trim-equivalent',after=lambda d,p:(d/'boot').write_bytes(b' '*131073+b'boot-identity\n'))
    corpus.case('boot-changed',after=lambda d,p:(d/'boot').write_bytes(b'other\n'),expected=4)
    corpus.case('boot-invalid-utf8',before=lambda d,p:(d/'boot').write_bytes(b'\xff'),initial_error=3)
    corpus.case('boot-long-invalid-utf8',before=lambda d,p:(d/'boot').write_bytes(b'x'*4097+b'\xc0\x80'),initial_error=3)
    corpus.case('boot-missing',before=lambda d,p:(d/'boot').unlink(),initial_error=3)
    for label,text in (
        ('exact',b'0::/trnmponpublic.slice'),('lf',b'0::/trnmponpublic.slice\n'),
        ('crlf',b'0::/trnmponpublic.slice\r\n'),('child',b'0::/trnmponpublic.slice/child\n'),
        ('unicode-child','0::/trnmponpublic.slice/\u96ea\n'.encode()),
        ('long-child',b'0::/trnmponpublic.slice/'+b'a'*131073+b'\n')):
        corpus.case('membership-'+label,before=lambda d,p,t=text:(d/'membership').write_bytes(t))
    for label,text in (
        ('empty',b''),('root',b'0::/\n'),('wrong-parent',b'0::/other\n'),
        ('sibling',b'0::/trnmponpublic.slice-else\n'),('trailing-slash',b'0::/trnmponpublic.slice/\n'),
        ('double-slash',b'0::/trnmponpublic.slice//a\n'),('dot',b'0::/trnmponpublic.slice/.\n'),
        ('dotdot',b'0::/trnmponpublic.slice/..\n'),('multiline',b'0::/trnmponpublic.slice\n0::/other\n'),
        ('second-empty-line',b'0::/trnmponpublic.slice\n\n'),('invalid-utf8',b'0::/trnmponpublic.slice/\xff'),
        ('v1',b'1:cpu:/trnmponpublic.slice\n')):
        corpus.case('membership-'+label,before=lambda d,p,t=text:(d/'membership').write_bytes(t),initial_error=3)
    for name,value in LIMITS.items():
        stem=name.replace('.','-')
        valid = value.rstrip(b'\n')
        corpus.case(stem+'-128',before=changed_file(name,valid+b' '*(128-len(valid))))
        corpus.case(stem+'-129',before=changed_file(name,valid+b' '*(129-len(valid))),initial_error=5)
        corpus.case(stem+'-utf8',before=changed_file(name,b'\xff'),initial_error=5)
        corpus.case(stem+'-bad-number',before=changed_file(name,b'x'),initial_error=6)
        corpus.case(stem+'-missing',before=lambda d,p,n=name:(p/n).unlink(),initial_error=5)
        def symlink(d,p,n=name):
            (p/n).rename(p/(n+'.target'));(p/n).symlink_to(n+'.target')
        corpus.case(stem+'-symlink',before=symlink,initial_error=5)
        def fifo(d,p,n=name):
            (p/n).unlink();os.mkfifo(p/n,0o600)
        corpus.case(stem+'-fifo',before=fifo,initial_error=5)
        def directory(d,p,n=name):
            (p/n).unlink();(p/n).mkdir()
        corpus.case(stem+'-directory',before=directory,initial_error=5)
    for label,value,expected in (
        ('max-valid',b'250000 1000000',0),('above-quota',b'250001 1000000',6),
        ('above-period',b'25000 1000001',6),('too-much-bandwidth',b'25001 100000',6),
        ('zero',b'0 100000',6),('plus',b'+25000 +100000',0),('extra',b'25000 100000 0',6),
        ('overflow',b'18446744073709551616 100000',6),('vertical-tab-separator',b'25000\x0b100000',6),
        ('vertical-tab-trim',b'\x0b25000 \x0b100000',0),('unicode-trim','\u200725000 \u3000100000\u0085'.encode(),0)):
        corpus.case('cpu-'+label,before=changed_file('cpu.max',value),initial_error=expected)
    for label,value,expected in (('max',b'2147483648',0),('above',b'2147483649',6),('zero',b'0',6),
                                 ('unicode','\u0085+1024\u3000'.encode(),0),('overflow',b'18446744073709551616',6)):
        corpus.case('memory-'+label,before=changed_file('memory.max',value),initial_error=expected)
    for label,value,expected in (('one',b'1',0),('above',b'257',6),('zero',b'0',6)):
        corpus.case('pids-'+label,before=changed_file('pids.max',value),initial_error=expected)
    corpus.case('burst-plus-zero-refused',before=changed_file('cpu.max.burst',b'+0'),initial_error=6)
    corpus.case('swap-leading-zero-refused',before=changed_file('memory.swap.max',b'00'),initial_error=6)
    corpus.case('controller-missing',before=lambda d,p:(d/'controllers').unlink(),initial_error=2)
    def controller_link(d,p):
        (d/'controllers').rename(d/'controller-target');(d/'controllers').symlink_to('controller-target')
    corpus.case('controller-original-follow-link',before=controller_link)
    def parent_file(d,p):
        shutil.rmtree(p);p.write_bytes(b'not directory')
    corpus.case('parent-is-file',before=parent_file,initial_error=1)
    def nondir_no_controller(d,p):
        parent_file(d,p);(d/'controllers').unlink()
    corpus.case('controller-precedes-parent-type',before=nondir_no_controller,initial_error=2)
    corpus.case('initial-parent-mode',before=lambda d,p:p.chmod(0o770),initial_error=1)
    for index,relative in enumerate((Path('sys'),Path('sys/fs'),Path('sys/fs/cgroup'),PARENT)):
        def ancestor(d,p,r=relative):
            original=d/r;target=original.with_name(original.name+'-real');original.rename(target);original.symlink_to(target.name)
        corpus.case(f'ancestor-symlink-{index}',before=ancestor,initial_error=1)
        def ancestor_controller(d,p,mutate=ancestor):
            mutate(d,p);(d/'controllers').unlink()
        corpus.case(f'ancestor-before-controller-{index}',before=ancestor_controller,initial_error=1)
    corpus.case('fresh-parent-new-inode',after=replace_parent,expected=4)
    corpus.case('fresh-parent-mode',after=lambda d,p:p.chmod(0o770),expected=4)
    def fresh_link(d,p):
        old=p.with_name(p.name+'-original');p.rename(old);p.symlink_to(old.name)
    corpus.case('fresh-parent-symlink',after=fresh_link,expected=4)
    corpus.case('fresh-membership-wrong',after=lambda d,p:(d/'membership').write_bytes(b'0::/other\n'),expected=3)
    for name,value in [('cpu.max',b'20000 100000'),('memory.max',b'1024'),('pids.max',b'255')]:
        corpus.case('changed-'+name.replace('.','-'),after=changed_file(name,value),expected=7)
    corpus.case('parsed-equivalent-limits',after=changed_file('cpu.max',b' +25000\t+100000 \r\n'))
    def bad_cpu_missing_pids(d,p):
        (p/'cpu.max').write_bytes(b'bad');(p/'pids.max').unlink()
    corpus.case('read-before-parse-error-order',after=bad_cpu_missing_pids,expected=5)
    def bad_context_missing_limit(d,p):
        (d/'membership').write_bytes(b'broken');(p/'cpu.max').unlink()
    corpus.case('context-before-limits',after=bad_context_missing_limit,expected=3)
    corpus.case('boot-rechecked-next-boundary',gate=1,mutation=lambda d,p:(d/'boot').write_bytes(b'other'),second_error=4)
    corpus.case('gate1-parent-replaced',gate=1,mutation=replace_parent,expected=4)
    corpus.case('gate2-relative-fd-final-fence',gate=2,mutation=replace_parent,expected=4)
    corpus.case('gate3-final-fence',gate=3,mutation=replace_parent,expected=4)
    corpus.case('gate3-parse-before-fence',after=changed_file('cpu.max',b'bad'),gate=3,mutation=replace_parent,expected=6)
    corpus.case('gate4-fence-before-changed-limits',after=changed_file('memory.max',b'1024'),gate=4,mutation=replace_parent,expected=4)
    corpus.case('gate4-symlink',gate=4,mutation=fresh_link,expected=4)


def wait_observation(predicate, label: str, *, timeout: float = 5):
    end = time.monotonic()+timeout
    while time.monotonic() < end:
        value = predicate()
        if value is not None and value is not False:
            return value
        time.sleep(0.001)
    raise RuntimeError('Actual native synchronization not observed: ' + label)


def proc_syscall(pid: int):
    text = Path(f'/proc/{pid}/syscall').read_text().strip()
    parts = text.split()
    if len(parts) < 7 or parts[0] == 'running':
        return None
    try:
        return [int(parts[0])] + [int(part,16) for part in parts[1:7]]
    except ValueError:
        return None


def context_switches(pid: int) -> int:
    text = Path(f'/proc/{pid}/status').read_text()
    return int(re.search(r'^voluntary_ctxt_switches:\s*(\d+)$',text,re.MULTILINE).group(1))


def blocked_resource_read(pid: int, expected_pointer=None):
    call = proc_syscall(pid)
    if call and call[0] == 0 and call[1] >= 3:
        if expected_pointer is None or call[2] == expected_pointer:
            return call
    return None


def signal_cases(corpus: Corpus) -> None:
    for kind in ('open-eintr','read-eintr','physical-short-read'):
        directory = corpus.output/kind;directory.mkdir();provision(directory)
        session = Session(corpus.image,directory)
        writer = None
        try:
            before = session.receipt()
            (directory/'boot').unlink();os.mkfifo(directory/'boot',0o600)
            session.request()
            pid = session.process.pid
            wait_observation(lambda: Path(f'/proc/{pid}/wchan').read_text().strip() == 'wait_for_partner',
                             'open blocked on actual FIFO partner')
            signals = []
            if kind == 'open-eintr':
                switches = context_switches(pid)
                os.kill(pid,signal.SIGUSR1)
                wait_observation(lambda: context_switches(pid) > switches,
                                 'actual signal interruption and open reentry')
                wait_observation(lambda: Path(f'/proc/{pid}/wchan').read_text().strip() == 'wait_for_partner',
                                 'FIFO open reentered after signal')
                signals.append({'signal':'SIGUSR1','blocked_open_observed':True})
            writer = os.open(directory/'boot',os.O_WRONLY | os.O_NONBLOCK)
            first = wait_observation(lambda: blocked_resource_read(pid),'actual blocking read')
            observations = [first]
            if kind == 'read-eintr':
                switches = context_switches(pid)
                os.kill(pid,signal.SIGUSR1)
                wait_observation(lambda: context_switches(pid) > switches,'signal return and read reentry')
                wait_observation(lambda: blocked_resource_read(pid,first[2]),'same unconsumed read after EINTR')
                signals.append({'signal':'SIGUSR1','blocked_read_observed':True})
            if kind == 'physical-short-read':
                pointer = first[2]
                for chunk in (b'b',b'oo',b't-identity\n'):
                    require(os.write(writer,chunk) == len(chunk),'Actual fixture write was short')
                    pointer += len(chunk)
                    observations.append(wait_observation(lambda p=pointer:blocked_resource_read(pid,p),
                                                         'read pointer advanced by actual chunk length'))
            else:
                require(os.write(writer,b'boot-identity\n') == 14,'Actual FIFO input was short')
            os.close(writer);writer=None
            final = session.receipt()
            if kind.endswith('eintr'):
                require(final['EINTR'] > before['EINTR'],'Native EINTR was not observed')
            else:
                require(final['reads']-before['reads'] == 16,'Three positive FIFO reads and EOF were not counted')
                require(final['positive_short_reads']-before['positive_short_reads'] == 9,'Actual positive partial reads differ')
            row=session.finish();row.update(name=kind,actual_syscall_observations=observations,signals=signals)
            write_json(directory/'synchronization.json',{'syscalls':observations,'signals':signals})
            corpus.rows.append(row)
        except BaseException as error:
            session.abort(type(error).__name__+': '+str(error));raise
        finally:
            if writer is not None:os.close(writer)


def protocol_and_allocation_cases(corpus: Corpus) -> None:
    for label, payload in (
        ('count-zero',struct.pack('<QQQ',0,0,4096)),
        ('count-over',struct.pack('<QQQ',1000001,0,4096)),
        ('gate-over',struct.pack('<QQQ',1,5,4096)),
        ('chunk-zero',struct.pack('<QQQ',1,0,0)),
        ('chunk-over',struct.pack('<QQQ',1,0,4097)),
    ):
        directory=corpus.output/label;directory.mkdir();provision(directory)
        session=Session(corpus.image,directory)
        try:
            session.receipt();session.write(payload);session.receipt(11)
            row=session.finish(11);row['name']=label;corpus.rows.append(row)
        except BaseException as error:
            session.abort(str(error));raise
    for number in (1,2,3,4):
        directory=corpus.output/f'gate-{number}-eof';directory.mkdir();provision(directory)
        session=Session(corpus.image,directory)
        try:
            session.receipt();session.request(gate=number);session.gate(number)
            session.process.stdin.close();session.process.stdin=None
            session.receipt(9)
            out,err=session.process.communicate(timeout=5)
            require(not out and not err and session.process.returncode==73,'Gate EOF must keep first CONTROL error')
            row=session.save('PASS');row['name']=directory.name;corpus.rows.append(row)
        except BaseException as error:
            session.abort(str(error));raise
    directory=corpus.output/'actual-mremap-allocation-failure';directory.mkdir();provision(directory)
    (directory/'boot').write_bytes(b'x'*524289)
    session=Session(corpus.image,directory,address_limit=1048576)
    try:
        receipt=session.receipt(10)
        require(receipt['state_capacity'] < 1048576 and receipt['read_bytes'] > 8192,
                'Actual state-growth failure and consumed prefix must be observed')
        row=session.finish(10);row.update(name=directory.name,rlimit_as_bytes=1048576)
        corpus.rows.append(row)
    except BaseException as error:
        session.abort(str(error));raise


def malicious_source(canonical: bytes, command: list[int], *, unterminated=False) -> bytes:
    entries=list(re.finditer(rb'^fn ([A-Za-z_][A-Za-z_0-9]*)\(',canonical,re.MULTILINE))
    helper=[]
    for index,entry in enumerate(entries):
        if entry.group(1) in (b'host_read',b'host_put'):
            end=entries[index+1].start() if index+1<len(entries) else len(canonical)
            helper.append(canonical[entry.start():end])
    require(len(helper)==2,'Actual canonical word helper inventory differs')
    lines=['hia-asm.v1 hepta.hia.program.v8 trnm_host_actual_adapter_negative',
           'fn f0(e:readbuf,c:mutbuf,s:mutbuf) -> (u32) effects(read,write,trap) entry(entry)',
           'block entry(e:readbuf,c:mutbuf,s:mutbuf)',
           '  off:u64 = const() {"value":8}',
           '  phase:u64 = call(e,off) {"function":"host_read"}',
           '  zero:u64 = const() {"value":0}',
           '  first:bool = compare.eq(phase,zero)',
           '  branch first bad(c) later(c,phase)',
           'block bad(cbad:mutbuf)']
    def put(buf,offset,value,label):
        lines.extend([f'  off_{label}:u64 = const() {{"value":{offset}}}',
                      f'  val_{label}:u64 = const() {{"value":{value}}}',
                      f'  out_{label}:u64 = call({buf},off_{label},val_{label}) {{"function":"host_put"}}'])
    for index,value in enumerate(command):put('cbad',index*8,value,'bad'+str(index))
    if unterminated:
        lines.extend(['  p:usize = const() {"value":128}',
                      '  n:usize = const() {"value":256}',
                      '  x:u8 = const() {"value":120}',
                      '  _ = buffer.fill_range(cbad,p,n,x)'])
    else:
        put('cbad',128,int.from_bytes(b'/absent\0','little'),'path')
    lines.extend(['  issue:u32 = const() {"value":0}','  ret(issue)',
                  'block later(clater:mutbuf,oldphase:u64)',
                  '  one:u64 = const() {"value":1}',
                  '  second:bool = compare.eq(oldphase,one)',
                  '  branch second escaped(clater) done()',
                  'block escaped(cescape:mutbuf)'])
    for index,value in enumerate([1,1,128,8,0,0,0,2,2]):put('cescape',index*8,value,'escaped'+str(index))
    put('cescape',128,int.from_bytes(b'ESCAPE!!','little'),'marker')
    lines.extend(['  again:u32 = const() {"value":0}','  ret(again)',
                  'block done()','  terminal:u32 = const() {"value":128}','  ret(terminal)','end'])
    return ('\n'.join(lines)+'\n').encode()+b''.join(helper)


def adapter_cases(build: Build, output: Path) -> list[dict]:
    from hia.platform.build import run_native
    cwd=output/'adapter-negatives';cwd.mkdir()
    def command(nr,a=0,b=0,c=0,d=0,e=0,f=0,mask=0):return [nr,a,b,c,d,e,f,mask,1]
    cases={
        'unknown-syscall':command(39),
        'command-header-read':command(0,0,0,1,mask=2),
        'command-overrun-read':command(0,0,4095,2,mask=2),
        'state-header-read':command(0,0,0,1,mask=128),
        'state-overrun-read':command(0,0,8191,2,mask=128),
        'zero-read':command(0,0,128,0,mask=2),
        'oversize-read':command(0,0,4096,4097,mask=128),
        'read-pointer-wrap':command(0,0,18446744073709551615,1,mask=128),
        'write-nonstdio':command(1,3,128,1,mask=2),
        'writable-open':command(257,18446744073709551516,128,524289,mask=2),
        'relative-context-open':command(257,3,128,524288,mask=2),
        'invalid-canonical-dirfd':command(257,2,128,2818048,mask=2),
        'unterminated-path':command(257,18446744073709551516,128,524288,mask=2),
        'fstat-overrun':command(5,3,4090,mask=2),
        'clock-overrun':command(228,1,4090,mask=2),
        'unsupported-clock':command(228,0,768,mask=2),
        'stat-unsupported-flags':command(262,18446744073709551516,128,512,4096,mask=6),
        'wrong-pointer-mask':command(228,1,768,mask=0),
        'close-stdio':command(3,0),
    }
    original=command(25,0,8192,16384,1)
    for name,index,value in [('foreign-base',1,1),('wrong-old-size',2,4096),('wrong-new-size',3,32768),
                             ('wrong-flags',4,3),('new-address',5,4096),('extra-argument',6,1),('pointer-mask',7,128)]:
        values=original.copy();values[index]=value;cases['mremap-'+name]=values
    rows=[]
    for name,values in cases.items():
        source=malicious_source(build.host_sources['owner_policy.hepta'],values,unterminated=name=='unterminated-path')
        (cwd/(name+'.hepta')).write_bytes(source)
        build.core_check(source)
        policy=build.stage(build.compiler,source,'compile-adapter-'+name)
        image,identity=build.pack(policy,'emit-adapter-'+name)
        stdout,receipt=run_native(image,b'x',cwd,name)
        require(receipt['exit_code']==88 and not receipt['timed_out'] and not stdout and not receipt['stderr_hex'],
                'Native adapter did not reject before issuing forbidden command: '+name)
        rows.append({'name':name,'status':'PASS','command':values,'source_sha256':sha256(source),
                     'image':identity,'native':receipt,'finite_qualification_only':True})
    return rows


def audit_trace(text: str, *, expected_checks: int, expected_error: int,
                growing: bool = False) -> dict:
    """Independent strace syntax/FD/order checks, never a synthetic execution proof."""
    calls=[]
    active={}
    opened=[]
    groups=[]
    current=None
    canonical=[]
    initial_metadata=[]
    before_boot=True
    writes=0
    growth=0
    permitted={'execve','mmap','mremap','rt_sigaction','rt_sigreturn','getuid','gettid',
               'clock_gettime','openat','read','write','close','fstat','newfstatat','exit'}
    for raw in text.splitlines():
        line=re.sub(r'^\s*(?:\[pid\s+\d+\]|\d+)\s+','',raw).strip()
        if not line or line.startswith(('---','+++')):
            continue
        if line.startswith('exit('):
            require(not active,'Native exit retained resource descriptors')
            continue
        match=re.fullmatch(r'([a-zA-Z0-9_]+)\((.*)\)\s+=\s+(-?\d+|0x[0-9a-fA-F]+)(?:\s+.*)?',line)
        require(match is not None,'Unparsed or unfinished independent syscall: '+line)
        name,args,value=match.groups();result=int(value,0)
        require(name in permitted,'Unexpected native syscall: '+name)
        call={'name':name,'args':args,'result':result}
        calls.append(call)
        if name=='mmap':
            require('PROT_EXEC' not in args and 'MAP_PRIVATE' in args and 'MAP_ANONYMOUS' in args,
                    'Unexpected native memory mapping')
        elif name=='mremap':
            require('MREMAP_MAYMOVE' in args and 'MREMAP_FIXED' not in args,
                    'Unexpected state mapping flags')
            growth+=1
        elif name=='rt_sigaction':
            require(args.startswith(('SIGPIPE,','SIGUSR1,')),'Unexpected process signal mutation')
        elif name=='openat':
            fields=re.fullmatch(r'([^,]+), "([^\"]*)", (.*)',args)
            require(fields is not None,'Unexpected openat path syntax')
            dirfd,spelling,flags=fields.groups()
            require(not any(flag in flags for flag in ('O_WRONLY','O_RDWR','O_CREAT','O_TRUNC','O_APPEND')),
                    'Resource file was opened writable')
            require('O_CLOEXEC' in flags,'Resource open omitted CLOEXEC')
            if dirfd=='AT_FDCWD':
                path=spelling
            else:
                number=int(dirfd)
                require(number in active,'Relative open lacks current captured directory')
                path=str(Path(active[number])/spelling)
            call.update(path=path,spelling=spelling,flags=flags)
            if before_boot and spelling!='boot':
                require('O_PATH' in flags and 'O_NOFOLLOW' in flags,'Canonical ancestor walk was not no-follow')
                canonical.append(spelling)
                if spelling != 'trnmponpublic.slice':
                    require('O_DIRECTORY' in flags,'Canonical ancestor was not a directory open')
            if spelling=='boot':
                before_boot=False
                if current is not None:
                    groups.append(current)
                current=[]
            if spelling in LIMITS:
                require('O_NOFOLLOW' in flags and 'O_NONBLOCK' in flags and dirfd!='AT_FDCWD',
                        'Limit open lost bounded relative no-follow profile')
            if spelling==str(PARENT):
                require('O_PATH' in flags and 'O_DIRECTORY' in flags and 'O_NOFOLLOW' in flags,
                        'Fresh parent open lost original search-only no-follow profile')
            if result>=0:
                require(result not in active,'Native open reused an unclosed descriptor')
                active[result]=path;opened.append(path)
        elif name in ('read','write','close','fstat'):
            head=args.split(',',1)[0]
            require(re.fullmatch(r'\d+',head) is not None,'Unexpected descriptor syntax')
            number=int(head)
            if name=='write':
                require(number in (1,2),'Write escaped standard observation descriptors')
                require(not active,'Native receipt was issued before resource FD cleanup')
                writes+=1
            elif name=='read' and number==0:
                pass
            else:
                require(number in active,'Native descriptor action has no fresh open')
                call['path']=active[number]
                if name=='close':
                    del active[number]
        elif name=='newfstatat':
            fields=re.fullmatch(r'AT_FDCWD, "([^\"]*)", (.*), ([^,]*)',args)
            require(fields is not None,'Unexpected metadata path syntax')
            path,metadata,flags=fields.groups()
            require(path in ('controllers',str(PARENT)),'Unexpected metadata path')
            if path==str(PARENT):
                require('AT_SYMLINK_NOFOLLOW' in flags,'Final identity fence followed a link')
            else:
                require(flags=='0','Controller test must preserve original follow semantics')
            call.update(path=path,flags=flags)
            if before_boot:
                initial_metadata.append(call)
        if current is not None and name in ('openat','read','close','fstat','newfstatat'):
            if name!='read' or not args.startswith('0,'):
                current.append(call)
    require(bool(calls) and not active and writes>0,'Incomplete native trace or missing output')
    require(calls[0]['name']=='execve' and calls[0]['result']==0
            and calls[0]['args'].startswith('"/proc/self/fd/')
            and sum(call['name']=='execve' for call in calls)==1,
            'Independent native trace lacks the exact sealed-image exec boundary')
    if current is not None:
        groups.append(current)
    expected_canonical=['.','sys','fs','cgroup','trnmponpublic.slice']
    if expected_error==1:
        require(canonical and canonical==expected_canonical[:len(canonical)] and len(canonical)<=5,
                'Ancestor refusal did not occur during the actual canonical walk')
        require(not groups,'Ancestor refusal reached boot/resource authority')
        require(not initial_metadata,'Ancestor refusal reached controller or parent metadata')
    else:
        require(canonical==expected_canonical,'Complete initial fixed-path walk was not observed')
        require([call['path'] for call in initial_metadata]==['controllers',str(PARENT)]
                and all(call['result']==0 for call in initial_metadata),
                'Original controller-before-parent metadata acquisition order differs')
    if expected_error==5:
        require(len(groups)==1,'Initial final-limit refusal reached a later full check')
        failed=[call for call in groups[0] if call['name']=='openat' and call['result']<0]
        require(len(failed)==1 and failed[0]['spelling']=='pids.max',
                'Trace did not observe the actual last-limit I/O failure')
        for name in list(LIMITS)[:-1]:
            reads=[call for call in groups[0] if call['name']=='read'
                   and call.get('path')==str(PARENT/name)]
            require(len(reads)>=2 and reads[-1]['result']==0,
                    'Earlier limit was not fully read before the final I/O refusal')
    completed=[]
    for group in groups[1:]:
        order=[c['spelling'] for c in group if c['name']=='openat']
        require(order==['boot',str(PARENT),'membership',*LIMITS],
                'Fresh checkpoint open order differs')
        for path in ('boot','membership',*[str(PARENT/name) for name in LIMITS]):
            reads=[c for c in group if c['name']=='read' and c.get('path')==path]
            require(len(reads)>=2 and reads[-1]['result']==0
                    and all(c['result']>0 for c in reads[:-1]),'Stream was not freshly read through EOF: '+path)
        stats=[c.get('path') for c in group if c['name']=='fstat']
        require(stats==[str(PARENT),*[str(PARENT/name) for name in LIMITS]],'Fresh metadata association differs')
        fence=[index for index,c in enumerate(group) if c['name']=='newfstatat' and c['path']==str(PARENT)]
        require(len(fence)==1 and group[fence[0]]['result']==0,'Missing successful final parent fence')
        eof=max(index for index,c in enumerate(group) if c['name']=='read')
        require(fence[0]>eof,'Final path fence preceded complete limit reads')
        closing=group[fence[0]+1:]
        require(len(closing)==1 and closing[0]['name']=='close' and closing[0]['path']==str(PARENT),
                'Current parent was not closed immediately after final fence')
        if not growing:
            require(len(group)==37,'Normal fresh check omitted or repeated a core syscall')
        completed.append({'core_syscalls':len(group),'streams_through_EOF':7,'relative_limits':5,'final_fence':True})
    require(len(completed)==expected_checks,'Independent complete-check count differs')
    if growing:
        require(growth>0,'Actual growing context trace lacked native mremap')
    return {'status':'PASS','actual_trace_required_by_caller':True,
            'syscalls':len(calls),'checks':completed,'canonical_walk':canonical,
            'mremap_calls':growth,'all_resource_FDs_closed':True,'resource_writes':0}


def independent_trace(build: Build, output: Path) -> dict:
    executable=shutil.which('strace')
    if executable is None:
        return {'status':'UNKNOWN','reason':'Independent strace is unavailable'}
    root=output/'independent-trace';root.mkdir()
    rows=[]
    for name,error,count,growing in [('fresh-checks',0,2,False),('ancestor-link',1,0,False),
                                      ('last-limit-unavailable',5,0,False),('growing-context',0,1,True)]:
        directory=root/name;directory.mkdir();parent=provision(directory)
        if error==1:
            (directory/'sys').rename(directory/'sys-real');(directory/'sys').symlink_to('sys-real')
        if error==5:
            (parent/'pids.max').unlink()
        if growing:
            (directory/'boot').write_bytes(b'x'*131073+b'\n')
        fd=sealed_executable(build.fixture_executable,'hia-host-independent-trace')
        command=[executable,'-f','-qq','-s','256','-o',str(directory/'syscalls.raw'),'/proc/self/fd/'+str(fd)]
        payload=struct.pack('<QQQ',count,0,4096) if count else b''
        try:
            process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,cwd=directory,pass_fds=(fd,),
                                     start_new_session=True)
            try:
                stdout,stderr=process.communicate(payload,timeout=15)
            except BaseException:
                if process.poll() is None:
                    os.killpg(process.pid,signal.SIGKILL)
                process.communicate()
                raise
        finally:
            os.close(fd)
        (directory/'stdout.raw').write_bytes(stdout);(directory/'stderr.raw').write_bytes(stderr)
        text=(directory/'syscalls.raw').read_text()
        row={'name':name,'argv':command,'exit_code':process.returncode,'stdout_sha256':sha256(stdout),
             'stderr_sha256':sha256(stderr),'trace_sha256':sha256(text.encode()),
             'executable_sha256':sha256(build.fixture_executable),'native_source_inputs':build.source_inputs}
        rows.append(row)
        if b'Operation not permitted' in stderr and not stdout and not text:
            row['status']='UNKNOWN'
            write_json(directory/'result.json',row)
            return {'status':'UNKNOWN','reason':'Actual PTRACE_TRACEME refused by execution environment',
                    'observations':rows,'synthetic_trace_substituted':False}
        try:
            require(not stderr and process.returncode==(64+error if error else 0),
                    'Independent traced native process did not complete as expected')
            expected_size=128 if error else 256
            require(len(stdout)==expected_size,'Traced native output size differs')
            result=dict(zip(FIELDS,struct.unpack('<16Q',stdout[-128:])))
            require(result['magic']==MAGIC and result['fixture']==1 and result['error']==error,
                    'Traced native receipt differs')
            row['audit']=audit_trace(text,expected_checks=count+1 if not error else 0,
                                     expected_error=error,growing=growing)
            row['status']='PASS'
        except BaseException as error_detail:
            row.update(status='FAIL',failure=type(error_detail).__name__+': '+str(error_detail))
            write_json(directory/'result.json',row)
            return {'status':'FAIL','observations':rows,'synthetic_trace_substituted':False}
        write_json(directory/'result.json',row)
    return {'status':'PASS','observations':rows,'synthetic_trace_substituted':False}


def production_observation(build: Build, output: Path) -> dict:
    from hia.platform.build import run_native
    stdout,row=run_native(build.executable,b'',output,'actual-production-fixed-parent')
    require(len(stdout)==128 and not row['timed_out'] and not row['stderr_hex'],
            'Production owner did not complete an actual initial observation')
    result=dict(zip(FIELDS,struct.unpack('<16Q',stdout)))
    require(result['magic']==MAGIC and result['fixture']==0,'Wrong production observation identity')
    require(row['exit_code']==(64+result['error'] if result['error'] else 0),'Production exit does not match receipt')
    return {'status':'PASS' if result['error']==0 else 'ACTUAL_REFUSAL',
            'fixed_parent_positive':result['error']==0,'receipt':result,'native':row}


def run(output: Path, require_trace: bool) -> dict:
    build = Build(output/'build')
    built = build.build()
    corpus = Corpus(build.fixture_executable,output/'physical')
    report = {'schema':'trnm.hia.fresh-host-qualification.v2','status':'FAIL',
              'build':built,'cases':corpus.rows,'whole_hia_node':'OPEN',
              'original_4s_16_worker_service_budget':'OPEN',
              'resource_counter_sampler':'OPEN','production_fixed_parent_positive':False,
              'previous_candidate_results_inherited':False,
              'independent_syscall_trace':{'status':'UNKNOWN','reason':'not executed'},
              'require_trace':require_trace}
    try:
        physical_cases(corpus)
        signal_cases(corpus)
        protocol_and_allocation_cases(corpus)
        report['adapter_negative_cases'] = adapter_cases(build,output)
        report['actual_production_observation'] = production_observation(build,output)
        report['production_fixed_parent_positive'] = report['actual_production_observation']['fixed_parent_positive']
        report['independent_syscall_trace'] = independent_trace(build,output)
        build.check_pin()
        report['physical_cases_passed'] = len(corpus.rows)
        report['physical_cases_failed'] = 0
        trace=report['independent_syscall_trace']['status']
        require(trace!='FAIL','Independent actual syscall trace failed validation')
        require(not require_trace or trace=='PASS','Required independent syscall trace is not qualified')
        report['status']='PASS'
        report['physical_total']=len(corpus.rows)+len(report['adapter_negative_cases'])
    except BaseException as error:
        report['failure'] = type(error).__name__+': '+str(error)
    write_json(output/'report.json',report)
    return report

def main() -> int:
    if not __debug__:
        raise RuntimeError('Host qualification refuses optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--require-trace', action='store_true')
    args = parser.parse_args()
    output = new_output(args.output)
    result = run(output,args.require_trace)
    print(json.dumps({'status':result['status'],'cases':len(result['cases']),
                      'failure':result.get('failure'),'report':str(output/'report.json')}))
    return 0 if result['status'] == 'PASS' else 1

if __name__ == '__main__':
    raise SystemExit(main())
