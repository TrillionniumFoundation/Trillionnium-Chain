"""Real native process and Linux failure observations; no queue or lease execution model."""
from pathlib import Path
import hashlib,json,os,re,select,signal,struct,subprocess,sys,time,traceback
from .cases import command,envelope
from .native_io import parse
from .contract import identity,need,write_json,file_identity
from hia.platform.build import sealed_executable

def frame(c):
    b=bytes.fromhex(c['input']);return struct.pack('<Q',len(b))+b

def run_physical(binary,output,check_sources):
    out=Path(output);out.mkdir(mode=0o700)
    need(__debug__ and not os.environ.get('PYTHONOPTIMIZE'),'Optimized Python is not admitted')
    observer=Path('/usr/bin/strace')
    observer_before=file_identity(observer)
    check_sources()
    rows=[];report={'schema':'trnm.mempool-native-process-physical.v1','status':'FAIL','executable':identity(binary),'controls':rows,'native_test_traits_only':True,'node_or_persistent_pool_authority_claimed':False,'kernel_injected_enomem_is_real_host_exhaustion':False}
    def run(name,payload,code,replies,*,mode='normal',inject=None,trace=False,releases=None,diagnostic=True):
        directory=out/name;directory.mkdir();(directory/'stdin.raw').write_bytes(payload)
        fd=sealed_executable(binary,'m05-physical');argv=['/proc/self/fd/'+str(fd)];files=[];pre=None
        std={'stdin':subprocess.PIPE,'stdout':subprocess.PIPE,'stderr':subprocess.PIPE}
        if mode.endswith('-regular'):
            which=mode.split('-')[0];p=directory/('regular-'+which+'.bin')
            if which=='stdin':p.write_bytes(payload);f=p.open('rb')
            else:f=p.open('xb')
            files.append(f);std[which]=f
        elif mode=='alias-output':std['stderr']=subprocess.STDOUT
        elif mode.startswith('nonblocking-'):
            n={'stdin':0,'stdout':1,'stderr':2}[mode.split('-')[1]]
            pre=lambda:os.set_blocking(n,False)
        if trace or inject:
            argv=['/usr/bin/strace','-qq','-f','-xx','-s','128','-o',str(directory/'syscalls.raw'),'-e','trace=read,write,mmap,mremap,mprotect,munmap,fstat,fcntl,rt_sigaction,exit,exit_group']+(['-e','inject='+inject] if inject else [])+argv
        start=time.monotonic_ns();cleanup=None
        try:p=subprocess.Popen(argv,**std,preexec_fn=pre,cwd=directory,env={'PATH':''},pass_fds=(fd,),start_new_session=True)
        finally:os.close(fd)
        try:stdout,stderr=p.communicate(None if std['stdin']!=subprocess.PIPE else payload,timeout=30)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid,signal.SIGKILL);stdout,stderr=p.communicate(timeout=3);cleanup='SIGKILL_TIMEOUT'
        for f in files:f.close()
        stdout=stdout or b'';stderr=stderr or b''
        (directory/'stdout.raw').write_bytes(stdout);(directory/'stderr.raw').write_bytes(stderr)
        row={'name':name,'status':'FAIL','pid':p.pid,'exit_code':p.returncode,'cleanup':cleanup,'elapsed_ns':time.monotonic_ns()-start,'actual_syscall_injection':inject,'mode':mode,'files':{n:identity((directory/n).read_bytes()) for n in ('stdin.raw','stdout.raw','stderr.raw')}};rows.append(row)
        if trace or inject:row['syscall_trace']=identity((directory/'syscalls.raw').read_bytes())
        (directory/'receipt.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
        assert p.returncode==code and cleanup is None,row
        actual=parse(stdout);assert len(actual)==replies,(name,len(actual),replies)
        if code==0:assert stderr==b'',(name,stderr)
        elif diagnostic:
            assert len(stderr)>=32 and stderr[:8]==b'MTFAIL01',(name,stderr)
            err,closed,n=struct.unpack_from('<3Q',stderr,8);assert err==code and len(stderr)==32+16*n
            events=[list(struct.unpack_from('<2Q',stderr,32+16*i)) for i in range(n)]
            row['cleanup_status']=closed;row['actual_native_cleanup_events']=events
            if releases is not None:assert closed==0 and events==[[15,x] for x in releases],(name,closed,events)
        else:assert stderr==b'' and stdout==b''
        row.update(status='PASS',returned_commands=len(actual),actual_semantic=actual)
        (directory/'receipt.json').write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
        return row
    initial=frame(command(0,2,0,2<<20));pending=frame(envelope(3,tag=177,body=b'held'));close=frame(command(22));stats=frame(command(8))
    try:
        run('clean-exact-close',initial+pending+stats+close,0,4)
        run('eof-before-first-command',b'',74,0)
        for n in range(1,8):run('partial-length-'+str(n),struct.pack('<Q',40)[:n],74,0)
        run('zero-frame',struct.pack('<Q',0),64,0)
        run('signed-overflow-frame',struct.pack('<Q',1<<63),64,0)
        run('unknown-op-after-pending',initial+pending+frame(command(24)),64,2,releases=[177])
        wrong=bytearray(frame(command(8)));wrong[8]=0
        run('bad-magic-after-pending',initial+pending+wrong,64,2,releases=[177])
        run('unexpected-eof-releases-once',initial+pending,74,2,releases=[177])
        for n in (0,39,40,319,320):run('partial-body-after-pending-'+str(n),initial+pending+frame(envelope(digest=2))[:8+n],74,2,releases=[177])
        bad=bytearray(frame(envelope(digest=2)));struct.pack_into('<Q',bad,8+192,22)
        run('malformed-adapter-error-after-pending',initial+pending+bad,64,2,releases=[177])
        run('trailing-after-close-refuses-final-publication',initial+pending+close+b'x',74,2)
        run('constructor-capacity-arithmetic-overflow',frame(command(0,(1<<64)-1,0,32)),72,0)
        for mode in ('stdin-regular','stdout-regular','stderr-regular','alias-output','nonblocking-stdin','nonblocking-stdout','nonblocking-stderr'):
            run('refuse-'+mode,initial+close,64,0,mode=mode,diagnostic=False)
        large=frame(envelope(4,digest=2,tag=188,body=bytes(range(256))*4097))
        actual=run('actual-moving-mremap-with-owned-bodies',initial+pending+large+frame(command(6))+frame(command(11,1))+close,0,6,trace=True)
        trace=(out/actual['name']/'syscalls.raw').read_text()
        moves=re.findall(r'mremap\((0x[0-9a-f]+),\s*(\d+),\s*(\d+),\s*MREMAP_MAYMOVE\)\s*=\s*(0x[0-9a-f]+)',trace)
        assert moves and any(a!=b for a,old,new,b in moves),moves
        actual['observed_mremaps']=[list(x) for x in moves]
        for ordinal in (1,2,3):
            row=run('actual-enomem-mremap-'+str(ordinal),initial+pending+large+close,72,2,inject=f'mremap:error=ENOMEM:when={ordinal}',releases=[177])
            assert re.search(r'mremap\([^\n]*\)\s*=\s*-1 ENOMEM[^\n]*INJECTED',(out/row['name']/'syscalls.raw').read_text())
        for syscall in ('read','write'):
            row=run('actual-eintr-'+syscall,initial+pending+stats+close,0,4,inject=syscall+':error=EINTR:when=1')
            assert row['actual_semantic']==rows[0]['actual_semantic']
            assert 'EINTR' in (out/row['name']/'syscalls.raw').read_text() and 'INJECTED' in (out/row['name']/'syscalls.raw').read_text()
        run('actual-read-eio-releases-once',initial+pending+stats+close,74,2,inject='read:error=EIO:when=5',releases=[177])
        run('actual-input-mprotect-eacces-releases-once',initial+pending+stats+close,72,2,inject='mprotect:error=EACCES:when=5',releases=[177])
        # Close the actual output consumer only after the pending lease exists.
        directory=out/'actual-closed-output-consumer';directory.mkdir();fd=sealed_executable(binary,'m05-closed-consumer')
        try:p=subprocess.Popen(['/proc/self/fd/'+str(fd)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},pass_fds=(fd,),start_new_session=True,bufsize=0)
        finally:os.close(fd)
        def read_exact(n):
            result=b'';until=time.monotonic()+5
            while len(result)<n:
                assert select.select([p.stdout],[],[],max(0,until-time.monotonic()))[0],'Native pipe timeout'
                data=os.read(p.stdout.fileno(),n-len(result));assert data,'Native EOF';result+=data
            return result
        stdout=b'';sent=b'';stderr=b''
        try:
            stdout=b'';sent=b''
            for payload in (initial,pending):
                sent+=payload;assert p.stdin.write(payload)==len(payload)
                header=read_exact(8);body=read_exact(struct.unpack('<Q',header)[0]);stdout+=header+body
            p.stdout.close();sent+=stats;assert p.stdin.write(stats)==len(stats);p.stdin.close()
            assert select.select([p.stderr],[],[],5)[0]
            stderr=b'';until=time.monotonic()+5
            while True:
                assert select.select([p.stderr],[],[],max(0,until-time.monotonic()))[0],'Cleanup stderr deadline'
                block=os.read(p.stderr.fileno(),4096)
                if not block:break
                stderr+=block
                assert len(stderr)<=4096,'Unbounded cleanup diagnostic'
            p.stderr.close();p.wait(timeout=3)
            assert p.returncode==74 and stderr[:8]==b'MTFAIL01' and struct.unpack('<3Q',stderr[8:32])==(74,0,1) and struct.unpack('<2Q',stderr[32:])==(15,177)
            for name,raw in (('stdin.raw',sent),('stdout.raw',stdout),('stderr.raw',stderr)):(directory/name).write_bytes(raw)
            rows.append({'name':directory.name,'status':'PASS','exit_code':p.returncode,'pid':p.pid,'returned_commands':2,'actual_native_cleanup_events':[[15,177]],'actual_consumer_closed_after_pending':True,'files':{n:identity((directory/n).read_bytes()) for n in ('stdin.raw','stdout.raw','stderr.raw')}})
        finally:
            for suffix,observed in (('stdin.raw',sent),('stdout.raw',stdout),('stderr.raw',stderr)):
                path=directory/suffix
                if not path.exists():path.write_bytes(observed)
            if p.poll() is None:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                p.wait(timeout=3)
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream is not None and not stream.closed:stream.close()
        report.update(status='PASS',actual_native_processes=len(rows),actual_completed_commands=sum(r['returned_commands'] for r in rows))
        need(len(rows)==38,'Incomplete physical control set')
        report['strace']=observer_before
        check_sources()
        return report
    except BaseException as error:report['failure']={'error':repr(error),'traceback':traceback.format_exc()};raise
    finally:
        failure=None
        try:
            check_sources()
            need(file_identity(observer)==observer_before,'Syscall observer changed')
            report['source_after']='MATCH'
        except BaseException as error:
            failure=error;report['source_after']='FAIL';report['status']='FAIL';report['source_failure']=repr(error)
        write_json(out/'report.json',report)
        if failure is not None:raise failure


# Independent replay of the already observed bytes.  This code never executes
# the owner, strace, or a semantic queue implementation.
def _same_value(left, right):
    return json.dumps(left, sort_keys=True, separators=(",", ":")) == json.dumps(right, sort_keys=True, separators=(",", ":"))

def _reply(op, counts=(0, 0, 0), *, events=(), handle=0, present=0,
           fresh=(1, 1), limit=2 << 20, outcome=0, reason=0, metadata=None, headroom=None):
    result = {"op": op, "outcome": outcome, "reason": reason, "present": present,
        "handle": handle, "counts": list(counts), "streak": 0,
        "max_body_bytes": limit, "fresh": list(fresh), "events": [list(x) for x in events]}
    if metadata is not None:
        result["metadata"] = metadata
    if headroom is not None:
        result["headroom"] = list(headroom)
    return result

def _admit_events():
    return [[n, 0] for n in range(1, 9)] + [[9, 1], [12, 1], [11, 1]]

def _metadata(digest=1, body=b"held"):
    return {"digest": digest.to_bytes(32, "little").hex(), "signer": (7).to_bytes(32, "little").hex(),
        "nonce": 1, "fee_limit": "0", "max_gas": 1, "max_bytes": len(body), "body": body.hex()}

def physical_specifications():
    """The fixed existing 38 controls, reconstructed from their bound inputs."""
    initial = frame(command(0, 2, 0, 2 << 20))
    pending = frame(envelope(3, tag=177, body=b"held"))
    close = frame(command(22)); stats = frame(command(8))
    first = _reply(0)
    second = _reply(3, (1, 0, 1), events=_admit_events())
    prefix = [first, second]
    clean = prefix + [_reply(8, (1, 0, 1), headroom=(1, 0, 1)),
        _reply(22, events=((15, 177),), fresh=(0, 0))]
    specs = []
    def add(name, payload, code, expected=(), *, mode="normal", inject=None,
            trace=False, cleanup=71, releases=(), consumed=None, closed=False):
        specs.append({"name": name, "stdin": payload, "exit": code, "expected": list(expected),
            "mode": mode, "injection": inject, "trace": trace or inject is not None,
            "diagnostic": code != 0 and mode == "normal", "cleanup": cleanup,
            "releases": [list(x) for x in releases], "consumed": consumed, "closed": closed})
    add("clean-exact-close", initial + pending + stats + close, 0, clean)
    add("eof-before-first-command", b"", 74)
    for n in range(1, 8):
        add("partial-length-" + str(n), struct.pack("<Q", 40)[:n], 74)
    add("zero-frame", struct.pack("<Q", 0), 64)
    add("signed-overflow-frame", struct.pack("<Q", 1 << 63), 64)
    add("unknown-op-after-pending", initial + pending + frame(command(24)), 64, prefix,
        cleanup=0, releases=((15, 177),))
    wrong = bytearray(frame(command(8))); wrong[8] = 0
    add("bad-magic-after-pending", initial + pending + wrong, 64, prefix, cleanup=0, releases=((15, 177),))
    add("unexpected-eof-releases-once", initial + pending, 74, prefix, cleanup=0, releases=((15, 177),))
    for n in (0, 39, 40, 319, 320):
        add("partial-body-after-pending-" + str(n), initial + pending + frame(envelope(digest=2))[:8+n],
            74, prefix, cleanup=0, releases=((15, 177),))
    bad = bytearray(frame(envelope(digest=2))); struct.pack_into("<Q", bad, 8+192, 22)
    add("malformed-adapter-error-after-pending", initial + pending + bad, 64, prefix,
        cleanup=0, releases=((15, 177),))
    add("trailing-after-close-refuses-final-publication", initial + pending + close + b"x", 74, prefix)
    add("constructor-capacity-arithmetic-overflow", frame(command(0, (1 << 64)-1, 0, 32)), 72)
    for mode in ("stdin-regular", "stdout-regular", "stderr-regular", "alias-output",
                 "nonblocking-stdin", "nonblocking-stdout", "nonblocking-stderr"):
        add("refuse-" + mode, initial + close, 64, mode=mode)
    large = frame(envelope(4, digest=2, tag=188, body=bytes(range(256))*4097))
    moved = prefix + [_reply(4, (2, 0, 2), fresh=(0, 0), events=_admit_events()),
        _reply(6, (1, 0, 1), handle=1, present=1, metadata=_metadata()),
        _reply(11, (1, 0, 1), handle=1, present=1, metadata=_metadata()),
        _reply(22, events=((15, 177), (15, 188)), fresh=(0, 0))]
    payload = initial + pending + large + frame(command(6)) + frame(command(11, 1)) + close
    add("actual-moving-mremap-with-owned-bodies", payload, 0, moved, trace=True, consumed=len(payload))
    for ordinal in (1, 2, 3):
        consumed = len(initial + pending) + (8 if ordinal == 1 else len(large))
        add("actual-enomem-mremap-" + str(ordinal), initial + pending + large + close, 72, prefix,
            inject="mremap:error=ENOMEM:when=" + str(ordinal), cleanup=0, releases=((15, 177),),
            consumed=consumed)
    for syscall in ("read", "write"):
        payload = initial + pending + stats + close
        add("actual-eintr-" + syscall, payload, 0, clean, inject=syscall + ":error=EINTR:when=1",
            consumed=len(payload))
    add("actual-read-eio-releases-once", initial + pending + stats + close, 74, prefix,
        inject="read:error=EIO:when=5", cleanup=0, releases=((15, 177),), consumed=len(initial + pending))
    add("actual-input-mprotect-eacces-releases-once", initial + pending + stats + close, 72, prefix,
        inject="mprotect:error=EACCES:when=5", cleanup=0, releases=((15, 177),), consumed=len(initial + pending)+8)
    add("actual-closed-output-consumer", initial + pending + stats, 74, prefix,
        cleanup=0, releases=((15, 177),), closed=True)
    need(len(specs) == 38 and len({s["name"] for s in specs}) == 38, "Physical source roster is incomplete")
    return specs

def _trace_replay(raw, spec, streams):
    """Consume every selected syscall and reconcile each observable pipe prefix."""
    text = raw.decode("ascii", "strict")
    need(text.endswith("\n") and "\r" not in text, "Truncated or noncanonical syscall trace")
    calls = []; tid = None; exited = False; notice = False
    pattern = re.compile(r"(?:\[pid[ \t]+([0-9]+)\]|([0-9]+))[ \t]+([a-z_][a-z0-9_]*)\((.*)\)[ \t]+=[ \t]+(.*)")
    for line in text.splitlines():
        notification = re.fullmatch(r"(?:\[pid[ \t]+([0-9]+)\]|([0-9]+))[ \t]+\+\+\+ exited with ([0-9]+) \+\+\+", line)
        if notification:
            need(exited and not notice and int(notification[1] or notification[2]) == tid
                 and int(notification[3]) == spec["exit"], "Invalid trace exit notification")
            notice = True
            continue
        match = pattern.fullmatch(line)
        need(match is not None and not exited, "Unconsumed syscall trace line")
        current = int(match[1] or match[2])
        need(current > 0 and (tid is None or current == tid), "Unexpected native trace TID")
        tid = current
        name, args, result = match[3], match[4], match[5]
        calls.append((name, args, result))
        if name == "exit":
            need(args == str(spec["exit"]) and result == "?", "Native trace exit differs")
            exited = True
    need(exited and len(calls) >= 17, "Native trace has no complete lifecycle")
    need([x[0] for x in calls[:10]] == ["fstat", "fcntl"] * 3 + ["rt_sigaction"] + ["mmap"] * 3,
         "Native descriptor admission or arena allocation is missing")
    counters = {}; positions = [0, 0, 0]; maps = {}; order = []; removed = []
    injections = []; moves = []; fatal = False; eof = 0
    wanted = None
    if spec["injection"] is not None:
        m = re.fullmatch(r"([a-z]+):error=([A-Z]+):when=([1-9][0-9]*)", spec["injection"])
        need(m is not None, "Invalid bound injection")
        wanted = (m[1], m[2], int(m[3]))
    for index, (name, args, result) in enumerate(calls):
        counters[name] = counters.get(name, 0) + 1
        fault = re.fullmatch(r"-1 ([A-Z][A-Z0-9]+) \([^()\n]*\) \(INJECTED(?:: retval)?\)", result)
        if fault:
            need(wanted == (name, fault[1], counters[name]) and not injections,
                 "Unexpected, repeated or wrong-ordinal injected error")
            injections.append((name, fault[1], counters[name]))
            if fault[1] != "EINTR":
                fatal = True
        else:
            need(not result.startswith("-1") and "INJECTED" not in result, "Unexpected native syscall failure")
        if name == "fstat":
            fd = index // 2
            need(index in (0, 2, 4) and re.fullmatch(str(fd) + r", \{st_mode=S_IFIFO\|0[0-7]{3}, st_size=0, \.\.\.\}", args)
                 and result == "0", "Native stdio type admission differs")
        elif name == "fcntl":
            fd = index // 2
            need(index in (1, 3, 5) and args == str(fd) + ", F_GETFL"
                 and result == ("0 (flags O_RDONLY)" if fd == 0 else "0x1 (flags O_WRONLY)"),
                 "Native stdio access admission differs")
        elif name == "rt_sigaction":
            need(index == 6 and args == "SIGPIPE, {sa_handler=SIG_IGN, sa_mask=[], sa_flags=0}, NULL, 8"
                 and result == "0", "Native SIGPIPE installation differs")
        elif name == "mmap":
            need(index in (7, 8, 9) and args == "NULL, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0"
                 and re.fullmatch(r"0x[0-9a-f]+", result), "Unexpected native arena mapping")
            address = int(result, 16)
            need(address != 0 and address not in maps, "Aliased native arena")
            maps[address] = (4096, "PROT_READ|PROT_WRITE", index-7); order.append(index-7)
        elif name == "mremap":
            m = re.fullmatch(r"(0x[0-9a-f]+), ([0-9]+), ([0-9]+), MREMAP_MAYMOVE", args)
            need(m is not None and not removed, "Unexpected native remapping")
            old, old_size, new_size = int(m[1], 16), int(m[2]), int(m[3])
            need(old in maps and maps[old][0] == old_size and old_size == 4096 and new_size == 2097152
                 and maps[old][2] == counters[name]-1, "Native remap owner/extent differs")
            if not fault:
                need(not fatal and re.fullmatch(r"0x[0-9a-f]+", result), "Invalid native remap result")
                new = int(result, 16)
                need(new != 0 and (new == old or new not in maps), "Native remap aliases an arena")
                extent, protection, owner = maps.pop(old); maps[new] = (new_size, protection, owner)
                moves.append([m[1], m[2], m[3], result])
        elif name == "mprotect":
            m = re.fullmatch(r"(0x[0-9a-f]+), ([0-9]+), (PROT_READ(?:\|PROT_WRITE)?)", args)
            need(m is not None, "Unexpected native memory permission")
            address, extent, protection = int(m[1], 16), int(m[2]), m[3]
            need(address in maps and maps[address][0] == extent, "Native protection has no owned mapping")
            if not fault:
                need(result == "0" and (not fatal or protection == "PROT_READ|PROT_WRITE"),
                     "Native cleanup protection differs")
                maps[address] = (extent, protection, maps[address][2])
        elif name == "munmap":
            m = re.fullmatch(r"(0x[0-9a-f]+), ([0-9]+)", args)
            need(m is not None and result == "0", "Native arena cleanup failed")
            address, extent = int(m[1], 16), int(m[2])
            need(address in maps and maps[address][:2] == (extent, "PROT_READ|PROT_WRITE"),
                 "Native arena cleanup has stale ownership")
            need(maps[address][2] == len(removed), "Native arena cleanup order differs")
            removed.append(maps.pop(address)[2])
        elif name in ("read", "write"):
            m = re.fullmatch(r"([012]), (.*), ([0-9]+)", args)
            need(m is not None and not removed, "Invalid native pipe operation")
            fd, token, requested = int(m[1]), m[2], int(m[3])
            need(requested > 0 and ((name == "read" and fd == 0) or (name == "write" and fd in (1, 2))),
                 "Unexpected native pipe descriptor")
            need(not fatal or fault is not None or (name == "write" and fd == 2),
                 "Native continued public work after terminal fault")
            quoted = re.fullmatch(r'"((?:\\x[0-9a-f]{2})*)"(\.\.\.)?', token)
            if fault:
                need((quoted is not None if name == "write" else re.fullmatch(r"0x[0-9a-f]+", token) is not None),
                     "Injected pipe operation has invalid observation")
                transferred = 0
            else:
                need(re.fullmatch(r"[0-9]+", result) is not None and quoted is not None, "Missing native pipe bytes")
                transferred = int(result)
                need(transferred <= requested and positions[fd] + transferred <= len(streams[fd]),
                     "Native pipe extent exceeds observed bytes")
                if transferred == 0:
                    need(name == "read" and requested == 1 and positions[0] == len(streams[0]),
                         "Unexpected early native EOF")
                    eof += 1
            if quoted is not None:
                dumped = bytes.fromhex(quoted[1].replace("\\x", ""))
                display_extent = requested if name == "write" else transferred
                need(len(dumped) == min(128, display_extent) and bool(quoted[2]) == (display_extent > 128),
                     "Native syscall byte truncation differs")
                need(streams[fd][positions[fd]:positions[fd]+len(dumped)] == dumped,
                     "Native syscall bytes disagree with the actual pipe")
            if not fault:
                positions[fd] += transferred
        elif name == "exit":
            need(index == len(calls)-1 and not maps and removed == [0, 1, 2],
                 "Native process exited before all arenas were retired")
        else:
            need(False, "Unexpected selected native syscall")
    need(injections == ([] if wanted is None else [wanted]), "Mandatory actual injection was not observed")
    need(positions == [spec["consumed"], len(streams[1]), len(streams[2])],
         "Syscall trace did not consume the actual observed pipe extents")
    need(eof == (1 if spec["exit"] == 0 else 0), "Native final EOF proof differs")
    expected_remaps = 3 if spec["name"] == "actual-moving-mremap-with-owned-bodies" else (
        wanted[2] if wanted is not None and wanted[0] == "mremap" else 0)
    need(counters.get("mremap", 0) == expected_remaps, "Actual remap ordinal coverage differs")
    if spec["name"] == "actual-moving-mremap-with-owned-bodies":
        need(len(moves) == 3 and any(a != b for a, old, new, b in moves),
             "No actual arena moved with owned bodies")
    return moves

def verify_physical(output, binary):
    """Validate the full existing physical evidence without re-running native code."""
    from .contract import file_bytes, load_json
    out = Path(output)
    report = load_json(file_bytes(out / "report.json"))
    need(report.get("schema") == "trnm.mempool-native-process-physical.v1"
         and report.get("status") == "PASS" and report.get("source_after") == "MATCH"
         and report.get("executable") == identity(binary)
         and report.get("native_test_traits_only") is True
         and report.get("node_or_persistent_pool_authority_claimed") is False
         and report.get("kernel_injected_enomem_is_real_host_exhaustion") is False,
         "Physical scope, executable or source fence differs")
    specs = physical_specifications(); rows = report.get("controls")
    need(isinstance(rows, list) and [r.get("name") for r in rows] == [s["name"] for s in specs],
         "Physical control roster/order differs")
    need(type(report.get("actual_native_processes")) is int and report["actual_native_processes"] == 38
         and type(report.get("actual_completed_commands")) is int and report["actual_completed_commands"] == 50,
         "Physical declared counts differ")
    observer = report.get("strace")
    need(isinstance(observer, dict) and set(observer) == {"bytes", "sha256"}
         and type(observer["bytes"]) is int and observer["bytes"] > 0
         and re.fullmatch(r"[0-9a-f]{64}", observer["sha256"]) is not None, "Physical strace identity absent")
    files = {"report.json"}; commands = 0; trace_count = 0
    for row, spec in zip(rows, specs, strict=True):
        directory = out / spec["name"]
        need(row.get("status") == "PASS" and type(row.get("pid")) is int and row["pid"] > 0
             and type(row.get("exit_code")) is int and row["exit_code"] == spec["exit"],
             "Physical actual process exit differs")
        streams = [file_bytes(directory / name) for name in ("stdin.raw", "stdout.raw", "stderr.raw")]
        files.update(spec["name"] + "/" + name for name in ("stdin.raw", "stdout.raw", "stderr.raw"))
        need(streams[0] == spec["stdin"] and row.get("files") == dict(zip(
            ("stdin.raw", "stdout.raw", "stderr.raw"), map(identity, streams), strict=True)),
            "Physical source input or full pipe identities differ")
        actual = parse(streams[1])
        need(_same_value(actual, spec["expected"]) and type(row.get("returned_commands")) is int
             and row["returned_commands"] == len(actual), "Physical native response semantics differ")
        commands += len(actual)
        if spec["closed"]:
            need(row.get("actual_consumer_closed_after_pending") is True
                 and set(row) == {"name", "status", "exit_code", "pid", "returned_commands",
                     "actual_native_cleanup_events", "actual_consumer_closed_after_pending", "files"},
                 "Closed-consumer actual operation differs")
        else:
            need(row.get("cleanup") is None and row.get("mode") == spec["mode"]
                 and row.get("actual_syscall_injection") == spec["injection"]
                 and type(row.get("elapsed_ns")) is int and row["elapsed_ns"] > 0
                 and _same_value(row.get("actual_semantic"), actual),
                 "Physical process/observation differs")
            receipt = load_json(file_bytes(directory / "receipt.json"))
            files.add(spec["name"] + "/receipt.json")
            need(_same_value(receipt, {k: v for k, v in row.items() if k != "observed_mremaps"}),
                 "Physical independent receipt differs")
        if spec["diagnostic"]:
            expected = b"MTFAIL01" + struct.pack("<3Q", spec["exit"], spec["cleanup"], len(spec["releases"]))
            expected += b"".join(struct.pack("<2Q", *event) for event in spec["releases"])
            need(streams[2] == expected and _same_value(row.get("actual_native_cleanup_events"), spec["releases"]),
                 "Physical cleanup did not release the exact owned leases once")
            if not spec["closed"]:
                need(type(row.get("cleanup_status")) is int and row["cleanup_status"] == spec["cleanup"],
                     "Physical cleanup status differs")
        else:
            need(streams[2] == b"" and "actual_native_cleanup_events" not in row and "cleanup_status" not in row,
                 "Unexpected physical diagnostics")
        if spec["mode"].endswith("-regular"):
            which = spec["mode"].split("-")[0]; name = "regular-" + which + ".bin"
            need(file_bytes(directory / name) == (spec["stdin"] if which == "stdin" else b""),
                 "Rejected regular stdio was modified")
            files.add(spec["name"] + "/" + name)
        need(("syscall_trace" in row) == spec["trace"], "Physical trace roster differs")
        if spec["trace"]:
            raw = file_bytes(directory / "syscalls.raw"); files.add(spec["name"] + "/syscalls.raw")
            need(identity(raw) == row["syscall_trace"], "Physical trace identity differs")
            moves = _trace_replay(raw, spec, streams); trace_count += 1
            if spec["name"] == "actual-moving-mremap-with-owned-bodies":
                need(_same_value(row.get("observed_mremaps"), moves), "Reported moving arenas differ from syscalls")
            else:
                need("observed_mremaps" not in row, "Unexpected remap summary")
    actual_files = set()
    for path in out.rglob("*"):
        need(not path.is_symlink(), "Symbolic physical evidence path")
        if path.is_dir():
            continue
        file_identity(path); actual_files.add(path.relative_to(out).as_posix())
    need(actual_files == files and trace_count == 8 and commands == 50,
         "Physical evidence inventory or derived coverage differs")
    return report
