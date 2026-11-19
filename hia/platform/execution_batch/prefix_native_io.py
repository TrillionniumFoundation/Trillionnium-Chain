"""Bounded observation of a real persistent native TransactionPrefix process."""
from pathlib import Path
import fcntl,hashlib,json,os,selectors,signal,struct,subprocess,time,traceback
U64=(1<<64)-1
def need(c,m):
    if not c:raise ValueError(m)
def identity(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def save(path,row):path.write_text(json.dumps(row,sort_keys=True,indent=2)+'\n')
def parse(raw,sequence,opcode):
    need(len(raw)>=256 and raw[:8]==b'PXOUT001','prefix output magic')
    h=struct.unpack('<32Q',raw[:256])
    need(h[1:3]==(sequence,opcode) and h[3] in (1,2,3,4),'prefix response identity/class')
    need(raw[216:256]==bytes(40),'prefix reserved output')
    need(len(raw)==256+h[18]+h[16]+h[17]+h[15],'complete prefix output extent')
    at=256;context=raw[at:at+h[18]];at+=h[18];held=raw[at:at+h[16]];at+=h[16];state=raw[at:at+h[17]];at+=h[17]
    receipts=[]
    for _ in range(h[14]):
        need(at+8<=len(raw),'receipt word');n=struct.unpack_from('<Q',raw,at)[0];at+=8
        need(n<=len(raw)-at,'receipt bytes');receipts.append(raw[at:at+n].hex());at+=n
    need(at==len(raw),'no receipt suffix')
    if context:
        need(len(context)>=576 and context[:4]==b'SDO1' and struct.unpack_from('<I',context,4)[0]==len(context),'complete internal context')
        need(context[8:16]==bytes(8) and context[468:480]==bytes(12),'context reserved')
        ec,sc,pl,ml,sl=struct.unpack_from('<5I',context,448)
        need((ec,sc)==(3,7) and 576+pl+ml+sl==len(context),'context selected constructor')
    if h[3]!=1:need(not state and raw[168:200]==bytes(32),'rejected prefix has no successor')
    if opcode==4:need(h[25]==0 and not held and not state,'closed prefix publishes no live state')
    return {'header':list(h),'context_hex':context.hex(),'held_state_hex':held.hex(),'state_hex':state.hex(),'receipts':receipts,'root_hex':raw[168:200].hex()}
class Session:
    def __init__(self,directory,elf):
        self.directory=Path(directory);self.directory.mkdir(mode=0o700)
        self.elf=elf;self.start=time.monotonic_ns();self.deadline=time.monotonic()+240
        self.streams={n:bytearray() for n in ('stdin','stdout','stderr','progress','replies')}
        self.commands=[];self.events=[];self.pending=bytearray();self.out=bytearray();self.child=None;self.handles=[];self.poller=None;self.finished=False;self.last_sequence=0
        self.image=os.memfd_create('hia-private-transaction-prefix',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING);self.handles.append(self.image)
        at=0
        while at<len(elf):
            n=os.write(self.image,elf[at:]);need(n>0,'ELF actual write');at+=n
        os.fchmod(self.image,0o500);fcntl.fcntl(self.image,getattr(fcntl,'F_ADD_SEALS',1033),15)
        self.pr,self.gw=os.pipe();self.handles.extend((self.pr,self.gw));self.gr,self.reply=os.pipe();self.handles.extend((self.gr,self.reply))
        self.child=subprocess.Popen(['/proc/self/fd/'+str(self.image)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(self.image,self.gw,self.gr),close_fds=True,env={'PATH':''},start_new_session=True)
        for fd in (self.gw,self.gr):os.close(fd);self.handles.remove(fd)
        self.poller=selectors.DefaultSelector()
        for name,fd in (('stdout',self.child.stdout.fileno()),('stderr',self.child.stderr.fileno()),('progress',self.pr)):
            os.set_blocking(fd,False);self.poller.register(fd,selectors.EVENT_READ,name)
        os.set_blocking(self.child.stdin.fileno(),False);os.set_blocking(self.reply,False)
    def write(self,fd,raw,name):
        at=0
        while at<len(raw):
            need(time.monotonic()<self.deadline,'actual prefix 240-second process budget')
            try:n=os.write(fd,raw[at:])
            except BlockingIOError:time.sleep(.002);continue
            need(n>0,'actual pipe write');self.streams[name].extend(raw[at:at+n]);at+=n
    def request(self,opcode,*,state=b'',transactions=(),height=10,timestamp=None,miner=bytes([1])*32,parent_id=bytes([2])*32,gate=None):
        need(not self.finished,'active prefix process')
        self.last_sequence+=1;sequence=self.last_sequence
        if opcode==1:
            need(len(miner)==len(parent_id)==32,'context hash lengths')
            frame=b'PFXREQ01'+struct.pack('<7Q',opcode,sequence,height,int(timestamp is not None),0 if timestamp is None else timestamp,self.gw,self.gr)+miner+parent_id+struct.pack('<2Q',len(state),0)+state
        else:frame=b'PFXREQ01'+struct.pack('<7Q',opcode,sequence,0,0,0,self.gw,self.gr)+bytes(64)+struct.pack('<2Q',0,len(transactions) if opcode==2 else 0)+b''.join(struct.pack('<Q',len(tx))+tx for tx in transactions)
        intended=struct.pack('<Q',len(frame))+frame
        begin={n:len(v) for n,v in self.streams.items()};event_begin=len(self.events)
        began=time.monotonic_ns();self.write(self.child.stdin.fileno(),intended,'stdin')
        next_progress=1;total=None
        while True:
            need(time.monotonic()<self.deadline,'actual prefix process exceeded 240 seconds')
            if len(self.out)>=256 and total is None:
                need(self.out[:8]==b'PXOUT001','actual output framing')
                h=struct.unpack('<32Q',self.out[:256]);total=256+h[18]+h[16]+h[17]+h[15]
            if total is not None and len(self.out)>=total:
                raw=bytes(self.out[:total]);del self.out[:total]
                need(not self.out,'no unsolicited successor')
                result=parse(raw,sequence,opcode)
                row={'sequence':sequence,'opcode':opcode,'result':result,'events':self.events[event_begin:],
                    'elapsed_ns':time.monotonic_ns()-began,'input':identity(intended),'output':identity(raw),
                    'stream_ranges':{n:[begin[n],len(v)] for n,v in self.streams.items()}}
                self.commands.append(row);save(self.directory/('command-'+str(sequence).zfill(4)+'.json'),row)
                return result
            need(self.child.poll() is None or any(key.data=='stdout' for key in self.poller.get_map().values()),'native prefix exited before complete response: '+str(self.child.returncode))
            for key,_ in self.poller.select(.02):
                try:raw=os.read(key.fd,65536)
                except BlockingIOError:continue
                if not raw:self.poller.unregister(key.fd);continue
                self.streams[key.data].extend(raw)
                if key.data=='stderr':raise ValueError('unexpected native stderr')
                if key.data=='stdout':self.out.extend(raw);continue
                self.pending.extend(raw)
                while len(self.pending)>=64:
                    record=bytes(self.pending[:64]);del self.pending[:64]
                    p=struct.unpack('<8Q',record)
                    need(record[:8]==b'PXPROG01' and p[1]==sequence and p[2]==0 and p[3]==next_progress and p[7]==0,'actual progress identity')
                    need(p[4] in (1,2,10,11,12,13,14,15,16,17),'actual fixed progress method')
                    next_progress+=1
                    event={'sequence':p[3],'kind':p[4],'index':p[5],'height':p[6],'observed_monotonic_ns':time.monotonic_ns(),'raw_hex':record.hex()}
                    classification,token,delta=(0,0,0) if gate is None else gate(event)
                    reply=b'PXGO0001'+struct.pack('<5Q',sequence,0,p[3]+delta,classification,token)
                    self.write(self.reply,reply,'replies')
                    event['reply_hex']=reply.hex();event['replied_monotonic_ns']=time.monotonic_ns();self.events.append(event)
    def finish(self,error=None):
        if self.finished:raise ValueError('one final process record')
        self.finished=True;cleanup=[];failure=None if error is None else {'error':repr(error)}
        if self.child is not None:
            try:
                self.child.stdin.close()
                if error is None:self.child.wait(timeout=3)
                elif self.child.poll() is None:os.killpg(self.child.pid,signal.SIGKILL);self.child.wait(timeout=3)
            except BaseException as caught:
                cleanup.append(repr(caught))
                if self.child.poll() is None:
                    try:os.killpg(self.child.pid,signal.SIGKILL);self.child.wait(timeout=3)
                    except BaseException as caught:cleanup.append(repr(caught))
            for name,stream in (('stdout',self.child.stdout),('stderr',self.child.stderr)):
                try:
                    while True:
                        try:raw=os.read(stream.fileno(),65536)
                        except BlockingIOError:break
                        if not raw:break
                        self.streams[name].extend(raw)
                except BaseException as caught:cleanup.append(repr(caught))
                stream.close()
        if self.poller is not None:self.poller.close()
        for fd in self.handles:
            try:os.close(fd)
            except BaseException as caught:cleanup.append(repr(caught))
        for name,raw in self.streams.items():(self.directory/(name+'.raw')).write_bytes(raw)
        status='PASS' if failure is None and not cleanup and self.child is not None and self.child.returncode==0 else 'FAIL'
        report={'schema':'trnm.transaction-prefix-native-process.v1','status':status,'failure':failure,'cleanup_errors':cleanup,'pid':None if self.child is None else self.child.pid,
            'exit_code':None if self.child is None else self.child.returncode,'elapsed_ns':time.monotonic_ns()-self.start,'wall_limit_seconds':240,'cleanup_limit_seconds':3,'executable':identity(self.elf),'commands':self.commands,
            'streams':{n:identity(raw) for n,raw in self.streams.items()},'events':self.events}
        save(self.directory/'report.json',report);return report
