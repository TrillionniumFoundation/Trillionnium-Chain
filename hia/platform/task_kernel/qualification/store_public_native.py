"""Qualification-only calls and observations of the real native public ABI."""
from pathlib import Path
import concurrent.futures,ctypes,json,struct,threading
ROOT=Path(__file__).resolve().parents[4]
STATE_NAMES={2:'capability',3:'session',4:'task',5:'bid',6:'lease',7:'escrow',44:'nonce_lane',45:'account',47:'bond'}
class Native:
    def __init__(self,path):
        self.lib=ctypes.CDLL(str(path));self.objects={};self.getters=0;self.calls=0;self.counter_lock=threading.Lock()
        self.exports=json.loads((ROOT/'hia/platform/task_kernel/store_owned_exports.json').read_text())['exports']
        for forbidden in ['f0','trnm_task_owner_new','trnm_task_owner_invoke','trnm_task_step_0','trnm_task_dispatch_private']:
            try:getattr(self.lib,forbidden)
            except AttributeError:pass
            else:raise AssertionError('Private ABI exported: '+forbidden)
        self.functions={}
    def fn(self,name,args):
        if name not in self.functions:
            f=getattr(self.lib,'trnm_task_'+name);f.argtypes=args;f.restype=ctypes.c_uint64;self.functions[name]=f
        return self.functions[name]
    def kind(self,p):
        with self.counter_lock:self.getters+=1
        return self.fn('owned_kind',[ctypes.c_void_p])(p)
    def scalar(self,name,p):
        out=ctypes.c_uint64(0xdeadbeef)
        with self.counter_lock:self.getters+=1
        assert self.fn(name,[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint64)])(p,ctypes.byref(out))==0
        return out.value
    def view(self,name,p,receipt_count=False):
        q=ctypes.c_void_p();n=ctypes.c_uint64()
        with self.counter_lock:self.getters+=1
        assert self.fn(name,[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(ctypes.c_uint64)])(p,ctypes.byref(q),ctypes.byref(n))==0
        return ctypes.string_at(q,n.value*(180 if receipt_count else 1)),n.value
    def pack(self,p):
        kind=self.kind(p)
        if kind==1:data=b''
        elif kind==2:
            data=self.view('readback_context',p)[0]+struct.pack('<H',self.scalar('readback_schema',p))+self.view('readback_store_id',p)[0]
            data+=struct.pack('<2Q',self.scalar('readback_sequence',p),self.scalar('readback_order_height',p))
            for field in ['order_block_id','state_root','journal_root','committed_block_root']:data+=self.view('readback_'+field,p)[0]
        elif kind==3:data=bytes([self.scalar('outcome_is_replay',p)])+self.view('outcome_receipt',p)[0]
        elif kind==4:
            data=struct.pack('<Q',self.scalar('preview_source_sequence',p))
            for field in ['source_state_root','source_journal_root','candidate_post_state_root']:data+=self.view('preview_'+field,p)[0]
            receipts,count=self.view('preview_candidate_receipts',p,True);data+=struct.pack('<Q',count)+receipts+self.view('preview_unchanged_inventory',p)[0]
        elif kind==5:data=self.view('confirmed_receipt',p)[0]
        elif kind==255:
            code=self.scalar('error_code',p);message=self.view('error_message',p)[0];display=self.view('error_display',p)[0]
            data=struct.pack('<4Q',code,len(message),len(display),0)+message+display
        else:data=self.view(STATE_NAMES[kind-100]+'_state_bytes',p)[0]
        return 'V|'+str(kind)+'|'+data.hex()
    def drop(self,p):
        with self.counter_lock:self.calls+=1
        assert self.fn('owned_drop',[ctypes.c_void_p])(p)==0
    def run(self,parts):
        action=parts[0]
        if action=='drop':self.drop(self.objects.pop(parts[1]));return 'D'
        if action=='observe':return self.pack(self.objects[parts[1]])
        if action=='equal':
            with self.counter_lock:self.calls+=1
            value=ctypes.c_uint64(99);assert self.fn('readback_equal',[ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint64)])(self.objects[parts[1]],self.objects[parts[2]],ctypes.byref(value))==0
            return 'S|'+str(value.value)
        if action=='parallel':
            owner=self.objects[parts[1]];threads=int(parts[2]);repeats=int(parts[3])
            f=self.fn('store_fresh_readback',[ctypes.c_void_p,ctypes.POINTER(ctypes.c_void_p)])
            def worker(_):
                rows=[]
                for _ in range(repeats):
                    with self.counter_lock:self.calls+=1
                    result=ctypes.c_void_p();code=f(owner,ctypes.byref(result));assert code==0 and result.value
                    try:rows.append(self.pack(result.value))
                    finally:self.drop(result.value)
                return rows
            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:rows=list(pool.map(worker,range(threads)))
            return 'P|'+';'.join(x for row in rows for x in row)
        assert parts[1] not in self.objects
        with self.counter_lock:self.calls+=1
        held=[]
        def bytesarg(value):
            raw=bytes.fromhex(value);p=ctypes.create_string_buffer(raw);held.append((p,raw));return p,len(raw)
        out=ctypes.c_void_p(0xdeadbeef);pointer=ctypes.POINTER(ctypes.c_void_p);void=ctypes.c_void_p;u64=ctypes.c_uint64
        if action in ['open','existing']:
            raw,n=bytesarg(parts[2]);name='store_open' if action=='open' else 'store_open_existing';code=self.fn(name,[void,u64,pointer])(raw,n,ctypes.byref(out))
        elif action in ['clone','fresh','error_clone']:
            name={'clone':'store_clone','fresh':'store_fresh_readback','error_clone':'error_clone'}[action]
            code=self.fn(name,[void,pointer])(self.objects[parts[2]],ctypes.byref(out))
        elif action=='execute':
            ex,n=bytesarg(parts[3]);cmd,m=bytesarg(parts[4]);code=self.fn('store_execute',[void,void,u64,void,u64,pointer])(self.objects[parts[2]],ex,n,cmd,m,ctypes.byref(out))
        elif action in ['empty','confirm']:
            data,n=bytesarg(parts[3]);name='store_advance_empty' if action=='empty' else 'store_confirm_receipt';code=self.fn(name,[void,void,u64,pointer])(self.objects[parts[2]],data,n,ctypes.byref(out))
        elif action=='preview':
            block,_=bytesarg(parts[5]);commands,n=bytesarg(parts[6]);code=self.fn('store_preview',[void,void,u64,void,void,u64,pointer])(self.objects[parts[2]],self.objects[parts[3]],int(parts[4]),block,commands,n,ctypes.byref(out))
        elif action=='state':
            name='store_'+STATE_NAMES[int(parts[3])]+'_state';ident,_=bytesarg(parts[4]);code=self.fn(name,[void,void,pointer])(self.objects[parts[2]],ident,ctypes.byref(out))
        else:raise AssertionError(action)
        assert code==0 and out.value not in (None,0xdeadbeef),(action,code,out.value)
        self.objects[parts[1]]=out.value
        for p,raw in held:
            assert p.raw[:len(raw)]==raw,'Native input mutated'
            ctypes.memset(p,0xa5,len(p))
        return self.pack(out.value)
    def close(self):
        for p in list(self.objects.values()):self.drop(p)
        self.objects.clear()

