"""Native cached execution against the independent scalar state transition/root.

The inherited scenario supplies signed real commands; it is not learned-model evidence.
Each process is owned from spawn and closed on errors, timeout and teardown.
"""
from __future__ import annotations
import copy,json,os,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
from ledger import *
from native_session import NativeExecutionSession,FramedProcess
import test_native_execution as scenarios
BINARY=Path(os.environ.get('TRNM_SESSION_BINARY',str(Path(os.environ.get('CARGO_TARGET_DIR',ROOT/'trillionnium/target'))/'release/examples/pon_execute_session')))
class NativeSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BINARY.is_file():raise RuntimeError('Build the native session; no skipped pass')
    def test_all_twelve_tags_run_in_1_2_4_8_worker_persistent_sessions(self):
        case=scenarios.NativeExecutionTests('test_all_twelve_tags_match_for_1_2_4_8_workers');case.setUp()
        sessions={n:NativeExecutionSession(BINARY)for n in [1,2,4,8]}
        def run_block(fixture,txs,advance=1):
            fixture.height+=advance;parent=H('transition-parent',u64(fixture.height));before=copy.deepcopy(fixture.state)
            expected,receipts=execute_reference(fixture.state,txs,fixture.height,public(key(0)),parent)
            fixture.tags.update(tx_decode(raw)['tag']for raw in txs)
            for n,session in sessions.items():
                actual,observed,metrics=session.execute(fixture.state,txs,fixture.height,public(key(0)),parent,n)
                self.assertEqual(actual,expected);self.assertEqual(observed,receipts)
                self.assertLessEqual(metrics['commitment_nodes'],2*len(actual)-1)
                fixture.last_metrics[n]=metrics
            self.assertEqual(fixture.state,before);fixture.state=expected
        case.run_block=types.MethodType(run_block,case)
        try:
            case.test_all_twelve_tags_match_for_1_2_4_8_workers()
            self.assertEqual(case.tags,set(range(1,13)))
            self.assertTrue(all(s.reset_count==1 for s in sessions.values()))
        finally:
            for s in sessions.values():s.close()
    def test_exact_repeat_is_pure_cache_and_parent_switch_rebuilds(self):
        s=NativeExecutionSession(BINARY);initial=genesis_state()
        try:
            tx=sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=7))
            a=s.execute(initial,[tx],1,public(key(0)),GENESIS,4);pid=s.process.child.pid
            self.assertEqual(s.sequence,1)
            b=s.execute(initial,[tx],1,public(key(0)),GENESIS,4)
            self.assertEqual(a[:2],b[:2]);self.assertTrue(b[2]['request_cache_hit']);self.assertEqual(b[2]['bridge_request_bytes'],0);self.assertEqual(b[2]['bridge_response_bytes'],0);self.assertEqual(s.sequence,1);self.assertEqual(s.process.child.pid,pid)
            a[0]['meta:issued']=0
            self.assertNotEqual(s.execute(initial,[tx],1,public(key(0)),GENESIS,4)[0]['meta:issued'],0)
            expected,_=execute_reference(initial,[],1,public(key(1)),GENESIS)
            c=s.execute(initial,[],1,public(key(1)),GENESIS,4)
            self.assertEqual(c[0],expected);self.assertEqual(s.reset_count,2)
        finally:s.close()
    def test_bad_signature_closes_cache_and_never_changes_parent(self):
        state=genesis_state();before=copy.deepcopy(state);s=NativeExecutionSession(BINARY)
        tx=bytearray(sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=7)));tx[-1]^=1
        try:
            with self.assertRaisesRegex(ValueError,'SIGNATURE'):s.execute(state,[bytes(tx)],1,public(key(0)),GENESIS,8)
            self.assertEqual(state,before);self.assertIsNone(s.process)
            actual=s.execute(state,[],1,public(key(0)),GENESIS,8)
            self.assertEqual(actual[0],execute_reference(state,[],1,public(key(0)),GENESIS)[0])
        finally:s.close()
    def test_tampered_delta_reply_rejects_and_reaps_child(self):
        s=NativeExecutionSession(BINARY);state=genesis_state();before=copy.deepcopy(state)
        original=s._exchange
        def altered(message):
            result=original(message)
            if result.get('op')=='executed':result['changes'][-1]['before_present']=not result['changes'][-1]['before_present']
            return result
        try:
            with patch.object(s,'_exchange',altered),self.assertRaisesRegex(ValueError,'SESSION_BEFORE'):
                s.execute(state,[],1,public(key(0)),GENESIS,1)
            self.assertEqual(state,before);self.assertIsNone(s.process)
        finally:s.close()
    def test_wrong_sequence_does_not_advance_native_state(self):
        s=NativeExecutionSession(BINARY);state=genesis_state()
        try:
            s._open(state);root=state_root(state).hex()
            bad=s._exchange(dict(op='execute',sequence=99,root=root,transactions=[],height=1,miner=public(key(0)).hex(),parent=GENESIS.hex(),workers=1))
            self.assertEqual(bad,{'op':'rejected','error':'SESSION_PREDECESSOR','root':root,'sequence':0})
            self.assertEqual(s.execute(state,[],1,public(key(0)),GENESIS,1)[0],execute_reference(state,[],1,public(key(0)),GENESIS)[0])
        finally:s.close()
    def test_duplicate_json_unknown_field_and_float_fail_closed(self):
        state=genesis_state();valid=dict(op='open',network=NETWORK.hex(),parameters=PARAMETER_HASH.hex(),state=state,root=state_root(state).hex())
        duplicate=canonical(valid)[:-1]+b',"op":"open"}'
        for raw in [duplicate,canonical(dict(valid,extra=1)),b'{"op":"open","n":1.5}']:
            process=FramedProcess([str(BINARY)])
            try:
                with self.assertRaises(ValueError):process.exchange(raw)
                self.assertIsNotNone(process.child.poll())
            finally:process.close()
    def test_null_is_not_absence_and_unchanged_null_survives(self):
        state=genesis_state();state['fixture:null']=None;s=NativeExecutionSession(BINARY)
        try:
            actual=s.execute(state,[],1,public(key(0)),GENESIS,2)[0]
            self.assertIn('fixture:null',actual);self.assertIsNone(actual['fixture:null'])
            self.assertEqual(state_root(actual),state_root(execute_reference(state,[],1,public(key(0)),GENESIS)[0]))
        finally:s.close()
    def test_real_ledger_make_admit_recover_uses_explicit_native_session(self):
        with tempfile.TemporaryDirectory()as d,patch.dict(os.environ,{'TRNM_NATIVE_SESSION':str(BINARY),'TRNM_EXECUTION_WORKERS':'8'}):
            ledger=Ledger(d)
            try:
                tx=sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=3))
                h,t,p=ledger.make(GENESIS,[tx]);bid=ledger.admit(h,t,p,PARAMS['genesis_timestamp']+1000)
                self.assertIsNotNone(ledger.native_session)
                self.assertEqual(ledger.native_session.sequence,1)
                ledger.recover();self.assertEqual(ledger.active()[0],bid)
                self.assertEqual(state_root(ledger.read_active()[2]),header_decode(h)['state'])
            finally:ledger.close()
    def test_missing_session_binary_is_not_reference_fallback(self):
        with tempfile.TemporaryDirectory()as d,patch.dict(os.environ,{'TRNM_NATIVE_SESSION':'/absent/pon-session'}):
            ledger=Ledger(d)
            try:
                with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):ledger.make(GENESIS,[])
            finally:ledger.close()
class SessionBoundaryTests(unittest.TestCase):
    def test_exact_predecessor_memo_does_not_skip_returned_root_verification(self):
        session=NativeExecutionSession(BINARY)
        try:
            first=session.execute(genesis_state(),[],1,public(key(0)),GENESIS)[0]
            with patch('native_session.state_root',wraps=state_root) as recompute:
                actual=session.execute(first,[],2,public(key(0)),H('next-parent'))
                self.assertEqual(recompute.call_count,1)
                self.assertEqual(recompute.call_args.args[0],actual[0])
            self.assertEqual(actual[:2],execute_reference(first,[],2,public(key(0)),H('next-parent')))
        finally:session.close()

    def test_lost_reply_discards_advanced_cache_and_retries_same_input(self):
        state=genesis_state();before=copy.deepcopy(state);session=NativeExecutionSession(BINARY)
        original=session._exchange
        observed=[]
        def lose(message):
            result=original(message)
            if message['op']=='execute':
                observed.append(session.process.child)
                raise OSError('simulated lost reply after native execution')
            return result
        try:
            with patch.object(session,'_exchange',lose),self.assertRaises(OSError):
                session.execute(state,[],1,public(key(0)),GENESIS,4)
            self.assertEqual(state,before);self.assertIsNone(session.process)
            self.assertIsNotNone(observed[0].poll())
            actual=session.execute(state,[],1,public(key(0)),GENESIS,4)
            self.assertEqual(actual[:2],execute_reference(state,[],1,public(key(0)),GENESIS))
            self.assertEqual(session.reset_count,2)
        finally:session.close()

    def test_boolean_sequence_alias_is_rejected_on_open_and_execute(self):
        for operation in ['open','execute']:
            with self.subTest(operation=operation):
                session=NativeExecutionSession(BINARY);original=session._exchange
                def altered(message):
                    result=original(message)
                    if message['op']==operation:result['sequence']=bool(result['sequence'])
                    return result
                try:
                    with patch.object(session,'_exchange',altered),self.assertRaisesRegex(ValueError,'CONTEXT|PREDECESSOR'):
                        session.execute(genesis_state(),[],1,public(key(0)),GENESIS)
                    self.assertIsNone(session.process)
                finally:session.close()

    def test_boolean_before_value_does_not_alias_integer_zero(self):
        session=NativeExecutionSession(BINARY);original=session._exchange;state=genesis_state()
        state['meta:issued']=0
        for name,value in state.items():
            if name.startswith('account:'):value['balance']=0
        def altered(message):
            result=original(message)
            if message['op']=='execute':
                item=next(c for c in result['changes'] if c['key']=='meta:issued')
                self.assertEqual(item['before'],0);item['before']=False
            return result
        try:
            with patch.object(session,'_exchange',altered),self.assertRaisesRegex(ValueError,'SESSION_BEFORE'):
                session.execute(state,[],1,public(key(0)),GENESIS)
            self.assertIsNone(session.process)
        finally:session.close()

    def test_type_distinct_predecessor_reopens_instead_of_python_equality(self):
        session=NativeExecutionSession(BINARY);state=genesis_state();state['fixture:type']=True
        try:
            first=session.execute(state,[],1,public(key(0)),GENESIS)[0]
            second=copy.deepcopy(first);second['fixture:type']=1
            self.assertEqual(first,second);self.assertNotEqual(state_root(first),state_root(second))
            actual=session.execute(second,[],2,public(key(0)),H('other-parent'))
            self.assertEqual(actual[:2],execute_reference(second,[],2,public(key(0)),H('other-parent')))
            self.assertEqual(session.reset_count,2)
        finally:session.close()

    def test_receipt_count_metrics_and_delta_order_substitution_reject(self):
        def reverse(r):r['changes'].reverse()
        def receipts(r):r['receipts']=['00']
        def metrics(r):r['metrics']['signature_verifications']=True
        def sequence(r):r['sequence']=True
        def nan(r):r['metrics']['state_root_ns']='NaN'
        for mutate in [reverse,receipts,metrics,sequence,nan]:
            with self.subTest(mutate=mutate.__name__):
                session=NativeExecutionSession(BINARY);original=session._exchange
                def altered(message):
                    result=original(message)
                    if message['op']=='execute':mutate(result)
                    return result
                try:
                    with patch.object(session,'_exchange',altered),self.assertRaises(ValueError):
                        session.execute(genesis_state(),[],1,public(key(0)),GENESIS)
                    self.assertIsNone(session.process)
                finally:session.close()

    def test_multiple_selected_backends_reject_before_starting_cache(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{
            'TRNM_NATIVE_SESSION':str(BINARY),'TRNM_NATIVE_EXECUTOR':'/explicit/other-backend'}):
            ledger=Ledger(d)
            try:
                with self.assertRaisesRegex(ValueError,'NATIVE_BACKEND_CONFLICT'):ledger.make(GENESIS,[])
                self.assertIsNone(ledger.native_session)
                self.assertEqual(ledger.active()[0],GENESIS)
            finally:ledger.close()

    def test_changed_selected_binary_cannot_reuse_previous_success(self):
        with tempfile.TemporaryDirectory() as d,patch.dict(os.environ,{'TRNM_NATIVE_SESSION':str(BINARY)}):
            ledger=Ledger(d)
            try:
                ledger.make(GENESIS,[]);child=ledger.native_session.process.child
                with patch.dict(os.environ,{'TRNM_NATIVE_SESSION':'/absent/changed-backend'}):
                    with self.assertRaisesRegex(ValueError,'UNAVAILABLE'):ledger.make(GENESIS,[])
                self.assertIsNotNone(child.poll())
                self.assertIsNone(ledger.native_session)
            finally:ledger.close()

    def test_client_pages_confirm_and_reorg_with_explicit_session_after_restart(self):
        from client_confirmation import history_pages,receive_page,confirmation
        with tempfile.TemporaryDirectory() as a,tempfile.TemporaryDirectory() as b,patch.dict(os.environ,{
                'TRNM_NATIVE_SESSION':str(BINARY),'TRNM_EXECUTION_WORKERS':'8'}):
            source,receiver=Ledger(a),Ledger(b);now=PARAMS['genesis_timestamp']+10000
            try:
                tx=sign(key(0),1,'transfer',dict(recipient=public(key(1)),amount=3))
                hb,txs,proof=source.make(GENESIS,[tx]);included=source.admit(hb,txs,proof,now);source.recover()
                tip=included
                for _ in range(PARAMS['confirmation_depth']):
                    hb,txs,proof=source.make(tip,[]);tip=source.admit(hb,txs,proof,now);source.recover()
                cursor=GENESIS
                for raw in history_pages(source,tip,blocks_per_page=2):
                    result=receive_page(receiver,raw,expected_tip=tip,after=cursor,observed_now=now)
                    cursor=bytes.fromhex(result['next_after'])
                    receiver.close();receiver=Ledger(b);receiver.recover()
                observed=confirmation(receiver,H('tx-id',tx),included,observed_now=now)
                self.assertEqual(observed['status'],'confirmed');self.assertFalse(observed['finalized'])
                fork=GENESIS
                for _ in range(PARAMS['confirmation_depth']+2):
                    hb,txs,proof=source.make(fork,[],miner=public(key(1)))
                    fork=source.admit(hb,txs,proof,now);source.recover()
                cursor=GENESIS
                for raw in history_pages(source,fork,blocks_per_page=2):
                    result=receive_page(receiver,raw,expected_tip=fork,after=cursor,observed_now=now)
                    cursor=bytes.fromhex(result['next_after'])
                self.assertEqual(confirmation(receiver,H('tx-id',tx),included,observed_now=now)['status'],'reorged')
                self.assertEqual(receiver.active()[0],fork)
                self.assertEqual(state_root(receiver.read_active()[2]),source.block(fork)[6])
            finally:source.close();receiver.close()

class FramedProcessTests(unittest.TestCase):
    def test_invalid_timeout_and_limit_fail_before_process_creation(self):
        for options in [{'timeout':float('nan')},{'timeout':float('inf')},{'timeout':True},{'limit':True},{'limit':2**31}]:
            with patch('native_session.subprocess.Popen',side_effect=AssertionError('must not spawn')),self.assertRaisesRegex(ValueError,'SESSION_ARGUMENT'):
                FramedProcess([sys.executable,'-c','pass'],**options)

    def test_response_size_and_timeout_reap_owned_process(self):
        cases=[('import os;os.write(1,(2**31).to_bytes(4,"big"))',2,'FRAME_LIMIT'),
               ('import time;time.sleep(60)',.1,'TIMEOUT')]
        for code,timeout,message in cases:
            child=FramedProcess([sys.executable,'-c',code],timeout=timeout)
            with self.assertRaisesRegex(ValueError,message):child.exchange(b'{}')
            self.assertTrue(child.closed);self.assertIsNotNone(child.child.poll())
    def test_stderr_flood_is_bounded_and_owned(self):
        child=FramedProcess([sys.executable,'-c','import os,time;os.write(2,b"x"*70000);time.sleep(60)'],timeout=2)
        with self.assertRaisesRegex(ValueError,'STDERR_LIMIT'):child.exchange(b'{}')
        self.assertLessEqual(len(child.stderr),65537);self.assertIsNotNone(child.child.poll())
if __name__=='__main__':unittest.main(verbosity=2)
