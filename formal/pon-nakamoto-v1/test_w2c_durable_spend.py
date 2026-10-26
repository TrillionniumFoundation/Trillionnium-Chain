import tempfile,os,unittest,hmac,hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from contract_wire import H
from w2c_receiver_admission import Grant,solve
from w2c_durable_spend import DurableSpendGate

A=b'A'*32; S=b'S'*32; E=b'E'*32; C=b'C'*32; P=H('test-proposal')

def make(nonce_seed,bits=8,ms=100):
    token=nonce_seed.to_bytes(8,'little')+bytes(24)
    grant=Grant(A,E,H('w2c-stateless-caller-proposal-v1',C,P),token,bits,ms,ms+2000,b'')
    grant=replace(grant,mac=hmac.new(S,grant.unsigned(),hashlib.sha256).digest())
    return grant,solve(grant,cap=262144)[0]

class DurableTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=os.path.join(self.tmp.name,'spent.db')
    def tearDown(self):self.tmp.cleanup()
    def gate(self,**k):return DurableSpendGate(self.path,A,S,E,**k)
    def test_crash_reopen_and_replay(self):
        g,n=make(1);self.assertIsNotNone(n)
        x=self.gate();self.assertEqual(x.consume(g,P,C,n,120),'READY_RESOURCE_ONLY');x.close()
        x=self.gate();self.assertEqual(x.consume(g,P,C,n,130),'REPLAY');x.close()
    def test_parallel_same_host_two_connections(self):
        g,n=make(2);a=self.gate();b=self.gate()
        with ThreadPoolExecutor(max_workers=8) as pool:
            rows=list(pool.map(lambda i:(a if i%2 else b).consume(g,P,C,n,120),range(32)))
        self.assertEqual(rows.count('READY_RESOURCE_ONLY'),1);self.assertEqual(rows.count('REPLAY'),31)
        a.close();b.close()
    def test_price_survives_reopen_and_cannot_rollback(self):
        old,n=make(3);x=self.gate();x.raise_minimum_bits(12)
        self.assertEqual(x.consume(old,P,C,n,130),'PRICE_POLICY');x.close()
        with self.assertRaisesRegex(ValueError,'PRICE_ROLLBACK'):
            self.gate(minimum_bits=8)
        new,m=make(4,12)
        x=self.gate(minimum_bits=12)
        self.assertEqual(x.consume(new,P,C,m,140),'READY_RESOURCE_ONLY');x.close()
    def test_wrong_mac_wrong_host_and_capacity(self):
        g,n=make(5);x=self.gate(capacity=1)
        self.assertEqual(x.consume(replace(g,mac=bytes(32)),P,C,n,120),'GRANT_MAC')
        self.assertEqual(x.pending_paid(),0)
        self.assertEqual(x.consume(g,P,b'B'*32,n,120),'CONTEXT')
        self.assertEqual(x.consume(g,P,C,n,120),'READY_RESOURCE_ONLY')
        h,m=make(6)
        self.assertEqual(x.consume(h,P,C,m,120),'PAID_CAPACITY_BUSY')
        x.close()
    def test_monotonic_and_expiration(self):
        g,n=make(7);x=self.gate(capacity=1)
        self.assertEqual(x.consume(g,P,C,n,130),'READY_RESOURCE_ONLY')
        with self.assertRaisesRegex(ValueError,'CLOCK_REGRESSION'):
            x.consume(g,P,C,n,120)
        h,m=make(8,ms=2100)
        self.assertEqual(x.consume(h,P,C,m,2110),'READY_RESOURCE_ONLY')
        self.assertEqual(x.pending_paid(),1);x.close()
    def test_capacity_and_ttl_cannot_widen_on_reopen(self):
        x=self.gate(capacity=1,lifetime_ms=2000);x.close()
        with self.assertRaisesRegex(ValueError,'HOST_POLICY_MISMATCH'):
            self.gate(capacity=1024)
        with self.assertRaisesRegex(ValueError,'HOST_POLICY_MISMATCH'):
            self.gate(capacity=1,lifetime_ms=1000)
    def test_scope_clone_rejected_on_same_db(self):
        x=self.gate();x.close()
        with self.assertRaisesRegex(ValueError,'HOST_SCOPE_MISMATCH'):
            DurableSpendGate(self.path,A,b'X'*32,E)
if __name__=='__main__':unittest.main(verbosity=2)
