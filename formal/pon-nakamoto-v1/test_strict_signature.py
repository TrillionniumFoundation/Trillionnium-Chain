"""Exact weak-point, scalar and native/Python rejection parity regressions."""
import copy,os,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from strict_signature import verify,strict_point,P,L
from ledger import *
from native_execution import execute_native

class StrictSignatureTests(unittest.TestCase):
    def test_rfc8032_known_vector(self):
        public=bytes.fromhex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')
        signature=bytes.fromhex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b')
        verify(public,signature,b'')
    def test_small_order_and_noncanonical_point_rejections(self):
        encodings=[bytes(32),bytes([1])+bytes(31),(P-1).to_bytes(32,'little'),P.to_bytes(32,'little')]
        for encoding in encodings:
            for sign in [0,128]:
                candidate=encoding[:31]+bytes([encoding[31]|sign])
                with self.subTest(point=candidate.hex()),self.assertRaises(ValueError):strict_point(candidate)
    def test_all_declared_order_eight_points_reject(self):
        for value in ['26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05','c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a']:
            point=bytes.fromhex(value)
            for sign in [0,128]:
                encoded=point[:31]+bytes([(point[31]&127)|sign])
                with self.assertRaises(ValueError):strict_point(encoded)
    def test_signature_scalar_and_R_rejections(self):
        message=b'bounded-owned-signature';signature=key(0).sign(message);pub=public(key(0))
        verify(pub,signature,message)
        s=int.from_bytes(signature[32:],'little')
        for bad in [signature[:32]+(s+L).to_bytes(32,'little'),bytes([1])+bytes(31)+signature[32:]]:
            with self.assertRaises(ValueError):verify(pub,bad,message)
    def test_native_and_reference_reject_weak_sender_without_state_change(self):
        binary=Path(os.environ.get('CARGO_TARGET_DIR',str(ROOT/'trillionnium/target')))/'release/examples/pon_execute'
        if not binary.is_file():raise RuntimeError('Build actual native executor; no skip')
        identity=bytes([1])+bytes(31);weak_signature=identity+bytes(32)
        state=genesis_state();state,_=execute_reference(state,[sign(key(0),1,'transfer',dict(recipient=identity,amount=5000))],1,public(key(0)),GENESIS)
        unsigned=tx_unsigned(NETWORK,identity,1,1000,10000,NAMES['transfer'],dict(recipient=public(key(1)),amount=1))
        transaction=unsigned+weak_signature;before=copy.deepcopy(state)
        with self.assertRaisesRegex(ValueError,'SIGNATURE'):execute_reference(state,[transaction],2,public(key(0)),GENESIS)
        for workers in [1,2,4,8]:
            with self.assertRaisesRegex(ValueError,'SIGNATURE'):execute_native(state,[transaction],2,public(key(0)),GENESIS,workers,binary)
        self.assertEqual(state,before)
    def test_weak_consumer_cannot_authorize_quota(self):
        identity=bytes([1])+bytes(31);provider=public(key(1));quota=quota_identity(public(key(0)),1,identity,provider,1,10)
        state,_=execute_reference(genesis_state(),[sign(key(0),1,'reserve_quota',dict(quota=quota,consumer=identity,provider=provider,units=1,deadline=10))],1,public(key(0)),GENESIS)
        tx=sign(key(1),1,'consume_quota',dict(quota=quota,units=1,result=H('bad-authority'),consumer_signature=identity+bytes(32)))
        with self.assertRaisesRegex(ValueError,'SIGNATURE'):execute_reference(state,[tx],2,public(key(0)),GENESIS)

if __name__=='__main__':unittest.main(verbosity=2)
