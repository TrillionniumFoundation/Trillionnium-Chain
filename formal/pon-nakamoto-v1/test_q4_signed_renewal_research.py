"""Development-only signatures are deterministic and NOT production key custody."""
from __future__ import annotations
import hashlib
import unittest

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:  # Research backend is optional, NEVER a fake verification pass.
    Ed25519PrivateKey = None
    Encoding = PublicFormat = None

from q4_signed_renewal_research import (
    Q4PacketError, checked_prepare, decode_lease, hash_pon, verify_tag22,
)


def k(label):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public(key):
    return key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)


def h(label):
    return hashlib.sha256(label.encode()).digest()


def lease_bytes(*, net, params, requester, source, source_record, auth, avm, avroot,
                revision, start, expires, slot=7, generation=3, purpose=2):
    demand=hash_pon(b'qualified-demand-id-v2',net,params,requester,generation.to_bytes(8,'little'))
    hashes=[net,params,demand,requester,source,source_record,auth,avm,avroot]
    numbers=[generation,revision,start,expires,expires+100]
    data = (b'QDL2' + (2).to_bytes(2,'little') + bytes([slot,purpose]) +
            b''.join(hashes) + b''.join(v.to_bytes(8,'little') for v in numbers) + b'\x01' +bytes(7))
    assert len(data)==344
    return data


def make_fixture():
    rk,sk=k('requester dev fixture'),k('source dev fixture')
    requester,source=public(rk),public(sk)
    net,params,genesis,record,auth,avm,avroot=[h(x) for x in ['net','params','genesis','record','auth','avm','avroot']]
    common=dict(net=net,params=params,requester=requester,source=source,source_record=record,auth=auth,avm=avm,avroot=avroot)
    old=lease_bytes(**common,revision=1,start=1,expires=100)
    new=lease_bytes(**common,revision=2,start=80,expires=500)
    dec=decode_lease(new)
    demand=dec.demand_id
    model,inp,task=h('model'),h('input'),h('matrix task')
    layer=hash_pon(b'qualified-task-layer-v1',model,b'entire-row-major-field-layer-64x64')
    recipe=hash_pon(b'qualified-task-recipe-v1',b'canonical-field-matrix64-product-v1')
    claims=[net,params,hash_pon(b'qualified-task-profile-v1',b'pon-matmul-transcript-64-v1'),
            source,demand,hash_pon(b'qualified-demand-source-record-v2',dec.lease_id,record),
            model,layer,inp,recipe,task,avm,avroot,auth,
            hash_pon(b'qualified-demand-frontier-v2',dec.lease_id),
            hash_pon(b'qualified-task-output-meter-v1',net,params,demand,model,layer,inp,recipe,task)]
    assert len(claims)==16
    qwt=(b'QWT1'+(1).to_bytes(2,'little')+bytes([2,1,1,0,1,0])+b''.join(claims)+
         b'@\x00@\x00@\x00\x00\x00'+b''.join(x.to_bytes(8,'little') for x in [2,80,500,600,64**3])+
         b''.join(x.to_bytes(4,'little') for x in [16384,16384,1]))
    assert len(qwt)==584
    unsigned_source=b'QWA2'+dec.lease_id+qwt
    assert len(unsigned_source)==620
    signed_source=unsigned_source+sk.sign(hash_pon(b'qualified-task-source-sign-v2',unsigned_source))
    payload=new+signed_source
    assert len(payload)==1028
    unsigned_outer=(b'PNX1'+net+requester+(9).to_bytes(8,'little')+
                    (700).to_bytes(8,'little')+(100_000).to_bytes(8,'little')+
                    bytes([22])+(1028).to_bytes(2,'little')+payload)
    assert len(unsigned_outer)==1123
    raw=unsigned_outer+rk.sign(hash_pon(b'tx-sign',unsigned_outer))
    assert len(raw)==1187
    return dict(raw=raw,old=old,new=new,net=net,params=params,genesis=genesis,rk=rk,sk=sk)


@unittest.skipUnless(Ed25519PrivateKey is not None, "requires optional cryptography for actual signatures")
class SignedQ4Research(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture=make_fixture()

    def verify(self, raw=None, old=None, **kwargs):
        f=self.fixture
        return verify_tag22(raw if raw is not None else f['raw'],
                            old if old is not None else f['old'],f['net'],f['params'],
                            containing_height=kwargs.pop('height',90),
                            old_source_sequence=kwargs.pop('source_sequence',1),
                            expected_requester_sequence=kwargs.pop('requester_sequence',9),
                            expected_old_lease_id=kwargs.pop('expected_old_lease_id',decode_lease(f['old']).lease_id),**kwargs)

    def test_real_two_signature_packet_bound_to_actual_bytes(self):
        result=self.verify()
        self.assertEqual(result.source_sequence,2)
        self.assertEqual(result.requester_sequence,9)
        self.assertEqual(result.new_start,80)
        self.assertEqual(result.old_expires,100)
        self.assertEqual(result.transaction_id,hash_pon(b'tx-id',self.fixture['raw']))
        self.assertNotEqual(result.transaction_id,result.raw_sha256)
        self.assertNotEqual(result.old_lease_id,result.new_lease_id)

    def test_old_lease_is_not_authenticated_just_by_a_new_signature(self):
        fake=bytearray(self.fixture['old']);fake[8+5*32]^=1
        with self.assertRaises(Q4PacketError):self.verify(old=bytes(fake))

    def test_both_independent_signatures_are_required(self):
        for pos in (1122,1186):
            with self.subTest(pos=pos):
                b=bytearray(self.fixture['raw']);b[pos]^=1
                with self.assertRaises(Q4PacketError):self.verify(raw=bytes(b))

    def test_context_and_outer_opcode_do_not_substitute(self):
        for pos in (4,36,92,93,95,439,475,800):
            with self.subTest(pos=pos):
                b=bytearray(self.fixture['raw']);b[pos]^=1
                with self.assertRaises(Q4PacketError):self.verify(raw=bytes(b))

    def test_signed_overlap_at_both_endpoints_and_after_expiry(self):
        self.assertEqual(self.verify(height=80).included_height,80)
        self.assertEqual(self.verify(height=100).included_height,100)
        for at in (0,79,101,1010):
            with self.subTest(height=at):
                with self.assertRaises(Q4PacketError):self.verify(height=at)

    def test_source_and_requester_sequence_replay_fails(self):
        for seq in (0,2,3,2**64):
            with self.subTest(source=seq):
                with self.assertRaises(Q4PacketError):self.verify(source_sequence=seq)
        for seq in (0,8,10):
            with self.subTest(requester=seq):
                with self.assertRaises(Q4PacketError):self.verify(requester_sequence=seq)

    def test_all_old_lease_bytes_are_independently_pinned(self):
        """A valid new dual signature must not authenticate an altered old lease."""
        original=self.fixture['old']
        original_id=decode_lease(original).lease_id
        for pos in range(len(original)):
            altered=bytearray(original)
            altered[pos]^=1
            with self.subTest(byte=pos):
                with self.assertRaises(Q4PacketError):
                    self.verify(old=bytes(altered), expected_old_lease_id=original_id)
        # Changing the old not_before at byte 312 keeps its syntactic bounds
        # legal but changes its identity; the independent old pin must fail.
        changed=bytearray(original)
        changed[312]^=1
        self.assertNotEqual(decode_lease(bytes(changed)).lease_id,original_id)
        with self.assertRaisesRegex(Q4PacketError,'OLD_LEASE_PIN'):
            self.verify(old=bytes(changed),expected_old_lease_id=original_id)

    def test_every_byte_in_signed_transaction_is_fenced(self):
        """All 1187 byte positions must change a bound statement or a signature."""
        raw=self.fixture['raw']
        for pos in range(len(raw)):
            b=bytearray(raw)
            b[pos]^=1
            with self.subTest(byte=pos):
                with self.assertRaises(Q4PacketError):
                    self.verify(raw=bytes(b))

    def test_all_raw_lengths_reject(self):
        f=self.fixture
        for n in (0,95,344,1186,1188,2048):
            with self.subTest(n=n):
                with self.assertRaises(Q4PacketError):self.verify(raw=f['raw'][:n] if n<=1187 else f['raw']+bytes(n-1187))

    def test_no_fake_crypto_backend_can_grant_approval(self):
        import builtins
        original_import=builtins.__import__
        def broken(name,*args,**kwargs):
            if name.startswith('cryptography'):
                raise ImportError('simulated unavailable')
            return original_import(name,*args,**kwargs)
        builtins.__import__=broken
        try:
            with self.assertRaisesRegex(Q4PacketError,'CRYPTO_BACKEND_UNAVAILABLE'):self.verify()
        finally:
            builtins.__import__=original_import

    def test_intent_mismatch_prevents_all_journal_writes(self):
        f=self.fixture
        parsed=self.verify()
        class FakeOutbox:
            context=(f['net'],f['params'],f['genesis'])
            calls=0
            def prepare(self,intent):
                self.calls+=1
                return intent.operation_id
        class FakeIntent:
            operation_id=h('operation')
            network=f['net'];parameters=f['params'];genesis=f['genesis']
            signed_transaction=f['raw']
            old_lease_digest=parsed.old_lease_id;next_lease_digest=parsed.new_lease_id
            signed_from=80;last_legal_height=100
            requester_sequence=9;source_sequence=2
        out=FakeOutbox(); intent=FakeIntent()
        self.assertEqual(checked_prepare(out,intent,f['old'],containing_height=90,old_source_sequence=1,expected_old_lease_id=parsed.old_lease_id),intent.operation_id)
        self.assertEqual(out.calls,1)
        for key,value in [('old_lease_digest',h('wrong')),('source_sequence',3),('signed_from',81),
                          ('requester_sequence',8),('last_legal_height',99),('genesis',h('different genesis'))]:
            class Changed: pass
            broken=Changed()
            broken.__dict__.update(intent.__dict__)
            broken.__dict__.update({k:getattr(intent,k) for k in ('operation_id','network','parameters','genesis','signed_transaction','old_lease_digest','next_lease_digest','signed_from','last_legal_height','requester_sequence','source_sequence')})
            setattr(broken,key,value)
            with self.subTest(key=key):
                with self.assertRaises(Q4PacketError):
                    checked_prepare(out,broken,f['old'],containing_height=90,old_source_sequence=1,expected_old_lease_id=parsed.old_lease_id)
        self.assertEqual(out.calls,1)

    def test_renamed_intent_and_mutated_old_lease_cannot_create_authority(self):
        """Outbox metadata cannot self-attest a different old lease identity."""
        f=self.fixture
        parsed=self.verify()
        old=bytearray(f['old']); old[312]^=1  # remains a well-formed old lease
        forged_id=decode_lease(bytes(old)).lease_id
        self.assertNotEqual(forged_id,parsed.old_lease_id)
        class FakeOutbox:
            context=(f['net'],f['params'],f['genesis'])
            calls=0
            def prepare(self,intent):
                self.calls+=1
                return intent.operation_id
        class FakeIntent:
            operation_id=h('new operation alias')
            network=f['net'];parameters=f['params'];genesis=f['genesis']
            signed_transaction=f['raw']
            old_lease_digest=forged_id  # caller changes its own metadata too
            next_lease_digest=parsed.new_lease_id
            signed_from=80;last_legal_height=100
            requester_sequence=9;source_sequence=2
        out=FakeOutbox()
        with self.assertRaisesRegex(Q4PacketError,'OLD_LEASE_OWNER_PIN'):
            checked_prepare(out,FakeIntent(),bytes(old),containing_height=90,
                            old_source_sequence=1,expected_old_lease_id=parsed.old_lease_id)
        self.assertEqual(out.calls,0)
        # The non-authoritative research check deliberately cannot certify its
        # own caller's expected pin; production must fetch parent-state identity.
        with self.assertRaisesRegex(Q4PacketError,'OLD_LEASE_OWNER_PIN'):
            checked_prepare(out,FakeIntent(),f['old'],containing_height=90,
                            old_source_sequence=1,expected_old_lease_id=parsed.old_lease_id)
        self.assertEqual(out.calls,0)


if __name__=='__main__':
    unittest.main()
