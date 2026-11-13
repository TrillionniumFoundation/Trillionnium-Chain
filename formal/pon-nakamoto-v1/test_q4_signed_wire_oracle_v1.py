"""Independent Q4 signed-wire tests using real Ed25519 development keys.

This checks cryptographic bytes and matching caller-declared branch facts, NOT a
real PoN state transition, operator identity, Work proof or external authority.
"""
from __future__ import annotations

from dataclasses import replace
import hashlib
import struct
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from q4_signed_wire_oracle_v1 import H, parse_lease, parse_manifest, inspect_presigned_q4, Q4Reject


def k(seed: bytes):
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def pub(key) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


class Fixture:
    def __init__(self):
        self.requester = k(b'RESEARCH_REQUESTER_NOT_PRODUCTION')
        self.source = k(b'RESEARCH_SOURCE_NOT_PRODUCTION')
        self.network = H('network',b'fresh-q4-study')
        self.parameters = H('parameters',b'development-revision12')
        self.req_key, self.source_key = pub(self.requester), pub(self.source)
        self.old = self.lease(revision=1,start=1,end=1000)
        self.bound = {'model':H('artifact',b'study-model'),
                      'input':H('qualified-task-input-v1',b'study-input'),
                      'matrix_task':H('task',b'study-matrix'),
                      'output_meter':None}
        self.bound['output_meter'] = self.meter()

    def lease(self,*,revision,start,end,slot=7,source_key=None,requester_key=None,
              generation=4,authorization=None):
        source_key = source_key or self.source_key
        requester_key = requester_key or self.req_key
        hashes = [
            self.network, self.parameters,
            H('qualified-demand-id-v2',self.network,self.parameters,requester_key,struct.pack('<Q',generation)),
            requester_key,source_key, H('record',b'owner'),
            authorization or H('authorized-scope',b'valid'),
            H('available',b'manifest'),H('available',b'root'),
        ]
        assert 0 < revision < 100 and end > start and end-start <=1000
        wire = (b'QDL2\x02\x00'+bytes((slot,4))+b''.join(hashes)+
                struct.pack('<5Q',generation,revision,start,end,end+100)+b'\x01'+b'\0'*7)
        assert len(wire)==344
        return wire

    def meter(self) -> bytes:
        old=parse_lease(self.old)
        return H('qualified-task-output-meter-v1',self.network,self.parameters,
                 old['demand_id'],self.bound['model'],
                 H('qualified-task-layer-v1',self.bound['model'],b'entire-row-major-field-layer-64x64'),
                 self.bound['input'],H('qualified-task-recipe-v1',b'canonical-field-matrix64-product-v1'),
                 self.bound['matrix_task'])

    def packet(self, *,next_start=850,next_end=1500,next_slot=7,next_revision=2,
               source_key=None,requester_key=None,source_sequence=2,model=None,expiry=1800,
               fee=15000,wrong_source_signer=False,wrong_outer_signer=False):
        successor=self.lease(revision=next_revision,start=next_start,end=next_end,
                             slot=next_slot,source_key=source_key,requester_key=requester_key)
        next_lease=parse_lease(successor)
        m=model if model is not None else self.bound['model']
        layer=H('qualified-task-layer-v1',m,b'entire-row-major-field-layer-64x64')
        meter=H('qualified-task-output-meter-v1',self.network,self.parameters,
                next_lease['demand_id'],m,layer,self.bound['input'],
                H('qualified-task-recipe-v1',b'canonical-field-matrix64-product-v1'),self.bound['matrix_task'])
        hashes=[
            self.network,self.parameters,H('qualified-task-profile-v1',b'pon-matmul-transcript-64-v1'),
            next_lease['source'],next_lease['demand_id'],
            H('qualified-demand-source-record-v2',next_lease['id'],next_lease['source_record']),
            m,layer,self.bound['input'],H('qualified-task-recipe-v1',b'canonical-field-matrix64-product-v1'),
            self.bound['matrix_task'],next_lease['availability_manifest'],next_lease['availability_root'],
            next_lease['authorization_scope'],H('qualified-demand-frontier-v2',next_lease['id']),meter,
        ]
        manifest=(b'QWT1\x01\x00'+bytes((4,1,1,0,1,0))+b''.join(hashes)+
                  struct.pack('<4H',64,64,64,0)+
                  struct.pack('<5Q',source_sequence,next_start,next_end,next_end+100,262144)+
                  struct.pack('<3I',16384,16384,1))
        assert len(manifest)==584
        statement=b'QWA2'+next_lease['id']+manifest
        assert len(statement)==620
        source_signer = self.requester if wrong_source_signer else self.source
        qwa=statement+source_signer.sign(H('qualified-task-source-sign-v2',statement))
        payload=successor+qwa
        assert len(payload)==1028
        outer=(b'PNX1'+self.network+self.req_key+struct.pack('<3Q',4,expiry,fee)+
               bytes([22])+struct.pack('<H',len(payload))+payload)
        assert len(outer)==1123
        outer_signer=self.source if wrong_outer_signer else self.requester
        result=outer+outer_signer.sign(H('tx-sign',outer))
        assert len(result)==1187
        return result

    def inspect(self,raw=None,**kwargs):
        return inspect_presigned_q4(raw if raw is not None else self.packet(),self.old,
                containing_height=kwargs.pop('height',900),network=kwargs.pop('network',self.network),
                parameters=kwargs.pop('parameters',self.parameters),
                expected_old_lease_id=kwargs.pop('expected_old_lease_id',H('qualified-demand-lease-v2',self.old)),
                expected_requester_sequence=kwargs.pop('nonce',4),
                previous_source_sequence=kwargs.pop('source_sequence',1),
                previous_material=kwargs.pop('bound',self.bound),
                previous_status=kwargs.pop('status','active'),**kwargs)


class SignedQ4ResearchTests(unittest.TestCase):
    def setUp(self):
        self.fx=Fixture()

    def test_real_signatures_and_delayed_height_reuse(self):
        raw=self.fx.packet()
        ids=set()
        for h in (850,899,900,950,999,1000):
            result=self.fx.inspect(raw,height=h)
            self.assertEqual(result.transaction_sequence,4)
            self.assertEqual(result.source_sequence,2)
            ids.add(result.transaction_id)
        self.assertEqual(len(ids),1)
        self.assertEqual(len(next(iter(ids))),32)

    def test_window_and_revocation_boundary(self):
        for h in (849,1001,1100,1500):
            with self.subTest(height=h),self.assertRaisesRegex(Q4Reject,'RENEW_OVERLAP'):
                self.fx.inspect(height=h)
        with self.assertRaisesRegex(Q4Reject,'OWNER_STATE'):
            self.fx.inspect(status='revoked')
        with self.assertRaisesRegex(Q4Reject,'OWNER_STATE'):
            self.fx.inspect(status='expired')

    def test_exact_both_signatures_must_verify(self):
        for raw in (self.fx.packet(wrong_source_signer=True),
                    self.fx.packet(wrong_outer_signer=True)):
            with self.assertRaisesRegex(Q4Reject,'SIGNATURE'):
                self.fx.inspect(raw)
        original=self.fx.packet()
        for index in (1059,1063,1123,1186):
            changed=bytearray(original);changed[index]^=1
            with self.subTest(index=index),self.assertRaises(Q4Reject):
                self.fx.inspect(bytes(changed))

    def test_source_sequence_and_requester_nonce(self):
        with self.assertRaisesRegex(Q4Reject,'SOURCE_SEQUENCE'):
            self.fx.inspect(self.fx.packet(source_sequence=3))
        with self.assertRaisesRegex(Q4Reject,'TRANSACTION_CONTEXT'):
            self.fx.inspect(nonce=5)
        with self.assertRaisesRegex(Q4Reject,'TRANSACTION_CONTEXT'):
            self.fx.inspect(self.fx.packet(expiry=899))
        with self.assertRaisesRegex(Q4Reject,'TRANSACTION_CONTEXT'):
            self.fx.inspect(self.fx.packet(fee=10_000_001))

    def test_renewal_identity_and_previous_material(self):
        with self.assertRaisesRegex(Q4Reject,'RENEW_SLOT'):
            self.fx.inspect(self.fx.packet(next_slot=6))
        with self.assertRaisesRegex(Q4Reject,'RENEW_REVISION'):
            self.fx.inspect(self.fx.packet(next_revision=3))
        with self.assertRaisesRegex(Q4Reject,'RENEW_OVERLAP'):
            self.fx.inspect(self.fx.packet(next_start=1001,next_end=1700))
        with self.assertRaisesRegex(Q4Reject,'MATERIAL_MODEL'):
            self.fx.inspect(self.fx.packet(model=H('artifact',b'substitute')))

    def test_context_identity_and_source_independence_of_public_keys(self):
        with self.assertRaisesRegex(Q4Reject,'NETWORK'):
            self.fx.inspect(network=H('bad',b'network'))
        with self.assertRaisesRegex(Q4Reject,'LEASE_CONTEXT'):
            self.fx.inspect(parameters=H('bad',b'parameters'))
        with self.assertRaisesRegex(Q4Reject,'LEASE_IDENTITY'):
            self.fx.inspect(self.fx.packet(source_key=self.fx.req_key))
        with self.assertRaisesRegex(Q4Reject,'REQUESTER'):
            self.fx.inspect(self.fx.packet(requester_key=pub(k(b'OTHER_REQUESTER'))))

    def test_length_flags_and_unsigned_input_rejected(self):
        valid=self.fx.packet()
        for data in (valid[:-1],valid+b'X',b'T'*1187):
            with self.assertRaises(Q4Reject):self.fx.inspect(data)
        for index in (95,101,103,433,439,443,459,1057):
            data=bytearray(valid);data[index]^=1
            with self.subTest(index=index),self.assertRaises(Q4Reject):self.fx.inspect(bytes(data))

    def test_source_identity_not_created_from_packet(self):
        raw=self.fx.packet()
        bad=dict(self.fx.bound)
        bad['model']=H('other-model',b'malformed')
        with self.assertRaisesRegex(Q4Reject,'MATERIAL_MODEL'):
            self.fx.inspect(raw,bound=bad)
        with self.assertRaisesRegex(Q4Reject,'MATERIAL_BINDING_FIELDS'):
            self.fx.inspect(raw,bound={'model':self.fx.bound['model']})
        with self.assertRaisesRegex(Q4Reject,'OWNER_STATE'):
            self.fx.inspect(raw,source_sequence=(1<<64)-1)


if __name__=='__main__':unittest.main()
