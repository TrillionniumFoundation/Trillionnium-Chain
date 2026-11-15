"""Real OpenSSL ML-DSA-65 adversarial PCB1/PCA1/PCC1 provenance tests."""
from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from pq_envelope import Reject, make_unsigned, public_key_id, sign_reference
from pq_cell_custody import (
    catalog_from_chunks, catalog_id, release_frame_id, sign_catalog_binding_fixture,
    Challenge, chunk_proof, sign_response_fixture, verify_response_research,
)
from pq_cell_provenance import (
    CONTENT_DOMAIN, CONTEXT_DOMAIN, EVAL_DOMAIN, MANIFEST_DOMAIN, RELEASE_DOMAIN,
    parse_pcb1_strict, verify_cell_provenance_research, BASE_SELECTOR,
)


def be8(x):return x.to_bytes(8,'big')

def content_id(data):
    return hashlib.sha384(CONTENT_DOMAIN+be8(len(data))+data).digest()


class PQCellProvenanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='trnm-pq-provenance-')
        cls.addClassCleanup(cls.temp.cleanup)
        root=Path(cls.temp.name)
        cls.keys={}
        for who in ('release','eval1','eval2','eval3','provider','attacker'):
            sk=root/(who+'.secret.pem'); pk=root/(who+'.public.pem')
            subprocess.run(['openssl','genpkey','-algorithm','ML-DSA-65','-out',str(sk)],check=True,capture_output=True,timeout=15)
            subprocess.run(['openssl','pkey','-in',str(sk),'-pubout','-out',str(pk)],check=True,capture_output=True,timeout=15)
            cls.keys[who]=(sk,pk.read_bytes())
        cls.network=bytes(range(32));cls.family=bytes(range(32,64));cls.parent=bytes([0x19])*32
        cls.gen=9;cls.seq=7;cls.plan=bytes([0xFA])*48
        cls.objects={BASE_SELECTOR:b'base shared encoder v9 | neuron weights | public',
                     bytes([1])*32:b'Cell-1 weights v9 * compatibility family X',
                     bytes([2])*32:b'Cell-2 weights v9, memory, context, output'}
        cls.obj_id=bytes([1])*32
        base=cls.objects[BASE_SELECTOR]
        data=(b'PCB1\x01'+cls.network+cls.family+cls.parent+be8(cls.gen)
              +content_id(base)+be8(len(base))+b'\x02')
        for cell in (bytes([1])*32,bytes([2])*32):
            body=cls.objects[cell]
            data+=cell+be8(cls.gen)+content_id(body)+be8(len(body))
        cls.manifest_bytes=data
        cls.manifest=parse_pcb1_strict(data)
        cls.chunks=(cls.objects[cls.obj_id][:16],cls.objects[cls.obj_id][16:32],cls.objects[cls.obj_id][32:])
        cls.catalog=catalog_from_chunks(cls.network,cls.manifest.manifest_digest,cls.gen,cls.chunks,16)
        cls.release_key=public_key_id(cls.keys['release'][1]);cls.provider_key=public_key_id(cls.keys['provider'][1])
        cls.roster=frozenset(public_key_id(cls.keys[x][1]) for x in ('eval1','eval2','eval3'))
        context=hashlib.sha256(CONTEXT_DOMAIN+cls.network+cls.parent).digest()
        ep=EVAL_DOMAIN+cls.manifest.manifest_digest+cls.plan
        cls.review={}
        for name in ('eval1','eval2','eval3'):
            key=cls.keys[name]
            unsigned=make_unsigned(purpose=3,network=cls.network,context=context,
                       signer_key_id=public_key_id(key[1]),owner_generation=cls.gen,
                       operation_sequence=cls.seq,expires_at=4000,payload=ep)
            cls.review[name]=(key[1],sign_reference(unsigned,private_key_path=key[0]))
        cls.reviewers=(cls.review['eval1'],cls.review['eval2'])
        reviewer_ids=tuple(sorted(public_key_id(pub) for pub,_ in cls.reviewers))
        rp=(RELEASE_DOMAIN+cls.manifest.manifest_digest+cls.plan
            +bytes([len(reviewer_ids)])+b''.join(reviewer_ids))
        cls.release_frame=sign_reference(make_unsigned(purpose=4,network=cls.network,
                    context=context,signer_key_id=cls.release_key,owner_generation=cls.gen,
                    operation_sequence=cls.seq,expires_at=4000,payload=rp),private_key_path=cls.keys['release'][0])
        cls.frame_id=release_frame_id(cls.release_frame)
        cls.prior=bytes(48)
        cls.binding=sign_catalog_binding_fixture(cls.catalog,release_frame=cls.release_frame,
               previous_head=cls.prior,signer_public_pem=cls.keys['release'][1],
               signer_private_path=cls.keys['release'][0],sequence=cls.seq,expires_at=4000)

    def inputs(self,**changes):
        d=dict(manifest_bytes=self.manifest_bytes,catalog_bytes=self.catalog.encode(),
               complete_chunks=self.chunks,object_selector=self.obj_id,
               release_frame=self.release_frame,catalog_binding_frame=self.binding,
               release_public_pem=self.keys['release'][1],reviewer_frames=self.reviewers,
               expected_network=self.network,expected_family=self.family,
               expected_parent=self.parent,expected_generation=self.gen,
               expected_sequence=self.seq,expected_plan_id=self.plan,
               expected_manifest_digest=self.manifest.manifest_digest,
               expected_release_frame_id=self.frame_id,
               expected_catalog_digest=catalog_id(self.catalog),
               expected_prior_catalog_head=self.prior,
               trusted_release_key_id=self.release_key,trusted_reviewer_ids=self.roster,now=3000)
        d.update(changes)
        return d

    def check(self,**changes):return verify_cell_provenance_research(**self.inputs(**changes))

    def test_full_release_reviewer_catalog_and_exact_cell_weight_passes(self):
        result=self.check()
        self.assertEqual(result.object_selector,self.obj_id)
        self.assertEqual(result.object_content_id,content_id(self.objects[self.obj_id]))
        self.assertEqual(result.object_bytes,len(self.objects[self.obj_id]))
        self.assertEqual(result.checked_chunks,3)
        self.assertEqual(result.release_key_id,self.release_key)
        self.assertFalse(hasattr(result,'adoption_authorized'))
        self.assertFalse(hasattr(result,'storage_reward_authorized'))

    def test_actual_signed_pcb1_and_retrieval_proof_link(self):
        result=self.check()
        i=2; path=chunk_proof(self.chunks,i)
        q=Challenge(self.network,result.catalog_digest,bytes([3])*32,bytes([4])*32,
                    self.provider_key,self.gen,10,i,2999,3100)
        resp=sign_response_fixture(self.catalog,q,chunk=self.chunks[i],path=path,
              public_pem=self.keys['provider'][1],private_key_path=self.keys['provider'][0],now=3000)
        obs=verify_response_research(resp,catalog_bytes=self.catalog.encode(),challenge_bytes=q.encode(),
              provider_public_pem=self.keys['provider'][1],expected_release=result.manifest_digest,
              expected_catalog_digest=result.catalog_digest,expected_requester=q.requester_id,
              expected_nonce=q.nonce,expected_provider_key_id=self.provider_key,now=3000)
        self.assertEqual(obs.provider_key_id,self.provider_key)

    def test_untrusted_alternative_catalog_cannot_substitute_even_same_signed_release(self):
        altered=(b'y'*16,b'z'*16,b'c'*10)
        fake=catalog_from_chunks(self.network,self.manifest.manifest_digest,self.gen,altered,16)
        with self.assertRaises(Reject):
            self.check(catalog_bytes=fake.encode(),complete_chunks=altered)
        # A new valid release-owner signature alone cannot change a caller's exact catalog pin.
        signed=sign_catalog_binding_fixture(fake,release_frame=self.release_frame,
               previous_head=self.prior,signer_public_pem=self.keys['release'][1],
               signer_private_path=self.keys['release'][0],sequence=self.seq,expires_at=4000)
        with self.assertRaises(Reject):
            self.check(catalog_bytes=fake.encode(),complete_chunks=altered,catalog_binding_frame=signed)

    def test_wrong_actual_object_content_with_matching_merkle_root_rejected(self):
        changed=(b'v'*16,b'w'*16,b'x'*10)
        c=catalog_from_chunks(self.network,self.manifest.manifest_digest,self.gen,changed,16)
        bind=sign_catalog_binding_fixture(c,release_frame=self.release_frame,
                previous_head=self.prior,signer_public_pem=self.keys['release'][1],
                signer_private_path=self.keys['release'][0],sequence=self.seq,expires_at=4000)
        with self.assertRaisesRegex(Reject,'not the Cell weights'):
            self.check(catalog_bytes=c.encode(),complete_chunks=changed,
                       catalog_binding_frame=bind,expected_catalog_digest=catalog_id(c))

    def test_reviewer_and_release_signatures_are_not_bare_digest_check(self):
        m=bytearray(self.release_frame);m[-1]^=1
        with self.assertRaises(Reject):self.check(release_frame=bytes(m),expected_release_frame_id=release_frame_id(bytes(m)))
        m=bytearray(self.reviewers[0][1]);m[-1]^=1
        with self.assertRaises(Reject):self.check(reviewer_frames=((self.reviewers[0][0],bytes(m)),self.reviewers[1]))
        with self.assertRaises(Reject):self.check(release_public_pem=self.keys['attacker'][1])
        with self.assertRaises(Reject):self.check(reviewer_frames=(self.reviewers[0],)*2)
        with self.assertRaises(Reject):self.check(reviewer_frames=(self.reviewers[0],))
        with self.assertRaises(Reject):self.check(trusted_reviewer_ids=frozenset(public_key_id(p) for p,_ in self.reviewers))

    def test_release_cannot_be_used_as_reviewer_or_another_quorum(self):
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.reviewers[0],self.review['eval3']))
        with self.assertRaises(Reject):
            self.check(trusted_reviewer_ids=self.roster|{self.release_key})
        with self.assertRaises(Reject):
            self.check(reviewer_frames=(self.reviewers[0],(self.keys['release'][1],self.release_frame)))

    def test_exact_owner_pins_and_stale_generation(self):
        cases=(dict(expected_network=bytes(32)),dict(expected_family=bytes(32)),
               dict(expected_parent=bytes(32)),dict(expected_generation=8),
               dict(expected_generation=True),dict(expected_sequence=6),
               dict(expected_plan_id=bytes([5])*48),
               dict(expected_manifest_digest=bytes([8])*48),
               dict(expected_release_frame_id=bytes([8])*48),
               dict(expected_catalog_digest=bytes([8])*48),
               dict(expected_prior_catalog_head=bytes([8])*48),
               dict(trusted_release_key_id=bytes([8])*32),
               dict(now=4001),dict(now=True))
        for change in cases:
            with self.subTest(case=change),self.assertRaises(Reject):self.check(**change)

    def test_complete_chunks_must_exactly_reassemble_only_selected_cell(self):
        for chunks in (self.chunks[:-1],self.chunks[:-1]+(b'a'*9,),
                       tuple(reversed(self.chunks)),
                       (self.objects[BASE_SELECTOR],)):
            with self.subTest(chunks=chunks),self.assertRaises(Reject):
                self.check(complete_chunks=chunks)
        for selector in (BASE_SELECTOR,bytes([2])*32,bytes([3])*32):
            with self.subTest(selector=selector),self.assertRaises(Reject):
                self.check(object_selector=selector)

    def test_strict_second_pcb1_parser_rejects_mutation_and_noncanonical_rows(self):
        payload=self.manifest_bytes
        for position in range(len(payload)):
            bad=bytearray(payload);bad[position]^=1
            with self.subTest(position=position),self.assertRaises(Reject):
                self.check(manifest_bytes=bytes(bad))
        for bad in (payload[:-1],payload+b'\0',b'PCB2'+payload[4:],
                    payload[:165]+b'\xff'+payload[166:],
                    payload[:166]+payload[262:358]+payload[166:262]):
            with self.assertRaises(Reject):parse_pcb1_strict(bad)

    def test_no_authority_or_production_claims(self):
        result=self.check()
        for attr in ('verified_work','chainwork','final_use','adoption_authorized',
                     'production_ready','independent_accepted','storage_reward_authorized'):
            self.assertFalse(hasattr(result,attr))

if __name__=='__main__':unittest.main()
