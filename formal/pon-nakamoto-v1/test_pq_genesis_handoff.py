"""Actual dual-signature and immutable-liability PQG1 genesis handoff negatives.

Genuine ML-DSA-65 and Ed25519 are required. This is explicitly NOT a blockchain
consensus activation, source ledger verifier, trusted snapshot exporter or HSM test.
"""
from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from pq_genesis_handoff import (
    SOURCE_DOMAIN, U64_MAX, MAX_ACCOUNTS, MAX_LIABILITIES,
    KIND_TASK,KIND_REWARD,KIND_ESCROW, Liability,LegacyAccount,SourceSnapshot,
    MigrationEvidence,Reject, decode_snapshot, migration_statement, pq_key_id,
    sign_migration_fixture, sha384, verify_handoff, verify_pq,
    sign_pq_fixture,
)


class PQGenesisHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='pqg-actual-crypto-')
        cls.addClassCleanup(cls.tmp.cleanup)
        root=Path(cls.tmp.name)
        cls.old=[]; cls.pq=[]
        for i in range(4):
            secret=Ed25519PrivateKey.generate()
            public=secret.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
            cls.old.append((secret,public))
            p=root/f'pq{i}.pem'; pub=root/f'pq{i}.pub.pem'
            subprocess.run(['openssl','genpkey','-algorithm','ML-DSA-65','-out',str(p)],
                           check=True,capture_output=True,timeout=15)
            subprocess.run(['openssl','pkey','-in',str(p),'-pubout','-out',str(pub)],
                           check=True,capture_output=True,timeout=15)
            cls.pq.append((p,pub.read_bytes()))
        cls.old.sort(key=lambda x:x[1])
        cls.accounts=tuple(LegacyAccount(pub,(i+2)*1000,i+3,i+2)
                           for i,(_,pub) in enumerate(cls.old[:3]))
        cls.liabilities=tuple(sorted((
            Liability(bytes([40])*32,cls.accounts[0].old_ed25519_public,50,100,KIND_TASK),
            Liability(bytes([41])*32,cls.accounts[1].old_ed25519_public,75,200,KIND_REWARD),
            Liability(bytes([42])*32,cls.accounts[2].old_ed25519_public,125,300,KIND_ESCROW),
        ),key=lambda o:o.liability_id))
        cls.old_net=bytes([0x51])*32
        cls.new_net=bytes([0x61])*32
        cls.old_head=bytes([0x71])*32
        cls.revocation=bytes([0x81])*32
        cls.profile=bytes([0x91])*32
        supply=sum(a.balance for a in cls.accounts)+sum(o.amount for o in cls.liabilities)
        cls.snapshot=SourceSnapshot(cls.old_net,cls.new_net,cls.old_head,cls.revocation,
                                    cls.profile,supply,cls.accounts,cls.liabilities)
        cls.migrations=[]
        for i in (0,1):
            old_signer=next(sk for sk,p in cls.old if p==cls.accounts[i].old_ed25519_public)
            cls.migrations.append(sign_migration_fixture(cls.snapshot,cls.accounts[i],
                    old_private=old_signer,new_pq_public=cls.pq[i][1],
                    new_pq_private=cls.pq[i][0],expires_at=1000))
        cls.migrations=tuple(cls.migrations)

    def opts(self, snap=None, proofs=None, *, expected=None, now=999, revoked=None):
        s=self.snapshot if snap is None else snap
        return dict(raw_source=s.encode(),expected_source_digest=sha384(SOURCE_DOMAIN,s.encode())
                    if expected is None else expected,
                    expected_legacy_network=s.legacy_network,expected_new_network=s.new_network,
                    expected_legacy_head=s.legacy_head,
                    expected_revocation_head=s.revocation_head,
                    expected_new_protocol_hash=s.new_protocol_hash,
                    expected_issued_units=s.issued_units,
                    migration_evidence=self.migrations if proofs is None else proofs,
                    independently_revoked_old_keys=frozenset() if revoked is None else revoked,
                    now=now)

    def check(self, snap=None, proofs=None, **kwargs):
        return verify_handoff(**self.opts(snap,proofs,**kwargs))

    def test_real_mldsa_and_ed25519_two_migrations_quarantine_and_conservation(self):
        result=self.check()
        self.assertEqual(result.migrated_count,2)
        self.assertEqual(result.quarantined_count,1)
        self.assertEqual(result.imported_liability_count,3)
        self.assertEqual(result.conserved_units,self.snapshot.issued_units)
        self.assertTrue(result.target_state_bytes.startswith(b'PQS1\x01'))
        self.assertNotEqual(result.target_genesis_id, result.target_state_root)
        self.assertFalse(hasattr(result,'activated'))
        self.assertFalse(hasattr(result,'final_use'))
        self.assertFalse(hasattr(result,'chainwork'))

    def test_quarantine_all_old_only_accounts_no_classical_fallback(self):
        result=self.check(proofs=())
        self.assertEqual(result.migrated_count,0)
        self.assertEqual(result.quarantined_count,3)
        self.assertNotIn(b'\x01'+bytes(32),result.target_state_bytes)
        self.assertNotEqual(result.target_state_root,self.check().target_state_root)

    def test_exact_canonical_roundtrip_and_trailing_rejection(self):
        raw=self.snapshot.encode()
        self.assertEqual(decode_snapshot(raw),self.snapshot)
        for bad in (raw[:-1],raw+b'\x00',b'LEG1'+raw[4:],raw[:4]+b'\x02'+raw[5:]):
            with self.subTest(bad=bad[:10]),self.assertRaises(Reject):decode_snapshot(bad)

    def test_mutate_every_source_header_byte_with_original_external_pin(self):
        raw=self.snapshot.encode()
        original=self.opts()
        for i in range(177):
            changed=bytearray(raw);changed[i]^=1
            with self.subTest(offset=i),self.assertRaises(Reject):
                verify_handoff(**{**original,'raw_source':bytes(changed)})

    def test_attacker_consistent_source_is_not_original_independent_anchor(self):
        fake=replace(self.snapshot,accounts=tuple(
            replace(a,balance=a.balance+1) if i==0 else a
            for i,a in enumerate(self.accounts)),issued_units=self.snapshot.issued_units+1)
        opts=self.opts(fake)
        opts['expected_source_digest']=sha384(SOURCE_DOMAIN,self.snapshot.encode())
        with self.assertRaises(Reject):verify_handoff(**opts)

    def test_account_amount_or_total_supply_tampering_reject(self):
        with self.assertRaises(Reject):replace(self.snapshot,issued_units=self.snapshot.issued_units+1).encode()
        with self.assertRaises(Reject):replace(self.snapshot,accounts=self.accounts[:-1]).encode()
        with self.assertRaises(Reject):replace(self.accounts[0],balance=True).encode()
        with self.assertRaises(Reject):replace(self.snapshot,issued_units=U64_MAX+1).encode()

    def test_missing_escrow_even_if_attacker_rebalances_source_rejects_pin(self):
        reduced=replace(self.snapshot,liabilities=self.liabilities[:-1],
                        issued_units=self.snapshot.issued_units-self.liabilities[-1].amount)
        with self.assertRaises(Reject):self.check(reduced,expected=sha384(SOURCE_DOMAIN,self.snapshot.encode()))
        with self.assertRaises(Reject):self.check(reduced)  # old dual signatures bind original snapshot

    def test_liability_owners_sorted_and_known_no_duplicate(self):
        for l in ((self.liabilities[1],self.liabilities[0]),
                  (self.liabilities[0],self.liabilities[0])):
            with self.subTest(l=l),self.assertRaises(Reject):
                replace(self.snapshot,liabilities=l).encode()
        foreign=replace(self.liabilities[0],owner_old_public=bytes([251])*32)
        with self.assertRaises(Reject):replace(self.snapshot,liabilities=(foreign,)).encode()
        with self.assertRaises(Reject):replace(self.liabilities[0],kind=99).encode()
        with self.assertRaises(Reject):replace(self.liabilities[0],amount=0).encode()

    def test_account_owner_order_uniqueness_and_network_separation(self):
        with self.assertRaises(Reject):replace(self.snapshot,accounts=self.accounts[::-1]).encode()
        with self.assertRaises(Reject):replace(self.snapshot,accounts=(self.accounts[0],)*3).encode()
        with self.assertRaises(Reject):replace(self.snapshot,new_network=self.old_net).encode()
        with self.assertRaises(Reject):replace(self.snapshot,legacy_head=bytes(32)).encode()

    def test_wrong_old_ed_signature_rejected(self):
        tampered=replace(self.migrations[0],old_signature=self.migrations[0].old_signature[:-1]+b'\x00')
        # Deterministic tamper might equal original byte, flip guarantees alteration.
        raw=bytearray(self.migrations[0].old_signature);raw[-1]^=1
        tampered=replace(tampered,old_signature=bytes(raw))
        with self.assertRaises(Reject):self.check(proofs=(tampered,self.migrations[1]))
        with self.assertRaises(Reject):self.check(proofs=(replace(tampered,old_signature=bytes(64)),))

    def test_wrong_real_pq_signature_and_key_rejected(self):
        sig=bytearray(self.migrations[0].pq_signature);sig[-1]^=1
        with self.assertRaises(Reject):self.check(proofs=(replace(self.migrations[0],pq_signature=bytes(sig)),))
        with self.assertRaises(Reject):self.check(proofs=(replace(self.migrations[0],new_pq_public_pem=self.pq[3][1]),))
        with self.assertRaises(Reject):self.check(proofs=(replace(self.migrations[0],pq_signature=bytes(64)),))

    def test_cross_network_and_profile_or_head_remap_even_with_new_external_pin_reject(self):
        changes=({'new_network':bytes([0x62])*32},{'legacy_network':bytes([0x52])*32},
                 {'new_protocol_hash':bytes([0x92])*32},
                 {'legacy_head':bytes([0x72])*32},
                 {'revocation_head':bytes([0x82])*32})
        for kw in changes:
            with self.subTest(changed=kw),self.assertRaises(Reject):
                self.check(replace(self.snapshot,**kw))

    def test_generation_next_nonce_balance_rebind_reject(self):
        for kw in ({'generation':self.accounts[0].generation+1},
                   {'next_nonce':self.accounts[0].next_nonce+1},
                   {'balance':self.accounts[0].balance+1}):
            new_accounts=list(self.accounts)
            new_accounts[0]=replace(new_accounts[0],**kw)
            new_supply=self.snapshot.issued_units+int(kw.get('balance',self.accounts[0].balance))-self.accounts[0].balance
            altered=replace(self.snapshot,accounts=tuple(new_accounts),issued_units=new_supply)
            with self.subTest(changed=kw),self.assertRaises(Reject):self.check(altered)

    def test_expiry_and_boolean_now_reject(self):
        with self.assertRaises(Reject):self.check(now=1001)
        with self.assertRaises(Reject):self.check(now=True)
        with self.assertRaises(Reject):self.check(now=-1)
        self.assertEqual(self.check(now=1000).migrated_count,2)

    def test_duplicate_source_claim_rejected(self):
        with self.assertRaises(Reject):self.check(proofs=(self.migrations[0],self.migrations[0]))
        unknown=replace(self.migrations[0],old_public=self.old[3][1])
        with self.assertRaises(Reject):self.check(proofs=(unknown,))

    def test_same_pq_key_migration_from_two_old_accounts_rejected(self):
        account=self.accounts[1]
        old=next(sk for sk,p in self.old if p==account.old_ed25519_public)
        second=sign_migration_fixture(self.snapshot,account,old_private=old,
                new_pq_public=self.pq[0][1],new_pq_private=self.pq[0][0],expires_at=1000)
        with self.assertRaises(Reject):self.check(proofs=(self.migrations[0],second))

    def test_explicit_revocation_never_migrates_and_foreign_revocation_rejected(self):
        with self.assertRaises(Reject):self.check(revoked=frozenset({self.accounts[0].old_ed25519_public}))
        with self.assertRaises(Reject):self.check(revoked=frozenset({bytes([244])*32}))
        with self.assertRaises(Reject):self.check(revoked=set())
        result=self.check(proofs=(self.migrations[1],),revoked=frozenset({self.accounts[0].old_ed25519_public}))
        self.assertEqual(result.quarantined_count,2)

    def test_missing_expected_source_digest_or_wrong_issued_anchor_reject(self):
        with self.assertRaises(Reject):self.check(expected=bytes(48))
        for bad in (bytes(47),bytes(49),bytes(32)):
            with self.subTest(length=len(bad)),self.assertRaises(Reject):self.check(expected=bad)
        opts=self.opts();opts['expected_issued_units']=self.snapshot.issued_units+1
        with self.assertRaises(Reject):verify_handoff(**opts)

    def test_altered_old_public_key_identity_does_not_grant_target_account(self):
        proof=replace(self.migrations[0],old_public=self.accounts[2].old_ed25519_public)
        with self.assertRaises(Reject):self.check(proofs=(proof,))
        self.assertNotEqual(self.check().target_genesis_id,self.check(proofs=()).target_genesis_id)

    def test_classical_ed25519_pem_rejects_as_mldsa_public_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'legacy.pem'
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(p)],check=True,capture_output=True)
            result=subprocess.run(['openssl','pkey','-in',str(p),'-pubout'],check=True,capture_output=True)
            with self.assertRaises(Reject):pq_key_id(result.stdout)
            with self.assertRaises(Reject):self.check(proofs=(replace(self.migrations[0],new_pq_public_pem=result.stdout),))

    def test_external_spki_prefix_is_strict_and_no_fake_crypto_result(self):
        with self.assertRaises(Reject):pq_key_id(b'fake public key')
        self.assertEqual(pq_key_id(self.pq[0][1]),pq_key_id(self.pq[0][1]))
        with self.assertRaises(Reject):verify_pq(self.pq[0][1],b'fake',bytes(3309))
        with self.assertRaises(Reject):sign_pq_fixture(self.pq[0][0],b'x'*65537)

    def test_unsigned_generations_quarantined_snapshot_not_a_forged_authority(self):
        v=self.check(proofs=())
        self.assertFalse(hasattr(v,'allow_classical'))
        self.assertFalse(hasattr(v,'grant'))
        self.assertFalse(hasattr(v,'verified_work'))
        self.assertFalse(hasattr(v,'finalized'))

    def test_source_bounds_and_zero_typed_counters_reject(self):
        with self.assertRaises(Reject):replace(self.snapshot,accounts=()).encode()
        with self.assertRaises(Reject):replace(self.snapshot,accounts=(self.accounts[0],)*(MAX_ACCOUNTS+1)).encode()
        with self.assertRaises(Reject):replace(self.snapshot,liabilities=(self.liabilities[0],)*(MAX_LIABILITIES+1)).encode()
        with self.assertRaises(Reject):replace(self.accounts[0],next_nonce=0).encode()
        with self.assertRaises(Reject):replace(self.accounts[0],generation=0).encode()
        with self.assertRaises(Reject):replace(self.accounts[0],balance=-1).encode()
        with self.assertRaises(Reject):self.check(replace(self.snapshot,accounts=(replace(self.accounts[0],generation=U64_MAX),)+self.accounts[1:]))


if __name__=='__main__':unittest.main()
