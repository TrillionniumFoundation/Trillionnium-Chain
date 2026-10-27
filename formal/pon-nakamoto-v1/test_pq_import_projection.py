"""PQI1 read-only import invariants, exact PQG1/PQS1 byte contract."""
from dataclasses import replace
import hashlib
import unittest

from pq_import_projection import (Reject, U64_MAX, ACCOUNT_SIZE, LIABILITY_SIZE,
    project_pqs1, decode_import_exact, _frame_hash,
    STATE_DOMAIN, GENESIS_ID_DOMAIN, ACCOUNT_DOMAIN, QUARANTINE_DOMAIN)

NET = bytes([0x31])*32
PROFILE = bytes([0x42])*32
SOURCE = bytes([0x53])*48
OLD_1 = bytes([1])*32
OLD_2 = bytes([2])*32
OLD_3 = bytes([3])*32
KID_1 = bytes([21])*32
KID_2 = bytes([22])*32


def acct(old, mode, kid, balance, nonce, oldgen):
    a = (hashlib.sha256(ACCOUNT_DOMAIN+NET+old+kid).digest() if mode
         else hashlib.sha256(QUARANTINE_DOMAIN+NET+old).digest())
    return (bytes([mode])+a+(kid if mode else bytes(32))+old+
            balance.to_bytes(8,'big')+nonce.to_bytes(8,'big')+
            oldgen.to_bytes(8,'big')+(oldgen+1).to_bytes(8,'big'))


def liability(idx, old, kind, amount, due):
    return (bytes([idx])*32+old+amount.to_bytes(8,'big')+
            due.to_bytes(8,'big')+bytes([kind]))


def fixture():
    aa=(acct(OLD_1,1,KID_1,1200,2**40+7,9),
        acct(OLD_2,0,bytes(32),550,18,4),
        acct(OLD_3,1,KID_2,155,100,3))
    ll=(liability(1,OLD_1,1,21,0), liability(2,OLD_2,2,22,6),
        liability(3,OLD_3,3,23,900),liability(4,OLD_2,4,24,1))
    total=1200+550+155+21+22+23+24
    raw=(b'PQS1\x01'+NET+PROFILE+len(aa).to_bytes(2,'big')+
         b''.join(aa)+len(ll).to_bytes(2,'big')+b''.join(ll)+total.to_bytes(8,'big'))
    return raw,aa,ll,total


def pinned(raw):
    root=_frame_hash(STATE_DOMAIN,raw)
    return dict(expected_network=NET,expected_profile=PROFILE,
                expected_source_digest=SOURCE,expected_state_root=root,
                expected_genesis_id=_frame_hash(GENESIS_ID_DOMAIN,NET+PROFILE+SOURCE+root))


class PQImportProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw,cls.accounts,cls.liabilities,cls.total=fixture()
        cls.pins=pinned(cls.raw)

    def observe(self,raw=None,**k):
        opts=dict(self.pins);opts.update(k)
        return project_pqs1(self.raw if raw is None else raw,**opts)

    def test_preserves_every_liability_nonce_generation_and_quarantine(self):
        result=self.observe()
        self.assertEqual((result.active_count,result.quarantined_count,result.liability_count),(2,1,4))
        self.assertEqual(result.issued_units,self.total)
        self.assertEqual(result.projection_bytes[225:225+3*ACCOUNT_SIZE],b''.join(self.accounts))
        self.assertEqual(result.projection_bytes[225+3*ACCOUNT_SIZE:],b''.join(self.liabilities))
        self.assertEqual(int.from_bytes(result.projection_bytes[225+105:225+113],'big'),2**40+7)
        self.assertEqual(decode_import_exact(result.projection_bytes),result)
        for role in (b'final_use',b'activated',b'chainwork',b'granted',b'minted'):
            self.assertFalse(hasattr(result,role.decode()))

    def test_all_four_liability_kinds_preserved_and_expiry_not_applied(self):
        v=self.observe().projection_bytes
        offset=225+3*ACCOUNT_SIZE
        self.assertEqual([v[offset+i*LIABILITY_SIZE+80] for i in range(4)],[1,2,3,4])
        self.assertEqual([int.from_bytes(v[offset+i*LIABILITY_SIZE+64:offset+i*LIABILITY_SIZE+72],'big') for i in range(4)], [21,22,23,24])

    def test_mutate_all_pqs1_bytes_with_original_independent_pins(self):
        for i in range(len(self.raw)):
            x=bytearray(self.raw);x[i]^=1
            with self.subTest(byte=i),self.assertRaises(Reject):self.observe(bytes(x))

    def test_mutate_all_pqi1_bytes_with_original_reference(self):
        r=self.observe().projection_bytes
        for i in range(len(r)):
            x=bytearray(r);x[i]^=1
            with self.subTest(byte=i),self.assertRaises(Reject):decode_import_exact(bytes(x))

    def test_wrong_framing_and_legacy_pql1_rejected(self):
        raw=self.raw
        for bad in (raw[:-1],raw+b'x',b'PQL1'+raw[4:],b'PQS1\x02'+raw[5:],
                    raw[:69]+b'\x00\x00'+raw[71:], raw[:69]+b'\xff\xff'+raw[71:],
                    raw[:71+3*ACCOUNT_SIZE]+b'\xff\xff'+raw[71+3*ACCOUNT_SIZE+2:]):
            with self.subTest(length=len(bad)),self.assertRaises(Reject):self.observe(bad)
        encoded=self.observe().projection_bytes
        for bad in (encoded[:-1],encoded+b'a',b'PQL1'+encoded[4:],encoded[:4]+b'\x02'+encoded[5:]):
            with self.assertRaises(Reject):decode_import_exact(bad)

    def test_duplicate_pq_key_with_self_consistent_new_anchor_reject(self):
        raw,aa,ll,total=fixture()
        second=acct(OLD_2,1,KID_1,550,18,4)
        corrupt=raw[:71+ACCOUNT_SIZE]+second+raw[71+2*ACCOUNT_SIZE:]
        with self.assertRaises(Reject):project_pqs1(corrupt,**pinned(corrupt))

    def test_quarantine_cannot_hide_a_spendable_key(self):
        off=71+ACCOUNT_SIZE+33
        corrupt=self.raw[:off]+KID_1+self.raw[off+32:]
        with self.assertRaises(Reject):project_pqs1(corrupt,**pinned(corrupt))

    def test_account_key_and_id_tampering_with_rehashed_pin_reject(self):
        for loc in (71+1,71+33,71+65):
            raw=bytearray(self.raw);raw[loc]^=2
            with self.subTest(offset=loc),self.assertRaises(Reject):
                project_pqs1(bytes(raw),**pinned(bytes(raw)))

    def test_account_generation_and_nonce_loss_rejects_even_reanchored(self):
        for offset in (71+105,71+113,71+121):
            raw=bytearray(self.raw);raw[offset:offset+8]=bytes(8)
            with self.subTest(offset=offset),self.assertRaises(Reject):
                project_pqs1(bytes(raw),**pinned(bytes(raw)))
        # A valid old u64 max generation can never roll into a new one.
        raw=bytearray(self.raw);raw[71+113:71+121]=U64_MAX.to_bytes(8,'big')
        with self.assertRaises(Reject):project_pqs1(bytes(raw),**pinned(bytes(raw)))

    def test_account_order_and_duplicate_old_identity_fail(self):
        start=71;aa=self.accounts
        for badacc in ((aa[1],aa[0],aa[2]),(aa[0],aa[0],aa[2])):
            raw=self.raw[:start]+b''.join(badacc)+self.raw[start+len(b''.join(aa)):]
            with self.assertRaises(Reject):project_pqs1(raw,**pinned(raw))

    def test_liability_missing_owner_duplicates_kind_and_amount_fail(self):
        start=71+3*ACCOUNT_SIZE+2
        for loc,content in ((start+32,bytes([99])*32),(start+64,bytes(8)),
                            (start+80,b'\x07')):
            raw=self.raw[:loc]+content+self.raw[loc+len(content):]
            with self.subTest(loc=loc),self.assertRaises(Reject):project_pqs1(raw,**pinned(raw))
        raw=self.raw[:start+LIABILITY_SIZE]+self.liabilities[0]+self.raw[start+2*LIABILITY_SIZE:]
        with self.assertRaises(Reject):project_pqs1(raw,**pinned(raw))

    def test_omitted_liability_and_rebalanced_supply_does_not_match_original_pin(self):
        a,aa,b,t=fixture()
        ptr=71+3*ACCOUNT_SIZE
        remaining=b[:-1]
        changed=(a[:ptr]+len(remaining).to_bytes(2,'big')+b''.join(remaining)
                 +(t-24).to_bytes(8,'big'))
        with self.assertRaises(Reject):self.observe(changed)
        # Even self-consistent bytes are NOT original independently pinned head.
        with self.assertRaises(Reject):self.observe(changed,expected_state_root=pinned(changed)['expected_state_root'])
        # This is a deliberate trust boundary, not a claim to detect forged external pins.
        self.assertEqual(project_pqs1(changed,**pinned(changed)).liability_count,3)

    def test_supply_inconsistent_even_when_digest_reanchored(self):
        raw=self.raw[:-8]+(self.total+1).to_bytes(8,'big')
        with self.assertRaises(Reject):project_pqs1(raw,**pinned(raw))

    def test_wrong_external_pins_and_bad_types(self):
        raw=self.raw
        names={'expected_network':32,'expected_profile':32,'expected_source_digest':48,
               'expected_state_root':48,'expected_genesis_id':48}
        for name,width in names.items():
            for value in (bytes(width),bytes(width-1),bytes(width+1),'not bytes',True):
                with self.subTest(name=name,value=str(value)[:12]),self.assertRaises(Reject):
                    self.observe(**{name:value})
        with self.assertRaises(Reject):project_pqs1(bytearray(raw),**self.pins)
        with self.assertRaises(Reject):decode_import_exact(bytearray(self.observe().projection_bytes))

    def test_bounded_accounts_and_liabilities_even_reanchored(self):
        # Framing rejects candidate that pretends to have more than production bound.
        for count,location in ((129,69),(257,71+3*ACCOUNT_SIZE)):
            raw=bytearray(self.raw);raw[location:location+2]=count.to_bytes(2,'big')
            with self.assertRaises(Reject):project_pqs1(bytes(raw),**pinned(bytes(raw)))

if __name__ == '__main__':
    unittest.main()
