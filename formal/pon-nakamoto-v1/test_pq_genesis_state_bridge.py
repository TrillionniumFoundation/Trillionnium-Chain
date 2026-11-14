"""PQL2 exhaustive negative tests for PQG1/PQS1 value/nonce/liability projection.

This suite intentionally does not pretend to perform ML-DSA or old-chain source
authentication: those remain the separate upstream PQG1 cryptographic/owner gates.
"""
from __future__ import annotations
from dataclasses import replace
import hashlib
import unittest
from pq_genesis_state_bridge import (
    Source, SourceAccount, Liability, NewAccount, Reject, parse_source, project,
    SOURCE_DOMAIN, STATE_DOMAIN, GENESIS_ID_DOMAIN,
    U64_MAX, _commit,
)


def H(v: bytes) -> bytes:
    return hashlib.sha256(v).digest()


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.old = tuple(sorted((H(b"ed25519-pub-A"), H(b"ed25519-pub-B"))))
        self.source = Source(
            H(b"legacy-net"), H(b"new-pq-net"), H(b"legacy-tip"),
            H(b"withdrawal-tip"), H(b"PQL2 consensus profile"), 1800,
            (SourceAccount(self.old[0], 200, 23, 11),
             SourceAccount(self.old[1], 500, 91, 30)),
            tuple(sorted((Liability(H(b"due-task"), self.old[0], 300, 112, 1),
                          Liability(H(b"reward"),self.old[0],200, 132, 2),
                          Liability(H(b"quota"),self.old[1],400, 140, 3),
                          Liability(H(b"escrow"),self.old[1],200, 202, 4)),
                         key=lambda x:x.liability_id))
        )
        self.issuer = H(b"real-ML-DSA-65-key")
        self.accounts = (
            self._account(self.source.accounts[0], True),
            self._account(self.source.accounts[1], False),
        )
        self.raw_source = self.source.encode()
        self.raw_state = self._state(self.accounts)
        self.expected = self._pins()

    def _account(self, a, active):
        if active:
            kid = self.issuer
            target=H(b"TRNM/PQ/Account/v1\x00"+self.source.new_network+a.old_key+kid)
        else:
            kid=bytes(32)
            target=H(b"TRNM/PQ/Quarantine/v1\x00"+self.source.new_network+a.old_key)
        return NewAccount(int(active),target,kid,a,a.generation+1)

    def _state(self, accounts=None, liabilities=None, supply=None):
        if accounts is None:accounts=self.accounts
        if liabilities is None:liabilities=self.source.liabilities
        if supply is None:supply=self.source.issued
        return (b"PQS1\x01"+self.source.new_network+self.source.protocol
                +len(accounts).to_bytes(2,'big')
                +b''.join(a.encode_pqs1(self.source.new_network) for a in accounts)
                +len(liabilities).to_bytes(2,'big')
                +b''.join(l.encode() for l in liabilities)
                +supply.to_bytes(8,'big'))

    def _pins(self, source=None, state=None):
        src=self.raw_source if source is None else source
        s=self.raw_state if state is None else state
        sd=_commit(SOURCE_DOMAIN,src)
        root=_commit(STATE_DOMAIN,s)
        gid=_commit(GENESIS_ID_DOMAIN,self.source.new_network+self.source.protocol+sd+root)
        return dict(expected_source_digest=sd,expected_pqs1_root=root,expected_genesis_id=gid,
                    expected_legacy_network=self.source.legacy_network,
                    expected_new_network=self.source.new_network,
                    expected_legacy_head=self.source.legacy_head,
                    expected_withdrawal_head=self.source.revocation_head,
                    expected_protocol=self.source.protocol,expected_issued=self.source.issued)

    def go(self, source=None, state=None, **changes):
        pins=dict(self.expected)
        pins.update(changes)
        return project(self.raw_source if source is None else source,
                       self.raw_state if state is None else state,**pins)

    def test_preserves_inherited_nonce_and_generation_and_all_four_liabilities(self):
        p=self.go()
        self.assertEqual(p.inherited_nonce_floors,((self.accounts[0].account_id,23),
                                                  (self.accounts[1].account_id,91)))
        self.assertEqual(p.active_accounts,1)
        self.assertEqual(p.quarantined_accounts,1)
        self.assertEqual(p.carried_liabilities,4)
        self.assertEqual((p.spendable_units,p.quarantined_units,p.locked_liability_units),
                         (200,500,1100))
        self.assertEqual(p.spendable_units+p.quarantined_units+p.locked_liability_units,p.issued_units)
        self.assertEqual(p.issued_units,1800)
        self.assertEqual(p.state[:5],b'PQL2\x01')
        for item in (self.accounts[0].encode_pqs1(self.source.new_network),
                     self.accounts[1].encode_pqs1(self.source.new_network),
                     *[x.encode() for x in self.source.liabilities]):
            self.assertIn(item,p.state)
        self.assertFalse(hasattr(p,'adoption_authorized'))
        self.assertFalse(hasattr(p,'final_use'))

    def test_matches_upstream_pqg1_bytes_and_domain_exactly(self):
        self.assertEqual(parse_source(self.raw_source),self.source)
        self.assertEqual(self.go().projected_genesis_id,self.expected['expected_genesis_id'])
        self.assertEqual(self.go().projected_state_root,self.expected['expected_pqs1_root'])
        self.assertEqual(len(self.go().pql2_root),48)
        self.assertEqual(self.go().state,self.go().state)

    def test_every_source_header_byte_corruption_refused(self):
        for i in range(177):
            raw=bytearray(self.raw_source)
            raw[i]^=1
            with self.subTest(i=i), self.assertRaises(Reject):
                self.go(source=bytes(raw))

    def test_every_pqs1_byte_corruption_refused_by_independent_pin(self):
        for i in range(len(self.raw_state)):
            raw=bytearray(self.raw_state)
            raw[i]^=1
            with self.subTest(i=i),self.assertRaises(Reject):
                self.go(state=bytes(raw))

    def test_changed_hash_pins_fail_closed(self):
        for field in ('expected_source_digest','expected_pqs1_root','expected_genesis_id'):
            with self.subTest(field=field),self.assertRaises(Reject):
                self.go(**{field:bytes(48)})
            with self.subTest(field=field),self.assertRaises(Reject):
                self.go(**{field:b'X'*48})
        for field in ('expected_legacy_network','expected_new_network','expected_legacy_head',
                      'expected_withdrawal_head','expected_protocol'):
            with self.subTest(field=field),self.assertRaises(Reject):
                self.go(**{field:b'X'*32})
        with self.assertRaises(Reject): self.go(expected_issued=1801)
        with self.assertRaises(Reject): self.go(expected_issued=True)

    def test_even_attacker_reanchors_corrupt_state_rejected_semantically(self):
        changed=bytearray(self.raw_state)
        changed[71]=2   # invented PQ status; root is now independently changed
        with self.assertRaises(Reject): self.go(state=bytes(changed),**self._pins(state=bytes(changed)))

    def test_quarantine_must_not_receive_any_pq_key(self):
        changed=bytearray(self.raw_state)
        second=71+129
        changed[second+33:second+65]=self.issuer
        with self.assertRaises(Reject): self.go(state=bytes(changed),**self._pins(state=bytes(changed)))

    def test_quarantine_cannot_silently_become_active_even_with_reanchoring(self):
        altered=bytearray(self.raw_state)
        second=71+129
        altered[second]=1
        with self.assertRaises(Reject): self.go(state=bytes(altered),**self._pins(state=bytes(altered)))

    def test_no_silent_nonce_rewind_under_reanchored_projection(self):
        altered=bytearray(self.raw_state)
        # First account stored source next_nonce at record offsets 105..113
        altered[71+105:71+113]=(1).to_bytes(8,'big')
        with self.assertRaises(Reject): self.go(state=bytes(altered),**self._pins(state=bytes(altered)))

    def test_reject_duplicate_pq_id_even_if_new_address_hash_recomputed(self):
        accts=list(self.accounts)
        # Turn quarantined owner into active duplicate signer; recompute its exact address
        accts[1]=NewAccount(1,H(b'TRNM/PQ/Account/v1\x00'+self.source.new_network+
                                     accts[1].source.old_key+self.issuer),self.issuer,
                            accts[1].source,accts[1].generation)
        altered=self._state(tuple(accts))
        with self.assertRaises(Reject): self.go(state=altered,**self._pins(state=altered))

    def test_old_generation_overflow_refuses_target_state(self):
        with self.assertRaises(Reject):
            NewAccount(0,self.accounts[0].account_id,bytes(32),
                       replace(self.source.accounts[0],generation=U64_MAX),0).encode_pqs1(self.source.new_network)

    def test_dropped_liability_refuses_even_when_attacker_reanchors_state(self):
        altered=self._state(liabilities=self.source.liabilities[:-1])
        with self.assertRaises(Reject): self.go(state=altered,**self._pins(state=altered))

    def test_liability_perturbation_and_reordering_refused(self):
        for replacement in (self.source.liabilities[::-1],
                            self.source.liabilities[:1]+(replace(self.source.liabilities[1],amount=2),)
                            +self.source.liabilities[2:]):
            altered=self._state(liabilities=replacement)
            with self.assertRaises(Reject): self.go(state=altered,**self._pins(state=altered))

    def test_new_target_supply_must_not_absorb_escrow_into_balance(self):
        increased=replace(self.accounts[0],source=replace(self.accounts[0].source,balance=1300))
        changed=(b'PQS1\x01'+self.source.new_network+self.source.protocol
                 +len(self.accounts).to_bytes(2,'big')
                 +increased.encode_pqs1(self.source.new_network)
                 +self.accounts[1].encode_pqs1(self.source.new_network)
                 +len(self.source.liabilities).to_bytes(2,'big')
                 +b''.join(l.encode() for l in self.source.liabilities)
                 +self.source.issued.to_bytes(8,'big'))
        with self.assertRaises(Reject): self.go(state=changed,**self._pins(state=changed))

    def test_reject_truncated_trailing_and_wrong_types(self):
        for b in (self.raw_source[:-1],self.raw_source+b'z',b'PQX1'+self.raw_source[4:],
                  self.raw_source[:175]+b'\xff\xff'+self.raw_source[177:]):
            with self.assertRaises(Reject):self.go(source=b)
        for b in (self.raw_state[:-1],self.raw_state+b'_',b'PQX1'+self.raw_state[4:]):
            with self.assertRaises(Reject):self.go(state=b)
        with self.assertRaises(Reject):self.go(source='not bytes')
        with self.assertRaises(Reject):self.go(state='not bytes')

    def test_duplicate_unsorted_unknown_source_and_supply_rejected(self):
        with self.assertRaises(Reject):replace(self.source,accounts=self.source.accounts[::-1]).encode()
        with self.assertRaises(Reject):replace(self.source,accounts=(self.source.accounts[0],)*2).encode()
        with self.assertRaises(Reject):replace(self.source,liabilities=self.source.liabilities[::-1]).encode()
        with self.assertRaises(Reject):replace(self.source,liabilities=(replace(self.source.liabilities[0],old_owner=b'?'*32),)+self.source.liabilities[1:]).encode()
        with self.assertRaises(Reject):replace(self.source,issued=self.source.issued+1).encode()
        with self.assertRaises(Reject):replace(self.source,new_network=self.source.legacy_network).encode()

    def test_strict_balance_and_counter_bounds(self):
        for field,value in (('balance',True),('next_nonce',0),('generation',0),('generation',U64_MAX+1)):
            with self.subTest(field=field),self.assertRaises(Reject):
                replace(self.source.accounts[0],**{field:value}).encode()
        with self.assertRaises(Reject):replace(self.source.liabilities[0],amount=0).encode()
        with self.assertRaises(Reject):replace(self.source.liabilities[0],kind=5).encode()
        with self.assertRaises(Reject):replace(self.source.liabilities[0],due_height=-1).encode()
        with self.assertRaises(Reject):replace(self.source,issued=U64_MAX+1).encode()

    def test_cannot_infer_cryptographic_or_authority_status_from_projection(self):
        p=self.go()
        for attribute in ('signatures_verified','source_chain_finalized','release_authorized',
                          'final_use','block_accepted','verified_work','mining_permit',
                          'chainwork','issuer_private_key'):
            with self.subTest(attribute=attribute):
                self.assertFalse(hasattr(p,attribute))


if __name__=='__main__':
    unittest.main()
