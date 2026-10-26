"""Exhaustive single-bit research corruption screen of one genuine signed Q4 fixture.

This is NOT a formal proof of Q4 signer security or native consensus behavior.
"""
import unittest
from test_q4_signed_wire_oracle_v1 import Fixture
from q4_signed_wire_oracle_v1 import Q4Reject, parse_lease

class FullWireMutationTests(unittest.TestCase):
    def test_every_1187_signed_packet_byte_rejects_one_bit_corruption(self):
        fixture=Fixture()
        packet=fixture.packet()
        self.assertEqual(len(packet),1187)
        for offset in range(len(packet)):
            changed=bytearray(packet)
            changed[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(Q4Reject):
                fixture.inspect(bytes(changed),height=900)

    def test_every_old_lease_byte_cannot_be_replaced_without_new_owner_context(self):
        fixture=Fixture()
        packet=fixture.packet()
        self.assertEqual(len(fixture.old),344)
        for offset in range(len(fixture.old)):
            changed=bytearray(fixture.old)
            changed[offset]^=1
            with self.subTest(offset=offset), self.assertRaises(Q4Reject):
                from q4_signed_wire_oracle_v1 import inspect_presigned_q4
                inspect_presigned_q4(packet,bytes(changed),containing_height=900,
                    network=fixture.network,parameters=fixture.parameters,
                    expected_old_lease_id=fixture.inspect(packet).old_lease_id,
                    expected_requester_sequence=4,previous_source_sequence=1,
                    previous_material=fixture.bound)

    def test_caller_must_pin_the_exact_old_lease_identity(self):
        from q4_signed_wire_oracle_v1 import H
        fixture=Fixture()
        with self.assertRaisesRegex(Q4Reject,'OLD_LEASE_SNAPSHOT_DRIFT'):
            fixture.inspect(expected_old_lease_id=H('foreign-old-lease',b'different-parent'))
        with self.assertRaisesRegex(Q4Reject,'expected_old_lease_id_ID'):
            fixture.inspect(expected_old_lease_id=b'\0'*32)

if __name__=='__main__': unittest.main()
