"""Actual SHA-256 checks; arbitrary-IV fixed points are not W1 forgeries."""
import hashlib
import unittest
import w1_sha256_model_boundary as model


class Sha256ModelBoundaryTests(unittest.TestCase):
    def test_standard_iv_single_and_multiple_blocks_match_hashlib(self):
        messages = [b'', b'abc', bytes(range(64)), b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq']
        messages += [bytes((i * 7) % 256 for i in range(length)) for length in (1, 55, 56, 63, 65, 66, 119, 120, 128, 343, 512)]
        for message in messages:
            self.assertEqual(model.sha256(message), hashlib.sha256(message).digest())
        self.assertEqual(model.sha256(b'abc').hex(), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')

    def test_round_and_complete_permutation_roundtrip(self):
        states = [model.IV, (0,) * 8, (model.MASK,) * 8, tuple((i * 0x1234567) & model.MASK for i in range(8))]
        for block in (bytes(64), bytes(range(64)), b'\xff' * 64):
            words = model.schedule(block)
            for state in states:
                for index in range(64):
                    forward = model.round_forward(state, model.K[index], words[index])
                    self.assertEqual(model.round_inverse(forward, model.K[index], words[index]), state)
                    reverse = model.round_inverse(state, model.K[index], words[index])
                    self.assertEqual(model.round_forward(reverse, model.K[index], words[index]), state)
                self.assertEqual(model.permutation(model.permutation(state, block), block, inverse=True), state)
                self.assertEqual(model.permutation(model.permutation(state, block, inverse=True), block), state)

    def test_fixed_points_use_chosen_iv_and_supply_no_standard_iv_path(self):
        for block in (bytes(64), bytes(range(64)), b'\xff' * 64,
                      b'TRNM-PON-TRACE1\0' + bytes(range(32)) + bytes(16)):
            point = model.fixed_point(block)
            self.assertEqual(model.permutation(point, block), (0,) * 8)
            self.assertEqual(model.compress(point, block), point)
            self.assertNotEqual(point, model.IV)
            self.assertEqual(model.sha256(block), hashlib.sha256(block).digest())
            row = model.observation(block)
            self.assertTrue(row['compression_is_fixed_point'])
            for key in ('standard_iv_reachability_provided', 'canonical_w1_trace_provided',
                        'sha256_standard_iv_preimage_or_collision_provided'):
                self.assertIs(row[key], False)
        for key in ('global_arbitrary_cv_random_compression_bad_bound_instantiates_sha256',
                    'rooted_canonical_w1_path_bound_established', 'physical_resource_floor_established',
                    'production_activation', 'benchmark'):
            self.assertIs(model.summary()[key], False)


if __name__ == '__main__':
    unittest.main()
