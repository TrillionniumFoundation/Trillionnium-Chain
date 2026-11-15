"""Constructive circuit controls, explicitly separating gates and macro runs."""
from collections import Counter
from dataclasses import replace
import hashlib
import math
from pathlib import Path
import struct
import unittest

from reversible_components import decode
from w1_quantum_primitives import digest_bytes, primitive, sha_compress, INITIAL_STATE
from w1_quantum_oracle import (
    FixedTemplate, OracleProgram, SelectionControl, Shape, h_bytes, template_from_spec,
)


def fixture(shape=Shape(1, 1, 4, 1), profile="PNH1", nonce_bits=16):
    a = tuple((i * 3 + 2) % shape.q for i in range(shape.n**2))
    b = tuple((i * 5 + 3) % shape.q for i in range(shape.n**2))
    field = lambda values: struct.pack("<" + "I" * len(values), *values)
    task = hashlib.sha256(h_bytes(b"task", field(a), field(b))).digest()
    header = (b"PNH1\x01\0" + bytes([1]) * 32 + bytes([2]) * 32 + bytes([3]) * 32
              + struct.pack("<QQ", 7, 11) + bytes([255]) * 32
              + b"".join(bytes([i]) * 32 for i in range(5, 9)) + task + bytes(8))
    if profile == "PGH2":
        header = b"PGH2" + header + bytes([10]) * 32
    return FixedTemplate.from_header(header, a, b, nonce_bits, shape)


def reference(template, nonce):
    """Separately organized scalar relation for reduced-shape controls."""
    shape = template.shape
    n, r, q = shape.n, shape.r, shape.q
    challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
    factors, complete = [], []
    for label in range(4):
        accepted = []
        for counter in range(shape.noise_counters):
            digest = hashlib.sha256(h_bytes(b"noise", challenge, bytes([label]), struct.pack("<I", counter))).digest()
            for (raw,) in struct.iter_unpack("<I", digest):
                value = raw & ((1 << shape.field_bits) - 1)
                if value < q:
                    accepted.append(value)
        complete.append(len(accepted) >= n * r)
        factors.append((accepted + [0] * (n * r))[:n * r])
    def mm(a, b, rows, inner, cols):
        return [sum(a[i * inner + k] * b[k * cols + j] for k in range(inner)) % q
                for i in range(rows) for j in range(cols)]
    e = mm(factors[0], factors[1], n, r, n)
    f = mm(factors[2], factors[3], n, r, n)
    ap = [(x + y) % q for x, y in zip(template.a, e)]
    bp = [(x + y) % q for x, y in zip(template.b, f)]
    cells, transcript = [0] * (n * n), bytearray(b"TRNM-PON-TRACE1\0" + challenge)
    for i0 in range(0, n, r):
        for j0 in range(0, n, r):
            for k0 in range(0, n, r):
                for i in range(i0, i0 + r):
                    for j in range(j0, j0 + r):
                        pos = i * n + j
                        cells[pos] = (cells[pos] + sum(ap[i * n + k] * bp[k * n + j] for k in range(k0, k0 + r))) % q
                        transcript.extend(struct.pack("<I", cells[pos]))
    trace = hashlib.sha256(transcript).digest()
    ticket = hashlib.sha256(h_bytes(b"ticket", challenge, trace)).digest()
    return {"challenge": challenge.hex(), "trace": trace.hex(), "ticket": ticket.hex(),
            "noise_complete": complete,
            "winner": all(complete) and int.from_bytes(ticket, "big") <= template.target}


class LeafAndSelectionControls(unittest.TestCase):
    def test_add_and_accept_all_four_bit_inputs_including_noncanonical(self):
        add, accept = primitive("add", 4), primitive("accepted", 4)
        for a in range(16):
            self.assertEqual(accept.circuit.basis([a], 1), 1 ^ int(a < 11))
            for b in range(16):
                self.assertEqual(add.circuit.basis([a, b], 9), 9 ^ ((a + b) % 11))

    def test_unsigned_comparison_exhaustive_inclusive_boundary(self):
        compare = primitive("leq", 4)
        for a in range(16):
            for b in range(16):
                self.assertEqual(compare.circuit.basis([a, b], 1), 1 ^ int(a <= b))

    def test_selection_exhaustive_rejected_streams_arbitrary_xor_destination(self):
        control = SelectionControl(4, 2, 2)
        for a in range(16):
            for b in range(16):
                seeds = ((a ^ 7) & 15, (b ^ 9) & 15)
                result = control.execute((a, b), seeds)
                accepted = [value for value in (a, b) if value < 11]
                padded = (accepted + [0, 0])[:2]
                self.assertEqual(result["packed"], [x ^ y for x, y in zip(padded, seeds)])
                self.assertEqual(result["complete"], len(accepted) >= 2)
                self.assertEqual(result["accepted_count"], len(accepted))
                self.assertTrue(result["restored"])

    def test_selection_keeps_first_words_after_rejection_and_ignores_surplus(self):
        control = SelectionControl(4, 8, 3)
        for words in ((15, 11, 3, 14, 7, 1, 0, 10), (11,) * 8,
                      (12, 13, 14, 15, 11, 12, 13, 7)):
            result = control.execute(words)
            valid = [value for value in words if value < 11]
            self.assertEqual(result["packed"], (valid + [0, 0, 0])[:3])
            self.assertEqual(result["complete"], len(valid) >= 3)
            self.assertTrue(result["restored"])
        self.assertFalse(control.execute((1, 2, 3, 4, 5, 6, 7, 8), inverse=False)["restored"])

    def test_deleted_leaf_inverse_gate_is_detected_as_dirty_scratch(self):
        circuit = decode(primitive("add", 4).circuit.encode())
        circuit.gates.pop()
        with self.assertRaisesRegex(ValueError, "dirty ancilla"):
            circuit.basis([15, 15], 7)

    def test_scalar_compression_matches_universal_gate_chaining_inputs(self):
        leaf = primitive("sha")
        for message, chain in ((0, 0), ((1 << 512) - 1, (1 << 256) - 1)):
            seed = (1 << 255) + 17
            self.assertEqual(leaf.circuit.basis([message, chain], seed), seed ^ sha_compress(message, chain))


class FixedHeaderControls(unittest.TestCase):
    def test_pnh1_pgh2_native_known_hash_domains(self):
        # Exact published native pon_growth.rs vector, independently encoded.
        header = (b"PNH1\x01\0" + b"".join(bytes([i]) * 32 for i in (1, 2, 3))
                  + struct.pack("<QQ", 7, 11) + b"".join(bytes([i]) * 32 for i in range(4, 10))
                  + struct.pack("<Q", 13))
        growth = b"PGH2" + header + bytes([10]) * 32
        self.assertEqual(hashlib.sha256(h_bytes(b"challenge", header)).hexdigest(),
                         "ac255d77ec6355f0382a5cbe1ac003e692e4802c00ccc9468c759869a1b8421d")
        self.assertEqual(hashlib.sha256(h_bytes(b"permanent-account-growth-challenge-v2", growth)).hexdigest(),
                         "8f051f34d44a6385e3c386325c2d82091d2563b40ce4443f1056ef5abf633208")

    def test_fixed_prefix_precomputation_full_suffix_hashing_and_growth_witness(self):
        for profile, length, blocks in (("PNH1", 343, 1), ("PGH2", 407, 2)):
            template = fixture(profile=profile)
            program = OracleProgram(template)
            report = program.resources()
            self.assertEqual(report["classical_preprocessing"]["fixed_header_sha_compressions"], 5)
            self.assertEqual(report["hash_framing"]["challenge_bytes"], length)
            self.assertEqual(report["hash_framing"]["coherent_challenge_compressions"], blocks)
            for nonce in (0, 1, 65535):
                result = program.execute(nonce)
                expected = reference(template, nonce)
                for key, value in expected.items():
                    self.assertEqual(result[key], value, (profile, nonce, key))
                self.assertTrue(result["clean_ancillas"])
                self.assertTrue(result["nonce_preserved"])
        changed = bytearray(template.header)
        changed[-1] ^= 1
        other = OracleProgram(FixedTemplate.from_header(bytes(changed), template.a, template.b, 16, template.shape))
        self.assertNotEqual(program.execute(1)["challenge"], other.execute(1)["challenge"])

    def test_header_task_target_schema_and_domains_fail_closed(self):
        template = fixture()
        for header in (template.header[:-1], template.header + b"x", b"PGH2" + template.header,
                       template.header[:278] + bytes(32) + template.header[310:],
                       template.header[:118] + bytes(32) + template.header[150:]):
            with self.subTest(header=len(header)), self.assertRaises(ValueError):
                FixedTemplate.from_header(header, template.a, template.b, shape=template.shape)
        for values in ((True,), (11,), (-1,), (float("nan"),), (1.0,), ()):
            with self.subTest(values=values), self.assertRaises(ValueError):
                FixedTemplate.from_header(template.header, values, template.b, shape=template.shape)
        for shape in (Shape(n=True), Shape(n=0), Shape(n=3, r=2), Shape(noise_counters=129)):
            with self.assertRaises(ValueError):
                shape.validate()
        spec = template.spec()
        self.assertEqual(template_from_spec(spec), template)
        with self.assertRaises(ValueError):
            template_from_spec({**spec, "native_verified": True})


class ConstructionControls(unittest.TestCase):
    def test_leaf_output_cannot_alias_search_input(self):
        from w1_quantum_oracle import Constant, Operation, Runner
        program = OracleProgram(fixture())
        runner = Runner(program, 'gates')
        aliased = Operation(primitive('add', 16), (program.nonce, Constant(16, 0)), program.nonce)
        with self.assertRaisesRegex(ValueError, 'INPUT_OUTPUT_ALIAS'):
            runner.apply(aliased)

    def test_campaign_numeric_parser_and_git_commitment_fail_closed(self):
        from experiments import w1_quantum_oracle_campaign as campaign
        for raw in (b'{"x":NaN}', b'{"x":1e999}', b'{"x":-1e999}',
                    b'{"x":1,"x":2}', ('{"x":' + str(1 << 256) + '}').encode()):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                campaign.strict_load(raw)
        record = campaign.source_record()
        campaign.validate_source(record)
        record['all_sources_committed_at_head'] = not record['all_sources_committed_at_head']
        with self.assertRaisesRegex(ValueError, 'COMMITMENT_CLAIM'):
            campaign.validate_source(record)

    def test_symbolic_census_equals_enumerated_schedule_and_literal_reverse(self):
        program = OracleProgram(fixture(Shape(2, 1, 4, 1)))
        for stage in program.STAGES:
            operations = list(program.stage_operations(stage))
            observed = Counter(op.leaf for op in operations)
            self.assertEqual(dict(observed), program.stage_counts()[stage], stage)
            self.assertEqual(list(program.stage_operations(stage, True)), list(reversed(operations)), stage)

    def test_reduced_matrix_prefixes_match_independent_scalar_reference(self):
        for shape in (Shape(2, 1, 4, 1), Shape(2, 2, 4, 1), Shape(4, 2, 4, 2)):
            template = fixture(shape)
            program = OracleProgram(template)
            for nonce in (0, 7):
                observed = program.execute(nonce)
                for key, value in reference(template, nonce).items():
                    self.assertEqual(observed[key], value, (shape, nonce, key))
                self.assertTrue(observed["clean_ancillas"])

    def test_complete_reduced_gate_phase_success_and_forced_noise_exhaustion(self):
        template = fixture()
        program = OracleProgram(template)
        bad = None
        # A deliberate reduced-width control makes the native rare rejection
        # branches accessible. Real W1 remains width32/cap128 in native runs.
        for nonce in range(65536):
            challenge = hashlib.sha256(h_bytes(template.challenge_tag, template.header_for(nonce))).digest()
            if any(all((word[0] & 15) >= 11 for word in struct.iter_unpack(
                    '<I', hashlib.sha256(h_bytes(b'noise', challenge, bytes([label]), bytes(4))).digest())) for label in range(4)):
                bad = nonce
                break
        self.assertIsNotNone(bad)
        for nonce, winner in ((0, True), (bad, False)):
            result = program.execute(nonce, mode="gates")
            self.assertEqual(result["winner"], winner)
            self.assertEqual(result["phase"], -1 if winner else 1)
            self.assertTrue(result["clean_ancillas"])
            self.assertTrue(result["nonce_preserved"])
            self.assertEqual(result["leaf_gates_executed"] + result["outer_X_Z_gates_executed"],
                             program.resources()["phase_oracle_gate_count"])
            for key, value in reference(template, nonce).items():
                self.assertEqual(result[key], value)
        self.assertFalse(program.execute(0, inverse=False)["clean_ancillas"])

    def test_diffusion_small_statevector_is_reflection_and_clears_ancillas(self):
        n = 3
        program = OracleProgram(fixture(nonce_bits=n))
        gates = list(program.diffusion_gates())
        self.assertEqual(len(gates), program.resources()["diffusion"]["gate_count"])
        mapping = {wire: i for i, wire in enumerate(program.nonce.bits())}
        mapping.update({program.layout.qubits + i: n + i for i in range(n - 1)})
        for basis in range(1 << n):
            amplitudes = [0.0] * (1 << (2 * n - 1))
            amplitudes[basis] = 1.0
            for kind, wire, *controls in gates:
                bit = 1 << mapping[wire]
                if kind == "H":
                    for i in range(len(amplitudes)):
                        if not i & bit:
                            a, b = amplitudes[i], amplitudes[i | bit]
                            amplitudes[i], amplitudes[i | bit] = (a + b) / math.sqrt(2), (a - b) / math.sqrt(2)
                elif kind == "Z":
                    amplitudes = [-a if i & bit else a for i, a in enumerate(amplitudes)]
                else:
                    old = amplitudes[:]
                    for i in range(len(old)):
                        active = all(i >> mapping[c] & 1 for c in controls)
                        amplitudes[i ^ bit if active else i] = old[i]
            for i, value in enumerate(amplitudes):
                expected = (float(i == basis) - 2 / (1 << n)) if i < 1 << n else 0.0
                self.assertAlmostEqual(value, expected)

    def test_exported_request_accounts_phase_inverse_and_diffusion(self):
        from quantum_oracle_resources import ClassicalCosts, Workload, account
        program = OracleProgram(fixture())
        request = program.resource_request(Workload(1, 1, 1, 1, 1, (), 0), ClassicalCosts(5, 1, 1, 1, 100, 1))
        result = account(request)
        report = program.resources()
        self.assertEqual(result["complete_quantum_cost"]["per_grover_iteration"]["gate_count"],
                         report["phase_oracle_gate_count"] + report["diffusion"]["gate_count"])
        self.assertFalse(result["quantum_mining_qualified"])
        self.assertFalse(report["quantum_work_lower_bound_proved"])
        self.assertIsNone(report["physical_calibration"])

    def test_native_shape_symbolic_upper_counts_and_complete_macro_roundtrip(self):
        import work_oracle
        folder = Path(__file__).parent / "vectors"
        header, proof = (folder / "header.bin").read_bytes(), (folder / "work.bin").read_bytes()
        matrices = struct.unpack('<' + 'I' * 8192, proof[4:4 + 32768])
        template = FixedTemplate.from_header(header, matrices[:4096], matrices[4096:])
        program = OracleProgram(template)
        report = program.resources()
        census = Counter()
        for stage in program.stage_counts().values():
            for leaf, count in stage.items():
                census[leaf.kind] += count
        self.assertEqual(census["multiply"], 327680)
        self.assertEqual(census["add"], 335872)
        self.assertEqual(census["sha"], 3076)  # 1 + 1024 + 2049 + 2.
        self.assertEqual(census["select"], 4 * 1024 * 512)
        self.assertEqual(report["hash_framing"]["trace_bytes"], 131120)
        nonce = int.from_bytes(header[310:318], 'little')
        result = program.execute(nonce)
        challenge = hashlib.sha256(h_bytes(b'challenge', template.header_for(nonce))).digest()
        product, trace = work_oracle.evaluate(challenge, template.a, template.b)
        self.assertEqual(result["trace"], trace.hex())
        self.assertEqual(trace, proof[-32:])
        self.assertEqual(struct.pack('<' + 'I' * len(product), *product), proof[4 + 32768:-32])
        self.assertEqual(result["ticket"], hashlib.sha256(h_bytes(b'ticket', challenge, trace)).hexdigest())
        self.assertTrue(result["clean_ancillas"])
        self.assertIsNone(result["leaf_gates_executed"])
        self.assertFalse(result["quantum_hardware_executed"])
        with self.assertRaisesRegex(ValueError, "BUDGET"):
            program.execute(nonce, mode="gates", gate_limit=1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
