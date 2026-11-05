"""Independent codec and graph negatives for the TCD1 Rust boundary."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest

import cell_dependency_closure as closure


class DependencyClosureTests(unittest.TestCase):
    def setUp(self):
        self.vector = json.loads((Path(__file__).with_name("vectors") /
                                  "cell-dependency-closure-v1.json").read_text())
        self.value = copy.deepcopy(self.vector["closure"])
        self.wire = bytes.fromhex(self.vector["wire_hex"])

    def reject(self, value):
        with self.assertRaises(ValueError):
            closure.encode(value)

    def test_fixed_independent_vector_is_reproducible(self):
        self.assertEqual(closure.fixture(), self.vector)
        self.assertEqual(closure.encode(self.value), self.wire)
        self.assertEqual(closure.decode(self.wire), self.value)
        self.assertEqual(hashlib.sha256(closure.DOMAIN + self.wire).hexdigest(),
                         self.vector["closure_id"])

    def test_every_truncated_prefix_and_suffix_fail(self):
        for end in range(len(self.wire)):
            with self.subTest(end=end), self.assertRaises(ValueError):
                closure.decode(self.wire[:end])
        with self.assertRaises(ValueError):
            closure.decode(self.wire + b"\0")

    def test_portable_paths_exclude_traversal_reserved_and_aliases(self):
        for path in ("../weights", "/weights", "base/../weights", "base//weights",
                     "base/./weights", "base/model.", "base/.secret",
                     "base\\model", "base/model:stream", "base/model ", "base/模型",
                     "base/con.bin", "base/CON.bin", "base/com1.bin", "base/lpt9.bin",
                     "a/b/c/d/e/f/g/h/i", "base/" + "x" * 65):
            value = copy.deepcopy(self.value)
            value["files"][0]["path"] = path
            with self.subTest(path=path):
                self.reject(value)
        value = copy.deepcopy(self.value)
        value["files"][0]["path"] = "base"
        value["files"][1]["path"] = "base/tokenizer.json"
        self.reject(value)

    def test_owner_readme_case_is_preserved_without_case_fold_aliases(self):
        value = copy.deepcopy(self.value)
        value["files"][0]["path"] = "base/README.md"
        self.assertEqual(closure.decode(closure.encode(value)), value)
        value["files"][1]["path"] = "base/readme.md"
        self.reject(value)
        value["files"][0]["path"] = "BASE"
        value["files"][1]["path"] = "base/tokenizer.json"
        self.reject(value)

    def test_paths_and_indices_are_canonical_not_silently_reordered(self):
        value = copy.deepcopy(self.value)
        value["files"][0], value["files"][1] = value["files"][1], value["files"][0]
        self.reject(value)
        for dependencies in ([1, 0], [0, 0], [0, 3], [2], [False, 1]):
            value = copy.deepcopy(self.value)
            value["files"][2]["dependencies"] = dependencies
            self.reject(value)
        for roots in ([], [3], [2, 2], [2, 0]):
            value = copy.deepcopy(self.value)
            value["roots"] = roots
            self.reject(value)

    def test_cycle_and_unreachable_file_fail(self):
        value = copy.deepcopy(self.value)
        value["files"][0]["dependencies"] = [2]
        self.reject(value)
        value = copy.deepcopy(self.value)
        value["files"][2]["dependencies"] = [0]
        self.reject(value)

    def chain(self, count):
        value = copy.deepcopy(self.value)
        value["files"] = [{
            "path": f"f{i:03}.bin", "role": 1,
            "manifest": hashlib.sha256(f"manifest-{i}".encode()).hexdigest(),
            "payload_sha256": hashlib.sha256(f"payload-{i}".encode()).hexdigest(),
            "payload_bytes": 1, "dependencies": [] if i == 0 else [i - 1],
        } for i in range(count)]
        value["roots"] = [count - 1]
        return value

    def test_depth_bound_includes_shared_descendants(self):
        closure.encode(self.chain(16))
        self.reject(self.chain(17))
        value = self.chain(17)
        value["roots"] = [15, 16]
        self.reject(value)
        value = self.chain(4)
        value["files"][2]["dependencies"] = [0]
        value["files"][3]["dependencies"] = [1, 2]
        self.assertEqual(closure.decode(closure.encode(value)), value)

    def test_file_bound(self):
        value = self.chain(256)
        value["roots"] = list(range(256))
        for file in value["files"]:
            file["dependencies"] = []
        self.assertEqual(closure.decode(closure.encode(value)), value)
        self.reject(self.chain(257))

    def test_nonzero_context_generation_and_profile(self):
        for field, wrong in (("selected_generation", 0), ("selected_generation", 2**64),
                             ("selected_generation", True), ("loader_profile", "00" * 32)):
            value = copy.deepcopy(self.value)
            value[field] = wrong
            self.reject(value)
        value = copy.deepcopy(self.value)
        value["context"]["runtime"] = "00" * 32
        self.reject(value)

    def test_unknown_role_payload_size_and_manifest_alias_fail(self):
        for field, wrong in (("role", 0), ("role", 7), ("payload_bytes", 0),
                             ("payload_bytes", closure.MAX_CELL + 1),
                             ("manifest", "00" * 32), ("payload_sha256", "00" * 32)):
            value = copy.deepcopy(self.value)
            value["files"][0][field] = wrong
            self.reject(value)
        value = copy.deepcopy(self.value)
        value["files"][1]["manifest"] = value["files"][0]["manifest"]
        self.reject(value)

    def test_owner_binding_changes_identity(self):
        for field, changed in (("selected_generation", 8), ("loader_profile", "09" * 32),
                               ("roots", [0, 2])):
            value = copy.deepcopy(self.value)
            value[field] = changed
            changed_wire = closure.encode(value)
            self.assertNotEqual(hashlib.sha256(closure.DOMAIN + changed_wire).hexdigest(),
                                self.vector["closure_id"])

    def test_wire_bounds_and_embedded_release_membership(self):
        with self.assertRaises(ValueError):
            closure.decode(b"\0" * (closure.MAX_WIRE + 1))
        release_end = 48 + int.from_bytes(self.wire[44:48], "big")
        first_path_size = release_end + 2 + 2 * len(self.value["roots"]) + 2
        first_role = first_path_size + 2 + len(self.value["files"][0]["path"])
        for start, replacement in (
            (44, b"\xff" * 4), (release_end, (257).to_bytes(2, "big")),
            (first_path_size, (256).to_bytes(2, "big")), (first_role, b"\xff"),
            (first_role + 1, bytes([self.wire[first_role + 1] ^ 1])),
        ):
            bad = bytearray(self.wire)
            bad[start:start + len(replacement)] = replacement
            with self.subTest(start=start), self.assertRaises(ValueError):
                closure.decode(bytes(bad))


if __name__ == "__main__":
    unittest.main()
