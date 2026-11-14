#!/usr/bin/env python3
"""Offline source-builder contract controls; no provider or proof is simulated."""
import ast
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("w1_source_builder", ROOT / "scripts/build_w1_kaggle_source.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class SourceBuilderContract(unittest.TestCase):
    def setUp(self):
        # This inert function only exercises Python source serialization. It is
        # never executed or presented as a prover, verifier, or provider result.
        self.template = b"def main(config):\n    raise RuntimeError('serialization fixture only')\n"
        self.config = {"schema": builder.STATIC_SCHEMA,
                       "source_commit": "a" * 40, "source_tree": "b" * 40,
                       "template_sha256": builder.digest(self.template), "r0vm_sha256": "c" * 64,
                       "segment_workers": 2, "compression_mode": "balanced",
                       "compression_workers": 2, "rayon_threads": 2, "worker_wall_seconds": 3600}

    def test_exact_pinned_configuration_accepts_observed_four_cpu_envelope(self):
        self.assertEqual(builder.validate_static(self.config, self.template), self.config)
        sequential = dict(self.config, segment_workers=1, compression_mode="sequential",
                          compression_workers=1, rayon_threads=4)
        self.assertEqual(builder.validate_static(sequential, self.template), sequential)
        self.assertEqual(builder.REPO_URL, "https://github.com/TrillionniumFoundation/Trillionnium-Chain.git")
        self.assertEqual(builder.GUEST_SHA256,
                         "25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f")

    def test_unknown_schema_fields_and_boolean_or_float_budgets_are_rejected(self):
        cases = [dict(self.config, schema="old"), dict(self.config, repo_url="https://other.invalid"),
                 dict(self.config, worker_wall_seconds=True), dict(self.config, worker_wall_seconds=3600.0),
                 dict(self.config, worker_wall_seconds=7201), dict(self.config, worker_wall_seconds=59),
                 dict(self.config, segment_workers=True), dict(self.config, rayon_threads=2.0)]
        missing = dict(self.config)
        del missing["source_tree"]
        cases.append(missing)
        for case in cases:
            with self.subTest(config=case), self.assertRaises(ValueError):
                builder.validate_static(case, self.template)

    def test_source_tree_binary_and_template_identifiers_are_exact(self):
        for field in ("source_commit", "source_tree", "template_sha256", "r0vm_sha256"):
            for bad in ("", "a" * 39, "A" * 64, "g" * 64, 7, None):
                with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                    builder.validate_static(dict(self.config, **{field: bad}), self.template)

    def test_nested_parallel_oversubscription_and_implicit_compression_are_rejected(self):
        cases = [dict(self.config, segment_workers=3), dict(self.config, compression_workers=3),
                 dict(self.config, rayon_threads=3), dict(self.config, compression_mode="auto"),
                 dict(self.config, compression_mode="sequential"), dict(self.config, segment_workers=0)]
        for case in cases:
            with self.subTest(config=case), self.assertRaises(ValueError):
                builder.validate_static(case, self.template)

    def test_template_mutation_bom_crlf_and_wrong_entry_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "template digest"):
            builder.validate_static(self.config, self.template + b"# changed\n")
        for changed in (b"\xef\xbb\xbf" + self.template, self.template.replace(b"\n", b"\r\n"),
                        b"def other(config):\n    pass\n", b"def main(a, b):\n    pass\n"):
            with self.subTest(template=changed), self.assertRaises(ValueError):
                builder.render_source(changed, self.config)

    def test_duplicate_or_oversized_configuration_never_silently_normalizes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"schema":"one","schema":"two"}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                builder.read_object(path)
            path.write_text("[1,2]")
            with self.assertRaisesRegex(ValueError, "object"):
                builder.read_object(path)
            path.write_text('{"padding":"' + "a" * 100 + '"}')
            with self.assertRaisesRegex(ValueError, "bounded"):
                builder.read_object(path, limit=16)

    def test_serialization_is_deterministic_bounded_and_never_interpolates_code(self):
        config = dict(self.config, request_id="quote'\"\n__import__('os').system('unexpected')")
        source = builder.render_source(self.template, config)
        self.assertEqual(source, builder.render_source(self.template, dict(reversed(list(config.items())))))
        parsed = ast.parse(source)
        call = parsed.body[-1].body[-1].exc.args[0].args[0]
        self.assertEqual(json.loads(ast.literal_eval(call.args[0])), config)
        self.assertTrue(source.endswith(b"\n"))
        self.assertNotIn(b"\r", source)
        with self.assertRaisesRegex(ValueError, "byte budget"):
            builder.render_source(self.template, {"padding": "x" * builder.MAX_SOURCE_BYTES})
        with self.assertRaises(ValueError):
            builder.render_source(self.template, {"invalid_number": float("nan")})

    def test_existing_outputs_and_symlink_destinations_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output = root / "source.py"
            builder.write_new_bytes(output, b"immutable source\n")
            self.assertEqual(output.read_bytes(), b"immutable source\n")
            with self.assertRaises(FileExistsError):
                builder.write_new_bytes(output, b"changed\n")
            link = root / "link.py"
            link.symlink_to(output)
            with self.assertRaises(FileExistsError):
                builder.write_new_bytes(link, b"changed through link\n")
            self.assertEqual(output.read_bytes(), b"immutable source\n")
            with self.assertRaises(ValueError):
                builder.write_new_bytes(Path("relative.py"), b"not written\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
