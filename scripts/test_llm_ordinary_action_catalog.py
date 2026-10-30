"""Real bounded-file producer controls; synthetic declarations, no model/native use."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

import llm_cell_release as release
import llm_ordinary_action_catalog as catalog


class OrdinaryCatalogTests(unittest.TestCase):
    def row(self, index=0):
        return dict(memory_id=f"memory:{index}", revision=index + 1,
            content_sha256=release.digest(f"content:{index}".encode()), completion=f"label{index}")

    def frozen(self, root, count=3):
        source = root / "catalog-input.json"
        source.write_bytes(catalog.canonical(dict(schema=catalog.SCHEMA,
            records=[self.row(index) for index in range(count)])))
        args = SimpleNamespace(catalog_input=source, output=root / "frozen")
        result = catalog.freeze_catalog(args)
        return args, result, Path(result["path"])

    def fixture(self, root):
        _, fixed, path = self.frozen(root)
        _, actions = catalog.catalog(json.loads(path.read_bytes()))
        sources = {}
        for relative in release.SOURCE_PATHS:
            source = root / Path(relative).name
            source.write_bytes(("pinned-source:" + source.name).encode())
            sources[str(source)] = release.digest(source.read_bytes())
        target, wrapped = root / "target.json", root / "wrapped.json"
        target.write_bytes(b'{"target":"synthetic-only"}')
        wrapped.write_bytes(b'{"adapter":"synthetic-only"}')
        worker = dict(python="/not-invoked/python", script=str(root / "llm_neural_read_worker.py"),
            materials=str(root), run_directory=str(root / "not-started"),
            source_pins=sources, action_completions={a["action_id"]: a["completion"] for a in actions},
            target_contract=dict(path=str(target), sha256=release.digest(target.read_bytes())),
            wrapped_adapter=dict(path=str(wrapped), sha256=release.digest(wrapped.read_bytes())))
        for field in ("contract_digest", "adapter_digest", "backbone_digest", "tokenizer_digest"):
            worker[field] = release.digest(field.encode())
        sidecar = dict(schema=release.SCHEMA, scope="controlled-native-load-only", profile=release.PROFILE,
            operation_id="actual-content-operation", generation=2, family_id="family", family_file_sha256="11" * 32,
            model="model", revision="revision", artifact_sha256="22" * 32,
            execution_profile_sha256="33" * 32,
            sources=[dict(name=Path(k).name, sha256=v) for k, v in sorted(sources.items(), key=lambda pair: Path(pair[0]).name)],
            actions=copy.deepcopy(release.ACTIONS), tcr1_hex="00", tcr1_id="44" * 32,
            members=[dict(name=name) for name in release.ROSTER],
            **{name: worker[name] for name in ("contract_digest", "adapter_digest", "backbone_digest", "tokenizer_digest")})
        sidecar_path, host = root / "controlled-sidecar.json", root / "host.json"
        sidecar_path.write_bytes(release.canonical(sidecar))
        host.write_bytes(catalog.canonical(dict(schema="hepta-smollm-cognitive-host-v1", worker=worker,
            descriptor=dict(path=str(root / "not-qualified.json"), sha256="55" * 32), worker_id="configuration-only",
            resource_grant=dict(grant_id="configuration-only", authority_epoch=1, generation=1, expires_at_ms=1,
                revoked=False, maximum_models=1, maximum_active_requests=1, maximum_memory_bytes=1,
                semantic_digest="66" * 32), inference_journal=str(root / "not-opened"),
            inference_journal_capacity=1, final_use_authorizer_config=str(root / "no-authority"))))
        args = SimpleNamespace(catalog=path, catalog_sha256=fixed["sha256"], sidecar=sidecar_path,
            sidecar_sha256=release.digest(sidecar_path.read_bytes()), host_config=host,
            host_config_sha256=release.digest(host.read_bytes()), output=root / "ordinary")
        return args, actions, sidecar, worker

    def test_complete_fixed_catalogue_uses_real_tuple_hash_and_create_only_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            args, result, path = self.frozen(root, 128)
            raw = path.read_bytes()
            fixed, actions = catalog.catalog(json.loads(raw))
            self.assertEqual(raw, catalog.canonical(fixed))
            self.assertEqual(len(actions), 128)
            self.assertEqual(result["sha256"], release.digest(raw))
            self.assertEqual((args.output / "catalog-sha256.txt").read_text(), result["sha256"] + "\n")
            first = next(row for row in fixed["records"] if row["memory_id"] == "memory:0")
            expected = "memory-" + release.digest((8).to_bytes(8, "big") + b"memory:0"
                + first["revision"].to_bytes(8, "big") + first["content_sha256"].encode())
            self.assertIn(dict(action_id=expected, completion="label0"), actions)
            with self.assertRaises(FileExistsError):
                catalog.freeze_catalog(args)
            self.assertEqual(path.read_bytes(), raw)

    def test_unknown_query_expected_answer_authority_and_duplicate_inputs_refuse(self):
        original = dict(schema=catalog.SCHEMA, records=[self.row(0), self.row(1)])
        variants = []
        for key in ("query", "expected_answer", "scores", "installation_authorized"):
            value = copy.deepcopy(original)
            value[key] = "not a catalogue field"
            variants.append(value)
            value = copy.deepcopy(original)
            value["records"][0][key] = "not a record field"
            variants.append(value)
        for field, value in (("revision", True), ("revision", 0), ("content_sha256", "0" * 64),
                             ("memory_id", "not valid"), ("completion", "x" * 65)):
            item = copy.deepcopy(original)
            item["records"][0][field] = value
            variants.append(item)
        variants += [dict(original, records=[]), dict(original, records=[self.row(i) for i in range(129)]),
            dict(original, records=[self.row(0), self.row(0)])]
        duplicate_label = copy.deepcopy(original)
        duplicate_label["records"][1]["completion"] = "label0"
        variants.append(duplicate_label)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                catalog.catalog(value)

    def test_actual_export_consumes_catalogue_and_profile_without_touching_old_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            args, actions, old, worker = self.fixture(Path(temporary).resolve())
            before = args.sidecar.read_bytes(), args.host_config.read_bytes(), args.catalog.read_bytes()
            result = catalog.prepare_ordinary_host_config_v3(args)
            config = json.loads(Path(result["path"]).read_bytes())
            content = json.loads(Path(config["cell_content"]["path"]).read_bytes())
            self.assertEqual(config["schema"], "hepta-smollm-cognitive-cell-host-v3")
            self.assertEqual(config["action_catalog"], dict(path=str(args.catalog), sha256=args.catalog_sha256))
            self.assertEqual(content, dict(old, schema=catalog.CONTENT_SCHEMA, scope=catalog.CONTENT_SCOPE,
                actions=actions, execution_profile_sha256=result["execution_profile_sha256"]))
            sources = {Path(k).name: v for k, v in worker["source_pins"].items()}
            expected = ["hepta-smollm-single-token-action-score-v1", dict(sorted(sources.items())), actions,
                worker["contract_digest"], worker["adapter_digest"], worker["target_contract"]["sha256"],
                worker["wrapped_adapter"]["sha256"], worker["backbone_digest"], worker["tokenizer_digest"], 4]
            self.assertEqual(result["execution_profile_sha256"], release.digest(catalog.canonical(expected)))
            self.assertEqual((args.sidecar.read_bytes(), args.host_config.read_bytes(), args.catalog.read_bytes()), before)
            with self.assertRaises(FileExistsError):
                catalog.prepare_ordinary_host_config_v3(args)

    def test_host_map_or_source_rebinding_and_noncanonical_catalogue_refuse(self):
        for change in ("host-map", "source", "catalogue", "controlled-promotion"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                args, _, _, worker = self.fixture(Path(temporary).resolve())
                if change == "host-map":
                    host = json.loads(args.host_config.read_bytes())
                    host["worker"]["action_completions"]["memory-unregistered"] = "new"
                    args.host_config.write_bytes(catalog.canonical(host))
                    args.host_config_sha256 = release.digest(args.host_config.read_bytes())
                elif change == "source":
                    Path(next(iter(worker["source_pins"]))).write_bytes(b"changed source")
                elif change == "catalogue":
                    args.catalog.write_bytes(args.catalog.read_bytes() + b"\n")
                    args.catalog_sha256 = release.digest(args.catalog.read_bytes())
                else:
                    sidecar = json.loads(args.sidecar.read_bytes())
                    sidecar["scope"] = "qualified-host-content-only"
                    args.sidecar.write_bytes(release.canonical(sidecar))
                    args.sidecar_sha256 = release.digest(args.sidecar.read_bytes())
                with self.assertRaises(ValueError):
                    catalog.prepare_ordinary_host_config_v3(args)
                self.assertFalse(args.output.exists())

    def test_existing_cli_dispatches_actual_frozen_catalogue_producer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "records.json"
            source.write_bytes(catalog.canonical(dict(schema=catalog.SCHEMA, records=[self.row(0)])))
            result = subprocess.run([sys.executable, str(Path(release.__file__)), "freeze-ordinary-action-catalog-v1",
                "--catalog-input", str(source), "--output", str(root / "frozen")],
                capture_output=True, text=True, check=True)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["sha256"], release.digest(Path(receipt["path"]).read_bytes()))


if __name__ == "__main__":
    unittest.main()
