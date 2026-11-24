"""A named selfhost ELF called from an offline original-State Rust process."""
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from hia.platform.integer_model_snapshot.build import ENTRY, LIBRARY, build, check_direct_refusal, digest
from hia.tests.test_integer_model_load import outcomes
from hia.tests.integer_model_material_original import build_caller


def state_case(case):
    """Construct one unprojected synthetic state using complete application keys."""
    identity = case["id"]
    adjacent = ("0" if identity[0] != "0" else "1")+identity[1:]
    source = {
        "other:row": {"record":"unaltered"},
        "model:current": "synthetic-unrelated-view",
        f"linear-model-v1:{identity}:meta": 11,
        f"linear-model-v2:{identity}-closer:meta": True,
        f"linear-model-v2:{adjacent}:meta": "unrelated",
        f"linear-model-v3:{adjacent}:00": "another artifact",
        f"linear-model-v3:{identity.upper()}:01": "wrong namespace",
        f"linear-model-v2:{identity}\u0080:meta": "not a separator",
    }
    if identity == identity.upper():
        del source[f"linear-model-v3:{identity.upper()}:01"]
    for ns, version in (("old",2),("new",3)):
        for suffix, value in case[ns].items():
            source[f"linear-model-v{version}:{identity}:{suffix}"] = value
    return {"id":identity, "family":case["family"], "state":source}


def panel():
    original = outcomes()
    for case, code, data in original:
        query = state_case(case)
        yield query, code, data, (len(case["old"]),len(case["new"]))
    case, _, _ = original[0]
    query = state_case(case)
    exact = f"linear-model-v2:{query['id']}:"
    empty_suffix = deepcopy(query)
    empty_suffix["state"][exact] = "actual same-ID extra row"
    yield empty_suffix, 3, b"", (10,0)
    unrepresentable = deepcopy(query)
    unrepresentable["state"][exact+"beyond-private-key"] = "synthetic extra row"
    yield unrepresentable, 3, b"", None
    exceeded = deepcopy(query)
    exceeded["state"].update({exact+"10":0,exact+"11":0})
    yield exceeded, 3, b"", None
    padding_alias = deepcopy(query)
    padding_alias["state"][exact+"07\0"] = 0
    yield padding_alias, 3, b"", None


class IntegerModelSnapshotCaller(unittest.TestCase):
    def test_one_named_selfhost_abi_and_observed_direct_refusal(self):
        with tempfile.TemporaryDirectory(prefix="trnm-named-model-") as d:
            scratch = Path(d)
            path, native = build(scratch/"selfhost")
            self.assertEqual(path.name,LIBRARY)
            self.assertEqual(native["entry"],ENTRY)
            self.assertEqual(native["dynamic"]["dynamic_exports"],[ENTRY])
            self.assertEqual(native["dynamic"]["unresolved_imports"],[])
            self.assertEqual(native["needed"],[])
            self.assertTrue(native["linked_text_equals_relocatable_text"])
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                build(path.parent)
            self.assertEqual(path.read_bytes(),original)
            refused = check_direct_refusal(scratch/"direct")
            self.assertEqual(refused["result"],"NOT_INSTALLABLE")
            self.assertEqual(refused["imports"],["abort","memset"])
            self.assertFalse((scratch/"direct"/LIBRARY).exists())

    @unittest.skipUnless(os.environ.get("HIA_M06_ORACLE_PREBUILT"),
                         "requires exact trusted locked Rust/Serde/Hex prebuilt artifacts")
    def test_fresh_named_library_called_from_same_immutable_original_state(self):
        rows = list(panel())
        query = b"".join(json.dumps(case,ensure_ascii=True).encode("ascii")+b"\n" for case,_,_,_ in rows)
        with tempfile.TemporaryDirectory(prefix="trnm-named-model-rust-") as d:
            root = Path(d)
            path, receipt = build(root/"selfhost")
            work = root/"caller"
            work.mkdir()
            binary, original = build_caller(work,path,receipt["artifact_sha256"])
            self.assertTrue(original["physically_linked_exact_named_native"])
            self.assertEqual(original["bound_native_sha256"],receipt["artifact_sha256"])
            self.assertEqual(digest(path.read_bytes()),receipt["artifact_sha256"])
            result = subprocess.run([binary],input=query,check=True,capture_output=True,timeout=55,
                                    env={"PATH":"/usr/bin:/bin","LC_ALL":"C"})
            self.assertEqual(result.stderr,b"")
            self.assertEqual(digest(path.read_bytes()),receipt["artifact_sha256"])
        actual = [json.loads(line) for line in result.stdout.splitlines()]
        for (case,code,payload,namespace), row in zip(rows,actual,strict=True):
            with self.subTest(index=case["id"][:8],code=code,namespace=namespace):
                self.assertEqual(row["state_rows"],len(case["state"]))
                self.assertTrue(row["state_unchanged"])
                self.assertEqual(row["original_status"],code)
                if namespace is None:
                    self.assertEqual(row["projection"],"outside-private-abi")
                    self.assertEqual(row["native_calls"],0)
                else:
                    self.assertEqual(row["projection"],"named-native")
                    self.assertEqual(row["native_calls"],1)
                    self.assertEqual(row["namespace_rows"],list(namespace))
                    self.assertEqual(row["abi_status"],0)
                    self.assertEqual(row["native_status"],code)
                    self.assertEqual(bytes.fromhex(row["body_hex"]),payload)
