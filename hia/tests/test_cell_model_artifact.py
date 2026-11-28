"""Original public Cell Model artifact parity; generated inert matrices only."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import tomllib
import unittest

from hia.tests.native_support import NativeModule
from hia.tests.test_settlement_schema_read import execute

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "hia/src/model/cell_model_artifact.hepta"
REFERENCE = Path(__file__).with_name("rust_cell_model_artifact_reference.rs")
RUST_ROOT = ROOT / "trillionnium"
ORIGINAL = "563bb7e471b3db278d50feceb3cbac7de4ab281a"
PINS = {
    "Cargo.lock": "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e",
    "crates/trnm-pon-node/Cargo.toml": "9477254f6848188433666c4475abde000bc3654539243a94d3fe7d8cdf1c3012",
    "crates/trnm-pon-node/src/lib.rs": "baafb16f125fda88b09d2342a0b6badb253497742c9a106921e8416e930f108d",
    "crates/trnm-pon-node/src/cell_native_v1.rs": "d807c924d7e9657d4126d9092d32585427fccba8144133066deb3ea7db54fe26",
    "crates/trnm-protocol/src/pon_wire.rs": "ee443e739da946fc023f119e7f3b882f373b3787820295b29b182ef0ee3ef83b",
}


def original(directory):
    git = ["git", "-C", ROOT]
    if execute([*git, "rev-parse", "HEAD:trillionnium"]).stdout.decode().strip() != ORIGINAL:
        raise ValueError("Wrong locked original workspace tree")
    execute([*git, "diff", "--quiet", "HEAD", "--", "trillionnium"])
    for name, expected in PINS.items():
        if sha256((RUST_ROOT / name).read_bytes()).hexdigest() != expected:
            raise ValueError(f"Wrong original source: {name}")
    requested = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested, "--version"]).stdout
    sysroot = Path(execute([requested, "--print", "sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc, cargo = sysroot / "bin/rustc", sysroot / "bin/cargo"
    if version.decode().split()[1] != channel or execute([rustc, "--version"]).stdout != version:
        raise ValueError("Wrong original workspace compiler")
    target = directory / "target"
    manifest = RUST_ROOT / "crates/trnm-pon-node/Cargo.toml"
    env = {**os.environ, "RUSTC": str(rustc), "CARGO_BUILD_JOBS": "1",
           "CARGO_INCREMENTAL": "0", "CARGO_PROFILE_DEV_DEBUG": "0"}
    raw = execute([cargo, "build", "--locked", "--offline", "--no-default-features",
                   "--lib", "-p", "trnm-pon-node", "--manifest-path", RUST_ROOT / "Cargo.toml",
                   "--target-dir", target, "--message-format=json"], env=env, timeout=360).stdout
    messages = [json.loads(line) for line in raw.splitlines()]
    if messages[-1] != {"reason": "build-finished", "success": True}:
        raise ValueError("No locked original successful build")
    [matched] = [m for m in messages if m.get("reason") == "compiler-artifact"
                 and m["target"]["name"] == "trnm_pon_node" and "lib" in m["target"]["kind"]]
    if (matched["fresh"] or matched["features"] or Path(matched["manifest_path"]) != manifest
            or Path(matched["target"]["src_path"]) != manifest.parent / "src/lib.rs"):
        raise ValueError("Wrong actual original node library provenance")
    [rlib] = [f for f in matched["filenames"] if f.endswith(".rlib")]
    if not Path(rlib).is_relative_to(target):
        raise ValueError("Artifact is outside the checked private target")
    exe = directory / "original-cell-model"
    execute([rustc, "--edition=2021", REFERENCE, "-L", f"dependency={target/'debug/deps'}",
             "--extern", f"trnm_pon_node={rlib}", "-o", exe], env=env, timeout=90)
    return execute([exe]).stdout


class CellModelArtifactTests(unittest.TestCase):
    def test_public_original_canonical_model_artifact_two_native_emitters(self):
        with tempfile.TemporaryDirectory(prefix="trnm-cell-model-artifact-") as tmp:
            raw = original(Path(tmp))
        rows = []
        while raw:
            status, n = struct.unpack_from("<II", raw)
            d = 0 if status else 32
            self.assertLessEqual(n + d + 8, len(raw))
            rows.append((raw[8:8+n], status, raw[8+n:8+n+d]))
            raw = raw[8+n+d:]
        self.assertEqual([s for _, s, _ in rows], [0,0,0,0,0,1,2,2,3,2,2,2])
        self.assertEqual(len({d for _, s, d in rows if not s}), 5)
        small, full, mixed = (r[0] for r in rows[:3])
        self.assertEqual((len(small), len(full)), (7830, 27105))
        # The private wire projection also refuses alternative encodings.
        alternate = [b" " + small, mixed.replace(b"32767", b"32767.0", 1),
                     mixed.replace(b'{"base":[[0,', b'{"base":[[-0,', 1), mixed + b" "]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(
                SOURCE, byte_exports=("f0",), backend=backend,
            ) as native:
                sentinel, scratch = b"Z"*40, b"W"*1320
                cases = rows + [(data, 1, b"") for data in alternate]
                calls = [("f0", [data, sentinel, scratch]) for data, _, _ in cases]
                for call, (data, status, digest) in zip(native.call_many(calls), cases, strict=True):
                    got = call.require_returned()
                    self.assertEqual(got.value, int(status != 0))
                    self.assertEqual(got.arguments[:2], [data, digest + sentinel[len(digest):]])
                    self.assertEqual(got.arguments[2][1312:], scratch[1312:])
                for out, work in ((sentinel[:31], scratch), (sentinel, scratch[:1311])):
                    args = [small, out, work]
                    got = native.call("f0", args).require_returned()
                    self.assertEqual((got.value, got.arguments), (102, args))
