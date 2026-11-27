"""Read-only archive hash parity with actual typed TaskKernel methods."""

import hashlib
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
CRATE = ROOT / "trillionnium/crates/trnm-task-kernel"
SOURCE = ROOT / "hia/src/task_kernel/archive_hash.hepta"
REFERENCE = ROOT / "hia/tests/rust_task_archive_hash_reference.rs"
PINS = {
    "Cargo.toml": "91c4bbe354e2edb578951bdd4aab473fd777d4b88e46dade4e8ae9547e176738",
    "src/archive.rs": "f131b99ff3934aee03ea85398ab5c3d666442a25678c03700a77db491b459e75",
    "src/archive_verifier.rs": "0b68ad221bba64f8775b5452dc08377ec96021a4a305b23b2130aba2bc2b460d",
    "src/lib.rs": "235abe77de9c7bc6597bb466a9fee1e83c8a50bdd83109b70e83431a1114b54e",
    "src/error.rs": "436cb05ae5707862239fe1805c18525d2d76806b64bb7d412c19a8686f6fbd12",
    "src/codec.rs": "36a385d57c0b22ccad5b29b2a2180f6ce0dd0eb08ea12e94e013057ebdefb83a",
    "src/types.rs": "211e9bd2d7e51a78e5e6842600e034531845690e8b68dc870ba7d5479ad01522",
    "../../Cargo.lock": "86aa87b12d7299990b368a0c07b1236bce99b1f43c5f58482c2adf0266f9a25e",
}


def original(directory, reference=REFERENCE):
    for path, digest in PINS.items():
        if hashlib.sha256((CRATE / path).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Original TaskKernel input differs: {path}")
    requested = os.environ.get("TRNM_HIA_RUSTC", "rustc")
    revision = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    version = execute([requested, "--version"]).stdout
    sysroot = Path(execute([requested, "--print", "sysroot"]).stdout.decode().strip()).resolve(strict=True)
    rustc, cargo = sysroot / "bin/rustc", sysroot / "bin/cargo"
    if version.decode().split()[1] != revision or execute([rustc, "--version"]).stdout != version:
        raise ValueError("Original TaskKernel requires the pinned Rust")
    target = directory / "target"
    env = {**os.environ, "RUSTC": str(rustc), "CARGO_BUILD_JOBS": "2"}
    output = execute([cargo, "build", "--locked", "--offline", "--manifest-path",
                      ROOT / "trillionnium/Cargo.toml", "--target-dir", target,
                      "-p", "trnm-task-kernel", "--message-format=json"],
                     env=env, timeout=160).stdout
    artifacts = [json.loads(line) for line in output.splitlines()]
    extern = []
    for name in ("borsh", "trnm_task_kernel"):
        [event] = [e for e in artifacts if e.get("reason") == "compiler-artifact"
                   and e["target"]["name"] == name and "lib" in e["target"]["kind"]]
        if name == "trnm_task_kernel" and Path(event["manifest_path"]) != CRATE / "Cargo.toml":
            raise ValueError("Original TaskKernel crate is not source-bound")
        [lib] = [f for f in event["filenames"] if f.endswith(".rlib")]
        extern += ["--extern", f"{name}={lib}"]
    result = directory / "archive-hash-original"
    execute([rustc, "--edition=2021", reference, "-L", f"dependency={target}/debug/deps",
             "-L", f"native={next((target/'debug/build').glob('libsqlite3-sys-*/out'))}",
             *extern, "-o", result], env=env, timeout=60)
    return result


def head(op, name, schema=1):
    return (struct.pack("<BH", op, schema) + bytes(range(32))
            + struct.pack("<I", len(name)) + name + struct.pack("<I", 0xf0123456)
            + bytes(range(32, 64)))


MAX64 = (1 << 64) - 1
MAX32 = (1 << 32) - 1
BOUNDS = [MAX64, MAX32, MAX64, 4096, MAX64, MAX64]


def policy(name, values=BOUNDS, schema=1):
    return head(0, name, schema) + struct.pack("<QIQIQQ", *values)


def record(name, schema=1, paid=0):
    return (head(1, name, schema) + bytes(range(64, 96)) + struct.pack("<QQ", 0, MAX64)
            + bytes(range(96)) + struct.pack("<QQ", MAX64, 0) + paid.to_bytes(16, "little"))


class TaskArchiveHashTests(unittest.TestCase):
    def test_actual_typed_task_archive_hashes(self):
        names = [b"", b"x", "节点\x00🔐".encode(), bytes(512), b"x"*55, b"z"*127]
        valid = ([policy(name) for name in names] + [policy(b"lower", [1]*6)]
                 + [record(name, paid=(1 << 128)-1) for name in names] + [record(b"zero")])
        policy_bad = []
        for i in range(len(BOUNDS)):
            values = BOUNDS.copy()
            values[i] = 0
            policy_bad.append(policy(b"bounds", values))
        policy_bad.append(policy(b"hard-limit", [1, 1, 1, 4097, 1, 1]))
        mixed = [policy(b"bad-schema", [0]*6, 2), record(b"", schema=0)]
        malformed = [
            b"", policy(b"a")[:-1], record(b"x")+b"\0", policy(b"\xc0\xaf"),
            record(b"\xf4\x90\x80\x80"), b"\x02"+policy(b"")[1:],
        ]
        originals = valid + policy_bad + mixed + malformed
        frames = b"".join(struct.pack("<I", len(raw))+raw for raw in originals)
        with tempfile.TemporaryDirectory(prefix="m10-archive-hash-") as temp:
            exe = original(Path(temp))
            answers = list(struct.iter_unpack("<I32s", execute([exe], input=frames).stdout))
        self.assertEqual([code for code, _ in answers],
                         [0]*len(valid)+[1]*len(policy_bad)+[22]*len(mixed)+[100]*len(malformed))
        over_profile = [(policy(b"a"*513), 100), (record(b"a"*513), 100)]
        for backend in ("direct", "selfhost"):
            with self.subTest(backend=backend), NativeModule(SOURCE, byte_exports=("f0",),
                                                            backend=backend) as native:
                all_cases = list(zip(originals, answers, strict=True))
                all_cases += [(raw, (code, bytes(32))) for raw, code in over_profile]
                requests = [[raw, b"M"*39, b"K"*1264] for raw, _ in all_cases]
                for (_, (code, digest)), args, result in zip(
                        all_cases, requests, native.call_many([("f0", row) for row in requests]), strict=True):
                    reply = result.require_returned()
                    expected = digest + args[1][32:] if code == 0 else args[1]
                    self.assertEqual((reply.value, reply.arguments[:2]), (code, [args[0], expected]))
                    if code:
                        self.assertEqual(reply.arguments[2], args[2])
                for output, scratch in [(31, 1264), (32, 1263)]:
                    args = [valid[0], b"M"*output, b"K"*scratch]
                    reply = native.call("f0", args).require_returned()
                    self.assertEqual((reply.value, reply.arguments), (102, args))
