"""Independent exact-source SQLite C provider build; never runs task policy."""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
FENCE = "trnm-hia-task-kernel-sqlite-3.54.1-native-x86_64-v1"
AMALGAMATION = "0c657666d819f261cc4007526ad57e1669de9949df7a8ea847aa284a2bf0ee52"
UPSTREAM_BUILD = "769b31370a41aa722e1d5a530012432c985bb142eab34d095481ffd1a3436e1b"
SOURCE_ID = "2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6ca76"
HEADER = "d6c84557261893439b341d2e6c35187ae3ea24fbfd843ad94616f72d89242b8c"
DEPENDENCY_MANIFEST = "3fb7e11b7b71251e7e360511000befe692e5aee8d31415d477774f060577bb15"
TARGET = "x86_64-unknown-linux-gnu"
LAYOUT = [8, 4, 2, 8, 8, 168, 152, 120, 8, 0, 8, 24, 64, 24, 8, 0, 96, 8, 24]
OPTIONS = (
    "ATOMIC_INTRINSICS=1", "DEFAULT_AUTOVACUUM", "DEFAULT_CACHE_SIZE=-2000", "DEFAULT_FILE_FORMAT=4",
    "DEFAULT_FOREIGN_KEYS", "DEFAULT_JOURNAL_SIZE_LIMIT=-1", "DEFAULT_MMAP_SIZE=0", "DEFAULT_PAGE_SIZE=4096",
    "DEFAULT_PCACHE_INITSZ=20", "DEFAULT_RECURSIVE_TRIGGERS", "DEFAULT_SECTOR_SIZE=4096", "DEFAULT_SYNCHRONOUS=2",
    "DEFAULT_WAL_AUTOCHECKPOINT=1000", "DEFAULT_WAL_SYNCHRONOUS=2", "DEFAULT_WORKER_THREADS=0", "DIRECT_OVERFLOW_READ",
    "ENABLE_API_ARMOR", "ENABLE_COLUMN_METADATA", "ENABLE_DBSTAT_VTAB", "ENABLE_FTS3", "ENABLE_FTS3_PARENTHESIS",
    "ENABLE_FTS5", "ENABLE_LOAD_EXTENSION", "ENABLE_RTREE", "ENABLE_STAT4", "HAVE_ISNAN", "MALLOC_SOFT_LIMIT=1024",
    "MAX_ATTACHED=10", "MAX_COLUMN=2000", "MAX_COMPOUND_SELECT=500", "MAX_DEFAULT_PAGE_SIZE=8192", "MAX_EXPR_DEPTH=1000",
    "MAX_FUNCTION_ARG=1000", "MAX_LENGTH=1000000000", "MAX_LIKE_PATTERN_LENGTH=50000", "MAX_MMAP_SIZE=0x7fff0000",
    "MAX_PAGE_COUNT=0xfffffffe", "MAX_PAGE_SIZE=65536", "MAX_SCHEMA=10000000", "MAX_SQL_LENGTH=1000000000",
    "MAX_TRIGGER_DEPTH=1000", "MAX_VARIABLE_NUMBER=32766", "MAX_VDBE_OP=250000000", "MAX_WORKER_THREADS=8",
    "MUTEX_PTHREADS", "SOUNDEX", "SYSTEM_MALLOC", "TEMP_STORE=1", "THREADSAFE=1", "USE_URI",
)
FLAGS = (
    "SQLITE_CORE", "SQLITE_DEFAULT_FOREIGN_KEYS=1", "SQLITE_ENABLE_API_ARMOR",
    "SQLITE_ENABLE_COLUMN_METADATA", "SQLITE_ENABLE_DBSTAT_VTAB", "SQLITE_ENABLE_FTS3",
    "SQLITE_ENABLE_FTS3_PARENTHESIS", "SQLITE_ENABLE_FTS5", "SQLITE_ENABLE_JSON1",
    "SQLITE_ENABLE_LOAD_EXTENSION=1", "SQLITE_ENABLE_RTREE", "SQLITE_ENABLE_STAT4",
    "SQLITE_SOUNDEX", "SQLITE_THREADSAFE=1", "SQLITE_USE_URI", "HAVE_USLEEP=1",
    "HAVE_ISNAN", "_POSIX_THREAD_SAFE_FUNCTIONS", "HAVE_LOCALTIME_R",
)


def need(condition, message):
    if not condition:
        raise ValueError(message)


def identity(path):
    path = Path(path)
    need(path.is_absolute() and not path.is_symlink(), "Regular absolute input required: " + str(path))
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode), "Regular input required")
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)
        need(stamp(path.stat()) == stamp(before), "Input changed before capture")
        raw = stream.read()
        need(stamp(os.fstat(stream.fileno())) == stamp(before) == stamp(path.stat()), "Input changed during capture")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def environment_fence(env):
    for name, value in env.items():
        upper = name.upper()
        tool_override = any(upper == k or upper.startswith(k + "_") or upper.endswith("_" + k)
                            for k in ("CC", "CXX", "AR", "RANLIB", "CFLAGS", "CXXFLAGS", "CPPFLAGS", "ARFLAGS"))
        native_override = upper in {
            "CRATE_CC_NO_DEFAULTS", "CC_FORCE_DISABLE", "CC_KNOWN_WRAPPER_CUSTOM", "RUSTC_WRAPPER",
            "CC_SHELL_ESCAPED_FLAGS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "OBJC_INCLUDE_PATH",
            "LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH", "LD_PRELOAD", "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES", "SDKROOT", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "LIBSQLITE3_FLAGS",
            "SQLITE_MAX_VARIABLE_NUMBER", "SQLITE_MAX_EXPR_DEPTH", "SQLITE_MAX_COLUMN", "SQLITE3_LIB_DIR",
            "SQLITE3_INCLUDE_DIR", "SQLITE3_STATIC", "LIBSQLITE3_SYS_USE_PKG_CONFIG",
        } or upper.startswith("SQLCIPHER_") or "SQLITE_SHM_DIRECTORY" in upper or (
            upper.startswith("CARGO_TARGET_") and (upper.endswith("_LINKER") or upper.endswith("_RUSTFLAGS")))
        need(not (tool_override or native_override) or not value or
             (upper == "LIBSQLITE3_SYS_USE_PKG_CONFIG" and value == "0"),
             "External native build override refused: " + name)


class ProviderBuild:
    def __init__(self, dependency, output, target=TARGET):
        self.output = Path(output).absolute()
        need(self.output.resolve() == self.output and not self.output.exists(), "Fresh canonical output required")
        need(self.output != ROOT and ROOT not in self.output.parents, "Evidence must be outside the checkout")
        self.output.mkdir(parents=True, mode=0o700)
        self.report = {"schema": "trnm.hia.task-kernel.sqlite-provider.v1", "fence": FENCE,
                       "started": True, "finalized": False, "status": "FAIL", "stages": []}
        self.target = target
        self.write()
        try:
            self.dependency = Path(dependency).resolve(strict=True)
        except BaseException as error:
            self.report["failure"] = repr(error)
            self.write()
            raise

    def write(self):
        write_json(self.output / "build.json", self.report)

    def stage(self, name, argv, timeout=600):
        entry = {"name": name, "argv": [str(x) for x in argv], "started": True, "completed": False,
                 "timeout_seconds": timeout}
        self.report["stages"].append(entry)
        self.write()
        (self.output / (name + ".stdin.raw")).write_bytes(b"")
        started = time.monotonic()
        try:
            process = subprocess.run(argv, input=b"", capture_output=True, timeout=timeout, cwd=ROOT)
        except subprocess.TimeoutExpired as error:
            (self.output / (name + ".stdout.raw")).write_bytes(error.stdout or b"")
            (self.output / (name + ".stderr.raw")).write_bytes(error.stderr or b"")
            entry.update(error="TimeoutExpired", elapsed_seconds=time.monotonic()-started)
            self.write()
            raise
        except OSError as error:
            (self.output / (name + ".stdout.raw")).write_bytes(b"")
            (self.output / (name + ".stderr.raw")).write_bytes(b"")
            entry.update(error=repr(error), elapsed_seconds=time.monotonic()-started)
            self.write()
            raise
        (self.output / (name + ".stdout.raw")).write_bytes(process.stdout)
        (self.output / (name + ".stderr.raw")).write_bytes(process.stderr)
        entry.update(completed=True, exit=process.returncode, elapsed_seconds=time.monotonic()-started)
        self.write()
        process.check_returncode()
        return process

    def run(self):
        try:
            need(__debug__, "Optimized Python cannot run the independent build fence")
            need(self.target == TARGET and platform.system() == "Linux" and platform.machine() == "x86_64" and
                 struct.calcsize("P") == 8 and sys.byteorder == "little" and platform.libc_ver()[0] == "glibc",
                 "Unsupported native target")
            environment_fence(os.environ)
            self.stage("preflight", ["bash", str(ROOT / "scripts/project-preflight.sh"), "--audit"], 60)
            need(self.dependency.name == "libsqlite3-sys-0.39.1", "Exact bundled dependency required")
            include = self.dependency / "sqlite3"
            amalgamation = include / "sqlite3.c"
            upstream = self.dependency / "build.rs"
            witness = ROOT / "trillionnium/crates/trnm-sqlite-io-boundary/unix_layout_witness.c"
            sources = [amalgamation, include / "sqlite3.h", upstream, self.dependency / "Cargo.toml", witness,
                       HERE / "provider.c", HERE / "provider_abi.json", Path(__file__).resolve()]
            before = {str(p): identity(p) for p in sources}
            abi = json.loads((HERE / "provider_abi.json").read_text())
            need(abi.get("schema") == "trnm.hia.task-kernel.sqlite-provider-abi.v1" and
                 abi.get("build_fence") == FENCE and abi.get("target") == TARGET and
                 [row.get("op") for row in abi.get("operations", [])] == list(range(1, 30)),
                 "Provider ABI identity differs")
            need(before[str(amalgamation)] == {"bytes": 9582521, "sha256": AMALGAMATION}, "Amalgamation identity differs")
            need(before[str(upstream)] == {"bytes": 35413, "sha256": UPSTREAM_BUILD}, "Upstream build identity differs")
            need(before[str(include / "sqlite3.h")] == {"bytes": 695729, "sha256": HEADER}, "SQLite public C header differs")
            need(before[str(self.dependency / "Cargo.toml")] == {"bytes": 2641, "sha256": DEPENDENCY_MANIFEST},
                 "Bundled dependency manifest differs")
            self.report["source_before"] = before
            for i, path in enumerate(sources):
                captured = self.output / "source-snapshots" / (str(i) + "-" + path.name)
                captured.parent.mkdir(exist_ok=True)
                captured.write_bytes(path.read_bytes())
                need(identity(captured) == before[str(path)], "Source capture changed")
            compiler = Path(shutil.which("cc") or "/unavailable/cc").resolve(strict=True)
            self.report["compiler"] = {"path": str(compiler), **identity(compiler)}
            self.write()
            version = self.stage("compiler-version", [str(compiler), "--version"], 30)
            need(b"gcc" in version.stdout.lower() or b"clang" in version.stdout.lower() or b"free software foundation" in version.stdout.lower(),
                 "GNU/Clang native C compiler required")
            target = self.stage("compiler-target", [str(compiler), "-dumpmachine"], 30)
            need(target.stdout.strip() in (b"x86_64-linux-gnu", b"x86_64-unknown-linux-gnu"),
                 "Cross/foreign C target refused")
            common = [str(compiler), "-std=c11", "-O0", "-fPIC", "-fno-common", "-fno-strict-aliasing",
                      "-ffunction-sections", "-fdata-sections",
                      "-I", str(include), *["-D" + item for item in FLAGS]]
            for name, source, extra in [
                ("sqlite", amalgamation, []),
                ("witness", witness, ['-DTRNM_SQLITE_AMALGAMATION="' + str(amalgamation) + '"']),
                ("provider", HERE / "provider.c", ["-Wall", "-Wextra", "-Werror"]),
            ]:
                need(not any(c in str(amalgamation) for c in '\\"\n\r'), "Amalgamation include path cannot be quoted")
                self.stage("compile-" + name, common + extra + ["-c", str(source), "-o", str(self.output / (name + ".o"))])
                environment_fence(os.environ)
                need({str(p): identity(p) for p in sources} == before, "Source changed during native compile")
            library = self.output / "provider.so"
            self.stage("link", [str(compiler), "-shared", "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections",
                                *[str(self.output / (name + ".o")) for name in ("sqlite", "witness", "provider")],
                                "-lm", "-ldl", "-lpthread", "-o", str(library)])
            self.stage("symbols", ["nm", "--defined-only", str(library)], 30)
            # The observer executes the actual independently built provider and
            # the separate compile-time witness. It does not trust a supplied
            # provider identity string or a previous Cargo target directory.
            lib = ctypes.CDLL(str(library))
            lib.sqlite3_sourceid.restype = ctypes.c_char_p
            lib.trnm_io_witness_source_id.restype = ctypes.c_char_p
            lib.sqlite3_compileoption_get.argtypes = [ctypes.c_int]
            lib.sqlite3_compileoption_get.restype = ctypes.c_char_p
            lib.trnm_io_witness_compileoption.argtypes = [ctypes.c_int]
            lib.trnm_io_witness_compileoption.restype = ctypes.c_char_p
            lib.trnm_io_witness_layout.argtypes = [ctypes.c_int]
            lib.trnm_io_witness_layout.restype = ctypes.c_uint64
            options, witness_options = [], []
            i = 0
            while True:
                a = lib.sqlite3_compileoption_get(i)
                b = lib.trnm_io_witness_compileoption(i)
                need(a == b, "Runtime compile options differ from independent C witness")
                if a is None:
                    break
                options.append(a.decode())
                witness_options.append(b.decode())
                i += 1
            observation = {"runtime_version": lib.sqlite3_libversion_number(), "runtime_threadsafe": lib.sqlite3_threadsafe(),
                           "witness_version": lib.trnm_io_witness_version(),
                           "runtime_source_id": lib.sqlite3_sourceid().decode(),
                           "witness_source_id": lib.trnm_io_witness_source_id().decode(),
                           "runtime_options": options, "witness_options": witness_options,
                           "c_layout": [lib.trnm_io_witness_layout(i) for i in range(19)]}
            write_json(self.output / "observed-identity.json", observation)
            need(observation["runtime_version"] == observation["witness_version"] == 3054001, "SQLite version differs")
            need(observation["runtime_source_id"] == observation["witness_source_id"] == SOURCE_ID, "SQLite source ID differs")
            need(observation["runtime_threadsafe"] == 1 and observation["c_layout"] == LAYOUT, "C ABI differs")
            compiler_options = [item for item in options if item.startswith("COMPILER=")]
            need(len(compiler_options) == 1 and re.fullmatch(r"COMPILER=(gcc|clang)-.+", compiler_options[0]),
                 "Unknown SQLite compiler identity")
            need([item for item in options if not item.startswith("COMPILER=")] == list(OPTIONS),
                 "SQLite compile options differ from exact normal bundled profile")
            self.report["source_after"] = {str(p): identity(p) for p in sources}
            need(self.report["source_after"] == before, "Source changed before finalization")
            need(identity(compiler) == {k: v for k, v in self.report["compiler"].items() if k != "path"}, "Compiler changed")
            self.report["artifacts"] = {name: identity(self.output / name) for name in ("sqlite.o", "witness.o", "provider.o", "provider.so", "observed-identity.json")}
            self.report.update(finalized=True, status="PASS", target=TARGET,
                               claims={"independent_c_build_identity": True, "task_kernel_store_behavior": False,
                                       "pure_hia_sqlite": False, "whole_chain_native": False})
            self.write()
            return library
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error))
            self.write()
            raise


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dependency", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--target", default=TARGET)
    args = parser.parse_args()
    path = ProviderBuild(args.dependency, args.output, args.target).run()
    print(json.dumps({"status": "PASS", "provider": str(path), "fence": FENCE}))


if __name__ == "__main__":
    main()
