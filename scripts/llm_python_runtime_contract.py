#!/usr/bin/env python3
"""Admit the existing independently pinned cold-runtime snapshot before imports.

This is an observed byte/inventory contract, not an immutable namespace. The
snapshot includes the interpreter, venv, stdlib and observed native libraries;
the kernel and a hostile writer racing check/use remain outside this contract.
No package-reported version is accepted as evidence of executable byte identity.
"""
import hashlib
import importlib.abc
import importlib.machinery
import json
import os
from pathlib import Path
import stat
import sys
import sysconfig

SCHEMA = "hepta-controlled-cold-runtime-snapshot-v2"
MAX_SNAPSHOT = 16 * 1024 * 1024
MAX_FILES = 100_000
MAX_BYTES = 16 * 1024**3


def require(value, reason):
    if not value:
        raise ValueError("NEURAL_RUNTIME_" + reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "DUPLICATE_FIELD")
        result[key] = value
    return result


def valid_digest(value):
    return (type(value) is str and len(value) == 64 and
            all(character in "0123456789abcdef" for character in value))


def read_regular(path, maximum):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode), "FILE_TYPE")
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, "FILE_BOUND")
    return raw


def file_digest(path):
    # Existing v2 snapshots include the venv's interpreter symlink as well as
    # its canonical target. Hash the resolved regular file through one FD.
    path = Path(path).resolve(strict=True)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= MAX_BYTES,
                "FILE_BOUND")
        digest = hashlib.sha256()
        count = 0
        while block := source.read(1024 * 1024):
            count += len(block)
            require(count <= before.st_size, "FILE_CHANGED")
            digest.update(block)
        after = os.fstat(source.fileno())
        require(count == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns) == (after.st_dev, after.st_ino, after.st_size,
                                        after.st_mtime_ns, after.st_ctime_ns), "FILE_CHANGED")
    return digest.hexdigest(), count


def load_snapshot(path, expected):
    require(valid_digest(expected), "SNAPSHOT_PIN")
    path = Path(path)
    require(path.is_absolute() and not path.is_symlink(), "SNAPSHOT_PATH")
    raw = read_regular(path, MAX_SNAPSHOT)
    require(0 < len(raw) <= MAX_SNAPSHOT and hashlib.sha256(raw).hexdigest() == expected,
            "SNAPSHOT_BYTES")
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and value.get("schema") == SCHEMA, "SNAPSHOT_SCHEMA")
    files = value.get("files")
    require(type(files) is dict and 0 < len(files) <= MAX_FILES and
            all(type(path) is str and Path(path).is_absolute() and valid_digest(digest)
                for path, digest in files.items()), "FILES")
    inventory = value.get("managed_inventory")
    require(type(inventory) is list and 0 < len(inventory) <= MAX_FILES and
            all(type(path) is str and path in files for path in inventory) and
            inventory == sorted(set(inventory)), "INVENTORY")
    for key in ("prefix", "stdlib_root"):
        root = Path(value.get(key, ""))
        require(root.is_absolute() and root != Path("/") and root.is_dir() and
                root.resolve(strict=True) == root, "ROOT")
    python = value.get("python")
    require(type(python) is dict and python.get("executable") in files and
            type(python.get("version")) is str, "INTERPRETER_PIN")
    return value


def configure(value):
    """Set the sole import search roots without executing site or .pth code."""
    require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1 and sys.flags.no_user_site == 1 and
            sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
            "ISOLATED_ENTRY_REQUIRED")
    require(type(sys.pycache_prefix) is str and Path(sys.pycache_prefix).is_absolute() and
            not Path(sys.pycache_prefix).exists(), "PRIVATE_UNUSED_BYTECODE_PATH")
    require(os.environ.get("TRNM_PON_EVALUATION_POLICY") in (None, "legacy-first-two-v3"),
            "ORIGINAL_CONTRACT_POLICY")
    actual = str(Path("/proc/self/exe").resolve(strict=True))
    require(actual == value["python"]["executable"] and
            str(Path(sys.executable).resolve(strict=True)) == actual and
            sys.version == value["python"]["version"] and
            sysconfig.get_config_var("SOABI") == value["python"].get("abi"),
            "INTERPRETER_IDENTITY")
    require(file_digest(actual)[0] == value["files"][actual], "INTERPRETER_BYTES")
    prefix, stdlib = Path(value["prefix"]), Path(value["stdlib_root"])
    site = prefix / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
    roots = [stdlib, stdlib / "lib-dynload", site, Path(__file__).resolve().parent]
    require(all(root.is_dir() and root.resolve(strict=True) == root for root in roots),
            "IMPORT_ROOT")
    # -S suppresses venv prefix setup in CPython <=3.13 as well as site.py.
    # Restore only the independently pinned prefix, never execute .pth files.
    sys.prefix = sys.exec_prefix = str(prefix)
    sys.path[:] = list(dict.fromkeys(str(root) for root in roots))


def managed_inventory(value):
    paths = set()
    prefix, stdlib = Path(value["prefix"]), Path(value["stdlib_root"])
    entries = 0
    for root in (prefix, stdlib):
        for path in root.rglob("*"):
            entries += 1
            require(entries <= 2 * MAX_FILES, "DIRECTORY_BOUND")
            if root == stdlib and "site-packages" in path.relative_to(stdlib).parts:
                continue
            if path.is_file():
                paths.add(str(path))
                require(len(paths) <= MAX_FILES, "INVENTORY_BOUND")
    return sorted(paths)


def verify_files(value):
    """Measure complete installed bytes before the first third-party import."""
    require(managed_inventory(value) == value["managed_inventory"], "INVENTORY_DRIFT")
    total = 0
    for path, expected in value["files"].items():
        observed, size = file_digest(path)
        total += size
        require(total <= MAX_BYTES, "TOTAL_BYTE_BOUND")
        require(observed == expected, "BYTE_DRIFT: " + path)


class PinnedPythonSource(importlib.machinery.SourceFileLoader):
    """Execute exactly the admitted source bytes, never an ambient .pyc."""
    def __init__(self, fullname, path, expected):
        super().__init__(fullname, path)
        self.path, self.expected = path, expected

    def get_code(self, fullname):
        raw = read_regular(self.path, 16 * 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == self.expected, "IMPORT_BYTE_DRIFT")
        return compile(raw, self.path, "exec")


class PinnedImports(importlib.abc.MetaPathFinder):
    """Admit a resolved module before its loader can run third-party code."""
    def __init__(self, files):
        self.files = files

    def find_distributions(self, *args, **kwargs):
        # importlib.metadata discovers installed dist-info through this method.
        # Preserve that standard-library API over the same admitted sys.path.
        return importlib.machinery.PathFinder.find_distributions(*args, **kwargs)

    def find_spec(self, fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or spec.origin is None:
            return spec
        resolved = str(Path(spec.origin).resolve(strict=True))
        require(resolved in self.files, "UNDECLARED_IMPORT: " + resolved)
        if isinstance(spec.loader, importlib.machinery.SourceFileLoader):
            spec.loader = PinnedPythonSource(fullname, resolved, self.files[resolved])
        else:
            # Native loader check/use is still a path boundary; no held ELF
            # image is claimed. Before Ready, actual executable maps are checked.
            require(isinstance(spec.loader, importlib.machinery.ExtensionFileLoader),
                    "UNSUPPORTED_IMPORT_LOADER")
            require(file_digest(resolved)[0] == self.files[resolved], "NATIVE_IMPORT_DRIFT")
        return spec


def install_import_guard(value, sources):
    require(type(sources) is dict and 0 < len(sources) <= 64, "SOURCE_BOUND")
    allowed = dict(value["files"])
    for path, expected in sources.items():
        require(type(path) is str and Path(path).is_absolute() and valid_digest(expected),
                "SOURCE_PIN")
        require(file_digest(path)[0] == expected, "SOURCE_BYTE_DRIFT")
        resolved = str(Path(path).resolve(strict=True))
        require(resolved not in allowed, "SOURCE_RUNTIME_ALIAS")
        allowed[resolved] = expected
    # Builtin/frozen modules stay with the interpreter. Replace the ordinary
    # filesystem finder so a later project-path insertion cannot bypass checks.
    index = sys.meta_path.index(importlib.machinery.PathFinder)
    sys.meta_path[index] = PinnedImports(allowed)


def verify_loaded(value, sources):
    """Reject imported/mapped origins outside the pinned runtime/project set.

    /proc maps is an independent observation of executable native mappings.
    Python module origins are a consistency check, not a code attestation.
    """
    allowed = dict(value["files"])
    allowed.update({str(Path(path).resolve(strict=True)): digest for path, digest in sources.items()})
    origins = set()
    for module in tuple(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path is not None:
            require(type(path) is str, "MODULE_ORIGIN")
            origins.add(str(Path(path).resolve(strict=True)))
    with Path("/proc/self/maps").open() as source:
        raw = source.read(8 * 1024 * 1024 + 1)
    require(len(raw) <= 8 * 1024 * 1024, "MAPS_BOUND")
    for row in raw.splitlines():
        parts = row.split(maxsplit=5)
        if len(parts) == 6 and "x" in parts[1] and parts[5].startswith("/"):
            require(not parts[5].endswith(" (deleted)"), "DELETED_NATIVE_MAPPING")
            origins.add(str(Path(parts[5]).resolve(strict=True)))
    require(len(origins) <= MAX_FILES, "LOADED_BOUND")
    for path in sorted(origins):
        require(path in allowed, "UNDECLARED_LOADED_FILE: " + path)
        require(file_digest(path)[0] == allowed[path], "LOADED_BYTE_DRIFT: " + path)

