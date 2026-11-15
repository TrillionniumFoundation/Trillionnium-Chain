#!/usr/bin/env python3
"""Admit the existing independently pinned cold-runtime snapshot before imports.

This is an observed byte/inventory contract, not an immutable namespace. The
snapshot includes the interpreter, venv, stdlib and observed native libraries;
the kernel and a hostile writer racing check/use remain outside this contract.
No package-reported version is accepted as evidence of executable byte identity.
"""
import ast
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

# This sole generated profile is derived from the three actual pinned PyTorch
# sources. It does not authorize a directory, an arbitrary template or TorchScript.
TORCH_GENERATED_NAME = "_remote_module_non_scriptable"
TORCH_INSTANTIATOR = "torch.distributed.nn.jit.instantiator"
TORCH_GENERATED_SOURCES = (
    ("torch/distributed/nn/jit/instantiator.py",
     "567d1314ee27ff0b3bd22e7c4d1157246469de25e7a3183d96debe167b193615"),
    ("torch/distributed/nn/jit/templates/remote_module_template.py",
     "0ff1856bbd031b5298d46c06c0502abc20bd804f42c1949ed4127e8c773660cc"),
    ("torch/distributed/nn/api/remote_module.py",
     "d51779fdbafb1ca1d99d002e6f32cf17bc1fef730a6251e3ef0278d8078bd112"),
)
TORCH_GENERATED_ARGS = dict(
    assign_module_interface_cls="module_interface_cls = None",
    args="*args", kwargs="**kwargs", arg_types="*args, **kwargs",
    arrow_and_return_type="", arrow_and_future_return_type="", jit_script_decorator="")
MAX_GENERATED_SOURCE = 65_536


def _stable_regular_bytes(path, maximum):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        before = os.fstat(source.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                "GENERATED_FILE_BOUND")
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        named = os.stat(path, follow_symlinks=False)
    def identity(item):
        return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(len(raw) == before.st_size and
            identity(before) == identity(after) == identity(named), "GENERATED_FILE_CHANGED")
    return raw, identity(before)


def _derive_torch_generated_source(instantiator_raw, template_raw, caller_raw):
    """Parse literal data only. The caller must authenticate all three sources."""
    def one(nodes):
        require(len(nodes) == 1, "GENERATED_TEMPLATE_SHAPE")
        return nodes[0]
    def same(left, right):
        return ast.dump(left, include_attributes=False) == ast.dump(right, include_attributes=False)
    generator = ast.parse(instantiator_raw)
    function = one([node for node in generator.body if isinstance(node, ast.FunctionDef) and
                    node.name == "instantiate_non_scriptable_remote_module_template"])
    require(len(function.body) == 3 and not function.args.args and not function.args.posonlyargs and
            not function.args.kwonlyargs and function.args.vararg is None and function.args.kwarg is None and
            not function.decorator_list, "GENERATED_TEMPLATE_SHAPE")
    expected = ast.parse(
        'def fixture():\n'
        '    generated_module_name = f"{_FILE_PREFIX}non_scriptable"\n'
        '    str_dict = dict()\n'
        '    return _do_instantiate_remote_module_template(generated_module_name, str_dict, True)\n'
    ).body[0].body
    require(same(function.body[0], expected[0]) and same(function.body[2], expected[2]),
            "GENERATED_TEMPLATE_SHAPE")
    prefix = one([node for node in generator.body if isinstance(node, ast.Assign) and
                  len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
                  node.targets[0].id == "_FILE_PREFIX"])
    require(isinstance(prefix.value, ast.Constant) and prefix.value.value == "_remote_module_",
            "GENERATED_TEMPLATE_SHAPE")
    assignment = function.body[1]
    require(isinstance(assignment, ast.Assign) and len(assignment.targets) == 1 and
            isinstance(assignment.targets[0], ast.Name) and assignment.targets[0].id == "str_dict" and
            isinstance(assignment.value, ast.Call) and
            isinstance(assignment.value.func, ast.Name) and assignment.value.func.id == "dict" and
            not assignment.value.args, "GENERATED_TEMPLATE_ARGUMENTS")
    arguments = {}
    for item in assignment.value.keywords:
        require(item.arg is not None and item.arg not in arguments and
                isinstance(item.value, ast.Constant) and type(item.value.value) is str,
                "GENERATED_TEMPLATE_ARGUMENTS")
        arguments[item.arg] = item.value.value
    require(arguments == TORCH_GENERATED_ARGS, "GENERATED_TEMPLATE_ARGUMENTS")
    template = ast.parse(template_raw)
    names = ("_TEMPLATE_PREFIX", "_REMOTE_FORWARD_TEMPLATE_ENABLE_MOVING_CPU_TENSORS_TO_CUDA",
             "_REMOTE_FORWARD_TEMPLATE")
    values = {}
    for name in names:
        node = one([node for node in template.body if isinstance(node, ast.Assign) and
                    len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
                    node.targets[0].id == name])
        require(isinstance(node.value, ast.Constant) and type(node.value.value) is str,
                "GENERATED_TEMPLATE_LITERAL")
        values[name] = node.value.value
    selector = one([node for node in template.body if isinstance(node, ast.FunctionDef) and
                    node.name == "get_remote_module_template"])
    expected_selector = ast.parse(
        'def get_remote_module_template(enable_moving_cpu_tensors_to_cuda: bool):\n'
        '    return _TEMPLATE_PREFIX + (_REMOTE_FORWARD_TEMPLATE_ENABLE_MOVING_CPU_TENSORS_TO_CUDA '
        'if enable_moving_cpu_tensors_to_cuda else _REMOTE_FORWARD_TEMPLATE)\n').body[0]
    require(same(selector, expected_selector), "GENERATED_TEMPLATE_SHAPE")
    caller = ast.parse(caller_raw)
    call = one([node for node in caller.body if isinstance(node, ast.Assign) and
                len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and
                node.targets[0].id == "_NON_SCRIPTABLE_REMOTE_MODULE_MODULE"])
    expected_call = ast.parse(
        "_NON_SCRIPTABLE_REMOTE_MODULE_MODULE = "
        "instantiator.instantiate_non_scriptable_remote_module_template()\n").body[0]
    require(same(call, expected_call), "GENERATED_TEMPLATE_CALLER")
    return (values[names[0]] + values[names[1]]).format(**arguments).encode("utf-8")


class _GeneratedSourceAdmission:
    """One exact origin, only after this guard executed its pinned producer."""
    def __init__(self, raw, instantiator_path):
        self.raw = raw
        self.instantiator_path = instantiator_path
        self.producer = None
        self.origin = None
        self.file_identity = None
        self.module = None

    @staticmethod
    def directory(module):
        value = getattr(module, "INSTANTIATED_TEMPLATE_DIR_PATH", None)
        require(type(value) is str and Path(value).is_absolute(), "GENERATED_DIRECTORY")
        path = Path(value)
        require(path.resolve(strict=True) == path, "GENERATED_DIRECTORY")
        entry = path.stat()
        require(stat.S_ISDIR(entry.st_mode) and entry.st_uid == os.geteuid() and
                entry.st_mode & 0o077 == 0, "GENERATED_DIRECTORY")
        return str(path), (entry.st_dev, entry.st_ino, entry.st_mode, entry.st_uid, entry.st_gid)

    def producer_executed(self, module):
        require(self.producer is None and module.__name__ == TORCH_INSTANTIATOR and
                module.__file__ == self.instantiator_path, "GENERATED_PRODUCER")
        self.producer = (module, self.directory(module))

    def admit(self, fullname, origin):
        require(fullname == TORCH_GENERATED_NAME, "GENERATED_MODULE_NAME")
        require(self.producer is not None and
                sys.modules.get(TORCH_INSTANTIATOR) is self.producer[0] and
                self.producer[0].__file__ == self.instantiator_path and
                self.directory(self.producer[0]) == self.producer[1], "GENERATED_PRODUCER")
        expected_path = str(Path(self.producer[1][0]) / (TORCH_GENERATED_NAME + ".py"))
        require(origin == expected_path, "GENERATED_ORIGIN")
        require(self.origin is None, "GENERATED_ALREADY_ADMITTED")
        raw, identity = _stable_regular_bytes(origin, MAX_GENERATED_SOURCE)
        require(raw == self.raw, "GENERATED_BYTE_DRIFT")
        self.origin, self.file_identity = origin, identity
        return _PinnedGeneratedSource(self, raw, origin)

    def loaded(self, module):
        require(self.module is None and module.__name__ == TORCH_GENERATED_NAME and
                module.__file__ == self.origin, "GENERATED_MODULE_IDENTITY")
        self.module = module

    def verify_loaded(self):
        if self.origin is None:
            return None
        require(self.module is not None and sys.modules.get(TORCH_GENERATED_NAME) is self.module and
                self.module.__name__ == TORCH_GENERATED_NAME and self.module.__file__ == self.origin and
                self.producer is not None and sys.modules.get(TORCH_INSTANTIATOR) is self.producer[0] and
                self.producer[0].__name__ == TORCH_INSTANTIATOR and
                self.producer[0].__file__ == self.instantiator_path and
                self.directory(self.producer[0]) == self.producer[1], "GENERATED_MODULE_IDENTITY")
        raw, identity = _stable_regular_bytes(self.origin, MAX_GENERATED_SOURCE)
        require(raw == self.raw and identity == self.file_identity, "GENERATED_FILE_CHANGED")
        return self.origin


class _PinnedGeneratedSource(importlib.abc.Loader):
    """Compile the exact verified bytes; never reopen the path for execution."""
    def __init__(self, admission, raw, path):
        self.admission, self.raw, self.path = admission, raw, path

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        exec(compile(self.raw, self.path, "exec"), module.__dict__)
        self.admission.loaded(module)


def _generated_source_profile(value):
    prefix = value.get("prefix")
    if type(prefix) is not str:
        return None
    site = Path(prefix) / "lib" / ("python%d.%d" % sys.version_info[:2]) / "site-packages"
    paths = [(str(site / relative), expected) for relative, expected in TORCH_GENERATED_SOURCES]
    if not any(path in value["files"] for path, _ in paths):
        return None
    require(all(value["files"].get(path) == expected for path, expected in paths),
            "GENERATED_PROFILE_PIN")
    sources = []
    for path, expected in paths:
        raw, _ = _stable_regular_bytes(path, MAX_GENERATED_SOURCE)
        require(hashlib.sha256(raw).hexdigest() == expected, "GENERATED_SOURCE_DRIFT")
        sources.append(raw)
    raw = _derive_torch_generated_source(*sources)
    require(len(raw) == 2355 and hashlib.sha256(raw).hexdigest() ==
            "8205b16956fb264841ecd8644784a0d157f87df79b17c16825dc1163433ce5d8",
            "GENERATED_PROFILE_OUTPUT")
    return _GeneratedSourceAdmission(raw, paths[0][0])


class PinnedPythonSource(importlib.machinery.SourceFileLoader):
    """Execute exactly the admitted source bytes, never an ambient .pyc."""
    def __init__(self, fullname, path, expected, on_executed=None):
        super().__init__(fullname, path)
        self.path, self.expected = path, expected
        self.on_executed = on_executed

    def get_code(self, fullname):
        raw = read_regular(self.path, 16 * 1024 * 1024)
        require(hashlib.sha256(raw).hexdigest() == self.expected, "IMPORT_BYTE_DRIFT")
        return compile(raw, self.path, "exec")

    def exec_module(self, module):
        super().exec_module(module)
        if self.on_executed is not None:
            self.on_executed(module)


class PinnedImports(importlib.abc.MetaPathFinder):
    """Admit a resolved module before its loader can run third-party code."""
    def __init__(self, files, generated=None):
        self.files, self.generated = files, generated

    def find_distributions(self, *args, **kwargs):
        # importlib.metadata discovers installed dist-info through this method.
        # Preserve that standard-library API over the same admitted sys.path.
        return importlib.machinery.PathFinder.find_distributions(*args, **kwargs)

    def find_spec(self, fullname, path=None, target=None):
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None or spec.origin is None:
            return spec
        resolved = str(Path(spec.origin).resolve(strict=True))
        if resolved not in self.files:
            require(self.generated is not None and fullname == TORCH_GENERATED_NAME and
                    isinstance(spec.loader, importlib.machinery.SourceFileLoader),
                    "UNDECLARED_IMPORT: " + resolved)
            spec.loader = self.generated.admit(fullname, spec.origin)
            return spec
        if isinstance(spec.loader, importlib.machinery.SourceFileLoader):
            callback = None
            if (self.generated is not None and fullname == TORCH_INSTANTIATOR and
                    resolved == self.generated.instantiator_path):
                callback = self.generated.producer_executed
            spec.loader = PinnedPythonSource(fullname, resolved, self.files[resolved], callback)
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
    guard = PinnedImports(allowed, _generated_source_profile(value))
    sys.meta_path[index] = guard
    return guard


def verify_loaded(value, sources, guard):
    """Reject imported/mapped origins outside the pinned runtime/project set.

    /proc maps is an independent observation of executable native mappings.
    Python module origins are a consistency check, not a code attestation.
    """
    allowed = dict(value["files"])
    allowed.update({str(Path(path).resolve(strict=True)): digest for path, digest in sources.items()})
    require(isinstance(guard, PinnedImports) and guard.files == allowed and guard in sys.meta_path,
            "IMPORT_GUARD_IDENTITY")
    generated_origin = guard.generated.verify_loaded() if guard.generated is not None else None
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
        if path == generated_origin:
            continue
        require(path in allowed, "UNDECLARED_LOADED_FILE: " + path)
        require(file_digest(path)[0] == allowed[path], "LOADED_BYTE_DRIFT: " + path)

