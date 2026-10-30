"""Bounded runtime material declarations for the existing Cell release owner.

This module only inventories and independently reads back declared material. The
V1 wheel layout is canonical extraction: installed RECORD bytes must remain the
original wheel RECORD. Ordinary pip rewrites RECORD and adds installer metadata,
so a normal pip installation is not accepted by this version. A complete SmolLM
runtime still needs reviewed installer/vendored distribution metadata, .data/.pth
policy and execution namespace binding; the tiny cold interpreter control does not establish those.
It does not create a namespace capability, install a runtime, invoke a model, or
qualify I10. In particular, a digest is not protection against later mutation.
"""
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

SCHEMA = "hepta-runtime-material-release-v1"
SPEC_SCHEMA = "hepta-runtime-material-spec-v1"
DOMAIN = b"hepta.runtime-material-release.v1\0"
MAX_MANIFEST = 4 * 1024 * 1024
MAX_ENTRIES = 16_384
MAX_DEPTH = 32
MAX_BYTES = 2 * 1024 * 1024 * 1024
POLICY = {"site": "disabled", "pth": "reject", "bytecode": "reject",
          "generated_files": "explicit-inventory-only", "ambient_fallback": "reject"}
MARKER_FIELDS = {"implementation_name", "implementation_version", "os_name", "platform_machine",
                 "platform_release", "platform_system", "platform_version", "python_full_version",
                 "platform_python_implementation", "python_version", "sys_platform"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode()


def unique(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "RUNTIME_DUPLICATE_FIELD")
        value[key] = item
    return value


def decode(raw):
    require(type(raw) is bytes and 0 < len(raw) <= MAX_MANIFEST, "RUNTIME_MANIFEST_LIMIT")
    try:
        value = json.loads(raw, object_pairs_hook=unique,
                           parse_constant=lambda _: require(False, "RUNTIME_NUMBER"))
    except (RecursionError, UnicodeError) as error:
        raise ValueError("RUNTIME_MANIFEST_ENCODING") from error
    require(canonical(value) == raw, "RUNTIME_NONCANONICAL_MANIFEST")
    return value


def relative(value):
    require(type(value) is str and 0 < len(value) <= 1024, "RUNTIME_PATH")
    parts = value.split("/")
    require(len(parts) <= MAX_DEPTH and all(re.fullmatch(r"[A-Za-z0-9_+.@=-]{1,255}", p)
            and p not in {".", ".."} for p in parts), "RUNTIME_PATH")
    return value


def digest(value, width=64):
    require(type(value) is str and re.fullmatch("[0-9a-f]{" + str(width) + "}", value)
            and value != "0" * width, "RUNTIME_DIGEST")
    return value


def validate_spec(spec):
    require(type(spec) is dict and set(spec) == {"schema", "platform", "context",
            "interpreter", "stdlib", "entrypoint", "import_roots", "native_search_paths",
            "wheels", "marker_environment", "policy"}, "RUNTIME_SPEC_FIELDS")
    require(spec["schema"] == SPEC_SCHEMA and spec["policy"] == POLICY, "RUNTIME_SPEC_POLICY")
    platform = spec["platform"]
    require(type(platform) is dict and set(platform) == {"os", "machine", "python_abi"}
            and platform["os"] == "linux" and platform["machine"] in {"x86_64", "aarch64"}
            and platform["python_abi"] == "cpython-312-" + platform["machine"] + "-linux-gnu",
            "RUNTIME_PLATFORM")
    markers = spec["marker_environment"]
    require(type(markers) is dict and set(markers) == MARKER_FIELDS
            and all(type(v) is str and len(v) <= 256 and v.isascii() for v in markers.values())
            and markers["platform_machine"] == platform["machine"]
            and markers["implementation_name"] == "cpython" and markers["python_version"] == "3.12"
            and re.fullmatch(r"3\.12\.[0-9]+", markers["python_full_version"])
            and markers["implementation_version"] == markers["python_full_version"]
            and markers["os_name"] == "posix" and markers["sys_platform"] == "linux"
            and markers["platform_system"] == "Linux" and markers["platform_python_implementation"] == "CPython",
            "RUNTIME_MARKER_ENVIRONMENT")
    context = spec["context"]
    require(type(context) is dict and set(context) == {"chain_source", "hepta_source",
            "execution_profile_sha256", "model_release_sha256"}, "RUNTIME_CONTEXT")
    for key, value in context.items():
        digest(value, 40 if key.endswith("source") else 64)
    for field in ("interpreter", "stdlib", "entrypoint"):
        relative(spec[field])
    for field in ("import_roots", "native_search_paths"):
        paths = spec[field]
        require(type(paths) is list and 1 <= len(paths) <= 32 and all(type(p) is str for p in paths)
                and len(set(paths)) == len(paths), "RUNTIME_SEARCH_PATHS")
        for path in paths:
            relative(path)
    wheels = spec["wheels"]
    require(type(wheels) is list and len(wheels) <= 128, "RUNTIME_WHEELS")
    require(all(type(w) is dict and set(w) == {"archive", "installed_record", "origin", "sha256", "extras"}
                for w in wheels), "RUNTIME_WHEEL_FIELDS")
    names = []
    for wheel in wheels:
        names.append(relative(wheel["archive"]))
        relative(wheel["installed_record"])
        digest(wheel["sha256"])
        extras = wheel["extras"]
        require(type(extras) is list and len(extras) <= 16
                and all(type(e) is str and re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", e) and len(e) <= 128 for e in extras)
                and extras == sorted(set(extras)), "RUNTIME_WHEEL_EXTRAS")
        require(wheel["archive"].endswith(".whl") and wheel["installed_record"].endswith(".dist-info/RECORD")
                and type(wheel["origin"]) is str and 1 <= len(wheel["origin"]) <= 2048
                and wheel["origin"].startswith("https://")
                and all(33 <= ord(c) <= 126 for c in wheel["origin"]), "RUNTIME_WHEEL_PROVENANCE")
    require(names == sorted(set(names)), "RUNTIME_WHEEL_ORDER")
    return spec


def fingerprint(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def open_root(root):
    root = Path(root)
    require(root.is_absolute() and root.resolve(strict=True) == root, "RUNTIME_ROOT_PATH")
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def open_member(root_fd, path):
    parts = relative(path).split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=current)
    finally:
        os.close(current)


def snapshot(root_fd, maximum_bytes):
    require(type(maximum_bytes) is int and 1 <= maximum_bytes <= MAX_BYTES, "RUNTIME_BYTE_BUDGET")
    files, directories, observations, total = [], [], {}, 0

    def visit(fd, prefix, depth):
        nonlocal total
        require(depth <= MAX_DEPTH, "RUNTIME_DEPTH")
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and before.st_mode & 0o022 == 0,
                "RUNTIME_DIRECTORY_MODE")
        directories.append({"path": prefix, "mode": stat.S_IMODE(before.st_mode)})
        observations[prefix] = fingerprint(before)
        with os.scandir(fd) as entries:
            names = []
            for entry in entries:
                require(len(names) + len(files) + len(directories) < MAX_ENTRIES,
                        "RUNTIME_ENTRY_LIMIT")
                names.append(entry.name)
        for name in sorted(names):
            path = relative(prefix + "/" + name if prefix else name)
            require(not name.endswith((".pth", ".pyc", ".pyo")) and name != "__pycache__",
                    "RUNTIME_IMPORT_POLICY")
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            require(info.st_mode & 0o022 == 0 and not info.st_mode & 0o7000,
                    "RUNTIME_MEMBER_MODE")
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                try:
                    require(fingerprint(info) == fingerprint(os.fstat(child)), "RUNTIME_MEMBER_CHANGED")
                    visit(child, path, depth + 1)
                finally:
                    os.close(child)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                        "RUNTIME_MEMBER_TYPE_OR_ALIAS")
                total += info.st_size
                require(total <= maximum_bytes and len(files) + len(directories) < MAX_ENTRIES,
                        "RUNTIME_BYTE_OR_ENTRY_BUDGET")
                child = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                try:
                    require(fingerprint(info) == fingerprint(os.fstat(child)), "RUNTIME_MEMBER_CHANGED")
                    sha, observed = hashlib.sha256(), 0
                    while data := os.read(child, min(1024 * 1024, info.st_size + 1 - observed)):
                        observed += len(data)
                        require(observed <= info.st_size, "RUNTIME_MEMBER_CHANGED")
                        sha.update(data)
                    require(observed == info.st_size and fingerprint(info) == fingerprint(os.fstat(child)),
                            "RUNTIME_MEMBER_CHANGED")
                    files.append({"path": path, "size": observed, "mode": stat.S_IMODE(info.st_mode),
                                  "sha256": sha.hexdigest()})
                    observations[path] = fingerprint(info)
                finally:
                    os.close(child)
        require(fingerprint(before) == fingerprint(os.fstat(fd)), "RUNTIME_DIRECTORY_CHANGED")

    visit(root_fd, "", 0)
    return sorted(files, key=lambda r: r["path"]), sorted(directories, key=lambda r: r["path"]), total, observations


def elf_dependencies(fd, size, machine):
    """Read ELF metadata without executing ldd, a loader, or the declared file."""
    def read(offset, length):
        require(0 <= offset <= size and 0 <= length <= min(1024 * 1024, size - offset),
                "RUNTIME_ELF_BOUNDS")
        data = os.pread(fd, length, offset)
        require(len(data) == length, "RUNTIME_ELF_TRUNCATED")
        return data

    if read(0, min(4, size)) != b"\x7fELF":
        return None
    header = read(0, 64)
    require(header[4:7] == b"\x02\x01\x01" and struct.unpack_from("<H", header, 18)[0]
            == {"x86_64": 62, "aarch64": 183}[machine], "RUNTIME_ELF_PROFILE")
    offset = struct.unpack_from("<Q", header, 32)[0]
    width, count = struct.unpack_from("<HH", header, 54)
    require(width == 56 and 1 <= count <= 128, "RUNTIME_ELF_PROGRAM_HEADERS")
    headers = [struct.unpack("<IIQQQQQQ", read(offset + i * width, width)) for i in range(count)]
    dynamic, interpreter, loads = [], None, []
    for kind, _, position, virtual, _, file_size, _, _ in headers:
        if kind == 1:
            loads.append((virtual, position, file_size))
        elif kind == 2:
            require(not dynamic and file_size % 16 == 0, "RUNTIME_ELF_DYNAMIC")
            dynamic = list(struct.iter_unpack("<qQ", read(position, file_size)))
        elif kind == 3:
            require(interpreter is None and 1 <= file_size <= 1024, "RUNTIME_ELF_INTERPRETER")
            interpreter = read(position, file_size).rstrip(b"\0").decode("ascii")
    values = {}
    for kind, value in dynamic:
        if kind == 0:
            break
        values.setdefault(kind, []).append(value)
    if not values:
        return {"needed": [], "search": [], "interpreter": interpreter}
    require(len(values.get(5, [])) == len(values.get(10, [])) == 1, "RUNTIME_ELF_STRING_TABLE")
    address, length = values[5][0], values[10][0]
    require(0 < length <= 1024 * 1024, "RUNTIME_ELF_STRING_TABLE")
    strings = bytearray()
    # A valid string table may span adjacent PT_LOAD segments. Resolve every
    # byte range through its own file mapping instead of assuming one segment.
    while len(strings) < length:
        cursor = address + len(strings)
        ranges = [(pos + cursor - virtual, virtual + limit - cursor)
                  for virtual, pos, limit in loads if virtual <= cursor < virtual + limit]
        require(ranges and len({p for p, _ in ranges}) == 1, "RUNTIME_ELF_STRING_TABLE")
        position = ranges[0][0]
        count = min(length - len(strings), min(remaining for _, remaining in ranges))
        strings.extend(read(position, count))

    def string(index):
        require(index < len(strings), "RUNTIME_ELF_STRING_INDEX")
        end = strings.find(b"\0", index)
        require(end >= index and end - index <= 1024, "RUNTIME_ELF_STRING_LIMIT")
        return strings[index:end].decode("ascii")

    return {"needed": [string(i) for i in values.get(1, [])],
            "search": [string(i) for tag in (15, 29) for i in values.get(tag, [])],
            "interpreter": interpreter}


def native_closure(root_fd, files, spec):
    paths = {row["path"] for row in files}
    result = []
    for row in files:
        fd = open_member(root_fd, row["path"])
        try:
            native = elf_dependencies(fd, row["size"], spec["platform"]["machine"])
        finally:
            os.close(fd)
        if native is None:
            continue
        search = list(spec["native_search_paths"])
        parent = row["path"].split("/")[:-1]
        for group in native["search"]:
            for item in group.split(":"):
                require(item.startswith("$ORIGIN/") or item == "$ORIGIN", "RUNTIME_ELF_AMBIENT_SEARCH")
                parts = list(parent)
                for part in item.removeprefix("$ORIGIN").split("/"):
                    if part in {"", "."}:
                        continue
                    if part == "..":
                        require(bool(parts), "RUNTIME_ELF_SEARCH_ESCAPE")
                        parts.pop()
                    else:
                        parts.append(part)
                require(parts, "RUNTIME_ELF_SEARCH_ESCAPE")
                search.append(relative("/".join(parts)))
        dependencies = []
        for name in native["needed"]:
            require(relative(name) == name and "/" not in name, "RUNTIME_ELF_NEEDED_NAME")
            candidates = sorted({directory + "/" + name for directory in search if directory + "/" + name in paths})
            require(len(candidates) == 1, "RUNTIME_NATIVE_DEPENDENCY_MISSING_OR_AMBIGUOUS:" + name)
            dependencies.append({"name": name, "path": candidates[0]})
        loader = native["interpreter"]
        if loader is not None:
            require(loader.startswith("/") and relative(loader[1:]) in paths, "RUNTIME_NATIVE_LOADER_MISSING")
        result.append({"path": row["path"], "interpreter": loader, "dependencies": dependencies})
    require(spec["interpreter"] in {row["path"] for row in result}, "RUNTIME_INTERPRETER_NOT_ELF")
    return result


def wheel_closure(root_fd, members, spec, maximum_bytes):
    """Bind original wheel members to installed bytes, without importing them.

    This first format refuses wheel .data relocation, rewritten installed RECORD
    and installer-generated launchers. Resolution uses the fully pinned marker
    environment, never the verifier's ambient platform defaults or an import from
    the declared root.
    """
    from packaging.requirements import Requirement
    from packaging.specifiers import SpecifierSet
    from packaging.utils import canonicalize_name
    from packaging.version import Version
    owned, packages = set(), {}
    for wheel in spec["wheels"]:
        archive, record = wheel["archive"], wheel["installed_record"]
        require(archive in members and record in members
                and members[archive]["sha256"] == wheel["sha256"], "RUNTIME_WHEEL_MISSING_OR_CHANGED")
        parts = record.split("/")
        package_root, dist_info = "/".join(parts[:-2]), parts[-2]
        require(bool(package_root), "RUNTIME_WHEEL_INSTALL_ROOT")
        fd = open_member(root_fd, archive)
        with os.fdopen(fd, "rb") as stream, zipfile.ZipFile(stream) as bundle:
            infos = bundle.infolist()
            require(1 <= len(infos) <= MAX_ENTRIES and len({i.filename for i in infos}) == len(infos),
                    "RUNTIME_WHEEL_MEMBER_LIMIT_OR_DUPLICATE")
            files = {}
            expanded = 0
            for info in infos:
                name = relative(info.filename.rstrip("/"))
                require(not stat.S_ISLNK(info.external_attr >> 16) and not info.flag_bits & 1
                        and info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        and not any(p.endswith(".data") for p in name.split("/")), "RUNTIME_WHEEL_LAYOUT")
                if not info.is_dir():
                    expanded += info.file_size
                    require(expanded <= maximum_bytes, "RUNTIME_WHEEL_EXPANDED_BUDGET")
                    files[name] = info
            record_name = dist_info + "/RECORD"
            require(record_name in files and dist_info + "/METADATA" in files
                    and dist_info + "/WHEEL" in files and files[record_name].file_size <= MAX_MANIFEST
                    and files[dist_info + "/METADATA"].file_size <= 1024 * 1024,
                    "RUNTIME_WHEEL_METADATA")
            metadata = BytesParser().parsebytes(bundle.read(dist_info + "/METADATA"))
            require(len(metadata.get_all("Name", [])) == len(metadata.get_all("Version", [])) == 1,
                    "RUNTIME_WHEEL_IDENTITY")
            name = canonicalize_name(metadata["Name"], validate=True)
            version = str(Version(metadata["Version"]))
            python_constraints = metadata.get_all("Requires-Python", [])
            require(len(python_constraints) <= 1 and (not python_constraints or
                SpecifierSet(python_constraints[0]).contains(spec["marker_environment"]["python_full_version"])),
                "RUNTIME_WHEEL_PYTHON_VERSION")
            require(name not in packages and set(wheel["extras"]).issubset(
                {canonicalize_name(e, validate=True) for e in metadata.get_all("Provides-Extra", [])}),
                "RUNTIME_WHEEL_DUPLICATE_OR_EXTRA")
            requirements = metadata.get_all("Requires-Dist", [])
            require(len(requirements) <= 512 and all(len(r) <= 2048 for r in requirements),
                    "RUNTIME_WHEEL_REQUIREMENTS_LIMIT")
            packages[name] = {"version": version, "wheel": wheel, "requirements": requirements}
            rows = {}
            for row in csv.reader(io.StringIO(bundle.read(record_name).decode("utf-8"))):
                require(len(row) == 3 and row[0] not in rows, "RUNTIME_WHEEL_RECORD")
                rows[relative(row[0])] = row[1:]
            require(set(rows) == set(files), "RUNTIME_WHEEL_RECORD_CLOSURE")
            for name, info in files.items():
                path = package_root + "/" + name
                require(path in members and path not in owned, "RUNTIME_WHEEL_INSTALL_MISSING_OR_ALIAS")
                owned.add(path)
                value = hashlib.sha256()
                observed = 0
                with bundle.open(info) as content:
                    while data := content.read(1024 * 1024):
                        observed += len(data)
                        require(observed <= info.file_size, "RUNTIME_WHEEL_SIZE")
                        value.update(data)
                require(observed == info.file_size and members[path]["size"] == observed
                        and members[path]["sha256"] == value.hexdigest(), "RUNTIME_WHEEL_INSTALL_CHANGED")
                if name == record_name:
                    require(rows[name] == ["", ""], "RUNTIME_WHEEL_RECORD_SELF")
                else:
                    encoded = base64.urlsafe_b64encode(value.digest()).rstrip(b"=").decode()
                    require(rows[name] == ["sha256=" + encoded, str(observed)], "RUNTIME_WHEEL_RECORD_HASH")
    require({p for p in members if p.endswith(".dist-info/RECORD")}
            == {w["installed_record"] for w in spec["wheels"]}, "RUNTIME_DISTRIBUTION_NOT_DECLARED")
    resolved = []
    for name, package in sorted(packages.items()):
        needed = set()
        for raw in package["requirements"]:
            requirement = Requirement(raw)
            if requirement.marker is not None and not any(requirement.marker.evaluate(
                    environment=dict(spec["marker_environment"], extra=extra), context="metadata")
                    for extra in ["", *package["wheel"]["extras"]]):
                continue
            dependency = canonicalize_name(requirement.name)
            require(dependency in packages, "RUNTIME_PYTHON_DEPENDENCY_MISSING:" + dependency)
            target = packages[dependency]
            require(requirement.specifier.contains(target["version"], prereleases=True)
                    and {canonicalize_name(e) for e in requirement.extras}.issubset(target["wheel"]["extras"])
                    and (requirement.url is None or requirement.url == target["wheel"]["origin"]),
                    "RUNTIME_PYTHON_DEPENDENCY_BINDING:" + dependency)
            needed.add(dependency)
        resolved.append({"name": name, "version": package["version"],
                         "extras": package["wheel"]["extras"], "dependencies": sorted(needed)})
    return resolved


def inspect(root, spec, maximum_bytes):
    validate_spec(spec)
    fd = open_root(root)
    try:
        original = os.fstat(fd)
        files, directories, total, observations = snapshot(fd, maximum_bytes)
        members, dirs = {r["path"]: r for r in files}, {r["path"] for r in directories}
        require(spec["interpreter"] in members and members[spec["interpreter"]]["mode"] & 0o111
                and spec["entrypoint"] in members and spec["stdlib"] in dirs, "RUNTIME_REQUIRED_ROLE")
        require(all(p in dirs for p in spec["import_roots"] + spec["native_search_paths"]),
                "RUNTIME_SEARCH_ROOT_MISSING")
        python = wheel_closure(fd, members, spec, maximum_bytes)
        native = native_closure(fd, files, spec)
        # This second metadata/readback pass detects changes during native inspection.
        require(snapshot(fd, maximum_bytes) == (files, directories, total, observations), "RUNTIME_CHANGED_DURING_INSPECTION")
        require(fingerprint(original) == fingerprint(os.stat(root, follow_symlinks=False)), "RUNTIME_ROOT_REPLACED")
        return {"schema": SCHEMA, "spec": spec, "files": files, "directories": directories,
                "native_dependencies": native, "python_dependencies": python, "total_file_bytes": total}
    finally:
        os.close(fd)


def declare_runtime_release(root, spec_raw, expected_spec_sha256, maximum_bytes):
    require(hashlib.sha256(spec_raw).hexdigest() == digest(expected_spec_sha256), "RUNTIME_SPEC_PIN")
    result = canonical(inspect(root, decode(spec_raw), maximum_bytes))
    require(len(result) <= MAX_MANIFEST, "RUNTIME_MANIFEST_LIMIT")
    return result


def verify_runtime_release(root, manifest_raw, expected_runtime_root, expected_context, maximum_bytes):
    require(type(manifest_raw) is bytes and 0 < len(manifest_raw) <= MAX_MANIFEST, "RUNTIME_MANIFEST_LIMIT")
    require(hashlib.sha256(DOMAIN + len(manifest_raw).to_bytes(8, "big") + manifest_raw).hexdigest()
            == digest(expected_runtime_root), "RUNTIME_ROOT_PIN")
    manifest = decode(manifest_raw)
    require(type(manifest) is dict and set(manifest) == {"schema", "spec", "files", "directories",
            "native_dependencies", "python_dependencies", "total_file_bytes"} and manifest["schema"] == SCHEMA,
            "RUNTIME_MANIFEST_FIELDS")
    spec = validate_spec(manifest["spec"])
    require(spec["context"] == expected_context, "RUNTIME_RELEASE_CONTEXT")
    require(canonical(inspect(root, spec, maximum_bytes)) == manifest_raw, "RUNTIME_MATERIAL_MISMATCH")
    return {"schema": "hepta-runtime-material-readback-v1", "runtime_root": expected_runtime_root,
            "total_file_bytes": manifest["total_file_bytes"], "files": len(manifest["files"]),
            "scope": "DECLARED_MATERIAL_AND_STATIC_ELF_CLOSURE_ONLY",
            "runtime_execution_qualified": False, "ordinary_installation_qualified": False,
            "public_reward_eligible": False}
