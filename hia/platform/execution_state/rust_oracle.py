"""Actual original M06 State/View/Patch differential; no runtime dependency.

The complete source closure and original native pipes are admitted before Cargo
or source copying. Only one private test declaration is appended to the original.
"""
from __future__ import annotations
import argparse,ast,hashlib,json,lzma,os,re,shutil,signal,stat,struct,subprocess,sys,time,tomllib
from pathlib import Path
HERE=Path(__file__).absolute().parent
REPOSITORY=HERE.parents[2]
OWNED="hia/platform/execution_state"
STORE="trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs"
HOOK="hia_execution_state_oracle.rs"
DECLARATION=b'\n#[cfg(test)]\n#[path = "hia_execution_state_oracle.rs"]\nmod hia_execution_state_oracle;\n'
TEST="pon_executor::hia_execution_state_oracle::evaluate"
MARKER="SVP_ORIGINAL:"
ORIGINAL_TESTS=(
 "pon_executor::prefix_scan_tests::prefix_rows_preserve_original_filter_order_values_and_all_string_boundaries",
 "pon_executor::prefix_scan_tests::prefix_scan_overlays_writes_and_retains_the_original_snapshot",
 "pon_executor::prefix_scan_tests::prefix_scan_revalidation_keeps_insert_delete_and_value_conflicts",
 "pon_executor::prefix_scan_tests::prefix_scan_does_not_replace_point_read_or_write_conflict_checks",
 "pon_executor::prefix_scan_tests::empty_and_nested_prefix_snapshots_revalidate_the_complete_observed_sets",
)
OWNED_REQUIRED=frozenset({"README.md","abi.json","build.py","cases.py","includes.json","linux_emitter.hepta","owner.hepta","value.hepta","map.hepta","native_io.py","qualify.py","rust_oracle.py","rust_reference.rs","test_integrity.py","physical.py"})
SOURCE_SUFFIXES=frozenset({".py",".rs",".json",".hepta",".md"})
EXPLICIT_INPUTS=("hia/platform/build.py","hia/tools/toolchain.py","hia/components.json","hia/toolchain.lock.json","hia/qualification/compiler-binding.json","hia/qualification/compiler-cold.json","hia/qualification/compiler-cold-full.json.xz")
CANONICAL_ROOT="src/protocol/state_root_compact.hepta"
COMP_SCHEMA="trnm.execution-state-native-comparison.v1"
BUILD_SCHEMA="trnm.execution-state-build.v1"
REPORT_SCHEMA="trnm.execution-state-original-differential.v1"
MAX_U64=(1<<64)-1
FORBIDDEN_OVERRIDES=(
 "LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","RUSTC","RUSTDOC","RUSTC_WRAPPER",
 "RUSTC_WORKSPACE_WRAPPER","RUSTFLAGS","RUSTDOCFLAGS","RUSTC_BOOTSTRAP","CARGO",
 "CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","CARGO_BUILD_RUSTC",
 "CARGO_BUILD_RUSTDOC","CARGO_BUILD_RUSTC_WRAPPER","CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
 "CARGO_BUILD_RUSTFLAGS","CARGO_BUILD_RUSTDOCFLAGS","CARGO_BUILD_TARGET",
 "CARGO_BUILD_BUILD_DIR","CARGO_BUILD_TARGET_DIR","CARGO_TARGET_DIR")


def forbidden_override(name):
    return name in FORBIDDEN_OVERRIDES or name.startswith('CARGO_PROFILE_') or (
        name.startswith('CARGO_TARGET_') and name.endswith(('_RUSTFLAGS','_RUSTDOCFLAGS','_LINKER','_RUNNER')))


def clean_build_environment():
    for name,value in os.environ.items():
        need(not value or not forbidden_override(name),'Unbound original compilation/runtime override: '+name)
    result=dict(os.environ);result['PYTHONDONTWRITEBYTECODE']='1'
    return result


def original_artifacts(artifacts):
    serde=[row for row in artifacts if row.get('target',{}).get('name')=='serde_json'
        and row['target'].get('kind')==['lib']]
    binaries=[row for row in artifacts if row.get('target',{}).get('name')=='trnm_mvcc_fee'
        and row['target'].get('kind')==['lib'] and row.get('executable')
        and row.get('profile',{}).get('test') is True]
    return serde,binaries

def need(value, message):
    if not value:
        raise ValueError(message)

def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "Duplicate JSON key: " + str(key))
        result[key] = value
    return result

def invalid_constant(value):
    raise ValueError("Non-finite JSON number: " + value)

def load_json(raw):
    return json.loads(raw, object_pairs_hook=unique_keys, parse_constant=invalid_constant)

def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

def same_json(left, right):
    return canonical_json(left) == canonical_json(right)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw)}

def valid_identity(value):
    return (isinstance(value, dict) and set(value) == {"bytes", "sha256"}
        and type(value["bytes"]) is int and value["bytes"] >= 0
        and isinstance(value["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)

def canonical_root(value):
    path = Path(value).absolute()
    need(path.exists() and path.is_dir() and path.resolve(strict=True) == path,
         "Root is absent, symbolic, or noncanonical: " + str(path))
    current = path
    while current != current.parent:
        need(not current.is_symlink(), "Symlinked root ancestor: " + str(current))
        current = current.parent
    return path

def canonical_path(root, relative, *, directory=False):
    need(isinstance(relative, str) and relative and "\\" not in relative and "\0" not in relative,
         "Invalid relative source path")
    name = Path(relative)
    need(not name.is_absolute() and ".." not in name.parts
         and name.as_posix() == relative and relative != ".",
         "Escaping or noncanonical relative path: " + relative)
    root = canonical_root(root)
    current = root
    for component in name.parts:
        current = current / component
        need(not current.is_symlink(), "Symlinked source path: " + relative)
    metadata = current.stat()
    need(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
         "Not the required regular file/directory: " + relative)
    need(current.resolve(strict=True) == current, "Symbolic source ancestor: " + relative)
    return current

def file_identity(path):
    need(not path.is_symlink() and path.is_file(), "Not a regular artifact: " + str(path))
    size, sha = 0, hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1 << 20):
            size += len(block)
            sha.update(block)
    return {"bytes": size, "sha256": sha.hexdigest()}

def write_json(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2, allow_nan=False).encode() + b"\n"
    with path.open("xb") as stream:
        stream.write(raw)

def source_functions(raw):
    declarations = re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)
    bodies = re.findall(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw)
    need(len(declarations) == len(set(declarations)) == len(bodies)
         and set(declarations) == set(bodies), "Ambiguous HIA function boundaries")
    return {name.decode() for name in declarations}

def literal_assignment(raw, name):
    matches = []
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(target, ast.Name) and target.id == name for target in node.targets):
            need(len(node.targets) == 1, "Ambiguous bound constant: " + name)
            matches.append(ast.literal_eval(node.value))
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == name:
            matches.append(ast.literal_eval(node.value))
    need(len(matches) == 1, "Missing or ambiguous bound constant: " + name)
    return matches[0]

def bounded_xz(path, expected):
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
    remaining, pieces = len(expected), []
    with path.open("rb") as compressed:
        while not decoder.eof:
            block = compressed.read(65536) if decoder.needs_input else b""
            need(block or not decoder.needs_input, "Truncated corpus archive")
            decoded = decoder.decompress(block, max_length=min(1 << 20, remaining + 1))
            need(len(decoded) <= remaining, "Corpus archive exceeds source-defined extent")
            pieces.append(decoded)
            remaining -= len(decoded)
        need(remaining == 0 and not decoder.unused_data and compressed.read(1) == b"",
             "Truncated, concatenated, or trailing corpus archive")
    actual = b"".join(pieces)
    need(actual == expected, "Archived corpus differs from source-defined input bytes")
    return actual

def run_command(argv, cwd, output, label, stages, *, timeout, environment):
    """Keep actual streams even for launch, timeout, drain, and nonzero failures."""
    directory = output / label
    directory.mkdir(mode=0o700)
    receipt = {"stage": label, "argv": [str(item) for item in argv], "cwd": str(cwd),
               "wall_limit_seconds": timeout, "cleanup_limit_seconds": 10,
               "started_monotonic_ns": time.monotonic_ns(), "exit_code": None,
               "timed_out": False, "launch_error": None, "cleanup_error": None}
    stdout_path, stderr_path = directory / "stdout.raw", directory / "stderr.raw"
    process = None
    primary = None
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, start_new_session=True, umask=0o077)
            receipt["pid"] = process.pid
            try:
                receipt["exit_code"] = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                primary = error
                receipt["timed_out"] = True
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        receipt["cleanup_signal"] = "SIGKILL_SENT"
                    except ProcessLookupError:
                        receipt["cleanup_signal"] = "ALREADY_EXITED"
                    receipt["exit_code"] = process.wait(timeout=10)
                except BaseException as cleanup_error:
                    receipt["cleanup_error"] = repr(cleanup_error)
        except BaseException as error:
            if primary is None:
                primary = error
            receipt["launch_error"] = repr(error)
            if process is not None and process.poll() is None:
                try:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    receipt["exit_code"] = process.wait(timeout=10)
                except BaseException as cleanup_error:
                    receipt["cleanup_error"] = repr(cleanup_error)
    receipt["finished_monotonic_ns"] = time.monotonic_ns()
    receipt["elapsed_ns"] = receipt["finished_monotonic_ns"] - receipt["started_monotonic_ns"]
    receipt["stdout"] = file_identity(stdout_path)
    receipt["stderr"] = file_identity(stderr_path)
    receipt["output_files_closed"] = True
    receipt["status"] = "PASS" if primary is None and receipt["exit_code"] == 0 and not receipt["cleanup_error"] else "FAIL"
    write_json(directory / "receipt.json", receipt)
    stages.append(receipt)
    need(receipt["status"] == "PASS", "Actual subprocess failed; retained stage " + label)
    return stdout_path.read_bytes(), receipt

def assert_test_executed(raw, name):
    text = raw.decode()
    need(re.search(r"(?m)^running 1 test\r?$", text) is not None
         and re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", text) is not None,
         "Actual exact test did not execute once: " + name)

def parse_original_rows(raw):
    rows = []
    for line in raw.decode().splitlines():
        if MARKER in line:
            prefix, value = line.split(MARKER, 1)
            need(prefix in ("", "test " + TEST + " ... "), "Unexpected original oracle output framing")
            rows.append(load_json(value))
    return rows

def safe_target(value, output, repository, bundle, isolated):
    path = Path(value).absolute() if value else output / "cargo-target"
    need(path == path.resolve(), "Symbolic Cargo target")
    for source in (repository, bundle, isolated):
        need(path != source and source not in path.parents and path not in source.parents,
             "Cargo target overlaps bound input source")
    need(path==output/'cargo-target' or (path!=output and output not in path.parents and path not in output.parents),
         'Cargo target overlaps original evidence output')
    need(not path.exists() or path.is_dir(),'Cargo target is not a directory')
    # An external shared target is permitted only through the caller's serialized
    # ownership. Its previous cached binary is never used as evidence.
    return path

def capture_serde_graph(metadata, isolated, output):
    import io
    import tarfile
    import tomllib
    need(isinstance(metadata, dict) and isinstance(metadata.get("packages"), list)
         and isinstance(metadata.get("resolve"), dict), "Cargo metadata graph is missing")
    packages = [row for row in metadata["packages"] if row.get("name") == "serde_json"]
    need(len(packages) == 1 and packages[0].get("version") == "1.0.149",
         "The original locked serde_json package changed")
    package = packages[0]
    nodes = [row for row in metadata["resolve"].get("nodes", []) if row.get("id") == package["id"]]
    need(len(nodes) == 1 and {"default", "std"} <= set(nodes[0].get("features", [])),
         "The actual serde_json feature graph differs")
    cargo_lock = tomllib.loads(canonical_path(isolated, "trillionnium/Cargo.lock").read_text())
    locked = [row for row in cargo_lock["package"] if row.get("name") == "serde_json"]
    need(len(locked) == 1 and locked[0].get("version") == "1.0.149"
         and locked[0].get("source") == package.get("source")
         and isinstance(package.get("source"), str) and package["source"].startswith("registry+"),
         "Serde package source differs from Cargo.lock")
    checksum = locked[0].get("checksum")
    need(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum) is not None,
         "Locked registry archive checksum is missing")
    manifest = Path(package["manifest_path"]).absolute()
    crate = canonical_root(manifest.parent)
    need(manifest.name == "Cargo.toml" and crate.name == package["name"] + "-" + package["version"]
         and crate.parent.parent.name == "src" and crate.parent.parent.parent.name == "registry",
         "Unadmitted registry source/cache layout")
    canonical_path(crate, manifest.name)
    cache = canonical_root(crate.parent.parent.parent / "cache" / crate.parent.name)
    archive = canonical_path(cache, crate.name + ".crate")

    def archive_sources():
        # Hash and parse the same bounded immutable byte snapshot. A normal Cargo
        # registry unpack has no vendor .cargo-checksum.json; its .crate is the
        # object authenticated by the original Cargo.lock checksum.
        need(canonical_root(crate) == crate and canonical_root(cache) == cache,
             "Registry source/cache identity became symbolic")
        current_archive = canonical_path(cache, crate.name + ".crate")
        with current_archive.open("rb") as stream:
            raw = stream.read((16 << 20) + 1)
        need(len(raw) <= 16 << 20 and digest(raw) == checksum,
             "Actual registry archive differs from the original Cargo.lock checksum")
        found, total = {}, 0
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as packed:
            for member in packed:
                parts = member.name.split("/")
                need(member.isfile() and len(parts) >= 2 and parts[0] == crate.name
                     and all(part not in ("", ".", "..") for part in parts)
                     and "\\" not in member.name and "\x00" not in member.name,
                     "Nonregular or escaping registry archive member")
                relative = "/".join(parts[1:])
                need(relative not in found and relative != ".cargo-ok",
                     "Duplicate or Cargo-generated registry archive member")
                need(0 <= member.size <= 8 << 20 and len(found) < 4096,
                     "Registry archive member exceeds the source admission bound")
                total += member.size
                need(total <= 64 << 20, "Registry archive exceeds the source admission bound")
                with packed.extractfile(member) as stream:
                    data = stream.read(member.size + 1)
                need(len(data) == member.size, "Truncated registry archive member")
                found[relative] = identity(data)
        need("Cargo.toml" in found and "src/lib.rs" in found,
             "Incomplete locked registry archive")
        return identity(raw), found

    archive_identity, archived = archive_sources()

    def capture():
        observed_archive, observed_members = archive_sources()
        need(observed_archive == archive_identity and observed_members == archived,
             "Locked registry archive changed after admission")
        found = {}
        for path in sorted(crate.rglob("*")):
            relative = path.relative_to(crate).as_posix()
            need(not path.is_symlink(), "Symbolic serde dependency source")
            if path.is_file():
                found[relative] = file_identity(canonical_path(crate, relative))
            else:
                need(path.is_dir(), "Nonregular serde dependency source")
        need(set(archived) <= set(found) and set(found) - set(archived) <= {".cargo-ok"},
             "Missing or unexpected unpacked registry source")
        for name, expected in archived.items():
            need(found[name] == expected, "Serde file differs from the locked registry archive: " + name)
        if ".cargo-ok" in found:
            need(found[".cargo-ok"]["bytes"] <= 1024 and
                 same_json(load_json(canonical_path(crate, ".cargo-ok").read_bytes()), {"v": 1}),
                 "Unadmitted Cargo-generated readiness marker")
        return found

    sources = capture()
    binding = {"package": package, "resolve_node": nodes[0], "locked_package": locked[0],
               "crate_directory": str(crate), "crate_sources": sources,
               "crate_source_set_sha256": digest(canonical_json(sources)),
               "registry_archive": {"path": str(archive), **archive_identity},
               "archive_source_files": archived,
               "archive_source_set_sha256": digest(canonical_json(archived)),
               "optional_cargo_generated_files": {
                   name: sources[name] for name in (".cargo-ok",) if name in sources},
               "vendor_checksum_file_required": False}
    write_json(output / "serde-json-source-before.json", binding)
    return binding, capture

def complete_sources(repository):
    need(__debug__, 'Optimized Python is not admitted')
    repository=canonical_root(repository);captured={};owned_names=set()
    def capture(name):
        raw=canonical_path(repository,name).read_bytes()
        need(name not in captured or raw==captured[name], 'Source changed during capture: '+name)
        captured[name]=raw;return raw
    directory=canonical_path(repository,OWNED,directory=True)
    for path in sorted(directory.rglob('*')):
        need(not path.is_symlink() and path.name!='__pycache__' and path.suffix!='.pyc','Symbolic source or stale bytecode')
        if path.is_dir():continue
        need(path.suffix in SOURCE_SUFFIXES,'Unexpected owned artifact')
        name=path.relative_to(repository).as_posix();capture(name)
        if path.parent==directory:owned_names.add(path.name)
    need(OWNED_REQUIRED<=owned_names,'Missing required owned source: '+repr(sorted(OWNED_REQUIRED-owned_names)))
    builder=captured[OWNED+'/build.py']
    need(literal_assignment(builder,'EXPLICIT')==EXPLICIT_INPUTS,'Builder explicit closure declaration changed')
    need(literal_assignment(builder,'ROOT_SOURCE')==CANONICAL_ROOT,'Builder canonical root differs')
    need(literal_assignment(builder,'PREFIX')==OWNED+'/','Builder owned prefix differs')
    for name in EXPLICIT_INPUTS:capture(name)
    pinned=literal_assignment(captured['hia/platform/build.py'],'INPUTS')
    need(isinstance(pinned,(list,tuple)) and pinned and all(isinstance(n,str) for n in pinned) and len(set(pinned))==len(pinned),'Malformed pinned platform inputs')
    for name in pinned:capture('hia/'+name)
    canonical=load_json(captured['hia/components.json'])
    local=load_json(captured[OWNED+'/includes.json'])
    need(set(canonical)=={'schema','includes'} and canonical['schema']=='trnm.hia.component-includes.v1' and isinstance(canonical['includes'],dict),'Malformed canonical includes')
    need(set(local)=={'schema','includes'} and local['schema']=='trnm.hia.execution-state-includes.v1' and isinstance(local['includes'],dict),'Malformed owner includes')
    expected={name[4:] for name in captured if name.startswith(OWNED+'/') and name.endswith('.hepta')}
    need(set(local['includes'])==expected,'Owner HIA declaration inventory differs')
    def component_path(name):
        need(isinstance(name,str) and name.startswith(('src/','platform/','storage/')) and name.endswith('.hepta'),'Invalid HIA dependency path')
        return canonical_path(repository,'hia/'+name)
    for name in canonical['includes']:component_path(name)
    done={}
    def visit(name,ancestors=()):
        component_path(name);need(name not in ancestors,'Cyclic HIA dependency')
        if name in done:return done[name]
        raw=capture('hia/'+name);source_functions(raw)
        matches=list(re.finditer(rb'(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)',raw))
        own={m.group(1).decode():m.group(0) for m in matches};names=set(own);pieces=[raw.rstrip()+b'\n']
        rows=local['includes'][name] if name in local['includes'] else canonical['includes'].get(name,[])
        need(isinstance(rows,list),'Malformed include row list')
        for row in rows:
            need(isinstance(row,dict) and set(row)=={'source','functions'} and isinstance(row['functions'],list) and row['functions'] and all(isinstance(f,str) for f in row['functions']),'Malformed explicit include')
            combined,available=visit(row['source'],(*ancestors,name))
            for fn in row['functions']:
                need(fn in available and fn not in names,'Unknown, repeated or re-exported included function')
                names.add(fn);pieces.append(available[fn].rstrip()+b'\n')
        combined=b''.join(pieces)
        calls={value.decode() for value in re.findall(rb'"function"\s*:\s*"([A-Za-z_][A-Za-z_0-9]*)"',combined)}
        need(calls<=names,'Undeclared HIA callee in complete include closure')
        done[name]=(combined,own);return done[name]
    composed={name:visit('platform/execution_state/'+name+'.hepta')[0] for name in ('owner','linux_emitter')}
    composed['root']=visit(CANONICAL_ROOT)[0]
    for name,raw in captured.items():need(canonical_path(repository,name).read_bytes()==raw,'Source changed during closure discovery')
    return {name:identity(raw) for name,raw in sorted(captured.items())},composed


def complete_source_manifest(repository):return complete_sources(repository)[0]


def original_include_dependencies(repository):
    """Literal Rust data includes across the actual local Cargo dependency graph.

    The selected crate's unit tests are compiled, including modules unrelated to
    our retained tests. Every Rust source in each local package is inspected;
    test-only dependencies of those packages are conservatively included too.
    Unsupported include expressions are rejected instead of silently omitted.
    """
    repository=canonical_root(repository)
    workspace=tomllib.loads(canonical_path(repository,'trillionnium/Cargo.toml').read_text())
    inherited=workspace.get('workspace',{}).get('dependencies',{})
    need(isinstance(inherited,dict),'Malformed workspace dependencies')
    pending=['trillionnium/crates/trnm-mvcc-fee'];visited=set();required={}

    def relative(base,literal):
        need(isinstance(literal,str) and literal and not literal.startswith('/') and '\\' not in literal and '\x00' not in literal,'Noncanonical original dependency path')
        parts=base.split('/')
        for part in literal.split('/'):
            need(part!='','Empty original dependency path component')
            if part=='.':continue
            if part=='..':
                need(bool(parts),'Original dependency escaped repository');parts.pop()
            else:parts.append(part)
        need(bool(parts),'Original dependency resolves to repository')
        return '/'.join(parts)

    literal_pattern=re.compile(rb'include_(?:str|bytes)!\s*\(\s*"([^"\\\r\n]*)"\s*,?\s*\)')
    while pending:
        package=pending.pop()
        if package in visited:continue
        visited.add(package)
        directory=canonical_path(repository,package,directory=True)
        manifest=tomllib.loads(canonical_path(repository,package+'/Cargo.toml').read_text())
        tables=[manifest]
        targets=manifest.get('target',{})
        need(isinstance(targets,dict),'Malformed Cargo target tables')
        tables.extend(targets.values())
        for table in tables:
            need(isinstance(table,dict),'Malformed Cargo dependency table')
            for category in ('dependencies','dev-dependencies','build-dependencies'):
                dependencies=table.get(category,{})
                need(isinstance(dependencies,dict),'Malformed Cargo dependency map')
                for name,dependency in dependencies.items():
                    if isinstance(dependency,str):continue
                    need(isinstance(dependency,dict),'Malformed Cargo dependency')
                    origin=package
                    if dependency.get('workspace') is True:
                        need(name in inherited and isinstance(inherited[name],(dict,str)),'Missing workspace dependency')
                        dependency=inherited[name];origin='trillionnium'
                        if isinstance(dependency,str):continue
                    if 'path' in dependency:
                        target=relative(origin,dependency['path'])
                        canonical_path(repository,target+'/Cargo.toml');pending.append(target)
        for path in sorted(directory.rglob('*.rs')):
            source=path.relative_to(repository).as_posix()
            raw=canonical_path(repository,source).read_bytes()
            need(re.search(rb'\binclude!\s*\(',raw) is None,'Unsupported Rust source include: '+source)
            matches=list(literal_pattern.finditer(raw))
            need(len(matches)==len(re.findall(rb'\binclude_(?:str|bytes)!\s*\(',raw)),'Unsupported Rust data include expression: '+source)
            for match in matches:
                literal=match.group(1).decode('utf-8')
                target=relative(path.parent.relative_to(repository).as_posix(),literal)
                canonical_path(repository,target)
                required.setdefault(target,[]).append({'source':source,'literal':literal})
    return {'local_packages':sorted(visited),'data_includes':dict(sorted(required.items()))}


def original_manifest(repository):
    repository=canonical_root(repository);rows={}
    for dirname in ('trillionnium','config','formal'):
        directory=canonical_path(repository,dirname,directory=True)
        for path in sorted(directory.rglob('*')):
            need(not path.is_symlink(),'Symbolic original source')
            if path.is_dir():continue
            name=path.relative_to(repository).as_posix();rows[name]=file_identity(canonical_path(repository,name))
    need({'trillionnium/Cargo.lock','trillionnium/Cargo.toml',STORE}<=set(rows),'Missing complete original source')
    for name in original_include_dependencies(repository)['data_includes']:
        rows[name]=file_identity(canonical_path(repository,name))
    return dict(sorted(rows.items()))


def validate_source_bindings(repository,comparison):
    need(isinstance(comparison,dict) and comparison.get('schema')==COMP_SCHEMA and comparison.get('status')=='PASS','Native comparison did not pass')
    build=comparison.get('build');need(isinstance(build,dict) and build.get('schema')==BUILD_SCHEMA and build.get('status')=='PASS','Native build did not pass')
    supplied=build.get('source_inputs');need(isinstance(supplied,dict) and supplied,'Missing source bindings')
    for name,row in supplied.items():canonical_path(repository,name);need(valid_identity(row),'Malformed bound source identity')
    actual=complete_source_manifest(repository)
    need(supplied==actual and build.get('source_set_sha256')==digest(canonical_json(actual)),'Incomplete, extra, changed source closure or digest')
    need(build.get('source_after')=={'status':'PASS','errors':[]} and build.get('failure') is None and build.get('runtime_host_proxy') is False,'Build lacks source fence or has a runtime fallback')
    need(build.get('original_rust_executed') is False,'Native report cannot claim original Rust execution')
    if 'source_inputs' in comparison:need(comparison['source_inputs']==actual,'Top-level source map differs')
    pin=load_json(canonical_path(repository,'hia/qualification/compiler-binding.json').read_bytes())
    lock=load_json(canonical_path(repository,'hia/toolchain.lock.json').read_bytes())
    need(build.get('compiler_qualification_binding')==pin and build.get('compiler_sha256')==pin['compiler_sha256'] and build.get('toolchain')==lock,'Native compiler source/qualification pin differs')
    return actual


def bound_corpus(repository):
    path=canonical_path(repository,OWNED+'/cases.py');raw=path.read_bytes();tree=ast.parse(raw,filename=str(path))
    for item in ast.walk(tree):
        if isinstance(item,ast.Import):need(all(alias.name in {'json','struct','hashlib'} for alias in item.names),'Unbound corpus import')
        if isinstance(item,ast.ImportFrom):need(item.module=='__future__','Unbound corpus import')
    namespace={'__file__':str(path),'__name__':'_source_bound_execution_state_cases'}
    exec(compile(tree,str(path),'exec',dont_inherit=True),namespace)
    corpus=namespace['canonical_bytes']();need(type(corpus) is bytes and corpus.endswith(b'\n'),'Invalid canonical corpus bytes')
    rows=[load_json(line) for line in corpus.splitlines()]
    need(rows and same_json(rows,namespace['histories']()),'Source-defined histories differ from canonical bytes')
    names=set()
    for row in rows:
        need(set(row)=={'schema','name','commands'} and row['schema']=='trnm.execution-state-history.v1' and isinstance(row['name'],str) and row['name'] not in names,'Malformed/duplicate history')
        names.add(row['name']);need(isinstance(row['commands'],list) and row['commands'] and row['commands'][-1]['op']=='close','History must close its owner')
    need(path.read_bytes()==raw,'Corpus author changed')
    return corpus,rows


def native_frames(raw):
    result=[];cursor=0
    while cursor<len(raw):
        need(len(raw)-cursor>=8,'Truncated native response length')
        n=struct.unpack_from('<Q',raw,cursor)[0];cursor+=8
        need(n>=64 and n<=len(raw)-cursor,'Truncated native response')
        frame=raw[cursor:cursor+n];cursor+=n;need(frame[:8]==b'SVPR0001','Unexpected native response namespace')
        op,seq,status,returned,size,objects,blocks=struct.unpack('<7Q',frame[8:64]);need(size==len(frame)-64,'Response extent mismatch')
        if op==26 and status==0:need(objects==0 and blocks==0 and size==0,'Close did not reclaim all native objects/allocations')
        result.append({'op':op,'sequence':seq,'status':status,'result':returned,'data_hex':frame[64:].hex(),'live_objects':objects})
    return result


def validate_bundle(repository,bundle):
    repository=canonical_root(repository);bundle=canonical_root(bundle)
    comparison=load_json(canonical_path(bundle,'native-comparison.json').read_bytes())
    need(isinstance(comparison,dict) and set(comparison)=={'schema','status','build','corpus','histories'},'Unexpected comparison fields')
    source_inputs=validate_source_bindings(repository,comparison);build=comparison['build']
    original=original_manifest(repository)
    need(build.get('original_sources')==original and build.get('original_source_set_sha256')==digest(canonical_json(original)),'Original source identity/set differs')
    corpus,inputs=bound_corpus(repository);declared=comparison.get('corpus')
    need(isinstance(declared,dict) and set(declared)=={'path','raw','compressed'} and declared['path']=='corpus.jsonl.xz' and declared['raw']==identity(corpus) and valid_identity(declared['compressed']),'Corpus identity differs')
    need(canonical_path(bundle,'corpus.jsonl').read_bytes()==corpus,'Uncompressed corpus changed')
    compressed=canonical_path(bundle,'corpus.jsonl.xz');need(file_identity(compressed)==declared['compressed'],'Compressed corpus identity differs');bounded_xz(compressed,corpus)
    report=load_json(canonical_path(bundle,'native-report.json').read_bytes())
    need(report.get('schema')=='trnm.execution-state-qualification.v1' and report.get('status')=='PASS' and report.get('build')==build and report.get('corpus')==declared,'Native report/bundle binding differs')
    need(report.get('comparison')==file_identity(canonical_path(bundle,'native-comparison.json')),'Native comparison hash differs')
    need(report.get('verification')=={'primary_error':None,'cleanup_errors':[],'source_after':{'status':'PASS','errors':[]}},'Native verification did not close')
    scope=report.get('scope',{})
    need(scope.get('actual_private_state_view_patch_owner') is True and scope.get('canonical_hia_state_root') is True and scope.get('runtime_host_proxy') is False and scope.get('complete_node') is False and scope.get('admission_persistence') is False and scope.get('original_rust')=='NOT_RUN','Native scope declaration differs')
    images={name:canonical_path(bundle,'native-build/'+file).read_bytes() for name,file in (('owner','owner.flat'),('root','root.flat'),('linux_emitter','linux_emitter.elf'),('executable','owner.elf'))}
    need(build.get('images')=={n:identity(images[n]) for n in ('owner','root','linux_emitter')} and build.get('executable')==identity(images['executable']),'Native image bytes differ')
    need(images['executable'].startswith(b'\x7fELF') and images['executable'].endswith(images['owner']+images['root']),'Final ELF omits exact owner/root images')
    _,composed=complete_sources(repository);stages=build.get('stages');need(isinstance(stages,list) and len(stages)==4,'Incomplete actual compiler stages')
    joined=struct.pack('<QQ',len(images['owner']),len(images['root']))+images['owner']+images['root']
    for stage,name in zip(stages,('owner','root','linux_emitter','emit'),strict=True):
        payload=joined if name=='emit' else composed[name];emitted=images['executable'] if name=='emit' else images[name]
        expected_executable=identity(images['linux_emitter']) if name=='emit' else {'bytes':stage.get('executable_bytes'),'sha256':build['compiler_sha256']}
        need(stage.get('stage')==('emit-owner' if name=='emit' else 'compile-'+name) and stage.get('exit_code')==0 and stage.get('timed_out') is False and stage.get('stderr_hex')=='' and stage.get('cleanup') is None,'Native stage did not succeed')
        need({'bytes':stage.get('input_bytes'),'sha256':stage.get('input_sha256')}==identity(payload) and {'bytes':stage.get('output_bytes'),'sha256':stage.get('output_sha256')}==identity(emitted),'Native stage input/output binding differs')
        need(stage.get('executable_sha256')==expected_executable['sha256'],'Native compiler/emitter executable differs')
    opcodes=literal_assignment(canonical_path(repository,OWNED+'/native_io.py').read_bytes(),'OPCODES')
    need(isinstance(opcodes,dict) and len(set(opcodes.values()))==len(opcodes),'Invalid opcode declaration')
    need(load_json(canonical_path(repository,OWNED+'/abi.json').read_bytes()).get('opcodes')==opcodes,'ABI operation declarations differ')
    cases=comparison.get('histories');need(isinstance(cases,list) and len(cases)==len(inputs),'Native histories incomplete')
    controls=report.get('controls');need(isinstance(controls,list) and len(controls)==len(inputs),'Native control inventory incomplete')
    expected_files={'native-comparison.json','native-report.json','corpus.jsonl','corpus.jsonl.xz',*('native-build/'+n for n in ('owner.flat','root.flat','linux_emitter.elf','owner.elf'))};total_commands=0
    for index,(given,row,control) in enumerate(zip(inputs,cases,controls,strict=True)):
        need(row.get('name')==given['name'] and row.get('status')=='PASS' and row.get('failure') is None,'Native history identity/failure differs')
        directory='processes/%03d'%index;need(row.get('process_directory')==directory,'Noncanonical native process directory')
        names={name:directory+'/'+name for name in ('stdin.raw','stdout.raw','stderr.raw','receipt.json')};expected_files.update(names.values())
        raw={name:canonical_path(bundle,path).read_bytes() for name,path in names.items()}
        receipt=load_json(raw['receipt.json']);need(receipt==row.get('process'),'Actual native receipt differs')
        need(receipt.get('schema')=='trnm.execution-state-native-process.v1' and receipt.get('executable')==build['executable'] and receipt.get('exit_code')==0 and receipt.get('clean_close') is True and receipt.get('failure') is None and receipt.get('cleanup') is None and receipt.get('runtime_host_proxy') is False and receipt.get('unconsumed_stdout_hex')=='' and receipt.get('instrumentation')=={'trace':False,'mremap_errno_injected':False},'Native process was incomplete or refused')
        need(receipt.get('wall_limit_seconds')==240 and receipt.get('cleanup_limit_seconds')==3 and type(receipt.get('elapsed_ns')) is int and receipt['elapsed_ns']>0,'Unbounded or invalid process accounting')
        need(receipt.get('files')=={name:identity(raw[name]) for name in ('stdin.raw','stdout.raw','stderr.raw')} and raw['stderr.raw']==b'' and receipt.get('stderr_bytes')==0,'Native pipe identities differ')
        frames=native_frames(raw['stdout.raw']);need(same_json(frames,row.get('observations')) and len(frames)==len(given['commands']),'Raw native observations are incomplete or differ')
        handles={};requests=[]
        for ordinal,(step,observed) in enumerate(zip(given['commands'],frames,strict=True),1):
            need(observed['op']==opcodes[step['op']] and observed['sequence']==ordinal,'Native command/sequence differs')
            key=bytes.fromhex(step.get('key_hex',''));data=bytes.fromhex(step.get('data_hex',''));frame=b'SVP00001'+struct.pack('<7Q',opcodes[step['op']],handles.get(step.get('a'),0),handles.get(step.get('b'),0),step.get('arg',0),len(key),len(data),0)+key+data;requests.append(struct.pack('<Q',len(frame))+frame)
            if 'as' in step:handles[step['as']]=observed['result']
            for field,value in step.get('expect',{'status':0}).items():
                need((bool(observed['result'])==value if field=='result_nonzero' else observed.get(field)==value),'Source-defined native expectation differs')
        request=b''.join(requests);need(raw['stdin.raw']==request and receipt.get('stdin_attempted_bytes')==len(request) and receipt.get('stdin_actual_write_bytes')==len(request) and receipt.get('stdout_bytes')==len(raw['stdout.raw']) and receipt.get('commands')==len(frames),'Actual full native input/command accounting differs')
        need(frames[-1]['op']==26 and frames[-1]['status']==0 and frames[-1]['live_objects']==0,'Native owner did not close')
        need(control=={'name':given['name'],'status':'PASS','commands':len(frames),'failure':None},'Native control summary differs');total_commands+=len(frames)
    need(report.get('histories_total')==len(inputs) and report.get('histories_expected')==len(inputs) and report.get('actual_processes')==len(inputs) and report.get('native_commands')==total_commands,'Native totals differ')
    found=set()
    for path in bundle.rglob('*'):
        need(not path.is_symlink(),'Symbolic bundle descendant')
        if path.is_dir():continue
        name=path.relative_to(bundle).as_posix();canonical_path(bundle,name);found.add(name)
    need(found==expected_files,'Incomplete or extra native bundle artifact')
    artifacts={name:file_identity(canonical_path(bundle,name)) for name in sorted(found)}
    return {'comparison':comparison,'report':report,'source_inputs':source_inputs,'original_sources':original,'corpus_raw':corpus,'inputs':inputs,'bundle_artifacts':artifacts,'native_counts':{'histories':len(inputs),'commands':total_commands}}


def main():
    if not __debug__ or os.environ.get("PYTHONOPTIMIZE"):
        raise RuntimeError("Optimized Python is not admitted by this verifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    repository = canonical_root(args.repository)
    script = canonical_path(repository, OWNED + "/rust_oracle.py")
    need(script == Path(__file__).absolute(), "Run the exact oracle from the selected repository")
    bundle = canonical_root(args.bundle)
    output = args.output.absolute()
    need(output == output.resolve() and not output.exists() and not output.is_symlink(),
         "Use a fresh, nonsymbolic output directory")
    for source in (repository, bundle):
        need(output != source and source not in output.parents, "Output is inside bound input source")
    output.mkdir(parents=True, mode=0o700)
    started = time.monotonic_ns()
    base = {
        "schema": REPORT_SCHEMA, "production_runtime_dependency": False,
        "complete_node": False, "successor_admission": False, "arbitrary_commit": False,
        "original_state_view_patch_operations": True,
        "safe_test_only_immutable_base_materialization": True,
        "native_allocator_matches_rust_allocator_claimed": False,
        "original_production_function_bytes_preserved": True,
    }
    stages, source_fences, controls, retained = [], [], [], []
    primary_error, final_errors, missing = None, [], []
    admitted = None
    isolated = output / "isolated-source"
    copied = False
    original_store = hook = corpus_path = None
    isolated_expected = binary = binary_identity = compiled_binary = None
    serde = serde_capture = serde_artifact = compiler = compiler_tools = None
    partial_original = []
    status = "FAIL"

    def fence(label):
        observations, errors = {}, []
        def check(name, operation):
            try:
                observations[name] = operation()
            except BaseException as error:
                errors.append({"check": name, "error": repr(error)})
        if admitted is not None:
            def native_source():
                value = validate_source_bindings(repository, admitted["comparison"])
                need(value == admitted["source_inputs"], "Source closure changed after admission")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            def original_source():
                value = original_manifest(repository)
                need(value == admitted["original_sources"], "Original production source changed")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            def artifacts():
                observed = {name: file_identity(canonical_path(bundle, name))
                            for name in admitted["bundle_artifacts"]}
                need(observed == admitted["bundle_artifacts"], "Bound native bundle changed")
                raw, rows = bound_corpus(repository)
                need(raw == admitted["corpus_raw"] and rows == admitted["inputs"], "Canonical input generator changed")
                return {"status": "MATCH", "artifacts": observed}
            check("native_source", native_source)
            check("original_source", original_source)
            check("bundle_and_corpus", artifacts)
        if copied:
            def isolated_source():
                value = original_manifest(isolated)
                need(value == isolated_expected, "Isolated original/hook source changed or gained files")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            check("isolated_original_with_only_declared_hook", isolated_source)
            def actual_corpus():
                value = file_identity(canonical_path(output, "corpus.jsonl"))
                need(value == admitted["comparison"]["corpus"]["raw"], "Actual original corpus changed")
                return {"status": "MATCH", **value}
            check("actual_original_corpus", actual_corpus)
        if binary is not None:
            def executable():
                value = file_identity(canonical_path(output, "original-test-binary"))
                need(value == binary_identity, "Independent original test binary changed")
                return {"status": "MATCH", **value}
            check("independent_executable", executable)
        if serde_capture is not None:
            def dependency():
                value = serde_capture()
                need(value == serde["crate_sources"], "Locked actual serde dependency sources changed")
                return {"status": "MATCH", "files": len(value), "source_set_sha256": digest(canonical_json(value))}
            check("actual_serde_dependency", dependency)
        if compiler_tools is not None:
            def tools_identity():
                for name,row in compiler_tools.items():
                    need(file_identity(Path(row['path']))=={k:row[k] for k in ('bytes','sha256')},'Bound Rust tool changed: '+name)
                return {'status':'MATCH','tools':compiler_tools}
            check('actual_rust_tools',tools_identity)
        receipt = {"label": label, "status": ("NOT_REACHED" if admitted is None else "PASS") if not errors else "FAIL",
                   "observations": observations, "errors": errors}
        source_fences.append(receipt)
        write_json(output / (label + ".json"), receipt)
        need(not errors, "Final source/binary fence failed: " + repr(errors))

    try:
        environment=clean_build_environment()
        target=safe_target(args.target_dir,output,repository,bundle,isolated)
        admitted = validate_bundle(repository, bundle)
        write_json(output / "admission.json", {
            "status": "ADMITTED_NOT_ORIGINAL_EXECUTED",
            "source_inputs": admitted["source_inputs"], "original_sources": admitted["original_sources"],
            "native_source_set_sha256": admitted["comparison"]["build"]["source_set_sha256"],
            "bundle_artifacts": admitted["bundle_artifacts"], "native_counts": admitted["native_counts"],
            "corpus": admitted["comparison"]["corpus"]["raw"],
        })
        fence("source-before")
        missing = [name for name in ("cargo", "rustc") if shutil.which(name) is None]
        if missing:
            status = "NOT_RUN"
            raise RuntimeError("Required actual Rust tools are unavailable: " + repr(missing))
        corpus_path = output / "corpus.jsonl"
        with corpus_path.open("xb") as stream:
            stream.write(admitted["corpus_raw"])
        hook = canonical_path(repository, OWNED + "/rust_reference.rs").read_bytes()
        need(identity(hook) == admitted["source_inputs"][OWNED + "/rust_reference.rs"],
             "Original hook is not the native-bound source")
        isolated.mkdir(mode=0o700)
        for relative, expected in admitted["original_sources"].items():
            original_path = canonical_path(repository, relative)
            destination = isolated / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            with original_path.open("rb") as source, destination.open("xb") as destination_stream:
                shutil.copyfileobj(source, destination_stream, length=1 << 20)
            need(file_identity(destination) == expected, "Source changed while copying: " + relative)
        store = isolated / STORE
        original_store = store.read_bytes()
        need(b"mod hia_execution_state_oracle" not in original_store, "Original store already contains oracle")
        hook_path = store.parent / HOOK
        with hook_path.open("xb") as stream:
            stream.write(hook)
        with store.open("ab") as stream:
            stream.write(DECLARATION)
        isolated_expected = dict(admitted["original_sources"])
        isolated_expected[STORE] = identity(original_store + DECLARATION)
        isolated_expected[hook_path.relative_to(isolated).as_posix()] = identity(hook)
        copied = True
        fence("isolated-source-before")
        version, _ = run_command(["rustc", "-Vv"], isolated, output, "rustc-version", stages,
                                 timeout=15, environment=environment)
        compiler = version.decode()
        need(re.search(r"(?m)^host: x86_64-unknown-linux-gnu$", compiler) is not None,
             "Original target does not match native x86-64 Value/ownership domain")
        sysroot_raw,_=run_command(['rustc','--print','sysroot'],isolated,output,'rustc-sysroot',stages,
            timeout=15,environment=environment)
        sysroot=Path(sysroot_raw.decode().strip()).resolve(strict=True)
        compiler_tools={}
        for name in ('rustc','cargo','rustdoc'):
            executable=(sysroot/'bin'/name).resolve(strict=True)
            compiler_tools[name]={'path':str(executable),**file_identity(executable)}
        exact,_=run_command([compiler_tools['rustc']['path'],'-Vv'],isolated,output,'rustc-selected-version',stages,
            timeout=15,environment=environment)
        need(exact==version,'Selected actual compiler differs from discovered Rust toolchain')
        environment.update(RUSTC=compiler_tools['rustc']['path'],CARGO=compiler_tools['cargo']['path'],
            RUSTDOC=compiler_tools['rustdoc']['path'],RUSTC_WRAPPER='',RUSTC_WORKSPACE_WRAPPER='')
        metadata_raw, _ = run_command([compiler_tools['cargo']['path'], "metadata", "--locked", "--format-version=1",
            "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path",
            str(isolated / "trillionnium/Cargo.toml")], isolated, output,
            "cargo-original-metadata", stages, timeout=120, environment=environment)
        serde, serde_capture = capture_serde_graph(load_json(metadata_raw), isolated, output)
        built_raw, _ = run_command([compiler_tools['cargo']['path'], "test", "--locked", "--manifest-path",
            str(isolated / "trillionnium/Cargo.toml"), "-p", "trnm-mvcc-fee", "--lib", "--no-run",
            "--message-format=json", "--target-dir", str(target)], isolated, output,
            "cargo-original-test-build", stages, timeout=900, environment=environment)
        events = [load_json(line) for line in built_raw.splitlines() if line.startswith(b"{")]
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
        serde_rows,binaries=original_artifacts(artifacts)
        need(len(serde_rows) == 1 and len(binaries) == 1, "Expected one serde artifact and one actual M06 test binary")
        serde_artifact = serde_rows[0]
        need(serde_artifact["package_id"] == serde["package"]["id"]
             and set(serde_artifact.get("features", [])) == {"default", "std"},
             "Actually compiled serde package/features differ from the locked metadata graph")
        compiled_binary = Path(binaries[0]["executable"]).absolute()
        need(compiled_binary == compiled_binary.resolve(strict=True)
             and target.resolve() in compiled_binary.parents, "Cargo reported a binary outside its isolated target")
        binary_identity = file_identity(compiled_binary)
        binary = output / "original-test-binary"
        with compiled_binary.open("rb") as source, binary.open("xb") as destination:
            shutil.copyfileobj(source, destination, length=1 << 20)
        binary.chmod(0o500)
        need(file_identity(binary) == binary_identity and file_identity(compiled_binary) == binary_identity,
             "Original independent binary copy differs")
        write_json(output / "original-binary-before.json", {
            "source": str(compiled_binary), "retained": str(binary), **binary_identity,
            "independent_copy_before_all_tests": True, "mode": stat.S_IMODE(binary.stat().st_mode)})
        fence("compiled-source-and-binary-before")
        listed, _ = run_command([str(binary), "--list"], isolated, output, "list-original-tests",
                                 stages, timeout=30, environment=environment)
        tests = {line.removesuffix(": test") for line in listed.decode().splitlines()
                 if line.endswith(": test")}
        expected = {TEST, *ORIGINAL_TESTS}
        need(expected <= tests, "Actual original tests are not linked: " + repr(sorted(expected - tests)))
        for index, name in enumerate(ORIGINAL_TESTS):
            result, _ = run_command([str(binary), "--exact", name, "--nocapture", "--test-threads=1"],
                isolated, output, "retained-original-" + str(index), stages,
                timeout=240, environment=environment)
            assert_test_executed(result, name)
            retained.append(name)
        actual_environment = dict(environment, TRNM_HIA_EXECUTION_STATE_CORPUS=str(corpus_path))
        actual_raw, _ = run_command([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            isolated, output, "actual-execution-state-corpus", stages,
            timeout=600, environment=actual_environment)
        assert_test_executed(actual_raw, TEST)
        actual = parse_original_rows(actual_raw)
        partial_original = actual
        need(len(actual) == len(admitted["inputs"]) and
             [row.get("name") for row in actual] == [row["name"] for row in admitted["inputs"]],
             "Actual original histories are missing, duplicated or reordered")
        for native, observed in zip(admitted["comparison"]["histories"], actual, strict=True):
            differences=[]
            if not same_json(native["observations"], observed.get("observations")):
                differences.append("complete actual method observations differ")
            original_errors=observed.get("original_errors")
            need(isinstance(original_errors,list) and len(original_errors)==len(native["observations"]),"Original error observation count differs")
            for row,error in zip(observed["observations"],original_errors,strict=True):
                need(error=={0:None,69:"LIMIT",70:"RANGE",71:"NONCANONICAL"}.get(row["status"],"INVALID"),"Original root error mapping differs")
            need(observed.get("safe_test_base_clone") is True and observed.get("native_runtime_host_proxy") is False and isinstance(observed.get("actual_method_calls"),dict),"Original hook scope/calls absent")
            controls.append({"name":native["name"],"status":"FAIL" if differences else "PASS","differences":differences,"native":native,"original":observed})
        write_json(output / "comparison.json", {
            "schema": "trnm.execution-state-original-controls.v1", "controls": controls,
            "original_value_state_view_patch_methods": True,
            "safe_test_only_immutable_base_materialization": True,
            "native_allocator_matches_rust_allocator_claimed": False,
        })
        need(all(row["status"] == "PASS" for row in controls), "Actual original State/View/Patch differential failed")
        status = "PASS"
    except BaseException as error:
        primary_error = repr(error)
        if status != "NOT_RUN":
            status = "FAIL"
    finally:
        try:
            fence("source-and-binary-after")
        except BaseException as error:
            final_errors.append({"stage": "source-and-binary-after", "error": repr(error)})
            status = "FAIL"
        actual_path = output / "actual-execution-state-corpus/stdout.raw"
        if actual_path.is_file() and not partial_original:
            try:
                partial_original = parse_original_rows(actual_path.read_bytes())
            except BaseException as error:
                final_errors.append({"stage": "partial-original-output", "error": repr(error)})
                status = "FAIL"
        if partial_original:
            write_json(output / "original-observations.json", {
                "observed_case_rows": len(partial_original), "cases": partial_original,
                "complete_differential_pass": status == "PASS",
            })
        for stage in stages:
            try:
                directory = output / stage["stage"]
                need(file_identity(directory / "stdout.raw") == stage["stdout"]
                     and file_identity(directory / "stderr.raw") == stage["stderr"],
                     "Actual subprocess log changed after capture")
            except BaseException as error:
                final_errors.append({"stage": stage["stage"], "error": repr(error)})
                status = "FAIL"
        report = dict(base, status=status, primary_error=primary_error, final_errors=final_errors,
                      missing_tools=missing, stages=stages, source_fences=source_fences,
                      compiler=compiler, actual_rust_tools=compiler_tools, original_tests=retained,
                      required_original_tests=list(ORIGINAL_TESTS),
                      original_case_rows_observed=len(partial_original),
                      controls=len(controls), passed=sum(row["status"] == "PASS" for row in controls),
                      failed=sum(row["status"] != "PASS" for row in controls),
                      elapsed_ns=time.monotonic_ns() - started,
                      original_test_binary=None if binary is None else
                          {"path": str(binary), **binary_identity},
                      serde_json_source=serde, serde_json_artifact=serde_artifact)
        if admitted is not None:
            report.update(source_inputs=admitted["source_inputs"],
                original_sources=admitted["original_sources"],
                native_source_set_sha256=admitted["comparison"]["build"]["source_set_sha256"],
                exact_corpus=admitted["comparison"]["corpus"]["raw"],
                native_bundle_artifacts=admitted["bundle_artifacts"],
                original_store=None if original_store is None else identity(original_store),
                original_hook=None if hook is None else identity(hook),
                appended_declaration_hex=DECLARATION.hex())
        write_json(output / "report.json", report)
        print(json.dumps({"status": status, "controls": len(controls),
                          "original_case_rows_observed": len(partial_original),
                          "original_tests": len(retained), "report": str(output / "report.json")}))
    return 0 if status == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
