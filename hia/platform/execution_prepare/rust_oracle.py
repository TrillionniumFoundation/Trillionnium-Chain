"""Strict hosted evidence gate and actual unchanged ordinary M06 prepare oracle.

This module never executes in the native product.  Full source/corpus/process
admission precedes tool discovery, source copying, Cargo and original tests.
"""
from __future__ import annotations
import argparse,ast,hashlib,json,lzma,os,re,shutil,signal,stat,struct,subprocess,sys,time,tomllib
from pathlib import Path
HERE=Path(__file__).absolute().parent
REPOSITORY=HERE.parents[2]
OWNED="hia/platform/execution_prepare"
STORE="trillionnium/crates/trnm-mvcc-fee/src/pon_executor.rs"
HOOK="hia_execution_prepare_oracle.rs"
DECLARATION=b'\n#[cfg(test)]\n#[path = "hia_execution_prepare_oracle.rs"]\nmod hia_execution_prepare_oracle;\n'
TEST="pon_executor::hia_execution_prepare_oracle::evaluate"
ORIGINAL_TESTS=tuple("pon_executor::legacy_preparation_tests::"+name for name in (
 "canonical_wire_hashes_match_original_all_tags_and_variable_payload_boundaries",
 "malformed_wire_never_reaches_borrowed_hashes",
 "actual_preparation_keeps_strict_signatures_error_order_and_attempt_counts"))
OWNED_REQUIRED=frozenset({"README.md","abi.json","build.py","cases.py","linux_emitter.hepta",
 "native_io.py","owner_policy.hepta","source-inputs.json","qualify.py","rust_oracle.py",
 "rust_reference.rs","test_integrity.py"})
SOURCE_SUFFIXES=frozenset({".py",".rs",".json",".hepta",".md"})
EXPLICIT_INPUTS=("hia/platform/build.py","hia/tools/toolchain.py","hia/components.json",
 "hia/tests/native_support.py","hia/toolchain.lock.json","hia/qualification/compiler-binding.json")
CONFIGURATION_INPUTS=frozenset({"config/pon/devnet-v1.json","config/pon/ledger-v1.json",
 "config/pon/model-family-v1.json","config/pon/work-profile-v1.json"})
CANONICAL_ROOTS=("src/node/settings_development.hepta","src/protocol/pnx1.hepta",
 "src/crypto/sha256.hepta","src/crypto/ed25519_verify.hepta")
SKIP_ORIGINAL=frozenset({"target",".git","__pycache__",".pytest_cache"})
COMP_SCHEMA="trnm.native-legacy-preparation-comparison.v1"
BUILD_SCHEMA="trnm.hia.legacy-preparation-owner-build.v1"
NATIVE_SCHEMA="trnm.native-legacy-preparation-qualification.v1"
REPORT_SCHEMA="trnm.hia.original-legacy-preparation-differential.v1"
MAX_U64=(1<<64)-1

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


def complete_source_manifest(repository):
    """Mirror the actual builder's complete closure, without importing its code."""
    need(__debug__, "Optimized Python is not admitted")
    repository = canonical_root(repository)
    captured = {}
    def capture(relative):
        path = canonical_path(repository, relative)
        raw = path.read_bytes()
        need(relative not in captured or captured[relative] == raw,
             "Source changed during closure discovery: " + relative)
        captured[relative] = raw
        return raw

    directory = canonical_path(repository, OWNED, directory=True)
    names = set()
    for path in sorted(directory.iterdir()):
        need(not path.is_symlink(), "Owned symbolic path: " + path.name)
        need(path.name != "__pycache__" and path.suffix != ".pyc", "Stale owned Python cache")
        if path.is_dir():
            # Qualification data may be nested. Executable source is not silently
            # omitted merely because the current builder scans direct children.
            for nested in path.rglob("*"):
                need(not nested.is_symlink(), "Symbolic owned descendant")
                need(nested.name != "__pycache__" and nested.suffix not in
                     {".py", ".pyc", ".rs", ".hepta"}, "Unbound nested owner source/cache")
            continue
        need(path.is_file(), "Nonregular owned source path")
        if path.suffix in SOURCE_SUFFIXES:
            capture(path.relative_to(repository).as_posix())
            names.add(path.name)
    need(OWNED_REQUIRED <= names, "Missing mandatory owner sources: " +
         repr(sorted(OWNED_REQUIRED - names)))
    for relative in EXPLICIT_INPUTS:
        capture(relative)
    pinned = literal_assignment(captured["hia/platform/build.py"], "INPUTS")
    need(isinstance(pinned, (tuple, list)) and pinned
         and all(isinstance(name, str) for name in pinned)
         and len(pinned) == len(set(pinned)), "Malformed pinned platform INPUTS")
    for relative in pinned:
        capture("hia/" + relative)

    declared = load_json(captured[OWNED + "/source-inputs.json"])
    need(isinstance(declared, dict) and set(declared) == {"schema", "files"}
         and declared["schema"] == "trnm.hia.legacy-preparation-default-inputs.v1"
         and isinstance(declared["files"], list)
         and all(isinstance(name, str) for name in declared["files"])
         and len(declared["files"]) == len(set(declared["files"])), "Malformed default configuration declaration")
    need(set(declared["files"]) == CONFIGURATION_INPUTS,
         "Default Settings configuration declaration differs")
    for relative in declared["files"]:
        capture(relative)
    components = load_json(captured["hia/components.json"])
    need(isinstance(components, dict) and set(components) == {"schema", "includes"}
         and components["schema"] == "trnm.hia.component-includes.v1"
         and isinstance(components["includes"], dict), "Malformed component manifest")
    def component_path(name):
        need(isinstance(name, str) and name.startswith(("src/", "platform/", "storage/"))
             and name.endswith(".hepta"), "Invalid HIA dependency path")
        return canonical_path(repository, "hia/" + name)
    for name in components["includes"]:
        component_path(name)
    visited = {}
    def visit(name, ancestors):
        component_path(name)
        need(name not in ancestors, "Cyclic canonical HIA dependency")
        if name in visited:
            return visited[name]
        owned = source_functions(capture("hia/" + name))
        selected = set(owned)
        rows = components["includes"].get(name, [])
        need(isinstance(rows, list), "Component includes are not a list")
        for row in rows:
            need(isinstance(row, dict) and set(row) == {"source", "functions"}
                 and isinstance(row["functions"], list) and row["functions"]
                 and all(isinstance(function, str) and
                         re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", function)
                         for function in row["functions"]), "Malformed explicit HIA dependency")
            available = visit(row["source"], (*ancestors, name))
            for function in row["functions"]:
                need(function in available and function not in selected,
                     "Unknown, re-exported, or duplicate canonical function: " + function)
                selected.add(function)
        visited[name] = owned
        return owned
    for root in CANONICAL_ROOTS:
        visit(root, ())
    for relative, raw in captured.items():
        need(canonical_path(repository, relative).read_bytes() == raw,
             "Source changed during closure discovery: " + relative)
    return {name: identity(raw) for name, raw in sorted(captured.items())}


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
    repository = canonical_root(repository)
    found = {}
    for top in ("trillionnium", "config", "formal"):
        directory = canonical_path(repository, top, directory=True)
        for current, children, files in os.walk(directory, followlinks=False):
            children[:] = sorted(name for name in children if name not in SKIP_ORIGINAL)
            for name in children:
                canonical_path(repository, (Path(current) / name).relative_to(repository).as_posix(),
                               directory=True)
            for name in sorted(files):
                if name in SKIP_ORIGINAL:
                    continue
                relative = (Path(current) / name).relative_to(repository).as_posix()
                found[relative] = file_identity(canonical_path(repository, relative))
    need({"trillionnium/Cargo.lock", "trillionnium/Cargo.toml", STORE} <= set(found),
         "Complete original Cargo/store source is absent")
    for name in original_include_dependencies(repository)["data_includes"]:
        found[name]=file_identity(canonical_path(repository,name))
    return dict(sorted(found.items()))


def validate_source_bindings(repository, comparison):
    need(__debug__, "Optimized Python is not admitted")
    need(isinstance(comparison, dict) and comparison.get("schema") == COMP_SCHEMA
         and comparison.get("status") == "PASS", "Native comparison did not pass")
    built = comparison.get("build")
    need(isinstance(built, dict) and built.get("schema") == BUILD_SCHEMA
         and built.get("status") == "PASS", "Native build did not pass")
    supplied = built.get("source_inputs")
    need(isinstance(supplied, dict) and supplied, "Missing native source bindings")
    for relative, item in supplied.items():
        canonical_path(repository, relative)
        need(valid_identity(item), "Malformed source identity: " + relative)
    actual = complete_source_manifest(repository)
    need(supplied == actual, "Incomplete, extra, or changed native source dependency closure")
    need(built.get("source_set_sha256") == digest(canonical_json(actual)),
         "Native source-set digest differs")
    if "source_inputs" in comparison:
        need(comparison["source_inputs"] == actual, "Top-level source bindings differ")
    for key in ("source_inputs_stable",):
        need(built.get(key) is True, "Build lacks successful source fence: " + key)
    for key in ("runtime_host_proxy", "rust_or_interpreter_fallback", "complete_node",
                "successor_block_admission"):
        need(built.get(key) is False, "Unexpected build scope/runtime claim: " + key)
    return actual


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


def safe_target(value, output, repository, bundle, isolated):
    path = Path(value).absolute() if value else output / "cargo-target"
    need(path == path.resolve(), "Symbolic Cargo target")
    for source in (repository, bundle, isolated):
        need(path != source and source not in path.parents and path not in source.parents,
             "Cargo target overlaps bound input source")
    # An external shared target is permitted only through the caller's serialized
    # ownership. Its previous cached binary is never used as evidence.
    return path



FORBIDDEN_ORIGINAL_OVERRIDES=(
 "LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT",
 "RUSTC","RUSTDOC","RUSTC_WRAPPER","RUSTC_WORKSPACE_WRAPPER","RUSTFLAGS","RUSTDOCFLAGS",
 "CARGO_ENCODED_RUSTFLAGS","CARGO_ENCODED_RUSTDOCFLAGS","RUSTC_BOOTSTRAP","CARGO",
 "CARGO_BUILD_RUSTC","CARGO_BUILD_RUSTDOC","CARGO_BUILD_RUSTC_WRAPPER",
 "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER","CARGO_BUILD_RUSTFLAGS","CARGO_BUILD_RUSTDOCFLAGS",
 "CARGO_BUILD_TARGET","CARGO_BUILD_BUILD_DIR","CARGO_BUILD_TARGET_DIR","CARGO_TARGET_DIR")

def forbidden_original_override(key):
    return key in FORBIDDEN_ORIGINAL_OVERRIDES or key.startswith("CARGO_PROFILE_") or (
        key.startswith("CARGO_TARGET_") and key.endswith(("_RUSTFLAGS","_RUSTDOCFLAGS","_LINKER","_RUNNER")))

def original_environment(environment=None):
    """Reject unbound overrides before source copying, tool discovery or Cargo."""
    source=os.environ if environment is None else environment
    for key,value in source.items():
        need(not value or not forbidden_original_override(key),
             "Unbound original compilation/runtime override: "+key)
    result=dict(source)
    result["PYTHONDONTWRITEBYTECODE"]="1"
    return result

def check_original_toolchain(binding):
    for label in ("compiler_executable","cargo_executable"):
        observed=binding[label]
        path=Path(observed["path"])
        need(path.is_absolute() and path.resolve(strict=True)==path
             and file_identity(path)=={key:observed[key] for key in ("bytes","sha256")},
             "Bound original compiler or Cargo changed: "+label)
    return True

def capture_original_toolchain(output,isolated,stages,environment):
    selected=shutil.which("rustc",path=environment.get("PATH"))
    need(selected,"Original Rust compiler unavailable")
    selected=Path(selected).absolute()
    version,receipt=run_command([str(selected),"-Vv"],isolated,output,"rustc-version",
                                stages,timeout=30,environment=environment)
    need(receipt["stderr"]["bytes"]==0,"Unexpected selected compiler diagnostic")
    sysroot_raw,receipt=run_command([str(selected),"--print","sysroot"],isolated,output,
                                    "rustc-sysroot",stages,timeout=30,environment=environment)
    need(receipt["stderr"]["bytes"]==0,"Unexpected compiler sysroot diagnostic")
    sysroot=Path(sysroot_raw.decode("utf-8").strip()).resolve(strict=True)
    need(sysroot.is_dir(),"Actual selected sysroot is absent")
    compiler=(sysroot/"bin/rustc").resolve(strict=True)
    cargo=(sysroot/"bin/cargo").resolve(strict=True)
    binding={"schema":"trnm.hia.prepare-original-toolchain.v1","sysroot":str(sysroot),
             "selected_rustc":str(selected),"rustc_version":version.decode("utf-8"),
             "compiler_executable":{"path":str(compiler),**file_identity(compiler)},
             "cargo_executable":{"path":str(cargo),**file_identity(cargo)}}
    exact,receipt=run_command([str(compiler),"-Vv"],isolated,output,"rustc-bound-version",
                              stages,timeout=30,environment=environment)
    need(receipt["stderr"]["bytes"]==0 and exact==version,
         "Absolute original compiler differs from selected toolchain")
    check_original_toolchain(binding)
    write_json(output/"original-toolchain-before.json",binding)
    bound=dict(environment)
    bound["RUSTC"]=str(compiler);bound["CARGO"]=str(cargo)
    bound["RUSTC_WRAPPER"]="";bound["RUSTC_WORKSPACE_WRAPPER"]=""
    return binding,bound

def capture_serde_library(cargo_stdout,binding,target,output):
    """Bind the actual Cargo library artifact, excluding custom-build records."""
    rows=[load_json(line) for line in cargo_stdout.splitlines()]
    need(all(type(row) is dict for row in rows),"Malformed Cargo compiler artifact stream")
    candidates=[row for row in rows if row.get("reason")=="compiler-artifact"
      and row.get("target",{}).get("name")=="serde_json"
      and row.get("target",{}).get("kind")==["lib"]]
    need(len(candidates)==1,"Actual serde_json library artifact is not unique")
    artifact=candidates[0]
    need(artifact.get("package_id")==binding["package"]["id"],
         "Actual serde_json library package differs from locked metadata")
    features=artifact.get("features")
    need(type(features) is list and all(type(value) is str for value in features)
         and len(features)==2 and set(features)=={"default","std"},
         "Actual serde_json library features differ")
    crate=canonical_root(binding["crate_directory"])
    source=canonical_path(crate,"src/lib.rs")
    need(artifact["target"].get("src_path")==str(source)
         and file_identity(source)==binding["crate_sources"]["src/lib.rs"],
         "Actual serde_json library source differs from locked registry")
    files=artifact.get("filenames")
    need(type(files) is list and 0<len(files)<=16 and all(type(name) is str for name in files)
         and len(files)==len(set(files)),"Actual serde_json artifact paths are absent or duplicated")
    target=canonical_root(target);captured={}
    for name in files:
        path=Path(name)
        need(path.is_absolute() and target in path.parents,
             "Actual serde_json library escaped Cargo target")
        relative=path.relative_to(target).as_posix()
        canonical_path(target,relative)
        need(path.name not in captured,"Colliding independent serde artifact filename")
        captured[path.name]={"path":str(path),**file_identity(path)}
    directory=output/"serde-library"
    directory.mkdir(mode=0o700)
    for name,entry in captured.items():
        destination=directory/name
        shutil.copyfile(Path(entry["path"]),destination)
        need(file_identity(destination)=={key:entry[key] for key in ("bytes","sha256")},
             "Independent serde library copy differs")
    def check():
        need(file_identity(source)==binding["crate_sources"]["src/lib.rs"],
             "Actual serde library source changed")
        for name,entry in captured.items():
            expected={key:entry[key] for key in ("bytes","sha256")}
            need(file_identity(Path(entry["path"]))==expected and file_identity(directory/name)==expected,
                 "Actual or independent serde library changed: "+name)
        return True
    check()
    result={"compiler_artifact":artifact,"package_id":artifact["package_id"],
            "features":features,"source":str(source),"source_identity":file_identity(source),
            "files":captured,"independent_directory":"serde-library",
            "target_kind_filter":["lib"],"custom_build_is_not_a_library":True}
    write_json(output/"serde-library-before.json",result)
    return result,check


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


def bound_corpus(repository):
    path=canonical_path(repository,OWNED+"/cases.py");source=path.read_bytes()
    tree=ast.parse(source,filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node,ast.Import):
            need(all(a.name in {"hashlib","json","struct"} for a in node.names),"Unbound fixture import")
        elif isinstance(node,ast.ImportFrom):
            need(node.module in {"__future__","functools","pathlib"},"Unbound fixture import")
    namespace={"__file__":str(path),"__name__":"_bound_preparation_inputs"}
    exec(compile(tree,str(path),"exec",dont_inherit=True),namespace)
    raw=namespace["corpus_bytes"]();need(type(raw) is bytes and raw.endswith(b"\n"),"Incomplete canonical corpus")
    rows=[load_json(line) for line in raw.splitlines()]
    need(rows and same_json(rows,list(namespace["cases"]())),"Canonical iteration differs")
    names=set()
    for row in rows:
        need(isinstance(row,dict) and set(row)=={"name","height","wire_hex"},"Input schema")
        need(isinstance(row["name"],str) and re.fullmatch(r"[A-Za-z0-9-]+",row["name"])
             and row["name"] not in names,"Duplicate/invalid input name")
        names.add(row["name"])
        need(type(row["height"]) is int and 0<=row["height"]<=MAX_U64,"Height is not u64")
        raw_wire=bytes.fromhex(row["wire_hex"])
        need(raw_wire.hex()==row["wire_hex"],"Noncanonical wire hex")
    need(path.read_bytes()==source,"Fixture changed")
    return raw,rows

def observation_decoder(repository):
    path=canonical_path(repository,OWNED+"/native_io.py");source=path.read_bytes()
    tree=ast.parse(source);names={"identity","words","magic","frame","parse_context","parse_result","parse_value"}
    selected=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names]
    need(len(selected)==len(names) and {n.name for n in selected}==names,"Observation decoder boundary")
    constants=literal_assignment(source,"NAMES")
    namespace={"json":json,"struct":struct,"hashlib":hashlib,"need":need,"NAMES":constants}
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(path),"exec",dont_inherit=True),namespace)
    need(path.read_bytes()==source,"Observation decoder changed")
    return namespace

def context_projection(context):
    evaluators=context["evaluators_hex"]
    need(isinstance(evaluators,str) and len(evaluators)==192,"Evaluator observation")
    return {name:context[name] for name in ("network_hex","parameters_hex","family_hex","plan_hex","params","model","base_fees")}|{
      "evaluators":[evaluators[i:i+64] for i in range(0,192,64)]}

def case_projection(name,result,value):
    prepared=None
    if value is not None:
        prepared={"sender":value["sender"],"sender_hex":value["sender"],
          "nonce":value["nonce"],"fee_limit":value["fee_limit"],"tag":value["tag"],
          "payload_hex":value["payload_hex"],"encoded_length":result["encoded_length"],
          "transaction_id_hex":value["transaction_id_hex"],"native_pq_none":True,
          "legacy":{"network_hex":value["network_hex"],"sender_hex":value["sender"],
           "nonce":value["nonce"],"expiry":value["expiry"],"fee_limit":value["fee_limit"],
           "tag":value["tag"],"payload_hex":value["payload_hex"],"signature_hex":value["signature_hex"],
           "wire_hex":value["wire_hex"],"signing_digest_hex":value["signing_digest_hex"]}}
    return {"name":name,"error":result["error"],"signature_attempts":result["signature_attempts"],
      "prepared":prepared,"input_unchanged":True}

def read_bounded(path,limit):
    with path.open("rb") as stream:raw=stream.read(limit+1)
    need(len(raw)<=limit,"Artifact exceeds declared bound: "+str(path))
    return raw

def validate_bundle(repository,bundle):
    repository=canonical_root(repository);bundle=canonical_root(bundle)
    expected_files={"native-comparison.json","native-report.json","corpus.jsonl.xz","native.elf","raw/process.json"}|{
      "raw/"+name+".raw" for name in ("stdin","stdout","stderr","progress","replies")}
    found=set()
    for path in bundle.rglob("*"):
        relative=path.relative_to(bundle).as_posix()
        need(not path.is_symlink(),"Symbolic native bundle member")
        if path.is_dir():need(relative=="raw","Unexpected artifact directory")
        else:
            canonical_path(bundle,relative)
            found.add(relative)
    need(found==expected_files,"Incomplete or extra native bundle members")
    comparison_raw=read_bounded(canonical_path(bundle,"native-comparison.json"),64<<20)
    comparison=load_json(comparison_raw)
    sources=validate_source_bindings(repository,comparison)
    original=original_manifest(repository)
    need(comparison["build"].get("original_sources")==original,"Complete original source map differs")
    corpus,inputs=bound_corpus(repository)
    corpus_raw=bounded_xz(canonical_path(bundle,"corpus.jsonl.xz"),corpus)
    report_raw=read_bounded(canonical_path(bundle,"native-report.json"),8<<20);report=load_json(report_raw)
    need(isinstance(report,dict) and report.get("schema")==NATIVE_SCHEMA and report.get("status")=="PASS"
         and report.get("suite")=="semantic","Native semantic qualifier did not pass")
    need(type(report.get("native_cases")) is int and report["native_cases"]==len(inputs)
         and type(report.get("native_processes")) is int and report["native_processes"]==1,"Native semantic counts")
    need(report.get("source_set_sha256")==comparison["build"]["source_set_sha256"]
         and report.get("comparison")==identity(comparison_raw),"Actual native report binding")
    verification={"source_after":{"status":"PASS","source_set_sha256":comparison["build"]["source_set_sha256"],
      "native_source_files":len(sources),"original_source_files":len(original)},"primary_error":None,"cleanup_errors":[]}
    need(same_json(report.get("verification"),verification),"Successful qualifier source/cleanup fence absent")
    need(report.get("corpus")=={"raw":identity(corpus_raw),"compressed":file_identity(bundle/"corpus.jsonl.xz")},
         "Exact corpus identity")
    native=read_bounded(canonical_path(bundle,"native.elf"),8<<20)
    built=comparison["build"]["executable"]
    need(identity(native)=={k:built[k] for k in ("bytes","sha256")} and native[:4]==b"\x7fELF",
         "Native executable identity")
    process_raw=read_bounded(canonical_path(bundle,"raw/process.json"),4<<20);process=load_json(process_raw)
    need(comparison.get("process")==identity(process_raw) and report.get("process")==identity(process_raw),
         "Actual process receipt binding")
    need(type(process.get("exit_code")) is int and process["exit_code"]==0 and process.get("cleanup_errors")==[],
         "Native process did not exit successfully")
    need(process.get("executable")==identity(native),"Executed image differs")
    streams={}
    byte_bound=len(corpus)*3+(1<<20)
    for name in ("stdin","stdout","stderr","progress","replies"):
        streams[name]=read_bounded(canonical_path(bundle,"raw/"+name+".raw"),byte_bound)
        need(process.get(name)==identity(streams[name]),"Actual stream identity: "+name)
    need(process.get("events")==[] and streams["stderr"]==streams["progress"]==streams["replies"]==b"",
         "Unexpected semantic process diagnostics/callback stream")
    need(type(process.get("stdin_written_bytes")) is int and process["stdin_written_bytes"]==len(streams["stdin"]),
         "Actual stdin write extent")
    decoder=observation_decoder(repository);stdout=streams["stdout"]
    need(len(stdout)>=64,"Missing opened context")
    context_size=struct.unpack_from("<Q",stdout,16)[0]
    need(576<=context_size<=16384,"Context extent before decode")
    context=decoder["parse_context"](stdout[:64+context_size])
    need(same_json(context,comparison.get("context")),"Native context summary differs")
    position=64+context_size;seq=0;attempts=0
    expected_input=bytearray(struct.pack("<8Q",int.from_bytes(b"MPBOOT01","little"),0,MAX_U64,MAX_U64,0,0,0,0))
    native_rows=comparison.get("cases")
    need(isinstance(native_rows,list) and len(native_rows)==len(inputs),"Native case count")
    for request,observed in zip(inputs,native_rows):
        need(isinstance(observed,dict) and set(observed)=={"name","result","value","observation"}
             and observed["name"]==request["name"],"Native case order/schema")
        raw=bytes.fromhex(request["wire_hex"]);seq+=1
        expected_input.extend(decoder["frame"](1,seq,height=request["height"],body_len=len(raw))+raw)
        result=decoder["parse_result"](stdout[position:position+96]);position+=96
        need(result["sequence"]==seq and result["height"]==request["height"] and result["encoded_length"]==len(raw),
             "Native operation/input binding")
        need(same_json(result,observed["result"]),"Result summary differs from actual stdout")
        attempts+=result["signature_attempts"];value=None
        if result["code"]==0:
            need(len(stdout)>=position+64,"Private value header absent")
            size=struct.unpack_from("<Q",stdout,position+8)[0]
            need(287<=size<=2176,"Private value extent")
            value=decoder["parse_value"](stdout[position:position+size],result);position+=size
            need(value["wire_hex"]==request["wire_hex"],"Native private wire differs")
            seq+=1
            expected_input.extend(decoder["frame"](2,seq,generation=result["generation"]))
        need(same_json(value,observed["value"]),"Private value summary differs")
        need(same_json(case_projection(request["name"],result,value),observed["observation"]),
             "Native semantic projection differs from actual process")
    seq+=1;expected_input.extend(decoder["frame"](4,seq))
    expected_close=struct.pack("<4Q",int.from_bytes(b"MPCLOSED","little"),seq,attempts,0)
    need(stdout[position:]==expected_close,"Native close/attempts or trailing stdout differs")
    need(streams["stdin"]==bytes(expected_input),"Full actual stdin differs from canonical operations")
    return comparison,corpus,inputs,sources,original,report

def collect_original(raw,names):
    context=[];rows=[];completed=[]
    for line in raw.decode().splitlines():
        for marker,output in (("HIA_PREPARE_CONTEXT:",context),("HIA_PREPARE_CASE:",rows),("HIA_PREPARE_COMPLETE:",completed)):
            if marker in line:
                need(line.count(marker)==1,"Duplicate original marker")
                output.append(load_json(line.split(marker,1)[1]))
    need(len(context)==len(completed)==1 and type(completed[0]) is int and completed[0]==len(names),
         "Original corpus did not finish")
    need([r.get("name") for r in rows]==names,"Original case order/count differs")
    return context[0],rows

def main():
    need(__debug__ and not os.environ.get("PYTHONOPTIMIZE"),"Optimized Python is not admitted")
    parser=argparse.ArgumentParser()
    parser.add_argument("--bundle",type=Path,required=True);parser.add_argument("--output",type=Path)
    parser.add_argument("--cargo-target",type=Path);parser.add_argument("--check-bundle",action="store_true")
    args=parser.parse_args()
    environment=original_environment()
    repository=canonical_root(REPOSITORY);bundle=canonical_root(args.bundle)
    if not args.check_bundle:
        need(args.output is not None,"Original output is required")
        output=args.output.absolute()
        need(output.parent.resolve(strict=True)==output.parent and not output.exists(),"Output must be fresh and canonical")
        need(repository not in output.parents and bundle not in output.parents,"Output overlaps bound input")
        target=safe_target(args.cargo_target,output,repository,bundle,output/"isolated")
    admitted=validate_bundle(repository,bundle)
    comparison,corpus,inputs,sources,original,native_report=admitted
    if args.check_bundle:
        print(json.dumps({"status":"PASS","source_set_sha256":comparison["build"]["source_set_sha256"],
              "native_cases":len(inputs),"native_processes":1,"cargo_started":False,"native_started":False}));return
    need(args.output is not None,"Original output is required")
    output=args.output.absolute()
    need(output.parent.resolve(strict=True)==output.parent and not output.exists(),"Output must be fresh and canonical")
    need(repository not in output.parents and bundle not in output.parents,"Output overlaps bound input")
    output.mkdir(mode=0o700)
    isolated=output/"isolated";stages=[];primary=None;cleanup=[];source_after={};context=None;rows=[];differences=[]
    binary_identity=None;binary_copy=None;serde=None;serde_fence=None;isolated_expected=None
    toolchain=None;serde_artifact=None;serde_artifact_fence=None
    bundle_files={p.relative_to(bundle).as_posix():file_identity(p) for p in bundle.rglob("*") if p.is_file()}
    start=time.monotonic_ns()
    try:
        need(complete_source_manifest(repository)==sources and original_manifest(repository)==original,"Pre-copy source changed")
        isolated.mkdir(mode=0o700)
        for name in ("trillionnium","config","formal"):
            shutil.copytree(repository/name,isolated/name,symlinks=False,
              ignore=shutil.ignore_patterns("target",".git","__pycache__",".pytest_cache"))
        for name in original:
            if Path(name).parts[0] in ("trillionnium","config","formal"):continue
            source=canonical_path(repository,name);destination=isolated/name
            destination.parent.mkdir(parents=True,exist_ok=True)
            with destination.open("xb") as stream:stream.write(source.read_bytes())
        need(original_manifest(isolated)==original,"Isolated original copy differs")
        store=canonical_path(isolated,STORE);before=store.read_bytes()
        need(b"mod hia_execution_prepare_oracle" not in before,"Original observer already appended")
        hook=canonical_path(repository,OWNED+"/rust_reference.rs").read_bytes()
        with store.open("ab") as stream:stream.write(DECLARATION)
        (store.parent/HOOK).write_bytes(hook)
        isolated_expected=dict(original)
        isolated_expected[STORE]=identity(before+DECLARATION)
        isolated_expected[(Path(STORE).parent/HOOK).as_posix()]=identity(hook)
        need(original_manifest(isolated)==dict(sorted(isolated_expected.items())),"Unexpected original adaptation")
        (output/"corpus.jsonl").write_bytes(corpus)
        toolchain,environment=capture_original_toolchain(output,isolated,stages,environment)
        environment["CARGO_TARGET_DIR"]=str(target);environment["CARGO_BUILD_JOBS"]="2"
        environment["HIA_PREPARE_CORPUS"]=str(output/"corpus.jsonl")
        cargo=toolchain["cargo_executable"]["path"]
        check_original_toolchain(toolchain)
        metadata_raw,_=run_command([cargo,"metadata","--locked","--format-version","1","--manifest-path",str(isolated/"trillionnium/Cargo.toml")],
          isolated,output,"cargo-metadata",stages,timeout=120,environment=environment)
        metadata=load_json(metadata_raw)
        serde,serde_fence=capture_serde_graph(metadata,isolated,output)
        raw,_=run_command([cargo,"test","--locked","--manifest-path",str(isolated/"trillionnium/Cargo.toml"),
          "-p","trnm-mvcc-fee","--lib","--no-run","--message-format=json"],isolated,output,
          "cargo-original-test-build",stages,timeout=900,environment=environment)
        serde_artifact,serde_artifact_fence=capture_serde_library(raw,serde,target,output)
        check_original_toolchain(toolchain)
        candidates=[]
        for line in raw.splitlines():
            item=load_json(line)
            if item.get("reason")=="compiler-artifact" and item.get("target",{}).get("name")=="trnm_mvcc_fee" and item.get("profile",{}).get("test") is True and item.get("executable"):
                candidates.append(Path(item["executable"]))
        need(len(candidates)==1,"Actual original test binary is not unique")
        binary=candidates[0].absolute()
        need(target.resolve()==target and target in binary.parents and binary.resolve()==binary and binary.is_file(),"Original binary path")
        binary_identity=file_identity(binary)
        binary_copy=output/"original-m06-tests"
        shutil.copyfile(binary,binary_copy);binary_copy.chmod(0o700)
        need(file_identity(binary_copy)==binary_identity,"Independent original binary differs")
        listing,_=run_command([str(binary_copy),"--list"],isolated,output,"list-original-tests",stages,timeout=30,environment=environment)
        names={line.rsplit(b": ",1)[0].decode() for line in listing.splitlines() if line.endswith(b": test")}
        need({TEST,*ORIGINAL_TESTS}<=names,"Actual retained/oracle test discovery incomplete")
        for index,name in enumerate(ORIGINAL_TESTS):
            data,_=run_command([str(binary_copy),name,"--exact","--nocapture","--test-threads=1"],isolated,output,
              "retained-"+str(index),stages,timeout=240,environment=environment)
            assert_test_executed(data,name)
        data,_=run_command([str(binary_copy),TEST,"--exact","--nocapture","--test-threads=1"],isolated,output,
          "actual-private-prepare-corpus",stages,timeout=240,environment=environment)
        assert_test_executed(data,TEST)
        context,rows=collect_original(data,[r["name"] for r in inputs])
        projected=context_projection(comparison["context"])
        need(same_json(projected,{key:context[key] for key in projected}),"Actual installed Config differs")
        need(context.get("task_profile")=="legacy-task-v1" and context.get("task_windows_none") is True
          and context.get("native_pq_none") is True and context.get("is_pq_account_profile") is False
          and context.get("account_profile_error") is None and context.get("funded_config_error") is None,
          "Actual original default constructor scope differs")
        for native,actual in zip(comparison["cases"],rows):
            if not same_json(native["observation"],actual):differences.append({"name":native["name"],"native":native["observation"],"original":actual})
        need(not differences,"Actual private prepare differential mismatch")
    except BaseException as error:
        import traceback
        primary={"type":type(error).__name__,"message":str(error),"traceback":traceback.format_exc()}
    finally:
        for label,check in (
          ("native_sources",lambda:complete_source_manifest(repository)==sources),
          ("original_sources",lambda:original_manifest(repository)==original),
          ("native_bundle",lambda:{p.relative_to(bundle).as_posix():file_identity(p) for p in bundle.rglob("*") if p.is_file()}==bundle_files),
          ("isolated_original",lambda:isolated_expected is None or original_manifest(isolated)==dict(sorted(isolated_expected.items()))),
          ("locked_serde_sources",lambda:serde_fence is None or serde_fence()==serde["crate_sources"]),
          ("compiler_tools",lambda:toolchain is None or check_original_toolchain(toolchain)),
          ("serde_library_artifacts",lambda:serde_artifact_fence is None or serde_artifact_fence()),
          ("actual_binary",lambda:binary_identity is None or file_identity(binary_copy)==binary_identity)):
            try:
                need(check(),"Source/artifact changed: "+label);source_after[label]={"status":"PASS"}
            except BaseException as error:source_after[label]={"status":"FAIL","error":repr(error)}
        status="PASS" if primary is None and not cleanup and all(v["status"]=="PASS" for v in source_after.values()) else "FAIL"
        report={"schema":REPORT_SCHEMA,"status":status,"source_set_sha256":comparison["build"]["source_set_sha256"],
          "source_inputs":sources,"original_sources":original,"native_cases":len(inputs),"actual_original_cases":len(rows),
          "retained_tests":list(ORIGINAL_TESTS),"stages":stages,"context":context,"original_cases":rows,
          "differences":differences,"actual_binary":binary_identity,"independent_binary":str(binary_copy) if binary_copy else None,
          "serde_json":serde,"serde_json_artifact":serde_artifact,"original_toolchain":toolchain,
          "source_after":source_after,"primary_error":primary,"cleanup_errors":cleanup,
          "wall_ns":time.monotonic_ns()-start,"whole_node_qualified":False,"durable_admission_qualified":False}
        write_json(output/"report.json",report)
        print(json.dumps({"status":status,"actual_original_cases":len(rows),"retained_stages":sum(s["stage"].startswith("retained-") and s["status"]=="PASS" for s in stages),
          "differences":len(differences),"primary_error":primary,"source_after":source_after,"wall_ns":report["wall_ns"]}))
        if status!="PASS":raise SystemExit(1)
if __name__=="__main__":main()
