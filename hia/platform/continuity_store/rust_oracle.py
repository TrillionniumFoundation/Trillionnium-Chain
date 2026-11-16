"""Execute actual original Node calls from a source-bound native corpus bundle."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import re
import stat
import json
import lzma
import os
from pathlib import Path
import shutil
import sys

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[2]
STORE = "trillionnium/crates/trnm-pon-node/src/store.rs"
HOOK = "hia_continuity_staging_oracle.rs"
DECLARATION = b'\n#[cfg(test)]\n#[path = "hia_continuity_staging_oracle.rs"]\nmod hia_continuity_staging_oracle;\n'
TEST = "store::hia_continuity_staging_oracle::evaluate"
MARKER = "HIA_CONTINUITY_STAGE_ORACLE:"
ORIGINAL_TESTS = (
    "store::bounded_active_state_tests::live_state_cell_extent_and_type_refuse_before_root_and_keep_exact_repair",
    "store::bounded_active_state_tests::live_state_reads_exact_wire_edges_without_normalizing_sql_types",
    "store::bounded_active_state_tests::live_state_count_bound_and_cancellation_return_no_partial_state",
    "store::continuity_tests::recovery_rejects_missing_genesis_maintenance_even_with_recomputed_state_root",
)

# This discovery mirrors the builder's input boundary without importing Hepta
# or constructing a native compiler. Core admission remains the builder's job.
TYPED_SOURCE_NAMES = frozenset({
    "README.md", "abi.json", "build.py", "capacity.py", "cases.py", "includes.json",
    "linux_stage_emitter.hepta", "native_io.py", "qualify.py", "root_finalize.hepta",
    "rust_oracle.py", "rust_reference.rs", "stage_policy.hepta",
})
OWNED_SOURCE_NAMES = frozenset({
    "README.md", "abi.json", "build.py", "capacity.py", "cases.py", "context.hepta", "context_qualification.py",
    "continuity_policy.hepta", "includes.json", "linux_continuity_emitter.hepta", "native_io.py",
    "primary_policy.hepta", "qualify.py", "reference.py", "rust_oracle.py", "rust_reference.rs",
    "source-inputs.json", "test_integrity.py",
})
OWNED_SOURCE_SUFFIXES = frozenset({".py", ".rs", ".json", ".md", ".hepta"})
EXPLICIT_SOURCE_INPUTS = (
    "platform/build.py", "tools/toolchain.py", "components.json",
    "platform/transport_request/rust_oracle.py", "tests/test_state_root.py",
    "tests/native_support.py", "toolchain.lock.json", "qualification/compiler-binding.json",
)


def require(value, message):
    if not value:
        raise ValueError(message)


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "Duplicate qualification/manifest key: " + str(key))
        value[key] = item
    return value


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical_json_hash(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def canonical_path(root, relative, *, directory=False):
    require(isinstance(relative, str) and relative and "\\" not in relative and "\0" not in relative,
            "Noncanonical source path")
    name = Path(relative)
    require(not name.is_absolute() and ".." not in name.parts and name.as_posix() == relative,
            "Escaping or noncanonical source path: " + relative)
    require(root.is_absolute() and root.resolve(strict=True) == root and not root.is_symlink(),
            "Noncanonical source root")
    current = root
    for component in name.parts:
        current = current / component
        require(not current.is_symlink(), "Symlinked source path: " + relative)
    metadata = current.stat()
    require(stat.S_ISDIR(metadata.st_mode) if directory else stat.S_ISREG(metadata.st_mode),
            "Source is not the required regular file/directory: " + relative)
    require(current.resolve(strict=True) == current, "Symbolic source ancestor: " + relative)
    return current


def bytes_identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw)}


def valid_identity(value):
    return (isinstance(value, dict) and set(value) == {"bytes", "sha256"}
        and type(value["bytes"]) is int and value["bytes"] >= 0
        and isinstance(value["sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is not None)


def owned_functions(raw):
    names = re.findall(rb"(?m)^fn ([A-Za-z_][A-Za-z_0-9]*)\(", raw)
    matches = list(re.finditer(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)", raw))
    found = {match.group(1).decode(): match.group(0) for match in matches}
    require(len(names) == len(set(names)) == len(found)
            and {name.decode() for name in names} == set(found), "Ambiguous HIA function boundaries")
    return found


def complete_source_manifest(repository):
    """The complete current builder closure, without Hepta or Cargo execution."""
    require(__debug__, "Source binding validation refuses optimized Python")
    repository = Path(repository).absolute()
    hia = canonical_path(repository, "hia", directory=True)
    captured = {}
    def capture(relative):
        path = canonical_path(repository, relative)
        raw = path.read_bytes()
        require(relative not in captured or captured[relative] == raw,
                "Source changed during closure discovery: " + relative)
        captured[relative] = raw
        return raw
    for directory, required in (("typed_store", TYPED_SOURCE_NAMES),
                                ("continuity_store", OWNED_SOURCE_NAMES)):
        owned = canonical_path(repository, "hia/platform/" + directory, directory=True)
        observed = set()
        for path in sorted(owned.iterdir()):
            if path.suffix in OWNED_SOURCE_SUFFIXES:
                capture(path.relative_to(repository).as_posix())
                observed.add(path.name)
        require(required <= observed, "A mandatory native owner source is absent: " + directory)
    for relative in EXPLICIT_SOURCE_INPUTS:
        capture("hia/" + relative)
    installed = json.loads(captured["hia/platform/continuity_store/source-inputs.json"], object_pairs_hook=unique_keys)
    require(isinstance(installed, dict) and set(installed) == {"schema", "files"}
        and installed["schema"] == "trnm.hia.continuity-installed-inputs.v1"
        and isinstance(installed["files"], list) and len(installed["files"]) == 8
        and len(set(installed["files"])) == 8, "Malformed installed input declaration")
    for name in installed["files"]:
        require(isinstance(name, str) and name.startswith("config/pon/"), "Invalid installed input")
        capture(name)
    components = json.loads(captured["hia/components.json"], object_pairs_hook=unique_keys)
    require(isinstance(components, dict) and set(components) == {"schema", "includes"}
        and components["schema"] == "trnm.hia.component-includes.v1"
        and isinstance(components["includes"], dict), "Malformed canonical component manifest")
    private = {}
    for directory, schema, mandatory in (
            ("typed_store", "trnm.hia.typed-stage-includes.v1", {"stage_policy.hepta", "root_finalize.hepta"}),
            ("continuity_store", "trnm.hia.continuity-store-includes.v1",
             {"primary_policy.hepta", "continuity_policy.hepta", "context.hepta"})):
        document = json.loads(captured["hia/platform/" + directory + "/includes.json"], object_pairs_hook=unique_keys)
        require(isinstance(document, dict) and set(document) == {"schema", "includes"}
            and document["schema"] == schema and isinstance(document["includes"], dict)
            and set(document["includes"]) == mandatory, "Malformed private kernel roots")
        for name, rows in document["includes"].items():
            private["platform/" + directory + "/" + name] = rows
    def component_path(name):
        require(isinstance(name, str) and name.startswith(("src/", "platform/", "storage/"))
            and Path(name).suffix == ".hepta", "Noncanonical component dependency")
        return canonical_path(hia, name)
    for name in components["includes"]:
        component_path(name)
    def rows(value):
        require(isinstance(value, list), "HIA includes must be an explicit list")
        for row in value:
            require(isinstance(row, dict) and set(row) == {"source", "functions"}
                and isinstance(row["functions"], list) and row["functions"]
                and all(isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name)
                    for name in row["functions"]), "Malformed explicit HIA dependency")
            yield row
    admitted = {}
    def component(name, ancestry):
        component_path(name)
        require(name not in ancestry, "Cyclic HIA dependency closure")
        if name in admitted:
            return admitted[name]
        require(name.startswith("src/") or name in private, "Undeclared private component")
        own = owned_functions(capture("hia/" + name))
        selected = set(own)
        dependencies = private[name] if name in private else components["includes"].get(name, [])
        for row in rows(dependencies):
            available = component(row["source"], (*ancestry, name))
            for function in row["functions"]:
                require(function in available and function not in selected,
                    "Unknown, re-exported or duplicate HIA callee: " + function)
                selected.add(function)
        admitted[name] = own
        return own
    for name in ("platform/continuity_store/primary_policy.hepta", "platform/typed_store/root_finalize.hepta",
                 "platform/continuity_store/continuity_policy.hepta", "platform/continuity_store/context.hepta"):
        component(name, ())
    for name, raw in captured.items():
        require(canonical_path(repository, name).read_bytes() == raw, "Source changed during closure discovery")
    return {name: bytes_identity(raw) for name, raw in sorted(captured.items())}


def validate_source_bindings(repository, comparison):
    require(__debug__, "Source binding validation refuses optimized Python")
    require(isinstance(comparison, dict) and comparison.get("schema") == "trnm.hia.native-continuity-staging-comparison.v1"
            and comparison.get("status") == "PASS", "Native comparison did not pass")
    built = comparison.get("build")
    require(isinstance(built, dict) and built.get("schema") == "trnm.hia.continuity-staging-build.v1"
            and built.get("status") == "PASS", "Native build did not pass")
    supplied = built.get("source_inputs")
    require(isinstance(supplied, dict) and supplied, "Missing native source bindings")
    for relative, value in supplied.items():
        canonical_path(Path(repository).absolute(), relative)
        require(valid_identity(value), "Malformed source identity: " + relative)
    expected = complete_source_manifest(repository)
    require(set(supplied) == set(expected), "Incomplete or extra native source dependency closure")
    require(supplied == expected, "Native-bound source bytes differ")
    require(built.get("source_set_sha256") == canonical_json_hash(expected), "Native source-set digest differs")
    return expected


def canonical_corpus(repository):
    """Execute the complete bound input generator and its bound local imports."""
    repository = Path(repository).absolute()
    modules = (
        ("hia.tests.native_support", "hia/tests/native_support.py"),
        ("hia.tests.test_state_root", "hia/tests/test_state_root.py"),
        ("hia.platform.typed_store.cases", "hia/platform/typed_store/cases.py"),
        ("hia.platform.continuity_store.reference", "hia/platform/continuity_store/reference.py"),
        ("_trnm_bound_continuity_input_cases", "hia/platform/continuity_store/cases.py"),
    )
    previous = {}
    try:
        for name, relative in modules:
            path = canonical_path(repository, relative)
            previous[name] = sys.modules.get(name)
            spec = importlib.util.spec_from_file_location(name, path)
            require(spec is not None and spec.loader is not None, "Missing bound module loader")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            exec(compile(path.read_bytes(), str(path), "exec", dont_inherit=True), module.__dict__)
        cases = __import__("itertools").chain(module.cases(), module.capacity_cases())
        return b"".join((json.dumps(case.corpus(), separators=(",", ":")) + "\n").encode() for case in cases)
    finally:
        for name, value in previous.items():
            if value is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = value


def validate_corpus(repository, bundle, comparison):
    require(__debug__, "Corpus binding validation refuses optimized Python")
    expected = canonical_corpus(repository)
    require(valid_identity(comparison.get("corpus")) and comparison["corpus"] == bytes_identity(expected),
            "Native corpus identity differs from the complete source-defined input corpus")
    names = [json.loads(line)["name"] for line in expected.splitlines()]
    native_cases = comparison.get("cases")
    require(isinstance(native_cases, list) and all(isinstance(row, dict) for row in native_cases)
            and len(names) == len(set(names)) and [row.get("name") for row in native_cases] == names,
            "Native corpus cases are missing, reordered, extra or duplicated")
    raw_path = bundle / "corpus.jsonl"
    if raw_path.exists() or raw_path.is_symlink():
        source = canonical_path(bundle, "corpus.jsonl")
        with source.open("rb") as stream:
            actual = stream.read(len(expected) + 1)
        require(actual == expected, "Actual corpus bytes differ from source-defined inputs")
        return actual
    source = canonical_path(bundle, "corpus.jsonl.xz")
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
    remaining, blocks = len(expected), []
    with source.open("rb") as compressed:
        while not decoder.eof:
            block = compressed.read(65536) if decoder.needs_input else b""
            require(block or not decoder.needs_input, "Truncated native corpus archive")
            decoded = decoder.decompress(block, max_length=min(1 << 20, remaining + 1))
            require(len(decoded) <= remaining, "Native corpus archive exceeds its source-defined extent")
            blocks.append(decoded)
            remaining -= len(decoded)
        require(remaining == 0 and not decoder.unused_data and compressed.read(1) == b"",
                "Truncated or trailing native corpus archive")
    actual = b"".join(blocks)
    require(actual == expected, "Actual archived corpus differs from source-defined inputs")
    return actual


def validate_bundle(repository, bundle):
    """Validate before tool discovery, source copying or Cargo execution."""
    require(__debug__, "Bundle binding validation refuses optimized Python")
    bundle = Path(bundle).absolute()
    captured = canonical_path(bundle, "native-comparison.json").read_bytes()
    comparison = json.loads(captured, object_pairs_hook=unique_keys)
    sources = validate_source_bindings(repository, comparison)
    corpus = validate_corpus(repository, bundle, comparison)
    return comparison, captured, sources, corpus


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    if not __debug__:
        raise RuntimeError("Optimized Python is not admitted by this verifier")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=REPOSITORY)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path)
    args = parser.parse_args()
    repository = args.repository.resolve(strict=True)
    require(repository == REPOSITORY, "Run the exact continuity Store oracle from the selected repository")
    sys.path.insert(0, str(repository))
    output = args.output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError("Use a fresh oracle output directory")
    output.mkdir(mode=0o700, parents=True)
    base = {"schema": "trnm.hia.original-continuity-staging-differential.v1",
        "production_runtime_dependency": False, "whole_node_qualified": False,
        "sql_materialization_error_order_qualified": False,
        "full_serde_error_text_or_source_chain_parity": False}
    stages = []
    try:
        bundle = args.bundle.absolute()
        comparison, captured_comparison, source_inputs, corpus_raw = validate_bundle(repository, bundle)
        from hia.platform.build import sha256
        from hia.platform.typed_store.build import file_identity, original_manifest
        from hia.platform.transport_request.rust_oracle import command
        native = comparison["cases"]
        original = original_manifest(repository)
        for relative in original:
            canonical_path(repository, relative)
        if original != comparison["build"]["original_sources"]:
            raise ValueError("Original source differs from the source used by native qualification")
        hook = (repository / "hia/platform/continuity_store/rust_reference.rs").read_bytes()
        if source_inputs["hia/platform/continuity_store/rust_reference.rs"]["sha256"] != sha256(hook):
            raise ValueError("Original hook differs from the native source binding")
        missing = [name for name in ("cargo", "rustc") if shutil.which(name) is None]
        if missing:
            write_json(output / "report.json", dict(base, status="NOT_RUN", missing_tools=missing))
            return 1
        corpus = output / "corpus.jsonl"
        corpus.write_bytes(corpus_raw)
        del corpus_raw
        if file_identity(corpus) != comparison["corpus"]:
            raise ValueError("The exact native corpus bytes differ")
        isolated = output / "isolated-source"
        isolated.mkdir(mode=0o700)
        for relative in original:
            destination = isolated / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(repository / relative, destination)
        store = isolated / STORE
        original_store = store.read_bytes()
        if b"mod hia_continuity_staging_oracle" in original_store:
            raise ValueError("Original store already declares this oracle")
        hook_path = store.parent / HOOK
        if hook_path.exists():
            raise FileExistsError("Refusing to replace an original source")
        hook_path.write_bytes(hook)
        store.write_bytes(original_store + DECLARATION)
        def check_sources(binary=None, binary_hash=None):
            if canonical_path(bundle, "native-comparison.json").read_bytes() != captured_comparison:
                raise ValueError("Native comparison changed during original execution")
            if original_manifest(repository) != original:
                raise ValueError("Original source changed during execution")
            for relative, identity in original.items():
                path = isolated / relative
                if relative == STORE:
                    if path.read_bytes() != original_store + DECLARATION:
                        raise ValueError("Original store implementation was changed")
                elif file_identity(path) != identity:
                    raise ValueError("Isolated original source was changed: " + relative)
            if validate_source_bindings(repository, comparison) != source_inputs:
                raise ValueError("Complete native dependency closure changed")
            if hook_path.read_bytes() != hook or file_identity(corpus) != comparison["corpus"]:
                raise ValueError("Original hook or exact corpus changed")
            if binary is not None and file_identity(binary)["sha256"] != binary_hash:
                raise ValueError("Original executable changed")
        check_sources()
        version, row = command(["rustc", "-Vv"], isolated, output, "rustc-version", timeout=10)
        stages.append(row)
        target = args.target_dir.resolve() if args.target_dir else output / "cargo-target"
        if target == repository or repository in target.parents or target == isolated:
            raise ValueError("Cargo target must be outside the bound source repository")
        argv = ["cargo", "test", "--locked", "--manifest-path", str(isolated / "trillionnium/Cargo.toml"),
            "-p", "trnm-pon-node", "--lib", "--no-run", "--message-format=json", "--target-dir", str(target)]
        raw, row = command(argv, isolated, output, "cargo-original-test-build", timeout=900)
        stages.append(row)
        events = [json.loads(line) for line in raw.splitlines() if line.startswith(b"{")]
        artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
        serde = [event for event in artifacts if event["target"]["name"] == "serde_json"]
        binaries = [event for event in artifacts if event["target"]["name"] == "trnm_pon_node"
            and event.get("executable") and event["profile"].get("test")]
        if len(serde) != 1 or len(binaries) != 1:
            raise ValueError("Expected one actual serde artifact and one original Node test binary")
        if (not str(serde[0]["package_id"]).endswith("serde_json@1.0.149")
                or set(serde[0]["features"]) != {"default", "std"}):
            raise ValueError("The locked original serde feature profile changed")
        binary = Path(binaries[0]["executable"])
        binary_hash = file_identity(binary)["sha256"]
        check_sources(binary, binary_hash)
        listed, row = command([str(binary), "--list"], isolated, output, "list-original-tests", timeout=20)
        stages.append(row)
        tests = {line.removesuffix(": test") for line in listed.decode().splitlines() if line.endswith(": test")}
        if not set((TEST,) + ORIGINAL_TESTS) <= tests:
            raise ValueError("Required actual original tests are not linked: " +
                repr(set((TEST,) + ORIGINAL_TESTS) - tests))
        retained = []
        for index, name in enumerate(ORIGINAL_TESTS):
            _, row = command([str(binary), "--exact", name, "--nocapture", "--test-threads=1"],
                isolated, output, "retained-state-" + str(index), timeout=240)
            stages.append(row)
            retained.append(name)
        environment = dict(os.environ, TRNM_HIA_CONTINUITY_STAGE_CORPUS=str(corpus))
        raw, row = command([str(binary), "--exact", TEST, "--nocapture", "--test-threads=1"],
            isolated, output, "actual-apply-slot-root-corpus", env=environment, timeout=600)
        stages.append(row)
        check_sources(binary, binary_hash)
        actual = [json.loads(line.split(MARKER, 1)[1]) for line in raw.decode().splitlines() if MARKER in line]
        if [row["name"] for row in actual] != [row["name"] for row in native]:
            raise ValueError("Actual original oracle returned missing, reordered or extra cases")
        contexts = [json.loads(line.split("HIA_CONTINUITY_CONTEXT:", 1)[1])
            for line in raw.decode().splitlines() if "HIA_CONTINUITY_CONTEXT:" in line]
        if (not isinstance(comparison.get("contexts"), list) or len(contexts) != 4
                or [row.get("variant") for row in contexts] != list(range(4))
                or contexts != comparison["contexts"]):
            write_json(output / "context-comparison.json", {"native": comparison.get("contexts"), "original": contexts})
            raise ValueError("Actual original installed constructor snapshots differ")
        write_json(output / "context-comparison.json", {"status": "PASS", "native": comparison["contexts"], "original": contexts})
        controls = []
        for expected, observed in zip(native, actual, strict=True):
            same = all(expected[key] == observed[key] for key in
                ("name", "code", "progresses", "result_hex", "root_hex", "capacity", "context"))
            same = same and observed["rollback_exact"]
            controls.append({"name": observed["name"], "status": "PASS" if same else "FAIL",
                "native": expected, "original": observed})
        write_json(output / "comparison.json", {"controls": controls})
        if any(row["status"] != "PASS" for row in controls):
            raise ValueError("Actual original apply/slot_state/root differential failed")
        report = dict(base, status="PASS", controls=len(controls), failed=0,
            retained_original_tests=retained, compiler=version.decode(), stages=stages,
            executable_sha256=binary_hash, original_sources=original,
            native_source_set_sha256=comparison["build"]["source_set_sha256"],
            native_comparison_sha256=sha256(captured_comparison),
            exact_corpus=comparison["corpus"], serde_json_artifact=serde[0],
            original_store_sha256=sha256(original_store), hook_sha256=sha256(hook),
            appended_declaration_hex=DECLARATION.hex(), source_inputs_stable=True,
            actual_private_original_apply_slot_state_continuity_and_root_called=True,
            exact_installed_constructor_snapshots=contexts,
            all_original_configurations_covered=False, pq_config_and_anchor_covered=False,
            scope="finite fast-activation subsegment; no namespace, expected-root or commit authority",
            original_production_function_bytes_preserved=True)
        write_json(output / "report.json", report)
        print(json.dumps({"status": "PASS", "controls": len(controls),
            "original_tests": len(retained), "report": str(output / "report.json")}))
        return 0
    except BaseException as error:
        write_json(output / "report.json", dict(base, status="FAIL", error=repr(error), stages=stages))
        raise

if __name__ == "__main__":
    raise SystemExit(main())
