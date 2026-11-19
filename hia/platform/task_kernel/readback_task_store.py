"""Independently read every TaskStore case, original trace and code-to-ELF binding."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tomllib

FUNCTION = re.compile(rb"(?ms)^fn ([A-Za-z_][A-Za-z_0-9]*)\([^\n]*\n.*?^end(?:\n|$)")
CALLEE = re.compile(rb'"function"\s*:\s*"([A-Za-z_][A-Za-z_0-9]*)"')
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def fingerprint(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns, value.st_mode)


class Readback:
    def __init__(self, evidence, repo, roster, output):
        self.evidence = evidence.resolve(strict=True)
        self.repo = repo.resolve(strict=True)
        self.output = output.absolute()
        require(not self.output.exists() and self.evidence not in self.output.parents, "Fresh readback output outside evidence required")
        self.output.mkdir(parents=True, mode=0o700)
        self.checked = {}
        self.stamps = {}
        self.functions = {}
        self.builds = {}
        self.report = {"schema": "trnm.hia.task-store.independent-readback.v1", "status": "FAIL", "finalized": False,
                       "scope": "Main TaskKernelStore evidence; no archive business or StateImport completion",
                       "full_task_kernel_owner_qualified": False, "checks": {}}
        self.roster_path = roster.resolve(strict=True)
        self.save()

    def save(self):
        (self.output / "report.json").write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")

    def read(self, path, expected=None):
        path = Path(path).absolute()
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), "Regular evidence file required: " + str(path))
        raw = path.read_bytes()
        require(fingerprint(before) == fingerprint(path.lstat()), "File changed while reading: " + str(path))
        actual = identity(raw)
        if expected is not None:
            require(actual == {k: expected[k] for k in ("bytes", "sha256")}, "Content differs: " + str(path))
        if str(path) in self.checked:
            require(self.checked[str(path)] == actual, "Evidence changed between reads: " + str(path))
        self.checked[str(path)] = actual
        self.stamps[str(path)] = fingerprint(before)
        return raw

    def json(self, path):
        return json.loads(self.read(path))

    def passed(self, path):
        value = self.json(path)
        require(value.get("status") == "PASS" and value.get("finalized") is True, "Incomplete gate: " + str(path))
        if "source_before" in value:
            require(value["source_before"] == value["source_after"], "Source fence differs: " + str(path))
            for name, expected in value["source_before"].items():
                self.read(name, expected)
        return value

    def blobs(self, value, directory):
        if isinstance(value, dict):
            if {"path", "bytes", "sha256"} <= value.keys() and value["path"].startswith("blobs/"):
                path = Path(value["path"])
                require(not path.is_absolute() and ".." not in path.parts and path.parts[0] == "blobs", "Invalid blob path")
                require(path.name == value["sha256"], "Blob filename differs from content identity")
                self.read(directory / path, value)
            for child in value.values():
                self.blobs(child, directory)
        elif isinstance(value, list):
            for child in value:
                self.blobs(child, directory)

    def normal_stages(self, directory, rows, nested=False):
        names = []
        for row in rows:
            name = row["name"]
            require(name not in names, "Duplicate stage: " + name)
            names.append(name)
            require(row.get("completed", True) and row.get("exit_code", row.get("exit", -1)) == 0,
                    "Unsuccessful stage: " + name)
            prefix = directory / "stages" / name if nested else directory
            for stream in ("stdin", "stdout", "stderr"):
                path = prefix / (stream + ".raw" if nested else name + "." + stream + ".raw")
                self.read(path, row.get(stream))
        return names

    def parse_functions(self, raw):
        matches = list(FUNCTION.finditer(raw))
        result = {m[1].decode(): m[0] for m in matches}
        require(len(result) == len(matches) == len(re.findall(rb"(?m)^fn ", raw)), "Ambiguous assembly function boundaries")
        return result

    def exports(self, raw):
        require(raw[:7] == b"\x7fELF\x02\x01\x01" and len(raw) >= 64, "ELF64LE required")
        header = struct.unpack_from("<16sHHIQQQIHHHHHH", raw)
        require(header[1] == 3 and header[2] == 62 and header[11] == 64, "x86_64 ET_DYN required")
        sections = [struct.unpack_from("<IIQQQQIIQQ", raw, header[6] + i * 64) for i in range(header[12])]
        names = set()
        for section in sections:
            if section[1] != 11:
                continue
            require(section[9] == 24 and section[6] < len(sections), "Invalid dynamic symbol table")
            strings = sections[section[6]]
            table = raw[strings[4]:strings[4] + strings[5]]
            for at in range(section[4], section[4] + section[5], 24):
                name, info, other, index, value, size = struct.unpack_from("<IBBHQQ", raw, at)
                if index and info >> 4 in (1, 2):
                    require(name < len(table) and b"\0" in table[name:], "Invalid ELF symbol name")
                    names.add(table[name:table.index(b"\0", name)].decode())
        return names

    def native_build(self, name, public):
        directory = self.evidence / name
        build = self.passed(directory / "build.json")
        for path, expected in build["source_before"].items():
            source = Path(path)
            if source.is_relative_to(self.repo):
                snapshot = directory / "source-snapshots" / source.relative_to(self.repo)
            else:
                snapshot = directory / "source-snapshots/external" / hashlib.sha256(path.encode()).hexdigest() / source.name
            self.read(snapshot, expected)
        for filename, expected in build["artifacts"].items():
            self.read(directory / filename, expected)
        compiler = self.read(directory / "native-compiler")
        require(identity(compiler)["sha256"] == COMPILER, "Native compiler differs")
        receipts = {row["stage"]: row for row in build["native_stages"]}
        require(len(receipts) == len(build["native_stages"]), "Duplicate native compilation receipt")
        total_functions = 0
        default_dependencies = ["store_owner_common", "store_common", "store_files", "store_path", "typed_values", "codec", "kernel_policy", "agent_transaction_wire"]
        default_paths = [self.repo / ("hia/src/task_kernel/" + x + ".hepta") for x in default_dependencies]
        default_paths += [self.repo / x for x in ("hia/src/control_plane/core.hepta", "hia/src/crypto/sha256_stream.hepta",
            "hia/src/codec/json_primitives.hepta", "hia/src/crypto/ed25519_group.hepta", "hia/src/crypto/ed25519_verify_joint.hepta", "hia/src/crypto/sha512_arena.hepta")]
        for image, declarations in build["function_sources"].items():
            raw = self.read(directory / (image + ".hepta"))
            composed = self.parse_functions(raw)
            require(set(composed) == set(declarations), "Compiled function roster differs: " + image)
            includes = None
            if image == "root":
                primary = self.repo / ("hia/src/task_kernel/store_public.hepta" if public else "hia/platform/task_kernel/qualification/store_records_fixture.hepta")
                if public:
                    includes = self.repo / "hia/platform/task_kernel/store_public_includes.json"
            elif image.endswith("-emitter"):
                primary = self.repo / ("hia/platform/task_kernel/" + {"driver-emitter": "native_driver.hepta", "dispatch-emitter": "records_dispatch.hepta", "owned-emitter": "store_owned.hepta"}[image])
            else:
                primary = self.repo / ("hia/src/task_kernel/store_" + image + ".hepta")
                if image not in ("query", "files"):
                    includes = self.repo / ("hia/platform/task_kernel/store_" + image + "_includes.json")
            require(str(primary) in build["source_before"], "Canonical image owner is absent from build source fence")
            primary_functions = self.parse_functions(self.read(primary, build["source_before"][str(primary)]))
            owners = {function: str(primary) for function in primary_functions}
            if includes is not None:
                require(str(includes) in build["source_before"], "Canonical include declaration is not fenced")
                include = json.loads(self.read(includes, build["source_before"][str(includes)]))
                for function, relative in include["functions"].items():
                    path = Path(relative)
                    require(not path.is_absolute() and ".." not in path.parts and function not in owners,
                            "Invalid canonical function owner declaration")
                    owners[function] = str(self.repo / path)
                require(set(include["functions"]) == set(composed) - set(primary_functions), "Canonical include function roster differs")
            elif not image.endswith("-emitter"):
                for path in default_paths:
                    if path == primary:
                        continue
                    for function in self.parse_functions(self.read(path)):
                        if function != "f0":
                            require(function not in owners, "Ambiguous canonical dependency function owner")
                            owners[function] = str(path)
            for function, declaration in declarations.items():
                path = declaration["source"]
                require(owners.get(function) == path and path in build["source_before"],
                        "Compiled function is not bound to its canonical fenced owner: " + image + "/" + function)
                self.read(path, build["source_before"][path])
                if path not in self.functions:
                    self.functions[path] = self.parse_functions(self.read(path))
                require(function in self.functions[path], "Missing canonical function")
                body = self.functions[path][function]
                require(hashlib.sha256(body).hexdigest() == declaration["sha256"] and composed[function] == body.rstrip() + b"\n",
                        "Canonical function bytes differ: " + image + "/" + function)
            reachable, pending = set(), ["f0"]
            while pending:
                function = pending.pop()
                if function in reachable:
                    continue
                require(function in composed, "Unresolved actual call target")
                reachable.add(function)
                pending.extend(x.decode() for x in CALLEE.findall(composed[function]))
            require(reachable == set(composed), "Extraneous or missing function in exact call closure")
            stage = "compile-" + image
            row = receipts[stage]
            require(self.json(directory / "pinned-native" / stage / "receipt.json") == row, "Native receipt differs")
            require(row["exit_code"] == 0 and not row["timed_out"] and row["stderr_hex"] == "" and
                    row["wall_limit_seconds"] == 30 and row["cleanup_limit_seconds"] == 3 and
                    row["executable_sha256"] == COMPILER and row["executable_bytes"] == len(compiler), "Native compiler execution binding differs")
            require(self.read(directory / "pinned-native" / stage / "stdin.raw") == raw, "Actual compiler stdin differs")
            output = self.read(directory / "pinned-native" / stage / "stdout.raw")
            require(output == self.read(directory / (image + ".o")) and output.startswith(b"\x7fELF\x02\x01"), "Actual compiler ELF differs")
            require(identity(raw) == {"bytes": row["input_bytes"], "sha256": row["input_sha256"]} and
                    identity(output) == {"bytes": row["output_bytes"], "sha256": row["output_sha256"]} and
                    self.read(directory / "pinned-native" / stage / "stderr.raw") == b"", "Native raw stream identity differs")
            total_functions += len(composed)
        require(set(receipts) == {"compile-" + name for name in build["function_sources"]}, "Native compile stage roster differs")
        for emitter in ("driver", "dispatch", *(("owned",) if public else ())):
            raw = self.read(directory / (emitter + ".actual-output.raw"))
            count = struct.unpack_from("<Q", raw)[0]
            require(count <= len(raw) - 8 and raw[8:8 + count] == self.read(directory / (emitter + ".o")), "Actual HIA emitter object differs")
        self.normal_stages(directory, build["stages"])
        stages = {row["name"]: row for row in build["stages"]}
        units = ["root", "query", "files", "open", "roots", "schema", "objects", "operations", "markers", "blocks",
                 "records", "progress", "bootstrap", "verified", "policy", "grants", "budget", "task_create", "bid", "lease",
                 "provider_accept", "authorize", "scope", "consume", "execution", "empty", "preview"]
        emitters = ["driver", "dispatch"] + (["owned"] if public else [])
        require(set(build["function_sources"]) == set(units + [x + "-emitter" for x in emitters]), "Exact native image roster differs")
        for index, unit in enumerate(units):
            require(stages["rename-" + unit]["argv"] == ["objcopy", "--redefine-sym", "f0=trnm_task_step_" + str(index),
                    str(directory / (unit + ".o")), str(directory / (unit + "-named.o"))], "Actual native symbol rename differs")
        for emitter in emitters:
            require(stages["link-" + emitter + "-emitter"]["argv"] == ["ld", "-shared", "-z", "defs", "-z", "noexecstack",
                    "--build-id=none", str(directory / (emitter + "-emitter.o")), "-lc", "-o", str(directory / (emitter + "-emitter.so"))],
                    "Actual HIA emitter link differs")
        provider = self.passed(Path(build["provider_build"]))
        require(provider["fence"] == "trnm-hia-task-kernel-sqlite-3.54.1-native-x86_64-v1", "Provider fence differs")
        self.read(directory / "provider.so", provider["artifacts"]["provider.so"])
        abi = self.json(self.repo / "hia/platform/task_kernel/provider_abi.json")
        require([row["op"] for row in abi["operations"]] == list(range(1, 30)), "Shared provider operation roster differs")
        library = "task-store-native.so" if public else "store-records-native.so"
        link = [provider["compiler"]["path"], "-shared", "-Wl,-z,defs,-z,relro,-z,now,-z,noexecstack,--build-id=none,--gc-sections",
                str(directory / "driver.o"), str(directory / "dispatch.o"), *[str(directory / (x + "-named.o")) for x in units],
                *([str(directory / "owned.o"), "-Wl,--version-script=" + str(self.repo / "hia/platform/task_kernel/store_owned.map")] if public else []),
                "-L" + str(directory), "-Wl,-rpath,$ORIGIN", "-l:provider.so", "-lm", "-ldl", "-lpthread", "-o", str(directory / library)]
        require(stages["link-native"]["argv"] == link, "Actual final link is not the complete exact HIA object graph")
        expected_stages = ["preflight"] + ["rename-" + x for x in units] + ["link-" + x + "-emitter" for x in emitters]
        expected_stages += [x for name in emitters for x in ("emit-" + name, "inspect-" + name)] + ["link-native"]
        expected_stages += ["inspect-public-symbols"] if public else []
        require(list(stages) == expected_stages, "Actual native build stage roster differs")
        if public:
            expected = self.json(self.repo / "hia/platform/task_kernel/store_owned_exports.json")["exports"]
            require(set(build["public_symbols"]) == set(expected) and len(expected) == 51, "Public symbol declaration differs")
            require(self.exports(self.read(directory / "task-store-native.so")) == set(expected), "Actual ELF exports differ")
        self.report["checks"][name] = {"images": len(build["function_sources"]), "function_bindings": total_functions,
                                      "exact_compiler_stdin_stdout": True, "exact_emitted_objects": True,
                                      "exact_rename_emitter_and_final_link_graph": True}
        self.builds[name] = build
        return build

    def original(self, final, roster):
        names = self.normal_stages(self.evidence, final["stages"], nested=True)
        expected = ["preflight", "version-rustc", "version-cargo", "version-clippy-driver", "version-rustfmt", "source-commit",
                    "original-git-tree", "original-retained-tests", "compile-original-kernel-policy", "compile-original-store-audit",
                    "compile-original-store-records", "compile-original-store-public", "records-native-build", "records-native-original",
                    "public-native-build", "public-native-original", "public-allocation-lifecycle", "original-clippy", "original-format"]
        require(names == expected, "Complete qualification stage roster differs")
        stages = {row["name"]: row for row in final["stages"]}
        environment = final["environment"]
        rust_bin = Path(environment["RUSTC"]).parent
        require(rust_bin.is_absolute(), "Original Rust toolchain must be absolute")
        exact_environment = {"RUSTUP_TOOLCHAIN": "1.95.0", "RUSTC": str(rust_bin / "rustc"),
                             "RUSTDOC": str(rust_bin / "rustdoc"), "CLIPPY_DRIVER": str(rust_bin / "clippy-driver"),
                             "CARGO": str(rust_bin / "cargo"), "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "4",
                             "GIT_NO_LAZY_FETCH": "1", "CARGO_MANIFEST_DIR": str(self.repo / "trillionnium/crates/trnm-task-kernel"),
                             "CARGO_PKG_NAME": "trnm-task-kernel"}
        require(all(environment.get(key) == value for key, value in exact_environment.items()) and
                environment["PATH"].startswith(str(rust_bin) + ":") and
                set(environment) <= set(exact_environment) | {"PATH", "CARGO_HOME"}, "Actual qualification environment differs")
        require(set(final["toolchain"]) == {str(rust_bin / name) for name in
                ("rustc", "cargo", "rustdoc", "clippy-driver", "cargo-clippy", "rustfmt", "cargo-fmt")}, "Pinned tool executable roster differs")
        original_paths = ["trillionnium/crates/trnm-task-kernel", "trillionnium/Cargo.toml", "trillionnium/Cargo.lock",
                          "trillionnium/rust-toolchain.toml", "rust-toolchain.toml"]
        common = ["--manifest-path", str(self.repo / "trillionnium/Cargo.toml"), "--locked", "--offline", "-p", "trnm-task-kernel",
                  "--target-dir", str(self.evidence / "cargo-target")]
        here = self.repo / "hia/platform/task_kernel"
        python = str(Path(sys.executable).absolute())
        fixed = {
            "preflight": (["bash", "scripts/project-preflight.sh", "--audit"], 60),
            "version-rustc": ([str(rust_bin / "rustc"), "--version", "--verbose"], 60),
            "version-cargo": ([str(rust_bin / "cargo"), "--version", "--verbose"], 60),
            "version-clippy-driver": ([str(rust_bin / "clippy-driver"), "--version"], 60),
            "version-rustfmt": ([str(rust_bin / "rustfmt"), "--version"], 60),
            "source-commit": (["git", "rev-parse", "HEAD"], 60),
            "original-git-tree": (["git", "ls-tree", "-r", "-z", "HEAD", "--", *original_paths], 60),
            "original-retained-tests": ([str(rust_bin / "cargo"), "test", *common, "--message-format=json"], 600),
            "records-native-build": ([python, str(here / "build_store_records.py"), "--provider",
                stages["records-native-build"]["argv"][3], "--output", str(self.evidence / "records-native")], 180),
            "records-native-original": ([python, str(here / "qualification/store_records_observer.py"), str(self.evidence / "records-native"),
                str(self.evidence / "original-store-records/store-records-original"), str(self.evidence / "original-store-audit/store-audit-original"),
                str(self.evidence / "original-kernel-policy/kernel-policy-original"), str(self.evidence / "records-qualification")], 180),
            "public-native-build": ([python, str(here / "build_store_public.py"), "--provider",
                stages["records-native-build"]["argv"][3], "--output", str(self.evidence / "public-native")], 180),
            "public-native-original": ([python, str(here / "qualification/store_public_observer.py"), str(self.evidence / "public-native"),
                str(self.evidence / "original-store-public/store-public-original"), str(self.evidence / "records-qualification"),
                str(self.evidence / "public-qualification")], 180),
            "public-allocation-lifecycle": ([python, str(here / "qualify_store_owned_allocations.py"), "--build", str(self.evidence / "public-native"),
                "--records", str(self.evidence / "records-qualification"), "--output", str(self.evidence / "public-allocations")], 240),
            "original-clippy": ([str(rust_bin / "cargo"), "clippy", *common, "--all-targets", "--all-features", "--", "-D", "warnings"], 600),
            "original-format": ([str(rust_bin / "cargo"), "fmt", "--manifest-path", str(self.repo / "trillionnium/Cargo.toml"),
                                 "-p", "trnm-task-kernel", "--", "--check"], 120),
        }
        for name, row in stages.items():
            require(row["cwd"] == str(self.repo), "Qualification stage ran in a different checkout: " + name)
            if name in fixed:
                argv, timeout = fixed[name]
                require(row["argv"] == argv and row["timeout_seconds"] == timeout, "Actual stage command or timeout differs: " + name)
            else:
                require(name.startswith("compile-original-") and row["timeout_seconds"] == 120, "Unknown original compilation stage")
        for name in ("records-native", "public-native"):
            manifest = self.json(self.evidence / name / "build.json")
            require(manifest["provider_build"] == str(Path(stages["records-native-build"]["argv"][3]) / "build.json"),
                    "Actual build used a different provider from its invocation")
        require(self.read(self.evidence / "stages/source-commit/stdout.raw").strip().decode() == final["source_commit"], "Original source commit receipt differs")
        for name, prefix in (("rustc", b"rustc 1.95.0 "), ("cargo", b"cargo 1.95.0 "), ("clippy-driver", b"clippy 0.1.95 ")):
            require(self.read(self.evidence / "stages" / ("version-" + name) / "stdout.raw").startswith(prefix), "Pinned original toolchain differs")
        raw = self.read(self.evidence / "stages/original-retained-tests/stdout.raw")
        tests = [match[1] for line in raw.decode().splitlines() if (match := re.fullmatch(r"test (.+) \.\.\. ok", line))]
        require(sorted(tests) == roster["original_tests"] and len(tests) == 41, "Exact original test names differ")
        summaries = re.findall(rb"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out", raw)
        require(sum(int(row[0]) for row in summaries) == 41 and all(not any(int(x) for x in row[1:]) for row in summaries), "Original test summaries include omissions or failures")
        graph = []
        for line in raw.splitlines():
            if not line.startswith(b"{"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("reason") == "compiler-artifact":
                graph.append(row)
        require(graph == self.json(self.evidence / "cargo-actual-graph.json"), "Actual Cargo stdout graph differs")
        filenames = {name for row in graph for name in row["filenames"]}
        filenames |= {row["executable"] for row in graph if row.get("executable")}
        require(set(final["original_artifacts"]) == filenames, "Retained original artifact roster differs from actual Cargo output")
        required = {row["executable"] for row in graph if row.get("executable")}
        require(required <= set(final["original_artifacts"]), "Original test/example ELF was not retained")
        for path, value in final["original_artifacts"].items():
            self.read(self.evidence / value["retained"], value)
        for path, value in final["original_libraries"].items():
            self.read(path, value)
        for path, value in final["toolchain"].items():
            self.read(path, value)
        lock = tomllib.loads(self.read(self.repo / "trillionnium/Cargo.lock").decode())
        owners = [x for x in lock["package"] if x["name"] == "trnm-task-kernel"]
        require(len(owners) == 1, "Original Cargo owner is ambiguous")
        direct = {}
        for dependency in owners[0]["dependencies"]:
            parts = dependency.split()
            if parts[0] in ("sha2", "borsh", "rusqlite", "ed25519-dalek"):
                matches = [x for x in lock["package"] if x["name"] == parts[0] and (len(parts) == 1 or x["version"] == parts[1])]
                require(len(matches) == 1, "Locked original dependency is ambiguous")
                direct[parts[0].replace("-", "_")] = parts[0] + "@" + matches[0]["version"]
        require(direct == final["original_direct_package_ids"] and len(direct) == 4, "Original direct dependency versions differ")
        expected_libraries = {}
        for row in graph:
            name = row["target"]["name"]
            if name in direct and row["package_id"].rsplit("#", 1)[-1] == direct[name]:
                for filename in row["filenames"]:
                    if filename.endswith(".rlib"):
                        require(name not in expected_libraries, "Ambiguous actual original library")
                        expected_libraries[name] = str(self.evidence / final["original_artifacts"][filename]["retained"])
        require(set(expected_libraries.values()) == set(final["original_libraries"]), "Linked original libraries differ from exact Cargo package graph")
        git_objects = {}
        for item in self.read(self.evidence / "stages/original-git-tree/stdout.raw").split(b"\0"):
            if item:
                metadata, relative = item.split(b"\t", 1)
                mode, kind, oid = metadata.split()
                require(mode in (b"100644", b"100755") and kind == b"blob" and relative.decode() not in git_objects,
                        "Invalid original Git source tree entry")
                git_objects[relative.decode()] = oid.decode()
        require(git_objects == final["original_git_objects"], "Original source roster differs from actual Git output")
        for relative, oid in git_objects.items():
            raw = self.read(self.repo / relative)
            require(hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == oid, "Original Git blob changed")
        for kind in ("kernel-policy", "store-audit", "store-records", "store-public"):
            directory = self.evidence / ("original-" + kind)
            receipt = self.json(directory / "receipt.json")
            require(receipt["status"] == "PASS" and not receipt["original_source_changed"], "Original adapter build failed")
            source = self.repo / "trillionnium/crates/trnm-task-kernel/src/store.rs"
            self.read(source, receipt["source_prefix"])
            hook_directory = self.repo / "hia/platform/task_kernel/qualification"
            rendered = self.read(hook_directory / (kind.replace("-", "_") + "_original.rs")).decode()
            if kind != "store-public":
                hook = self.repo / "hia/platform/task_kernel/qualification" / (kind.replace("-", "_") + "_hook.rs")
                hook_raw = self.read(hook, receipt["hook"])
                require(self.read(directory / "original-store.rs", receipt["combined"]) == self.read(source) + b"\n" + hook_raw,
                        "Private original module is not the exact prefix plus observation hook")
            else:
                rendered = rendered.replace("PUBLIC_OBSERVATION_PATH", str(hook_directory / "store_public_hook.rs"))
            for label, filename in (("ERROR", "error.rs"), ("CODEC", "codec.rs"), ("TYPES", "types.rs"), ("STORE", "store.rs")):
                path = directory / "original-store.rs" if label == "STORE" and kind != "store-public" else source.parent / filename
                rendered = rendered.replace("ORIGINAL_" + label + "_PATH", str(path))
            require(self.read(directory / (kind + "-original.rs"), receipt["source"]) == rendered.encode(),
                    "Original adapter differs from the exact canonical observation source")
            executable = self.read(directory / (kind + "-original"), receipt["executable"])
            require(executable.startswith(b"\x7fELF"), "Actual original adapter ELF missing")
            require(receipt["argv"] == stages["compile-original-" + kind]["argv"], "Original compilation argv differs")
            expected_argv = [final["environment"]["RUSTC"], "--edition=2021", "-C", "opt-level=2", str(directory / (kind + "-original.rs"))]
            for name, path in sorted(expected_libraries.items()):
                expected_argv.extend(["--extern", name + "=" + path])
            expected_argv.extend(["-L", "dependency=" + str(self.evidence / "cargo-target/debug/deps"), "-o", str(directory / (kind + "-original"))])
            require(receipt["argv"] == expected_argv, "Actual original compiler input, packages, or output differs")
        self.report["checks"]["original"] = {"retained_tests": 41, "exact_test_names": True,
            "actual_cargo_artifacts": len(final["original_artifacts"]), "actual_executable_artifacts": len(required),
            "original_modules_and_hooks": 4, "no_test_filters": True, "strict_clippy_and_format": True}

    def observed_build(self, report, name, original_kind):
        build = self.builds[name]
        expected = dict(build["source_before"])
        expected[str(self.evidence / name / "build.json")] = identity(self.read(self.evidence / name / "build.json"))
        for filename, value in build["artifacts"].items():
            expected[str(self.evidence / name / filename)] = value
        original = self.evidence / ("original-" + original_kind) / (original_kind + "-original")
        expected[str(original)] = identity(self.read(original))
        require(all(report["source_before"].get(path) == value for path, value in expected.items()),
                "Observed native/original process is not bound to this actual build")

    def records(self, roster):
        directory = self.evidence / "records-qualification"
        report = self.passed(directory / "report.json")
        self.observed_build(report, "records-native", "store-records")
        self.blobs(report, directory)
        rows = [json.loads(x) for x in self.read(directory / "observations.jsonl").splitlines()]
        require(len(rows) == len(roster["records"]) == 1390, "Private case roster length differs")
        for index, (row, expected) in enumerate(zip(rows, roster["records"])):
            self.blobs(row, directory)
            raw = self.read(directory / row["input"]["path"], row["input"])
            original = self.read(directory / row["expected_output"]["path"], row["expected_output"])
            native = self.read(directory / row["actual_output"]["path"], row["actual_output"])
            observed = {"index": row["index"], "name": row["name"], "method": struct.unpack_from("<Q", raw, 8)[0]
                        if len(raw) >= 16 and raw[:8] == b"TKSR0001" else None, "return_code": row["expected_code"],
                        "error_code": struct.unpack_from("<Q", original)[0] if row["expected_code"] == 0 and len(original) >= 32 else None}
            require(observed == expected and row["index"] == index, "Exact private case differs: " + row["name"])
            require(native == original and row["return_code"] == row["expected_code"] and row["native_after"] == row["expected_after"],
                    "Private native/original data or database differs: " + row["name"])
            prefix = directory / ("original-" + format(index, "03d"))
            require(self.read(str(prefix) + ".stdin.raw") == raw.hex().encode() + b"\n", "Original case stdin differs")
            require(self.read(str(prefix) + ".stdout.raw") == str(row["expected_code"]).encode() + b"|" + original.hex().encode() + b"\n" and
                    self.read(str(prefix) + ".stderr.raw") == b"", "Original case raw output differs")
        require(report["native_calls"] == report["original_calls"] == len(rows), "Private summary differs from complete roster")
        self.normal_stages(directory, report["stages"])
        self.report["checks"]["records"] = {"exact_cases": len(rows), "raw_original_inputs_outputs": True,
                                            "native_original_full_values_and_database_bytes": True}

    def public(self, roster):
        directory = self.evidence / "public-qualification"
        report = self.passed(directory / "report.json")
        self.observed_build(report, "public-native", "store-public")
        require(report["original_exit_code"] == 0, "Original public process did not exit successfully")
        for key, filename in (("report", "report.json"), ("observations", "observations.jsonl")):
            self.read(self.evidence / "records-qualification" / filename, report["fixture_provenance"][key])
        self.blobs(report, directory)
        rows = [json.loads(x) for x in self.read(directory / "observations.jsonl").splitlines()]
        require(len(rows) == len(roster["public"]) == 445, "Public case roster length differs")
        inputs, outputs, calls, getters = [], [], 0, 0
        def getter_cost(text):
            parts = text.split("|", 2)
            require(len(parts) == 3 and parts[0] == "V", "Expected an observed owned value")
            kind = int(parts[1])
            return {1: 1, 2: 10, 3: 3, 4: 7, 5: 2, 255: 4}.get(kind, 2)
        for index, (row, expected) in enumerate(zip(rows, roster["public"])):
            self.blobs(row, directory)
            raw = self.read(directory / row["input"]["path"], row["input"])
            original = self.read(directory / row["expected"]["path"], row["expected"])
            native = self.read(directory / row["actual"]["path"], row["actual"])
            parts, value = raw.decode().strip().split("|"), original.decode()
            observed = {"index": row["index"], "action": row["action"], "argument_count": len(parts), "slot": parts[1],
                        "result_kind": value.split("|", 2)[:2] if value.startswith(("V|", "S|")) else [value[0]],
                        "parallel_calls": int(parts[2]) * int(parts[3]) if row["action"] == "parallel" else 0}
            require(observed == expected and row["index"] == index, "Exact public case differs: " + str(index))
            require(native == original and row["native_after"] == row["expected_after"], "Public complete value or database differs")
            if row["action"] == "parallel":
                values = value[2:].split(";")
                require(value.startswith("P|") and len(values) == observed["parallel_calls"] and parts[2] == "8", "Actual concurrent cohort differs")
                calls += len(values) * 2
                getters += sum(getter_cost(x) for x in values)
            elif row["action"] in ("drop", "equal"):
                calls += 1
            else:
                calls += row["action"] != "observe"
                getters += getter_cost(value)
            inputs.append(raw)
            outputs.append(original + b"\n")
        require(self.read(directory / "original.stdin.raw") == b"".join(inputs) and
                self.read(directory / "original.stdout.raw") == b"".join(outputs) and
                self.read(directory / "original.stderr.raw") == b"", "Complete original public process transcript differs")
        require(calls == report["native_method_drop_compare_calls"] == 413 and getters == report["native_getter_calls"] == 1877 and
                calls + getters == report["native_total_abi_calls"] == 2290 and report["live_values_after"] == 0, "Actual call accounting differs")
        self.report["checks"]["public"] = {"exact_cases": len(rows), "independently_counted_method_calls": calls,
                                           "independently_counted_getters": getters, "complete_original_process_transcript": True}

    def allocations(self, roster, public_build):
        directory = self.evidence / "public-allocations"
        build = self.passed(directory / "build.json")
        run = self.passed(directory / "run.json")
        self.read(directory / "build.json", run["build_manifest"])
        self.read(directory / "qualification/report.json", run["qualification"])
        for path, expected in build["source_before"].items():
            snapshot = directory / "source-snapshots" / hashlib.sha256(path.encode()).hexdigest() / Path(path).name
            self.read(snapshot, expected)
        for name, expected in build["artifacts"].items():
            self.read(directory / name, expected)
        for path, expected in build["exact_original_hia_objects"].items():
            self.read(path, expected)
            require(public_build["artifacts"][Path(path).name] == expected, "Allocator used different HIA object")
        self.read(directory / "provider.so", public_build["artifacts"]["provider.so"])
        self.normal_stages(directory, build["stages"])
        self.normal_stages(directory, run["stages"])
        report = self.passed(directory / "qualification/report.json")
        self.blobs(report, directory / "qualification")
        expected = roster["allocations"]
        observed = [{"name": row["name"], "ordinal": row.get("ordinal"), "code": row.get("code"), "allocations": row.get("allocations")}
                    for row in report["controls"]]
        require(observed == expected and len(observed) == 112, "Exact allocator control roster differs")
        normal, failed = {}, {}
        for row in report["controls"]:
            name = row["name"]
            if name.endswith("-normal"):
                normal[name.removesuffix("-normal")] = row["allocations"]
            elif name.endswith("-allocation-failure"):
                key = name.removesuffix("-allocation-failure")
                failed.setdefault(key, []).append(row["ordinal"])
                before, after = row["before"], row["after"]
                require(row["code"] == 103 and row["out_null"] and after["failures"] == before["failures"] + 1 and
                        after["live"] == before["live"] and after["bytes"] == before["bytes"] and after["bad_frees"] == 0,
                        "Actual allocation failure leaked or minted output")
            elif name.startswith("config-framing-") or "not-" in name or name == "null-store-clone":
                require(row["code"] == 104 and row["out_null"], "Invalid borrow/framing control differs")
                if "before" in row:
                    require(row["before"] == row["after"], "Invalid borrow allocated or freed memory")
            elif name == "concurrent-same-store-real-allocations":
                require(row["threads"] == 8 and row["calls"] == 32 and row["before"]["live"] == row["after"]["live"] and
                        row["before"]["bytes"] == row["after"]["bytes"], "Concurrent allocator cohort differs")
            else:
                raise ValueError("Unrecognized allocator control: " + name)
        require(set(normal) == set(failed) and all(failed[name] == list(range(1, count + 1)) for name, count in normal.items()) and
                sum(normal.values()) == 96, "Allocation ordinal coverage has gaps")
        final = report["final_allocator"]
        require(final["failures"] == 96 and final["calls"] == final["frees"] + 96 and
                all(final[name] == 0 for name in ("live", "bytes", "bad_frees")), "Final allocator lifecycle differs")
        self.report["checks"]["allocator"] = {"exact_controls": 112, "actual_failure_ordinals": 96,
                                               "all_hia_objects_identical_to_public_build": True, "final_allocator": final}

    def run(self):
        try:
            require(__debug__, "Optimized readback refused")
            canonical_reader = self.repo / "hia/platform/task_kernel/readback_task_store.py"
            canonical_roster = self.repo / "hia/platform/task_kernel/qualification/task_store_roster.json"
            require(Path(__file__).resolve(strict=True) == canonical_reader and self.roster_path == canonical_roster,
                    "Reader and fixed case roster must be the canonical files in the qualified checkout")
            reader = identity(self.read(canonical_reader))
            final = self.passed(self.evidence / "report.json")
            expected_sources = set()
            for subtree in (self.repo / "hia/platform/task_kernel", self.repo / "hia/src/task_kernel"):
                for path in subtree.rglob("*"):
                    if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                        expected_sources.add(str(path))
            original_tree = self.read(self.evidence / "stages/original-git-tree/stdout.raw")
            for item in original_tree.split(b"\0"):
                if item:
                    _, relative = item.split(b"\t", 1)
                    path = Path(relative.decode())
                    require(not path.is_absolute() and ".." not in path.parts, "Invalid original source pathname")
                    expected_sources.add(str(self.repo / path))
            require(set(final["source_before"]) == expected_sources, "Qualification omitted or added a current Task source input")
            require(final["source_before"].get(str(canonical_reader)) == reader and
                    final["source_before"].get(str(canonical_roster)) == identity(self.read(canonical_roster)),
                    "Reader or fixed case roster was not captured by the fresh qualification")
            roster = self.json(self.roster_path)
            require(roster["schema"] == "trnm.hia.task-store.exact-case-roster.v1", "Unknown fixed case roster")
            for path, value in final["source_before"].items():
                self.read(self.evidence / "source-snapshots" / value["sha256"] / Path(path).name, value)
            for path, value in final["qualifications"].items():
                self.read(self.evidence / path, value)
            self.original(final, roster)
            self.native_build("records-native", False)
            public_build = self.native_build("public-native", True)
            self.records(roster)
            self.public(roster)
            self.allocations(roster, public_build)
            for path, before in self.stamps.items():
                require(fingerprint(Path(path).lstat()) == before, "Input changed during complete readback: " + path)
            self.report.update(status="PASS", finalized=True, checked_files=self.checked,
                               evidence_report=identity(self.read(self.evidence / "report.json")),
                               reader_source=reader, roster_source=identity(self.read(self.roster_path)))
            self.save()
            return self.report
        except BaseException as error:
            self.report.update(status="FAIL", finalized=False, failure=repr(error), checked_files=self.checked)
            self.save()
            raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--roster", type=Path, default=Path(__file__).with_name("qualification") / "task_store_roster.json")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = Readback(args.evidence, args.repo, args.roster, args.output).run()
    print(json.dumps({"status": report["status"], "checked_files": len(report["checked_files"]), "checks": report["checks"],
                      "report": str(args.output / "report.json")}))


if __name__ == "__main__":
    main()
