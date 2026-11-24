"""Optional Settlement build/runtime identity receipt, not a qualification check.

Read bounded metadata only. The already-written full evidence inventory binds
the original binaries; this exporter never opens them or changes any gate.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import PurePosixPath
import re

from hia.tools import settlement_companion as compact


SCHEMA = "trnm.hia.settlement-ci-image-identity.v1"
EVIDENCE = "qualification/evidence.json"
BUILD = "build/build.json"
PUBLIC = "build/public/build.json"
ELF = "build/public/settlement-engine.so"
LINK = "build/public/link/receipt.json"
REPORT = "native/report.json"
REPOSITORY = "repository-after.json"
NATIVE = "stages/native/receipt.json"
BUILD_STAGE = "stages/build/receipt.json"
CORPUS = "source/hia/platform/service_settlement/qualification/fixtures.json.xz"
CORPUS_SHA256 = "bf417e6b3d4086767b0614c9de0094d8794945100a8e6e149823d84869decc26"
ALLOWED_UNITS = ("control", "receipt", "rollup", "settle", "values", "trust", "emitter", "arithmetic")
LINK_ROLES = ("control", "trust", "receipt", "rollup", "settle", "values")
LINK_PREFIX = ("-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
               "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both")
VERSION_MAP = "hia/platform/service_settlement/engine_owned.map"
COMPILER = "87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54"
HEPTA_REVISION = "f33d8da316de8fdf27b504371f1a5310997ff548"
MAX_MANIFEST = 8 * 1024 * 1024
MAX_OUTPUT = 8192
SHA256 = re.compile(r"[a-f0-9]{64}")


def check(condition, error="identity-mismatch"):
    if not condition:
        raise compact.Refused(error)


def sha(value):
    check(isinstance(value, str) and SHA256.fullmatch(value), "invalid-fields")
    return value


def identity(row, *, allow_empty=False):
    check(isinstance(row, dict), "invalid-fields")
    size = compact.scalar(row["bytes"])
    check(size > 0 or allow_empty, "invalid-fields")
    return {"bytes": size, "sha256": sha(row["sha256"])}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def complete(row):
    check(type(row["exit_code"]) is int and row["exit_code"] == 0 and row["timed_out"] is False
          and row["exception"] is None, "build-incomplete")


class Inventory:
    """An anchored view of specific metadata backed by an existing inventory."""

    def __init__(self, root):
        self.root = root
        raw = compact.read_member(root, EVIDENCE, MAX_MANIFEST)
        manifest = compact.strict_json(raw)
        compact.schema(manifest, "trnm.hia.service-settlement-engine.evidence.v1")
        check(isinstance(manifest["files"], dict), "invalid-fields")
        self.files = manifest["files"]
        compact.path_parts(manifest["origin"], absolute=True)
        compact.path_parts(manifest["source_root"], absolute=True)
        self.origin = PurePosixPath(manifest["origin"])
        self.source_root = PurePosixPath(manifest["source_root"])
        self.manifest_identity = compact.identity(raw)

    def descriptor(self, path):
        if path not in self.files:
            raise compact.Refused("missing")
        row = self.files[path]
        check(set(row) == {"bytes", "sha256"}, "invalid-fields")
        return identity(row)

    def doc(self, path):
        expected = self.descriptor(path)
        raw = compact.read_member(self.root, "qualification/" + path, compact.MAX_RECEIPT)
        check(compact.identity(raw) == expected)
        return compact.strict_json(raw)


def build_projection(store):
    top = store.doc(BUILD)
    compact.schema(top, "trnm.hia.service-settlement-engine-build.v1")
    check(top["status"] == "EIGHT_UNITS_AND_PUBLIC_NATIVE_LINKED_NOT_QUALIFIED"
          and top["finalized"] is True and top["source_unchanged"] is True
          and top["changed_inputs"] == [] and top["compiler_fallback_used"] is False
          and top["authored_reference_used"] is False
          and top["actual_hia_ownership_emitter_executed"] is True, "build-incomplete")
    source = top["source_inputs"]
    check(source == top["source_before"] == top["source_after"]
          and compact.identity(canonical(source))["sha256"] == sha(top["source_digest"]))
    check(set(top["units"]) == set(ALLOWED_UNITS) == set(top["unit_roster"]))
    pin = top["compiler_qualification_binding"]
    check(pin["compiler_sha256"] == COMPILER and pin["toolchain_revision"] == HEPTA_REVISION
          and top["toolchain"]["revision"] == HEPTA_REVISION
          and top["toolchain"]["target"] == "x86_64-linux-gnu")

    def tool(name):
        before = top["tools_before"][name]
        after = top["tools_after"][name]
        wanted = identity(before)
        check(before["snapshot"] == "tools/" + name
              and before["resolved_path"] == after["resolved_path"]
              and wanted == identity(after) == store.descriptor("build/tools/" + name))
        return wanted, before["resolved_path"]

    compiler, _ = tool("compiler")
    linker, ld = tool("ld")
    check(compiler["sha256"] == COMPILER)

    public = store.doc(PUBLIC)
    compact.schema(public, "trnm.hia.service-settlement-public-build.v1")
    check(top["public"]["status"] == public["status"] == "PUBLIC_NATIVE_LINKED_NOT_QUALIFIED"
          and top["public"]["directory"] == "public"
          and public["source_unchanged"] is True
          and top["public"]["build"] == store.descriptor(PUBLIC), "build-incomplete")
    image = identity(public["artifact"])
    check(image == identity(top["artifact"]) == store.descriptor(ELF))
    check(set(public["modules"]) == {"emitter", *LINK_ROLES})
    public_sources = public["source_inputs"]
    check(isinstance(public_sources, dict) and bool(public_sources)
          and all(source.get(path) == row for path, row in public_sources.items()))

    units = {}
    for role in ALLOWED_UNITS:
        base = "build/units/" + role + "/"
        unit = store.doc(base + "build.json")
        compact.schema(unit, "trnm.hia.service-settlement-unit-build.v1")
        check(unit["role"] == role and unit["entry"] == top["unit_roster"][role]
              and unit["status"] == "NATIVE_EMITTED_NOT_EXECUTED"
              and unit["compiler_fallback_used"] is False and unit["source_unchanged"] is True
              and unit["toolchain"] == top["toolchain"] and unit["compiler_sha256"] == COMPILER
              and identity(unit["tools"]["compiler"]) == compiler
              and top["units"][role]["directory"] == "units/" + role
              and top["units"][role]["build"] == store.descriptor(base + "build.json"))
        if role in public["modules"]:
            module = public["modules"][role]
            check(module["directory"] == str(store.origin / base.rstrip("/"))
                  and module["build"] == top["units"][role]["build"]
                  and identity(module["image"]) == identity(unit["artifact"])
                  and identity(module["object"]) == identity(unit["object"]))
        check(identity(unit["artifact"]) == identity(top["units"][role]["artifact"])
              == store.descriptor(base + "module.so"))
        compile_receipt = store.doc(base + "native-compile/receipt.json")
        complete(compile_receipt)
        compile_request = store.doc(base + "native-compile/request.json")
        check(len(compile_request["argv"]) == 1 and len(compile_request["pass_fds"]) == 1
              and compact.scalar(compile_request["pass_fds"][0]) > 2
              and compile_request["argv"][0] == "/proc/self/fd/" + str(compile_request["pass_fds"][0])
              and compile_request["environment"] == {"PATH": ""}
              and all(compile_receipt.get(k) == v for k, v in compile_request.items()))
        check(compile_receipt == unit["stages"][0]
              and identity(compile_receipt["stderr"], allow_empty=True) == compact.identity(b""))
        wire = identity(compile_receipt["stdin"])
        obj = identity(compile_receipt["stdout"])
        check(wire["sha256"] == sha(unit["compiler_wire_sha256"])
              and wire == store.descriptor(base + "native-compile/stdin.raw")
              and obj == identity(unit["object"]) == identity(top["units"][role]["object"])
              == store.descriptor(base + "module.o"))
        units[role] = {"composed": store.descriptor(base + "composed.hepta"),
                       "compiler_wire": wire, "object": obj}

    emitter = public["emitter_execution"]
    check(type(emitter["status"]) is int and emitter["status"] == 0
          and emitter["actual_compiled_hia_execution"] is True
          and emitter["authored_reference_used"] is False)
    emitted = identity(emitter["object"])
    check(emitted == store.descriptor("build/public/engine-owned.o")
          and emitted == store.descriptor("build/public/emitter-execution/engine-owned.o"))
    link_receipt = store.doc(LINK)
    complete(link_receipt)
    check(link_receipt == public["stages"][-1])
    public_path = store.origin / "build/public"
    expected = [ld, *LINK_PREFIX,
                "--version-script=" + str(store.source_root / VERSION_MAP),
                str(public_path / "engine-owned.o"),
                *(str(public_path / (role + ".o")) for role in LINK_ROLES),
                "-lc", "-o", str(public_path / "settlement-engine.so")]
    check(link_receipt["argv"] == expected
          and identity(link_receipt["stdin"], allow_empty=True) == compact.identity(b""))
    script = identity(public_sources[VERSION_MAP])
    check(script == store.descriptor("build/public/source/" + VERSION_MAP))
    objects = [emitted]
    for role in LINK_ROLES:
        obj = identity(public["modules"][role]["renamed"])
        check(obj == store.descriptor("build/public/" + role + ".o"))
        objects.append(obj)
    plan = {"version": 1, "linker": linker, "flags": [*LINK_PREFIX, "-lc"],
            "version_map": script, "emitter_input": identity(emitter["input"]),
            "ordered_objects": objects}
    return {"availability": "linked-verified", "image": image,
            "binary_rehashed_by_companion": False,
            "inventory": store.manifest_identity, "public_receipt": store.descriptor(PUBLIC),
            "source_digest": top["source_digest"], "compiler": compiler,
            "toolchain_revision": HEPTA_REVISION, "units": units,
            "portable_link_plan_sha256": compact.identity(canonical(plan))["sha256"]}


def stage(store, path, *, native=False):
    row = store.doc(path)
    view = compact.stage_receipt(row, fixed_budget=native)
    if native:
        argv = row["argv"]
        check(isinstance(argv, list) and len(argv) == 10 and isinstance(argv[0], str)
              and argv[1:] == ["-B", "-m", "hia.platform.service_settlement.qualification.native",
                              "--build", str(store.origin / "build/public"),
                              "--fee-build", str(store.origin / "build/units/arithmetic"),
                              "--output", str(store.origin / "native")])
    return view


def runtime_projection(store, linked):
    try:
        result = stage(store, NATIVE, native=True)
        check(result["started"] is True, "runtime-not-started")
        wanted = store.descriptor("native/fixture-progress.jsonl")
        raw = compact.read_member(store.root, compact.CURSOR,
                                  compact.MAX_CURSOR_ROWS * compact.MAX_CURSOR_ROW)
        check(compact.identity(raw) == wanted)
        cursor = compact.progress_record(raw)
        last = cursor["last_complete_row"]
        check(last is not None and last.get("capture_records", 0) > 0
              and 0 < last.get("public_dispatch_wall_ns", 0) <= last["wall_ns"],
              "public-dispatch-not-observed")
        prefix = [compact.strict_json(line) for line in raw.split(b"\n", 3)[:3]]
        check(len(prefix) == 3 and prefix[1].get("phase") == "fixture_start"
              and prefix[1].get("fixture_ordinal") == 1
              and prefix[2].get("phase") == "operation_start"
              and prefix[2].get("fixture_ordinal") == prefix[2].get("operation_ordinal") == 1,
              "invalid-cursor")
        corpus = store.descriptor(CORPUS)
        check(corpus["sha256"] == CORPUS_SHA256)
        evidence = {
            "availability": "checked-path-dispatch-observed",
            "stage_receipt": store.descriptor(NATIVE), "cursor": wanted,
            "stage_status": result["status"], "timed_out": result["timed_out"],
            "existing_fixture_corpus": corpus,
            "kernel_mapping_independently_verified": False,
        }
        if REPORT not in store.files:
            evidence["final_report"] = "missing"
            return evidence
        report = store.doc(REPORT)
        check(report["public_owned_api_tested"] is True
              and report["whole_engine_or_store_closed"] is False
              and identity(report["image"]) == linked["image"]
              and identity(report["build"]) == linked["public_receipt"]
              and report["source_inputs"] == store.doc(PUBLIC)["source_inputs"])
        if report["status"] == "PASS":
            check(result["status"] == "PASS" and result["timed_out"] is False
                  and result["exit_code"] == 0 and result["cleanup_complete"] is True
                  and cursor["trailing_fragment_bytes"] == 0 and last["phase"] == "stage_done"
                  and 0 < compact.scalar(report["fixtures"]) == last["completed_fixtures"]
                  and 0 < compact.scalar(report["fixture_operations"]) == last["completed_operations"]
                  and report["complete_fixture_bytes_equal"] is True
                  and type(report["live_owners"]) is int and report["live_owners"] == 0)
            evidence["availability"] = "completed-runtime-report-bound"
        else:
            check(report["status"] == result["status"] == "FAIL")
        evidence["final_report"] = store.descriptor(REPORT)
        return evidence
    except compact.ERRORS as error:
        return {"availability": compact.error_state(error)}


def export(root_path, head, run_id, run_attempt, source_after):
    check(isinstance(head, str) and re.fullmatch(r"[a-f0-9]{40}", head)
          and all(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value)
                  for value in (run_id, run_attempt)), "invalid-run-identity")
    envelope = {"schema": SCHEMA, "workflow": {"head": head, "run_id": run_id,
                "run_attempt": run_attempt}, "qualifies_execution": False,
                "substitutes_full_original_archive": False}
    try:
        with compact.safe_directory(root_path) as root:
            before, after = (compact.observe(root, p, lambda row: compact.source_pin(row, head))
                             for p in compact.PINS)
            check(source_after == "success" and before["availability"] == after["availability"] == "observed"
                  and before["projection"] == after["projection"], "source-unbound")
            expected = before["projection"]
            envelope["workflow"]["tree"] = expected["tree"]
            binding = compact.observe(root, compact.BINDING,
                                      lambda row: compact.binding_record(row, head, run_id, run_attempt))
            if binding["availability"] == "observed":
                check(binding["projection"]["tree"] == expected["tree"], "run-unbound")
                envelope["workflow"]["original_binding"] = binding["original"]
            else:
                check(binding["availability"] == "missing", "run-unbound")
                envelope["workflow"]["original_binding"] = "missing"
            store = Inventory(root)
            repo = store.doc(REPOSITORY)
            check(repo["head"] == head and repo["tree"] == expected["tree"]
                  and repo["repository_clean"] is True, "source-unbound")
            compile_stage = stage(store, BUILD_STAGE)
            check(compile_stage["status"] == "PASS" and compile_stage["started"] is True
                  and compile_stage["timed_out"] is False and compile_stage["exit_code"] == 0,
                  "build-incomplete")
            linked = build_projection(store)
            runtime = runtime_projection(store, linked)
    except compact.ERRORS as error:
        linked, runtime = {"availability": compact.error_state(error)}, {"availability": "linked-unavailable"}
    return {**envelope, "linked": linked, "runtime": runtime}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "output-dir", "head", "run-id", "run-attempt", "source-after-outcome"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    result = export(args.root, args.head, args.run_id, args.run_attempt, args.source_after_outcome)
    data = canonical(result) + b"\n"
    check(len(data) <= MAX_OUTPUT, "identity-over-byte-limit")
    with compact.safe_directory(args.output_dir) as output:
        fd = os.open("image-identity.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=output)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)


if __name__ == "__main__":
    main()
