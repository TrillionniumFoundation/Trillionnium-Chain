"""Same-run byte transfers for four bounded Work owner qualification jobs.

These transfers separate native execution, original execution, full independent
qualification and final downloaded-archive readback. A transport receipt grants
no runtime authority and cannot replace the final complete reader.
"""
from __future__ import annotations
import hashlib
import os
from pathlib import Path
import stat
import tarfile
import traceback

BINDING = "trnm.hia.work-owner-stage-binding.v1"
PACKAGE = "trnm.hia.work-owner-stage-evidence.v1"
PHASES = ("native", "original")
NATIVE_COUNTS = {
    "native_histories": 61, "native_progress_points": 27843, "primitive_controls": 177,
    "actual_syscall_traces": 3, "trace_controls": 27, "signal_controls": 14,
    "native_clock_fault_controls": 18, "primitive_actual_calls": 9503,
    "primitive_buffers": 546, "primitive_snapshots": 7819,
    "primitive_logical_capture_bytes": 6012238470, "primitive_chunk_count": 19432,
}
ORIGINAL_COUNTS = {
    "original_histories": 57, "original_progress_points": 27841,
    "original_worker_histories": 56, "retained_original_test_count": 44,
    "original_process_stages": 48, "original_clock_positive_processes": 2,
    "original_clock_fault_processes": 18, "original_clock_processes": 20,
    "original_clock_raw_controls": 32, "original_clock_raw_positive_controls": 2,
    "original_clock_raw_negative_controls": 30,
}


def stage_observations(q, root, phase):
    q.need(phase in PHASES, "Unknown Work transfer phase")
    return root / (q.PREFIX + "-" + phase + "-observations")


def current_context(q):
    expected = q.base.lineage()
    sources = q.build.source_manifest()
    originals = q.bundle.original_manifest(q.ROOT)
    readers = q.reader_manifest()
    q.need(q.reader_paths() == {name: q.ROOT / name for name in q.READERS},
           "Hosted transfer loaded a reader outside the exact source")
    q.base.check_committed_sources({**originals, **sources, **readers}, q.ROOT)
    return expected, sources, originals, readers


def check_binding(q, value, phase, expected, sources, originals, readers):
    q.need(phase in PHASES and type(value) is dict and value.get("schema") == BINDING
           and value.get("phase") == phase and value.get("status") == "PASS"
           and value.get("final_qualification_claimed") is False
           and q.same(value.get("lineage"), expected), "Failed, wrong-phase or foreign Work predecessor")
    q.need(q.same(value.get("source_inputs"), sources)
           and q.same(value.get("original_sources"), originals)
           and q.same(value.get("ci_reader_sources"), readers)
           and value.get("source_set_sha256") == q.object_hash(sources)
           and value.get("original_source_set_sha256") == q.object_hash(originals),
           "Complete predecessor source or reader closure differs")
    q.need(all(value.get(name) is False for name in q.SCOPES), "Predecessor expanded runtime authority")
    counts = NATIVE_COUNTS if phase == "native" else ORIGINAL_COUNTS
    q.need(all(type(value.get(name)) is int and value[name] == count for name, count in counts.items()),
           "Predecessor omitted, skipped or changed an actual stage count")
    files = value.get("evidence_files")
    q.need(type(files) is dict and files and value.get("evidence_set_sha256") == q.object_hash(files),
           "Missing complete predecessor byte roster")
    for name, identity in files.items():
        q.need(q.member_name(name).parts[0] in q.ROOT_LABELS and q.file_id(identity),
               "Malformed predecessor byte identity")
    required = {"observations/source-before.json", "observations/source-after.json"}
    if phase == "native":
        required |= {"native/report.json", "native/artifacts.json", "native/build/fixture.elf",
                     "native/primitives/raw-buffers/manifest.json", "native/primitives/raw-buffers/calls.jsonl",
                     "observations/source-controls/report.json", "observations/source-controls/stdout.raw",
                     "observations/source-controls/stderr.raw"}
        q.need(value.get("primitive_raw_readback") == "PASS" and value.get("physical_trace") == "PASS"
               and value.get("primitive_raw_guard_arenas_retained") is True
               and type(value.get("native_snapshot")) is dict,
               "Native predecessor lacks its complete guarded bytes or trace qualification")
    else:
        required |= {"original/report.json", "original/original-test-binary",
                     "original/source-before.json", "original/source-after.json",
                     "original/controlled-clock/report.json",
                     "original/controlled-clock/actual-reader-controls/report.json",
                     "original/actual-sqlite-qualification.json"}
        q.need(value.get("original_rust") == "PASS"
               and value.get("original_controlled_CLOCK1_fault_comparison") == "PASS"
               and value.get("native_replayed_in_this_capture") is False
               and type(value.get("native_predecessor")) is dict,
               "Original predecessor lacks actual execution or expands its replay scope")
        q.need(q.file_id(value.get("original_binary")) and value["original_binary"]["bytes"] > 0
               and q.same(files.get("original/original-test-binary"), value["original_binary"]),
               "Complete independent original executable absent")
    q.need(required <= set(files), "Required predecessor raw member absent")


def copy_tree(q, source, destination):
    files = q.file_tree(source)
    for name, expected in files.items():
        q.capture_file(source / q.member_name(name), destination / q.member_name(name), expected)
    q.need(q.same(q.file_tree(source), files) and q.same(q.file_tree(destination), files),
           "Complete retained predecessor copy changed")
    return files


def make_package(q, roots, output, binding, phase, precondition_error=None):
    """Retain failures too; a package cannot turn them into a successful predecessor."""
    output.mkdir(mode=0o700)
    record = {"schema": PACKAGE, "phase": phase, "packing_status": "FAIL",
              "predecessor_status": "FAIL", "final_qualification_claimed": False,
              "entries": {}, "special_entries": {}, "capture_errors": [],
              "complete_original_test_binary_is_not_excluded": phase == "original",
              "complete_primitive_bytes_is_not_excluded": phase == "native"}
    archive = output / "complete-evidence.tar.xz"
    try:
        files, special = q.evidence_inventory(roots, omit_binding=False)
        record["special_entries"] = special
        with tarfile.open(archive, "x:xz", preset=1) as stream:
            for name, expected in sorted(files.items()):
                label, relative = name.split("/", 1)
                path = roots[label] / q.member_name(relative)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                with os.fdopen(descriptor, "rb") as incoming:
                    before = os.fstat(incoming.fileno())
                    q.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                           and before.st_size == expected["bytes"], "Transferred file changed before open")
                    digest = hashlib.sha256()
                    class Reader:
                        def read(self, count):
                            raw = incoming.read(count)
                            digest.update(raw)
                            return raw
                    member = tarfile.TarInfo(name)
                    member.size = before.st_size
                    member.mode = 0o500 if name == "original/original-test-binary" else 0o600
                    stream.addfile(member, Reader())
                    after = os.fstat(incoming.fileno())
                stamp = lambda v: (v.st_dev, v.st_ino, v.st_size, v.st_mtime_ns, v.st_ctime_ns,
                                   v.st_mode, v.st_nlink)
                q.need(stamp(before) == stamp(after) == stamp(path.lstat())
                       and digest.hexdigest() == expected["sha256"], "Transferred file changed while reading")
                record["entries"][name] = expected
        record["archive_verification"] = q.verify_archive(archive, record["entries"])
        record["archive"] = record["archive_verification"]["archive"]
        q.need(q.same((files, special), q.evidence_inventory(roots, omit_binding=False)),
               "Transferred file roster changed while packing")
        q.need(not special and precondition_error is None and binding is not None,
               "Predecessor did not qualify: " + str(precondition_error))
        expected = q.base.lineage()
        check_binding(q, binding, phase, expected, q.build.source_manifest(),
                      q.bundle.original_manifest(q.ROOT), q.reader_manifest())
        q.need(set(files) == set(binding["evidence_files"]) | {"observations/binding.json"}
               and all(q.same(files[name], row) for name, row in binding["evidence_files"].items()),
               "Bound predecessor member omitted, added or changed")
        source = roots["observations"] / "binding.json"
        q.need(q.same(files["observations/binding.json"], q.identity(source)),
               "Actual predecessor binding bytes absent")
        q.capture_file(source, output / "binding.json", q.identity(source))
        record.update(binding=q.identity(output / "binding.json"), lineage=expected,
                      predecessor_status="PASS", packing_status="PASS")
    except BaseException as error:
        record["capture_errors"].append({"error": repr(error), "traceback": traceback.format_exc()})
        if archive.is_file() and not archive.is_symlink():
            record["partial_archive"] = q.identity(archive)
    finally:
        q.write_new(output / "package-manifest.json", record)
    q.need(record["packing_status"] == "PASS", "Work transfer failed; complete available bytes retained")
    return record


def pack_native(q, root):
    obs = stage_observations(q, root, "native"); obs.mkdir(mode=0o700, exist_ok=True)
    capture = root / (q.PREFIX + "-native-capture"); capture.mkdir(mode=0o700)
    roots = {"native": root / (q.PREFIX + "-native"), "observations": obs,
             "capture": capture, "bootstrap": root / "hia-bootstrap"}
    binding = None; failure = None
    try:
        expected, sources, originals, readers = current_context(q)
        pair = q.source_pair(obs, expected)
        admitted, result = q.native(roots["native"], q.ROOT)
        result.update(q.validate_controls(obs / "source-controls"))
        q.need(q.same(admitted["source_inputs"], sources) and q.same(admitted["original_sources"], originals),
               "Native predecessor source differs")
        for name, wanted in {**sources, **readers}.items():
            category = "source-inputs" if name in sources else "ci-readers"
            q.capture_file(q.ROOT / name, capture / category / q.member_name(name), wanted)
        files, special = q.evidence_inventory(roots)
        q.need(not special, "Successful native predecessor contains special artifacts")
        binding = dict(result, schema=BINDING, phase="native", status="PASS", lineage=expected,
                       final_qualification_claimed=False, source_inputs=sources, original_sources=originals,
                       source_set_sha256=q.object_hash(sources), original_source_set_sha256=q.object_hash(originals),
                       ci_reader_sources=readers, source_observations=pair, native_snapshot=admitted["snapshot"],
                       evidence_files=files, evidence_set_sha256=q.object_hash(files),
                       **{name: False for name in q.SCOPES})
        check_binding(q, binding, "native", expected, sources, originals, readers)
        q.need(q.same(pair, q.source_pair(obs, expected)), "Native CI source changed during capture")
        q.write_new(obs / "binding.json", binding)
    except BaseException as error:
        failure = repr(error)
        q.write_new(obs / "transfer-error.json", {"error": failure, "traceback": traceback.format_exc()})
    return make_package(q, roots, root / (q.PREFIX + "-native-artifact"), binding, "native", failure)


def validate_package(q, record, binding, phase, expected, directory):
    q.need(set(q.file_tree(directory)) == {"complete-evidence.tar.xz", "package-manifest.json", "binding.json"},
           "Unexpected transferred package file roster")
    q.need(type(record) is dict and record.get("schema") == PACKAGE and record.get("phase") == phase
           and record.get("packing_status") == record.get("predecessor_status") == "PASS"
           and record.get("final_qualification_claimed") is False
           and q.same(record.get("lineage"), expected)
           and record.get("capture_errors") == [] and record.get("special_entries") == {},
           "Failed or foreign predecessor package")
    q.need(record.get("complete_original_test_binary_is_not_excluded") is (phase == "original")
           and record.get("complete_primitive_bytes_is_not_excluded") is (phase == "native"),
           "Predecessor archive completeness scope differs")
    entries = record.get("entries")
    q.need(type(entries) is dict and all(q.file_id(row) for row in entries.values())
           and set(entries) == set(binding["evidence_files"]) | {"observations/binding.json"}
           and all(q.same(entries[name], row) for name, row in binding["evidence_files"].items())
           and q.same(q.identity(directory / "binding.json"), record.get("binding"))
           and q.same(entries["observations/binding.json"], record["binding"]),
           "Predecessor complete entry/binding bytes differ")
    q.need(q.file_id(record.get("archive"))
           and q.same(q.identity(directory / "complete-evidence.tar.xz"), record["archive"]),
           "Downloaded predecessor archive changed")
    return entries


def transfer_receipt(q, record, directory, phase, expected, sources, readers):
    return {"status": "VERIFIED_BYTES_TRANSFERRED_NOT_FINAL_QUALIFICATION", "phase": phase,
            "lineage": expected, "archive": record["archive"], "binding": record["binding"],
            "package_manifest": q.identity(directory / "package-manifest.json"),
            "source_set_sha256": q.object_hash(sources), "ci_reader_sources": readers}


def read_transfer(q, package, output, phase):
    expected, sources, originals, readers = current_context(q)
    record = q.read(package / "package-manifest.json")
    binding = q.read(package / "binding.json")
    check_binding(q, binding, phase, expected, sources, originals, readers)
    entries = validate_package(q, record, binding, phase, expected, package)
    verification = q.verify_archive(package / "complete-evidence.tar.xz", entries, destination=output)
    q.need(q.same(verification, record.get("archive_verification"))
           and q.regular(output / "observations/binding.json").read_bytes() ==
               q.regular(package / "binding.json").read_bytes(),
           "Written predecessor archive or internal binding differs")
    receipt = transfer_receipt(q, record, package, phase, expected, sources, readers)
    q.write_new(output / "transfer-receipt.json", receipt)
    for name in ("binding.json", "package-manifest.json"):
        q.capture_file(package / name, output / ("transferred-" + name), q.identity(package / name))
    return {"status": receipt["status"], "phase": phase, "archive": record["archive"]}


def prior(q, root, phase):
    directory = root / (q.PREFIX + "-" + phase + "-prior")
    binding = q.read(directory / "transferred-binding.json")
    receipt = q.read(directory / "transfer-receipt.json")
    expected, sources, originals, readers = current_context(q)
    check_binding(q, binding, phase, expected, sources, originals, readers)
    q.need(receipt.get("status") == "VERIFIED_BYTES_TRANSFERRED_NOT_FINAL_QUALIFICATION"
           and receipt.get("phase") == phase and q.same(receipt.get("lineage"), expected)
           and q.same(receipt.get("binding"), q.identity(directory / "transferred-binding.json"))
           and q.same(receipt.get("package_manifest"), q.identity(directory / "transferred-package-manifest.json"))
           and q.same(receipt.get("ci_reader_sources"), readers)
           and receipt.get("source_set_sha256") == q.object_hash(sources),
           "Actual predecessor transfer receipt differs")
    q.need(q.regular(directory / "observations/binding.json").read_bytes() ==
           q.regular(directory / "transferred-binding.json").read_bytes(), "Transferred binding copy differs")
    return directory, binding, receipt


def pack_original(q, root):
    obs = stage_observations(q, root, "original"); obs.mkdir(mode=0o700, exist_ok=True)
    capture = root / (q.PREFIX + "-original-capture"); capture.mkdir(mode=0o700)
    roots = {"original": root / (q.PREFIX + "-original"), "observations": obs, "capture": capture}
    binding = None; failure = None
    try:
        expected, sources, originals, readers = current_context(q)
        pair = q.source_pair(obs, expected)
        inherited, predecessor, receipt = prior(q, root, "native")
        native = inherited / "native"
        # The original CLI already executes the full public native admission.
        # This capture checks byte continuity and raw frames without claiming a
        # second primitive/trace replay. Final qualification repeats that replay.
        q.need(q.same(q.bundle.snapshot(native), predecessor["native_snapshot"]),
               "Native predecessor bytes changed after actual original execution")
        report = q.read(native / "report.json")
        q.need(q.same(q.bundle.source_bindings(report), sources)
               and q.same(report.get("original_sources"), originals), "Original capture native source differs")
        q.bundle.validate_build(native, report)
        roster = q.cases.corpus()
        q.need(len(report["semantic"]) == len(roster)
               and [row["name"] for row in report["semantic"]] == [row["name"] for row in roster],
               "Original capture native case roster differs")
        frames = [q.bundle.validate_physical(case, row["physical"], native / "semantic" / case["name"],
                                            report["build"]["images"]["fixture"]["sha256"])
                  for case, row in zip(roster, report["semantic"], strict=True)]
        admitted = {"report": report, "native": frames, "source_inputs": sources,
                    "original_sources": originals, "snapshot": predecessor["native_snapshot"]}
        result = q.original(roots["original"], q.ROOT, admitted, capture=capture,
                            expected_target=root / (q.PREFIX + "-cargo-target"))
        for name, wanted in sources.items():
            q.capture_file(q.ROOT / name, capture / "source-inputs" / q.member_name(name), wanted)
        for name, wanted in readers.items():
            q.capture_file(q.ROOT / name, capture / "ci-readers" / q.member_name(name), wanted)
        files, special = q.evidence_inventory(roots)
        q.need(not special, "Successful original predecessor contains special artifacts")
        binding = dict(result, schema=BINDING, phase="original", status="PASS", lineage=expected,
                       final_qualification_claimed=False, native_replayed_in_this_capture=False,
                       native_predecessor=receipt, source_inputs=sources, original_sources=originals,
                       source_set_sha256=q.object_hash(sources), original_source_set_sha256=q.object_hash(originals),
                       ci_reader_sources=readers, source_observations=pair,
                       evidence_files=files, evidence_set_sha256=q.object_hash(files),
                       **{name: False for name in q.SCOPES})
        check_binding(q, binding, "original", expected, sources, originals, readers)
        q.need(q.same(pair, q.source_pair(obs, expected))
               and q.same(q.bundle.snapshot(native), predecessor["native_snapshot"]),
               "Source or native bytes changed during original capture")
        q.write_new(obs / "binding.json", binding)
    except BaseException as error:
        failure = repr(error)
        q.write_new(obs / "transfer-error.json", {"error": failure, "traceback": traceback.format_exc()})
    return make_package(q, roots, root / (q.PREFIX + "-original-artifact"), binding, "original", failure)


def qualify_pack(q, root):
    expected, sources, originals, readers = current_context(q)
    native, native_binding, native_receipt = prior(q, root, "native")
    original, original_binding, original_receipt = prior(q, root, "original")
    q.need(q.same(original_binding.get("native_predecessor"), native_receipt),
           "Original execution used a different native predecessor")
    obs = q.observations(root); pair = q.source_pair(obs, expected)
    capture = original / "capture"
    result = q.assess(q.ROOT, native / "native", original / "original", capture=capture, live=False)
    q.need(q.same(result["source_inputs"], sources) and q.same(result["original_sources"], originals),
           "Full transferred qualification source differs")
    result.update(q.validate_controls(native / "observations/source-controls"))
    copy_tree(q, native / "observations/source-controls", obs / "source-controls")
    for phase, previous in (("native", native), ("original", original)):
        copy_tree(q, previous / "observations", capture / ("predecessor-" + phase))
        for name in ("transfer-receipt.json", "transferred-binding.json", "transferred-package-manifest.json"):
            q.capture_file(previous / name, capture / ("predecessor-" + phase) / name,
                           q.identity(previous / name))
        package = root / (q.PREFIX + "-" + phase + "-download")
        for name in ("complete-evidence.tar.xz", "package-manifest.json", "binding.json"):
            q.capture_file(package / name, capture / ("predecessor-" + phase) / "transport" / name,
                           q.identity(package / name))
    roots = {"native": native / "native", "original": original / "original",
             "capture": capture, "observations": obs, "bootstrap": native / "bootstrap"}
    result.update(schema=q.SCHEMA, stage=q.STAGE, status="PASS", lineage=expected,
                  source_observations=pair, ci_reader_sources=readers,
                  native_predecessor=native_receipt, original_predecessor=original_receipt,
                  complete_predecessor_regular_bytes_retained=True,
                  complete_predecessor_archives_retained=True,
                  pipeline="native-original-qualification-readback-v1")
    q.need(q.same(pair, q.source_pair(obs, expected)), "Qualification source changed during full replay")
    files, special = q.evidence_inventory(roots)
    q.need(not special, "Complete qualified Work evidence contains special artifacts")
    result.update(evidence_files=files, evidence_set_sha256=q.object_hash(files))
    q.check_binding(result, expected)
    validate_chain(q, roots, result)
    q.write_new(obs / "binding.json", result)
    package = q.pack_roots(roots, root / (q.PREFIX + "-artifact"), expected=expected, binding=result)
    q.need(package["qualification_status"] == "PASS", "Complete Work package was not qualified")
    return {"status": "QUALIFIED_COMPLETE_PACKAGE", "lineage": expected,
            "archive": package["archive"], "binding": package["binding"]}


def validate_chain(q, roots, final):
    """Re-read both whole predecessor archives, including their captured manifests."""
    expected = q.base.lineage()
    sources, originals, readers = (final[name] for name in
                                   ("source_inputs", "original_sources", "ci_reader_sources"))
    q.need(final.get("pipeline") == "native-original-qualification-readback-v1"
           and final.get("complete_predecessor_regular_bytes_retained") is True
           and final.get("complete_predecessor_archives_retained") is True,
           "Missing complete four-stage qualification chain")
    bindings = {}
    receipts = {}
    for phase in PHASES:
        directory = roots["capture"] / ("predecessor-" + phase)
        package = directory / "transport"
        manifest = q.read(package / "package-manifest.json")
        binding = q.read(package / "binding.json")
        receipt = q.read(directory / "transfer-receipt.json")
        check_binding(q, binding, phase, expected, sources, originals, readers)
        validate_package(q, manifest, binding, phase, expected, package)
        verification = q.verify_archive(package / "complete-evidence.tar.xz", manifest["entries"])
        q.need(q.same(verification, manifest["archive_verification"])
               and q.regular(package / "package-manifest.json").read_bytes()
                   == q.regular(directory / "transferred-package-manifest.json").read_bytes()
               and q.regular(package / "binding.json").read_bytes()
                   == q.regular(directory / "transferred-binding.json").read_bytes()
               and q.regular(package / "binding.json").read_bytes()
                   == q.regular(directory / "binding.json").read_bytes(),
               "Retained whole predecessor transport differs")
        expected_receipt = transfer_receipt(q, manifest, package, phase, expected, sources, readers)
        q.need(q.same(receipt, expected_receipt) and q.same(final.get(phase + "_predecessor"), receipt),
               "Final predecessor reference differs from actual complete transfer")
        for name, wanted in manifest["entries"].items():
            label, relative = name.split("/", 1)
            if label == "observations":
                actual = directory / q.member_name(relative)
            else:
                q.need(label in roots, "Transferred predecessor root was omitted")
                actual = roots[label] / q.member_name(relative)
            q.need(q.same(q.identity(actual), wanted),
                   "Predecessor full member differs from final retained evidence: " + name)
        bindings[phase] = binding
        receipts[phase] = receipt
    q.need(q.same(bindings["original"].get("native_predecessor"), receipts["native"]),
           "Original predecessor consumed another native archive")
    return {"status": "PASS", "whole_predecessor_archives": 2,
            "same_head_run_attempt": True, "same_complete_source": True,
            "actual_runtime_reexecuted": False}
