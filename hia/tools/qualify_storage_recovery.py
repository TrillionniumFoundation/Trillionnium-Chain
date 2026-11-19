"""Exercise explicit genesis initialization recovery in the real HIA StoreOwner.

The owner performs every runtime read, validation, write, synchronization and
rename. This hosted driver creates adversarial files, interrupts real processes
at native gates, and independently checks the resulting bytes and cold reopen.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import struct
import sys
import time
import traceback

if not __debug__:
    raise RuntimeError("optimized Python is forbidden for native HIA storage recovery qualification")

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hia.platform.build import new_output, write_json
from hia.storage.build import Build, digest
from hia.tools.qualify_storage import (CHUNK, CONTEXT, MAX_PAYLOAD, U64_MAX,
    Session as StorageSession, disk_chain, genesis)

FORMAT = b"HIAFMT02" + CONTEXT + struct.pack("<QQQ", MAX_PAYLOAD, U64_MAX, CHUNK)
RECOVERY_TAGS = frozenset({1, 2, 3, 4, 10, 11, 12, 13, 14, 15, 16, 20,
                          30, 31, 32, 33, 34, 35, 36, 37})


class Session(StorageSession):
    def pause(self, target: int) -> dict:
        assert self.gates
        while True:
            tag, sequence, partials, eintr = struct.unpack("<QQQQ", self.read(32, gate=True))
            record = {"tag": tag, "sequence": sequence,
                      "positive_partial_results": partials, "eintr_results": eintr,
                      "observed_monotonic_ns": time.monotonic_ns()}
            self.gate_records.append(record)
            if tag == target:
                return record
            assert tag in RECOVERY_TAGS, record
            self.resume()


def snapshot(directory: Path) -> dict:
    result = {}
    for p in sorted(directory.iterdir()):
        meta = p.lstat()
        row = {"mode": meta.st_mode, "uid": meta.st_uid, "links": meta.st_nlink,
               "bytes": meta.st_size, "inode": meta.st_ino}
        if stat.S_ISREG(meta.st_mode):
            row["sha256"] = digest(p.read_bytes())
        elif stat.S_ISLNK(meta.st_mode):
            row["target"] = os.readlink(p)
        result[p.name] = row
    return result


def write_file(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


class Qualification:
    def __init__(self, output: Path):
        self.output = output
        self.builder = Build(output / "build")
        self.build = self.builder.build()
        self.image = self.builder.executable
        self.results = []
        self.cases = output / "cases"
        self.cases.mkdir(mode=0o700)
        self.seeds = {}
        for name, tag in (("temporary", 2), ("published", 3)):
            root = output / ("actual-initialization-cut-" + name)
            root.mkdir(mode=0o700)
            directory = root / "namespace"
            directory.mkdir(mode=0o700)
            with Session(self.image, directory, root / "native-process", mode=1, gates=True) as owner:
                observed = owner.pause(tag)
                assert owner.kill()["exit_code"] == -signal.SIGKILL
            source = "HEAD.tmp" if tag == 2 else "HEAD"
            expected = b"HIAHD002" + bytes(16) + CONTEXT + genesis() + bytes(40)
            assert (directory / source).read_bytes() == expected
            assert set(p.name for p in directory.iterdir()) == {"owner.lock", source}
            self.seeds[name] = directory
            write_json(root / "seed.json", {"source": source, "gate": observed,
                "head_sha256": digest(expected), "physical_power_loss": False})

    def case(self, name, action):
        root = self.cases / name
        root.mkdir(mode=0o700)
        try:
            details = action(root)
            row = {"case": name, "status": "PASS", **details}
        except BaseException as error:
            row = {"case": name, "status": "FAIL", "error": repr(error),
                   "traceback": traceback.format_exc()}
        self.results.append(row)
        write_json(root / "case.json", row)

    def copy(self, root, seed="temporary", prefix=None):
        directory = root / "namespace"
        shutil.copytree(self.seeds[seed], directory, copy_function=shutil.copy2)
        if prefix is not None:
            write_file(directory / "FORMAT", FORMAT[:prefix])
        return directory

    def recover(self, root, directory, *, label="recovery", commit=True):
        with Session(self.image, directory, root / label, mode=3) as owner:
            assert owner.ready() == {"kind": 0, "sequence": 0, "length": 0, "digest": genesis()}
            assert owner.get() == b""
            if commit:
                owner.commit(b"native-after-initialization-recovery\x00\xff")
            owner.close()
        expected = disk_chain(directory)
        assert expected["sequence"] == int(commit)
        with Session(self.image, directory, root / (label + "-cold"), mode=2) as owner:
            assert owner.ready()["digest"] == expected["digest"]
            assert owner.get() == expected["payload"]
            owner.close()
        return {"cold_sequence": expected["sequence"],
                "cold_digest": expected["digest"].hex(),
                "payload_sha256": digest(expected["payload"])}

    def reject(self, root, mutate, *, seed="temporary", prefix=None, context=CONTEXT):
        directory = self.copy(root, seed, prefix)
        cleanup = mutate(directory, root)
        before = snapshot(directory)
        try:
            with Session(self.image, directory, root / "refusal", mode=3, context=context) as owner:
                row = owner.finish()
                assert row["exit_code"] in (65, 66), row
                assert row["stdout_bytes"] == 0, row
                assert row["diagnostic"]["uncertain"] == 0, row
            assert snapshot(directory) == before
            return {"exit_code": row["exit_code"], "all_existing_objects_unchanged": True,
                    "opened_receipt": False}
        finally:
            if cleanup:
                cleanup()

    def run(self):
        for seed in self.seeds:
            for prefix in (None, *range(65)):
                def complete(root, seed=seed, prefix=prefix):
                    directory = self.copy(root, seed, prefix)
                    return {"seed": seed, "format_prefix_bytes": prefix,
                            **self.recover(root, directory)}
                self.case(f"complete-{seed}-prefix-{prefix}", complete)

        def no_genesis(directory, root):
            (directory / "HEAD.tmp").unlink()
        self.case("refuse-lock-only", lambda root: self.reject(root, no_genesis))

        def both(directory, root):
            write_file(directory / "HEAD", (directory / "HEAD.tmp").read_bytes())
        self.case("refuse-ambiguous-head-and-temporary", lambda root: self.reject(root, both))

        self.case("refuse-wrong-context", lambda root: self.reject(root, lambda d, r: None,
            context=hashlib.sha256(b"unrelated-native-owner-context").digest()))

        for offset in (0, 8, 16, 24, 56, 88, 120):
            def corrupt_head(directory, root, offset=offset):
                p = directory / "HEAD.tmp"
                raw = bytearray(p.read_bytes()); raw[offset] ^= 1; p.write_bytes(raw)
            self.case(f"refuse-genesis-field-{offset}", lambda root, m=corrupt_head: self.reject(root, m))

        for size in (0, 1, 127, 129):
            def resized(directory, root, size=size):
                p = directory / "HEAD.tmp"
                p.write_bytes((p.read_bytes() + b"x")[:size])
            self.case(f"refuse-genesis-size-{size}", lambda root, m=resized: self.reject(root, m))

        for filename in ("txn.0000000000000001", "txn.0000000000000001.tmp", "unknown", "data.sqlite"):
            def extra(directory, root, filename=filename):
                write_file(directory / filename, b"must never be adopted or removed")
            self.case("refuse-name-" + filename, lambda root, m=extra: self.reject(root, m))

        for field in (0, 7, 8, 39, 40, 48, 56, 63):
            def corrupt_format(directory, root, field=field):
                raw = bytearray(FORMAT); raw[field] ^= 1
                write_file(directory / "FORMAT", raw)
            self.case(f"refuse-format-field-{field}", lambda root, m=corrupt_format: self.reject(root, m))
        self.case("refuse-format-extended", lambda root: self.reject(root,
            lambda d, r: write_file(d / "FORMAT", FORMAT + b"x")))

        for filename in ("HEAD.tmp", "FORMAT"):
            for kind in ("symlink", "directory", "fifo", "hardlink", "wrong-mode"):
                def special(directory, root, filename=filename, kind=kind):
                    p = directory / filename
                    original = p.read_bytes() if p.exists() else FORMAT[:17]
                    if p.exists(): p.unlink()
                    if kind == "symlink":
                        outside = root / "outside"; write_file(outside, original)
                        p.symlink_to(outside)
                    elif kind == "directory":
                        p.mkdir(mode=0o700)
                    elif kind == "fifo":
                        os.mkfifo(p, 0o600)
                        fd = os.open(p, os.O_RDWR | os.O_NONBLOCK)
                        marker = b"fifo-bytes-must-not-be-consumed"
                        assert os.write(fd, marker) == len(marker)
                        def cleanup():
                            assert os.read(fd, len(marker)) == marker
                            os.close(fd)
                        return cleanup
                    elif kind == "hardlink":
                        outside = root / "outside"; write_file(outside, original)
                        os.link(outside, p)
                    else:
                        write_file(p, original); p.chmod(0o644)
                self.case(f"refuse-{filename}-{kind}", lambda root, m=special: self.reject(root, m))

        def lock_contender(root):
            directory = self.copy(root)
            before = snapshot(directory)
            with Session(self.image, directory, root / "holder", mode=3, gates=True) as first:
                first.pause(30)
                with Session(self.image, directory, root / "contender", mode=3) as second:
                    second.finish(67)
                assert snapshot(directory) == before
                first.resume(); first.ready(); first.close()
            return {"second_owner_refused_busy": True, **self.recover(root, directory)}
        self.case("actual-two-process-recovery-lock", lock_contender)

        for tag in (30, 34, 36, 35, 31, 32, 33, 37, 20):
            def crash(root, tag=tag):
                directory = self.copy(root)
                with Session(self.image, directory, root / "interrupted", mode=3, gates=True) as owner:
                    observed = owner.pause(tag)
                    assert owner.kill()["exit_code"] == -signal.SIGKILL
                return {"observed_gate": observed, "physical_power_loss": False,
                        **self.recover(root, directory)}
            self.case(f"recovery-sigkill-{tag}", crash)

        for tag in (30, 34, 36, 35, 31, 32, 33, 37, 20):
            def gate_eof(root, tag=tag):
                directory = self.copy(root)
                uncertain = int(tag not in (30, 20))
                with Session(self.image, directory, root / "gate-eof", mode=3, gates=True) as owner:
                    owner.pause(tag)
                    os.close(owner.go); owner.go = None
                    row = owner.finish(71 if uncertain else 70)
                    assert row["diagnostic"]["uncertain"] == uncertain
                return {"actual_failure": "explicit gate pipe EOF", "unknown_initialization": bool(uncertain),
                        "filesystem_eio_injected": False, **self.recover(root, directory)}
            self.case(f"recovery-gate-eof-{tag}", gate_eof)

        def resource_cut(root):
            directory = self.copy(root, "published", 7)
            with Session(self.image, directory, root / "file-limit", mode=3, file_limit=16) as owner:
                row = owner.finish(71)
                assert row["diagnostic"]["uncertain"] == 1
            assert (directory / "FORMAT").read_bytes() == FORMAT[:16]
            return {"real_file_size_limit": 16, "retained_exact_prefix_bytes": 16,
                    **self.recover(root, directory)}
        self.case("actual-format-partial-pwrite-and-limit", resource_cut)

        # These are controlled file-object interference tests, not a claim of
        # safety against an arbitrary continuously hostile same-UID writer.
        interference = (("format-create-collision", 34, None, "FORMAT", 71),
                        ("head-noreplace-collision", 32, None, "HEAD", 71),
                        ("format-appeared-before-open", 30, None, "FORMAT", 66),
                        ("format-disappeared-before-open", 30, 17, "remove", 66))
        for label, tag, prefix, target, expected in interference:
            def collision(root, tag=tag, prefix=prefix, target=target, expected=expected):
                directory = self.copy(root, prefix=prefix)
                with Session(self.image, directory, root / "interleaving", mode=3, gates=True) as owner:
                    owner.pause(tag)
                    if target == "remove":
                        (directory / "FORMAT").unlink()
                    else:
                        write_file(directory / target, b"old-object-must-not-be-overwritten")
                    before = snapshot(directory)
                    owner.resume()
                    row = owner.finish(expected)
                    assert row["stdout_bytes"] == 0
                    assert snapshot(directory) == before
                return {"existing_objects_not_overwritten": True, "exit_code": expected,
                        "actual_native_open_or_noreplace_failure": True}
            self.case("interleave-" + label, collision)

        for label, tag, prefix, filename in (("validated-format-prefix", 35, 17, "FORMAT"),
                                             ("published-head", 37, None, "HEAD"),
                                             ("published-format", 37, None, "FORMAT")):
            def readback(root, tag=tag, prefix=prefix, filename=filename):
                directory = self.copy(root, prefix=prefix)
                with Session(self.image, directory, root / "changed-before-readback", mode=3, gates=True) as owner:
                    owner.pause(tag)
                    path = directory / filename
                    raw = bytearray(path.read_bytes()); raw[0] ^= 1; path.write_bytes(raw)
                    owner.resume()
                    if tag == 35:
                        # Let the real remaining write/fsync/rename gates run;
                        # the refusal must come from the native final readback.
                        owner.pause(37)
                        owner.resume()
                    row = owner.finish(71)
                    assert row["stdout_bytes"] == 0
                    assert row["diagnostic"]["uncertain"] == 1
                before = snapshot(directory)
                with Session(self.image, directory, root / "corrupt-state-not-repaired", mode=3) as owner:
                    owner.finish(66)
                    assert owner.row["stdout_bytes"] == 0
                assert snapshot(directory) == before
                return {"actual_pre_receipt_readback_refusal": True,
                        "opened_receipt_delivered": False, "subsequent_corruption_refused_unchanged": True}
            self.case("readback-refuses-" + label, readback)

        def complete_refusal(root):
            directory = self.copy(root)
            self.recover(root, directory)
            before = snapshot(directory)
            with Session(self.image, directory, root / "mode-three-refused-after-commit", mode=3) as owner:
                owner.finish(65)
            assert snapshot(directory) == before
            return {"mode_three_cannot_reinitialize_committed_namespace": True}
        self.case("refuse-committed-transaction-namespace", complete_refusal)

        self.builder.check_pin()
        report = {"schema": "trnm.hia.genesis-recovery-qualification.v1",
                  "status": "PASS" if all(r["status"] == "PASS" for r in self.results) else "FAIL",
                  "build": self.build, "passed": sum(r["status"] == "PASS" for r in self.results),
                  "total": len(self.results), "controls": self.results,
                  "scope": "explicit mode-3 recovery of a unique context-bound genesis and exact FORMAT prefix",
                  "runtime_proxy": False, "original_modes_one_and_two_changed": False,
                  "source_inputs_stable": True, "whole_node_replaced": False,
                  "not_qualified": ["physical power loss", "hostile same-UID mutation", "filesystem EIO",
                      "whole-directory rollback", "original service budgets", "typed Node state/reorg/replay/outbox"]}
        write_json(self.output / "report.json", report)
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = Qualification(new_output(args.output)).run()
    print(json.dumps({"status": report["status"], "passed": report["passed"],
                      "total": report["total"], "output": str(args.output)}))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
