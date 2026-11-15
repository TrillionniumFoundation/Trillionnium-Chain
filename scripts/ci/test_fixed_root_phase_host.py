#!/usr/bin/env python3
"""Contract attacks on separate ROOT placement; fixtures are not Host observations."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import stat

import run_fixed_root_phase_host as host
import run_native_phase_host as original_host


class FixedRootPhaseHostControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-fixed-root-host-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "baseline-fixed-root-host-control"
        self.control.mkdir()
        self.job = self.control / "root-phase-job.json"
        self.binary = self.root / "fixture-elf"
        # Input parser fixture only; this byte string is never executed.
        self.binary.write_bytes(b"\x7fELFcontract-fixture-not-an-executable")
        self.value = {
            "schema": host.PROFILE,
            "phase_path": str(self.root / "baseline"),
            "controller": {
                "process": {
                    "pid": 31337, "parent_pid": 11, "start_ticks": 1234,
                    "boot_id": "00000000-0000-0000-0000-000000000001",
                    "cgroup": "/system.slice/unique-campaign.service",
                    "executable": host.executable_identity(self.binary),
                },
                "cgroup": {"device": 28, "inode": 29, "uid": 0, "gid": 0, "mode": 0o755},
            },
            "binary_sha256": host.digest(self.binary),
            "state_backend": "authenticated-v1",
            "work_profile": "raw-r14",
            "mode": None,
            "method": 0,
            "seed": ["00"] * 4,
            "business": ["00"] * 21,
        }
        self.write(self.value)

    def write(self, value):
        self.job.write_text(json.dumps(value))

    def test_exact_job_and_raw_bytes_are_bound(self):
        value, digest = host.validate_job(self.job, self.binary)
        self.assertEqual(value, self.value)
        self.assertEqual(digest, hashlib.sha256(self.job.read_bytes()).hexdigest())

    def test_changed_binary_is_not_the_original_test_program(self):
        self.binary.write_bytes(b"\x7fELFchanged")
        with self.assertRaisesRegex(ValueError, "EXACT_PREBUILT_ELF"):
            host.validate_job(self.job, self.binary)

    def test_matching_non_native_program_is_rejected(self):
        self.binary.write_bytes(b"#!/bin/sh\nexit 0\n")
        self.value["binary_sha256"] = host.digest(self.binary)
        self.write(self.value)
        with self.assertRaisesRegex(ValueError, "NATIVE_ELF_REQUIRED"):
            host.validate_job(self.job, self.binary)

    def test_missing_unknown_and_duplicate_fields_fail(self):
        for missing in host.FIELDS:
            value = copy.deepcopy(self.value)
            del value[missing]
            self.write(value)
            with self.assertRaises(ValueError):
                host.validate_job(self.job, self.binary)
        value = dict(self.value, bypass=True)
        self.write(value)
        with self.assertRaises(ValueError):
            host.validate_job(self.job, self.binary)
        self.job.write_text(json.dumps(self.value)[:-1] + ',"schema":"again"}')
        with self.assertRaisesRegex(ValueError, "DUPLICATE_JOB_FIELD"):
            host.validate_job(self.job, self.binary)

    def test_original_denominators_modes_and_profiles_are_required(self):
        mutations = [
            ("seed", ["00"] * 3),
            ("business", ["00"] * 20),
            ("mode", "from-zero"),
            ("state_backend", "fallback"),
            ("work_profile", "no-work"),
            ("method", True),
            ("method", 8),
            ("method", 1),
            ("state_backend", "legacy-v2"),
            ("work_profile", "arithmetic-facts-v1"),
            ("schema", "new-implicit-profile"),
            ("business", ["AA"] * 21),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                job = copy.deepcopy(self.value)
                job[key] = value
                self.write(job)
                with self.assertRaises(ValueError):
                    host.validate_job(self.job, self.binary)

    def test_output_and_binary_symlinks_fail(self):
        for target, label in ((self.job, "job-link"), (self.binary, "binary-link")):
            link = self.root / label
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "REGULAR_EXACT_ABSOLUTE_INPUT"):
                host.validate_job(
                    link if target == self.job else self.job,
                    link if target == self.binary else self.binary,
                )

    def test_phase_cannot_escape_its_owned_control_directory(self):
        for name in (
            "/tmp/baseline",
            str(self.root / ".." / "baseline"),
            str(self.root / "other"),
        ):
            value = dict(self.value, phase_path=name)
            self.write(value)
            with self.assertRaisesRegex(ValueError, "OWNED_PHASE_PATH"):
                host.validate_job(self.job, self.binary)

    def test_no_local_provision_or_command_when_hosted_context_is_missing(self):
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(host.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(
                ValueError, "HOSTED_CI_ONLY_NO_LOCAL_PROVISION"
            ):
                host.outer(self.job, self.binary)
            run.assert_not_called()
        self.assertFalse((self.control / "host").exists())

    def test_unconfigured_optional_systemd_slice_is_not_a_provisioned_parent(self):
        values = dict.fromkeys(host.PROPERTIES, "")
        values.update(
            Id=host.UNIT,
            LoadState="loaded",
            ActiveState="inactive",
            SubState="dead",
            Transient="no",
            Job="0",
        )

        def raw(value):
            return "\n".join(name + "=" + value[name] for name in host.PROPERTIES)

        self.assertEqual(host.unused_parent(raw(values)), values)
        for key, value in (
            ("ActiveState", "active"),
            ("SubState", "running"),
            ("Transient", "yes"),
            ("Job", "123"),
            ("FragmentPath", "/tmp/unreviewed"),
            ("ControlGroup", "/trnmponpublic.slice"),
            ("LoadState", "masked"),
        ):
            changed = dict(values)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                host.unused_parent(raw(changed))
        with self.assertRaises(ValueError):
            host.unused_parent(raw(values) + "\nId=" + host.UNIT)

    def test_wrong_working_directory_and_root_controller_cannot_provision(self):
        repository = self.root / "source"
        repository.mkdir()
        environment = {
            "GITHUB_ACTIONS": "true",
            "CI": "true",
            "GITHUB_WORKSPACE": str(repository),
        }
        for cwd, uid, error in (
            (repository / "package", 1001, "ORIGINAL_CONTROLLER_REPOSITORY_DIRECTORY"),
            (repository, 0, "ORIGINAL_UNPRIVILEGED_CONTROLLER"),
        ):
            with (
                self.subTest(cwd=cwd, uid=uid),
                patch.dict(os.environ, environment, clear=True),
                patch.object(host, "ROOT", repository),
                patch.object(host.Path, "cwd", return_value=cwd),
                patch.object(host.os, "getuid", return_value=uid, create=True),
                patch.object(host.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(ValueError, error):
                    host.outer(self.job, self.binary)
                run.assert_not_called()
        self.assertFalse((self.control / "host").exists())

    def test_service_command_inherits_only_fixed_parent_and_original_program(self):
        command = host.command(self.job, self.binary, "exact.service", 1001, 1001)
        self.assertIn("--slice=trnmponpublic.slice", command)
        self.assertIn("--property=NoNewPrivileges=yes", command)
        self.assertIn("--property=CapabilityBoundingSet=", command)
        self.assertIn("--property=RuntimeMaxSec=300s", command)
        self.assertIn("--property=Nice=10", command)
        self.assertIn("--property=KillMode=control-group", command)
        self.assertNotIn("--scope", command)
        self.assertFalse(
            any(value.startswith("--property=CPUQuota") for value in command)
        )
        self.assertEqual(command[command.index("--binary") + 1], str(self.binary))
        self.assertEqual(command[command.index("--job") + 1], str(self.job))


    def test_root_pressure_job_is_separate_from_original_entry_and_whitelist(self):
        control = self.root / "valid-work-root-fixed-root-host-control"
        control.mkdir()
        job = control / "root-phase-job.json"
        value = dict(self.value, mode="valid-work-root", phase_path=str(self.root / "valid-work-root"))
        job.write_text(json.dumps(value))
        self.assertEqual(host.validate_job(job, self.binary)[0], value)
        with self.assertRaisesRegex(ValueError, "EXACT_PHASE_JOB_SCHEMA"):
            original_host.validate_job(job, self.binary)
        old_control = self.root / "valid-work-root-host-control"
        old_control.mkdir()
        old_job = old_control / "phase-job.json"
        old_value = dict(value, schema=original_host.PROFILE)
        del old_value["controller"]
        old_value["controller_cgroup"] = value["controller"]["process"]["cgroup"]
        old_job.write_text(json.dumps(old_value))
        with self.assertRaisesRegex(ValueError, "OWNED_PHASE_PATH"):
            original_host.validate_job(old_job, self.binary)

    def test_missing_partial_unknown_and_boolean_controller_fields_are_rejected(self):
        mutations = []
        for group, fields in (("process", self.value["controller"]["process"]),
                              ("cgroup", self.value["controller"]["cgroup"])):
            for field in fields:
                value = copy.deepcopy(self.value)
                del value["controller"][group][field]
                mutations.append(value)
        for field in ("pid", "parent_pid", "start_ticks"):
            value = copy.deepcopy(self.value)
            value["controller"]["process"][field] = True
            mutations.append(value)
        for field in ("device", "inode", "bytes", "modified_seconds", "modified_nanoseconds"):
            value = copy.deepcopy(self.value)
            value["controller"]["process"]["executable"][field] = True
            mutations.append(value)
        for identity in ("controller-by-env", {"process": {}}, dict(self.value["controller"], bypass=True)):
            value = copy.deepcopy(self.value)
            value["controller"] = identity
            mutations.append(value)
        for value in mutations:
            with self.subTest(value=value["controller"]):
                self.write(value)
                with self.assertRaises(ValueError):
                    host.validate_job(self.job, self.binary)

    def test_proc_stat_parentheses_do_not_change_pid_or_start_identity(self):
        fields = ["0"] * 20
        fields[0], fields[1], fields[19] = "S", "18", "99"
        raw = "25 (command ) with spaces) " + " ".join(fields)
        self.assertEqual(host.process_stat(raw, 25), (18, 99))
        for changed, pid in ((raw, 26), ("25 (missing start) S 18", 25), (raw, 1)):
            with self.subTest(changed=changed, pid=pid), self.assertRaises(ValueError):
                host.process_stat(changed, pid)

    def test_public_root_traversal_and_partial_controller_groups_are_refused(self):
        for value in ("", "/", "/../escape", "/a//b", "/a/./b", "/trnmponpublic.slice/child"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                host.external_cgroup(value)
        self.assertEqual(host.external_cgroup("/system.slice/exact.service"),
                         Path("/sys/fs/cgroup/system.slice/exact.service"))

    def test_external_launcher_requires_its_actual_parent_and_membership(self):
        identity = self.value["controller"]
        with patch.object(host.os, "getppid", return_value=31338), patch.object(host, "observe_process") as observe:
            with self.assertRaisesRegex(ValueError, "ROOT_LAUNCHER_ACTUAL_PARENT_REQUIRED"):
                host.controller_context(identity, self.binary, require_parent=True)
            observe.assert_not_called()
        with patch.object(host.os, "getppid", return_value=31337), patch.object(host, "bounded_text", return_value="0::/wrong\n"):
            with self.assertRaisesRegex(ValueError, "ROOT_LAUNCHER_CONTROLLER_MEMBERSHIP"):
                host.controller_context(identity, self.binary, require_parent=True)

    def test_controller_pid_reuse_boot_image_parent_or_membership_change_is_rejected(self):
        identity = self.value["controller"]
        for field, changed in (("start_ticks", 1235), ("parent_pid", 12),
                               ("boot_id", "00000000-0000-0000-0000-000000000002"),
                               ("cgroup", "/system.slice/other.service"),
                               ("executable", dict(identity["process"]["executable"], inode=1))):
            actual = dict(identity["process"], **{field: changed})
            with self.subTest(field=field), patch.object(host, "observe_process", return_value=actual):
                with self.assertRaisesRegex(ValueError, "ROOT_CONTROLLER_LIVE_IDENTITY_CHANGED"):
                    host.controller_context(identity, self.binary, require_parent=False)

    def test_controller_group_identity_and_both_resource_limits_are_exact(self):
        identity = self.value["controller"]
        metadata = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_dev=28, st_ino=29, st_uid=0, st_gid=0)
        def contents(path, _limit=16384):
            return {"cpu.max": "400000 100000\n", "memory.max": "17179869184\n"}[path.name]
        path = Path("/sys/fs/cgroup/system.slice/unique-campaign.service")
        with (patch.object(host, "observe_process", return_value=identity["process"]),
              patch.object(host.Path, "lstat", return_value=metadata),
              patch.object(host.Path, "resolve", return_value=path),
              patch.object(host, "bounded_text", side_effect=contents)):
            result = host.controller_context(identity, self.binary, require_parent=False)
            self.assertEqual(result["identity"], identity)
            metadata.st_ino = 30
            with self.assertRaisesRegex(ValueError, "ROOT_CONTROLLER_CGROUP_REPLACED"):
                host.controller_context(identity, self.binary, require_parent=False)
            metadata.st_ino = 29
            metadata.st_mode = stat.S_IFDIR | 0o777
            with self.assertRaisesRegex(ValueError, "ROOT_CONTROLLER_CGROUP_IDENTITY"):
                host.controller_context(identity, self.binary, require_parent=False)
            metadata.st_mode = stat.S_IFDIR | 0o755
            for field, value in (("cpu.max", "400001 100000"), ("memory.max", "34359738368")):
                def wrong(path, limit=16384):
                    return value if path.name == field else contents(path, limit)
                with self.subTest(field=field), patch.object(host, "bounded_text", side_effect=wrong):
                    with self.assertRaisesRegex(ValueError, "ROOT_CONTROLLER_RESOURCE_PROFILE"):
                        host.controller_context(identity, self.binary, require_parent=False)

    def test_f0_does_not_accept_any_new_scalar_or_timing_override(self):
        for name, value in (("refill_ns_per_second", 50_000_000), ("round_offsets_seconds", [12, 18, 24]),
                            ("phase_window_seconds", 60), ("skip_work", True), ("selector", "other")):
            self.write(dict(self.value, **{name: value}))
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "EXACT_PHASE_JOB_SCHEMA"):
                host.validate_job(self.job, self.binary)
        self.assertEqual(host.SELECTOR, "multiprocess_fixed_root_phase_owner_entry")
        self.assertNotEqual(host.PROFILE, original_host.PROFILE)


if __name__ == "__main__":
    unittest.main()
