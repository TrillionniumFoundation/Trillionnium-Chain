#!/usr/bin/env python3
"""Contract attacks on phase placement; these fixtures are not Host observations."""

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_native_phase_host as host


class PhaseHostControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-phase-host-controls-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.control = self.root / "baseline-host-control"
        self.control.mkdir()
        self.job = self.control / "phase-job.json"
        self.binary = self.root / "fixture-elf"
        # Input parser fixture only; this byte string is never executed.
        self.binary.write_bytes(b"\x7fELFcontract-fixture-not-an-executable")
        self.value = {
            "schema": host.PROFILE,
            "phase_path": str(self.root / "baseline"),
            "controller_cgroup": "/system.slice/unique-campaign.service",
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


if __name__ == "__main__":
    unittest.main()
