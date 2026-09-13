#!/usr/bin/env python3
"""Offline process regressions for the pinned installer's stdout protocol.

The real shell script, sha256sum, unzip, and installation commands execute.
Only curl is replaced with a local archive transport. A temporary script copy
pins that deliberately inert fixture's digest; the repository's release pin
and version remain untouched. These tests do not qualify the real compiler.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/ci/install_pinned_protoc.sh"
PIN = "3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a"


class InstallerProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        for command in ("bash", "sha256sum", "unzip", "install", "uname"):
            self.assertIsNotNone(shutil.which(command), f"required test tool: {command}")
        self.temporary = tempfile.TemporaryDirectory(prefix="trnm-protoc-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / "transport"
        self.bin.mkdir()
        self.tmp = self.root / "temporary files"
        self.tmp.mkdir()
        self.install_root = self.root / "cache with spaces" / "protoc-29.3"
        self.archive = self.root / "fixture.zip"
        self.script = self.root / "installer.sh"
        self.transport_log = self.root / "transport.log"
        curl = self.bin / "curl"
        curl.write_text(
            '#!/usr/bin/env bash\nset -euo pipefail\n'
            'printf "called\\n" >> "$TRNM_TEST_TRANSPORT_LOG"\n'
            '[[ "${TRNM_TEST_DOWNLOAD_FAILURE:-0}" == 0 ]] || exit 22\n'
            '[[ "${10}" == "https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-linux-x86_64.zip" ]]\n'
            '[[ "${11}" == "--output" && "$#" == 12 ]]\n'
            'cp -- "$TRNM_TEST_ARCHIVE" "${12}"\n', encoding="utf-8"
        )
        curl.chmod(0o755)
        self.env = dict(os.environ)
        for name in ("TRNM_PROTOC_VERSION", "TRNM_PROTOC_INSTALL_ROOT", "BASH_ENV", "ENV"):
            self.env.pop(name, None)
        self.env.update({
            "PATH": f"{self.bin}{os.pathsep}{os.environ['PATH']}",
            "TMPDIR": str(self.tmp), "LC_ALL": "C",
            "TRNM_TEST_ARCHIVE": str(self.archive),
            "TRNM_TEST_TRANSPORT_LOG": str(self.transport_log),
            "TRNM_TEST_DOWNLOAD_FAILURE": "0",
        })
        self.make_fixture()

    def make_fixture(self, *, version: str = "29.3", entry: str = "regular") -> None:
        with zipfile.ZipFile(self.archive, "w") as archive:
            if entry != "missing":
                info = zipfile.ZipInfo("bin/protoc")
                info.create_system = 3
                mode = stat.S_IFLNK | 0o777 if entry == "symlink" else stat.S_IFREG | 0o755
                info.external_attr = mode << 16
                content = "../absent" if entry == "symlink" else (
                    "#!/usr/bin/env bash\nset -euo pipefail\n"
                    '[[ "$#" == 1 && "$1" == "--version" ]] || exit 2\n'
                    f"printf 'libprotoc {version}\\n'\n"
                )
                archive.writestr(info, content)
            archive.writestr("include/test.proto", '// inert installer fixture\n')
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertEqual(source.count(f'ARCHIVE_SHA256="{PIN}"'), 1)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.script.write_text(source.replace(PIN, digest), encoding="utf-8")

    def run_installer(self, **environment: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(self.script), str(self.install_root)],
            env={**self.env, **environment}, text=True, capture_output=True,
            timeout=20, check=False,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result)
        self.assertEqual(result.stdout, "", result)
        self.assertFalse((self.install_root / "bin/protoc").exists())

    def test_cold_install_stdout_is_one_executable_path(self) -> None:
        result = self.run_installer()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.install_root}/bin/protoc\n")
        self.assertIn(": OK", result.stderr)
        self.assertIn("protoc_install=passed", result.stderr)
        self.assertTrue(os.access(self.install_root / "bin/protoc", os.X_OK))
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_workflow_command_substitution_and_environment_record(self) -> None:
        record = self.root / "github-env"
        result = subprocess.run(
            ["bash", "-c", 'set -euo pipefail; '
             'protoc_path="$(bash "$1" "$2")"; '
             'printf "%s\\n" "PROTOC=$protoc_path" >> "$GITHUB_ENV"; '
             '"$protoc_path" --version', "protoc-workflow", str(self.script), str(self.install_root)],
            env={**self.env, "GITHUB_ENV": str(record)}, text=True,
            capture_output=True, timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "libprotoc 29.3\n")
        self.assertEqual(record.read_text(), f"PROTOC={self.install_root}/bin/protoc\n")

    def test_warm_cache_stdout_is_one_path_without_download(self) -> None:
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.transport_log.unlink()
        result = self.run_installer(TRNM_TEST_DOWNLOAD_FAILURE="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"{self.install_root}/bin/protoc\n")
        self.assertIn("protoc_install=already-present", result.stderr)
        self.assertFalse(self.transport_log.exists())

    def test_checksum_mismatch_cannot_emit_path_or_install(self) -> None:
        self.archive.write_bytes(self.archive.read_bytes() + b"corrupted archive")
        result = self.run_installer()
        self.assert_rejected(result)
        self.assertIn("FAILED", result.stderr)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_download_failure_cannot_emit_path_or_install(self) -> None:
        result = self.run_installer(TRNM_TEST_DOWNLOAD_FAILURE="1")
        self.assert_rejected(result)
        self.assertEqual(result.returncode, 22)

    def test_wrong_compiler_version_cannot_emit_path_or_install(self) -> None:
        self.make_fixture(version="29.2")
        result = self.run_installer()
        self.assert_rejected(result)
        self.assertIn("unexpected version", result.stderr)

    def test_missing_executable_cannot_emit_path_or_install(self) -> None:
        self.make_fixture(entry="missing")
        result = self.run_installer()
        self.assert_rejected(result)
        self.assertIn("regular executable", result.stderr)

    def test_symlink_executable_cannot_emit_path_or_install(self) -> None:
        self.make_fixture(entry="symlink")
        result = self.run_installer()
        self.assert_rejected(result)
        self.assertIn("regular executable", result.stderr)

    def test_unsupported_version_is_rejected_before_transport(self) -> None:
        result = self.run_installer(TRNM_PROTOC_VERSION="29.2")
        self.assert_rejected(result)
        self.assertFalse(self.transport_log.exists())

    def test_existing_non_directory_root_is_preserved(self) -> None:
        self.install_root.parent.mkdir()
        self.install_root.write_bytes(b"operator-owned-file")
        result = self.run_installer()
        self.assert_rejected(result)
        self.assertEqual(self.install_root.read_bytes(), b"operator-owned-file")
        self.assertIn("refusing to replace", result.stderr)


class WorkflowCoverageTests(unittest.TestCase):
    def test_deep_ci_truth_executes_installer_regressions(self) -> None:
        checker = (ROOT / "scripts/ci/check_poco_bft_v0_ci_truth.sh").read_text()
        command = 'python3 -B "$root/scripts/ci/test_pinned_protoc_installer_v1.py"'
        self.assertEqual(checker.splitlines().count(command), 1)
        self.assertLess(checker.index(command), checker.index("trnm-native-ci-truth-v1"))

    def test_poco_checks_installer_contract_before_real_install(self) -> None:
        workflow = (ROOT / ".github/workflows/trnm-poco-bft-v0.yml").read_text()
        command = "run: bash ./scripts/ci/check_poco_bft_v0_ci_truth.sh"
        self.assertEqual(workflow.count(command), 1)
        self.assertLess(workflow.index(command), workflow.index("protoc_path="))


if __name__ == "__main__":
    unittest.main(verbosity=2)
