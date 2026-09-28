#!/usr/bin/env python3
"""Behavioral controls for the read-only fleet probe; no real SSH or fleet."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROBE = Path(__file__).with_name("probe_fleet.py")


class FleetProbeStdinTest(unittest.TestCase):
    def test_remote_probe_cannot_consume_coordinator_stdin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="trnm-probe-stdin-") as tmp:
            root = Path(tmp)
            ssh = root / "ssh"
            ssh.write_text(
                "#!" + sys.executable + "\n"
                "import sys\n"
                "unexpected = sys.stdin.buffer.read()\n"
                "if unexpected:\n"
                "    print('probe inherited coordinator input', file=sys.stderr)\n"
                "    sys.exit(73)\n"
                "print('hostname=fixture')\n"
                "print('kernel=fixture')\n"
                "print('arch=x86_64')\n"
                "print('cpu_threads=1')\n"
                "print('memory_bytes=4096')\n"
                "print('epoch_ns=1')\n"
            )
            ssh.chmod(0o700)
            inventory = root / "inventory.toml"
            inventory.write_text(
                'fleet_id = "stdin-fixture"\nnetwork_scope = "single-lan"\n'
                + "".join(
                    f'[[hosts]]\nid = "fixture-{i}"\n'
                    f'management = "fixture-{i}"\n'
                    'lan_ip = "127.0.0.1"\narch = "x86_64"\n'
                    for i in range(6)
                )
            )
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            completed = subprocess.run(
                [sys.executable, str(PROBE), "--inventory", str(inventory),
                 "--timeout-seconds", "3"],
                input=b"coordinator-must-run-next-command\n",
                capture_output=True, env=env, timeout=20, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            report = json.loads(completed.stdout)
            self.assertEqual(report["failures"], [])
            self.assertEqual(len(report["observations"]), 6)
            self.assertIs(report["geo_wan_evidence"], False)


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(FleetProbeStdinTest)
    )
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("fleet_probe_stdin_boundary=passed real_ssh=false validator_run=false")
