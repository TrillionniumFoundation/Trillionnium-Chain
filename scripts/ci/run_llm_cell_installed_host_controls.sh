#!/usr/bin/env bash
# CI-only temporary permission fixtures; this never installs a service or owner.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: run_llm_cell_installed_host_controls.sh ABSOLUTE_TRNM_CELL ABSOLUTE_HEPTA_NEURAL_AGENTD" >&2
  exit 2
fi
task_cell=$1
task_host=$2
if [[ $EUID -eq 0 || $task_cell != /* || $task_host != /* || ! -x $task_cell || ! -x $task_host ]]; then
  echo "NOT_CONFIGURED: run as the original nonroot CI caller with both actual absolute native binaries" >&2
  exit 2
fi
task_scripts=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
task_fixture=$(sudo -n mktemp -d /opt/hepta-cell-installed-test.XXXXXXXX)
case "$task_fixture" in
  /opt/hepta-cell-installed-test.????????) ;;
  *) echo "unexpected newly created fixture path" >&2; exit 2 ;;
esac
cleanup_fixture() {
  sudo -n rm -rf -- "$task_fixture"
}
trap cleanup_fixture EXIT

sudo -n python3 - "$task_fixture" "$task_host" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys

root, host = Path(sys.argv[1]), Path(sys.argv[2])
info = root.lstat()
if os.geteuid() != 0 or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or list(root.iterdir()):
    raise SystemExit("only the newly created empty root-owned fixture is accepted")
root.chmod(0o755)
for source, name in ((Path(shutil.which("echo")).resolve(), "native-argv-probe"), (host, "hepta-neural-agentd")):
    destination = root / name
    shutil.copyfile(source, destination)
    destination.chmod(0o555)
# Privilege metadata is placed only on inert, non-loadable bytes. No test execs
# these files and no runnable SUID/capability-bearing binary is introduced.
inert = b"\x7fcontrolled-inert-permission-fixture-not-ELF\0"
for name, mode in (("suid-probe", 0o4555), ("sgid-probe", 0o2555),
                   ("capability-probe", 0o555), ("writable-probe", 0o777), ("linked-probe", 0o555)):
    path = root / name
    path.write_bytes(inert)
    path.chmod(mode)
os.link(root / "linked-probe", root / "linked-probe-alias")
# Linux VFS_CAP_REVISION_2 with only CAP_NET_BIND_SERVICE in permitted. The
# target is deliberately not an executable image; the tested policy must reject
# the presence of this actual security.capability before any exec is possible.
os.setxattr(root / "capability-probe", "security.capability", struct.pack("<IIIII", 0x02000001, 1 << 10, 0, 0, 0))
writable = root / "writable-parent"
writable.mkdir(mode=0o777)
writable.chmod(0o777)
(writable / "native-argv-probe").write_bytes(inert)
(writable / "native-argv-probe").chmod(0o555)
print(json.dumps({"scope": "temporary-installed-image-controls-only", "fixture": str(root),
    "native_sha256": {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                      for name in ("native-argv-probe", "hepta-neural-agentd")}}, sort_keys=True))
PY

HEPTA_INSTALLED_TEST_DIR="$task_fixture" HEPTA_REQUIRE_INSTALLED_FIXTURE=1 TRNM_CELL_BIN="$task_cell" \
  python3 "$task_scripts/test_llm_cell_installed_host.py" -v
