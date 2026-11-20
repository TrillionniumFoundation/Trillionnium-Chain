"""Execute all eight actual HIA loader view admissions and refusals."""
import argparse
import json
from pathlib import Path
import struct
import traceback

from hia.platform.build import run_native
from hia.platform.peer_payload.contract import capture, identity, need

parser = argparse.ArgumentParser()
parser.add_argument("--image", type=Path, required=True)
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(mode=0o700)
image = capture(args.image)
report = {"status": "FAIL", "image": identity(image), "cases": [],
          "whole_payload_owner_qualified": False, "original_service_budget_qualified": False}
try:
    for mode, code in enumerate((0, 78, 78, 78, 78, 0, 0, 78)):
        expected = b"VIEWPASS" if code == 0 else b""
        stdout, receipt = run_native(image, struct.pack("<Q", mode), args.output, "mode-" + str(mode))
        report["cases"].append({"mode": mode, "exit_code": code,
                                "stdout_hex": expected.hex(), "receipt": receipt})
        need(not receipt["timed_out"] and receipt["exit_code"] == code
             and not receipt["stderr_hex"] and stdout == expected, "HIA view admission/refusal differs")
    need(capture(args.image) == image, "HIA view fixture executable changed")
    report.update(status="PASS", accepted=3, refused=5, cases_completed=8)
except BaseException as error:
    report.update(failure=repr(error), traceback=traceback.format_exc())
    raise
finally:
    (args.output / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in {"cases", "traceback"}}, sort_keys=True))
