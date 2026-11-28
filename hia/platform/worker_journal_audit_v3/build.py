"""Build the isolated, memory-only named WQX3 qualification artifact."""
import argparse
import json
from pathlib import Path

from hia.platform.worker_audit.build import build_named
from hia.tools.toolchain import HIA_ROOT

HERE = Path(__file__).resolve().parent
SOURCE = HIA_ROOT / "src/worker_agent/journal_audit_export_v3.hepta"
ENTRY = "trnm_worker_journal_audit_export_v3"
LIBRARY = "libtrnm_worker_journal_audit_v3.so"


def build(output):
    # There is intentionally no direct or library fallback for this profile.
    return build_named(output, "selfhost", source=SOURCE, entry=ENTRY, library_name=LIBRARY,
                       exports_map=HERE / "exports.map", header=HERE / "worker_journal_audit_v3.h",
                       schema="trnm.worker-journal-audit-owned-library.v3", extra=(Path(__file__).resolve(),))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    library, receipt = build(p.parse_args().output)
    print(json.dumps({"library": str(library), "entry": ENTRY, "sha256": receipt["artifact_sha256"]}))


if __name__ == "__main__":
    main()
