"""Build the separate private raw-journal WQX library, never a runtime bridge."""
import argparse
import json
from pathlib import Path

from hia.platform.worker_audit.build import build_named
from hia.tools.toolchain import HIA_ROOT

HERE = Path(__file__).resolve().parent
SOURCE = HIA_ROOT / "src/worker_agent/journal_audit_export.hepta"
ENTRY = "trnm_worker_journal_audit_export_v1"
LIBRARY = "libtrnm_worker_journal_audit_v1.so"
BACKENDS = ("selfhost",)


def build(output, backend):
    """The direct core is checked only as a fail-closed packaging control."""
    return build_named(output, backend, source=SOURCE, entry=ENTRY, library_name=LIBRARY,
                       exports_map=HERE / "exports.map", header=HERE / "worker_journal_audit.h",
                       schema="trnm.worker-journal-audit-owned-library.v1", extra=(Path(__file__).resolve(),))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=BACKENDS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    opts = parser.parse_args()
    library, proof = build(opts.output, opts.backend)
    print(json.dumps({"library": str(library), "entry": ENTRY, "sha256": proof["artifact_sha256"]}))


if __name__ == "__main__":
    main()
