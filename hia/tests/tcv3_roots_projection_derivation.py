"""Verification of the read-only selection facade's exact TCV3 validation."""
import hashlib
from pathlib import Path

DATA=Path(__file__).resolve().parents[1]/"src/data_availability"
SOURCE=DATA/"cell_version_content_lineage.hepta"
PIN="7c7c7fce77ca3c7286d9195c149469547ee8bc94979478cae79609c228659e10"
BEGIN="block room("
FAIL="block fail("


def derive(raw):
    if hashlib.sha256(raw).hexdigest()!=PIN:
        raise ValueError("published full TCV3 source changed")
    s=raw.decode("ascii")
    validation=s[s.index("fn f0("):s.index(BEGIN)]
    failures=s[s.index(FAIL):s.index("block internal()")]
    return validation,failures
