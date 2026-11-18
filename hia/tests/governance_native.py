"""Real isolated native execution of private HIA governance sessions.

The shared worker only seals/loads a native artifact and invokes its byte ABI.
It supplies no governance decisions, state, roles, clocks, or event values.
"""
import os
from pathlib import Path

from .escrow_native import EscrowNative, FAULT_SOURCE
from .native_support import NativeModule

SOURCE = Path(__file__).resolve().parents[1] / "src/governance/guard.hepta"
FIXTURE = SOURCE.with_name("boundary_fixture.hepta")


class GovernanceNative(EscrowNative):
    def __init__(self, *, fixture=False):
        NativeModule.__init__(self, FIXTURE if fixture else SOURCE, byte_exports=("f0",))
        configured = os.environ.get("TRNM_HIA_GOVERNANCE_OUTPUT")
        self.capture_directory = Path(configured).absolute() if configured else None
        self.capture_sequence = 100000 if fixture else 0
