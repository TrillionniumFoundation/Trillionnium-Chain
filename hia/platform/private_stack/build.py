"""Source-bound native private-stack adapter; no hosted ISA generation."""
from __future__ import annotations

from pathlib import Path
import sys

from hia.platform.build import Build as PinnedBuild, inspect_executable, sha256

HIA = Path(__file__).resolve().parents[2]
RELATIVE = "platform/private_stack/"
INPUTS = tuple(RELATIVE + name for name in ("README.md", "abi.json", "build.py", "linux_emitter.hepta"))
PREFIX_BYTES = 288
MAX_IMAGE_BYTES = 524288


class Guard:
    """Wrap a trusted native f0 kernel, preserving the six-register buffer ABI.

    The caller must capture INPUTS in its own complete source set as well.
    This class rechecks its independent captures before and after each stage.
    """

    def __init__(self, pinned: PinnedBuild):
        self.pinned = pinned
        self.inputs = {}
        for relative in INPUTS:
            path = HIA / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError("Missing or symlinked private-stack source: " + relative)
            self.inputs[relative] = path.read_bytes()
        sys.path.insert(0, str(pinned.toolchain))
        from hepta.hia_agent_assembly import assemble_program
        source = self.inputs[RELATIVE + "linux_emitter.hepta"]
        core = assemble_program(source).as_dict()
        self.core = {"functions": len(core["functions"]),
            "blocks": sum(len(f["blocks"]) for f in core["functions"]),
            "ops": sum(len(b["ops"]) for f in core["functions"] for b in f["blocks"])}
        self.check_sources()
        self.emitter = pinned.stage(pinned.compiler, source, "compile-private-stack-emitter")
        inspect_executable(self.emitter)
        self.check_sources()
        self.kernels = {}

    def check_sources(self):
        self.pinned.check_pin()
        for relative, raw in self.inputs.items():
            path = HIA / relative
            if path.is_symlink() or not path.is_file() or path.read_bytes() != raw:
                raise ValueError("Private-stack source changed: " + relative)

    def wrap(self, raw: bytes, name: str) -> tuple[bytes, dict]:
        if not name or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-_" for c in name):
            raise ValueError("Invalid private-stack stage label")
        if name in self.kernels or not 0 < len(raw) <= MAX_IMAGE_BYTES:
            raise ValueError("Duplicate or out-of-profile native kernel")
        self.check_sources()
        protected = self.pinned.stage(self.emitter, raw, "guard-" + name)
        if len(protected) != PREFIX_BYTES + len(raw) or protected[PREFIX_BYTES:] != raw:
            raise ValueError("Private-stack emitter changed the captured native kernel")
        self.check_sources()
        receipt = {"raw_image_sha256": sha256(raw), "raw_image_bytes": len(raw),
            "guarded_image_sha256": sha256(protected), "guarded_image_bytes": len(protected),
            "prefix_sha256": sha256(protected[:PREFIX_BYTES]), "prefix_bytes": PREFIX_BYTES,
            "kernel_bytes_preserved": True, "private_stack_bytes": 1048576,
            "guard_page_bytes_per_side": 4096, "late_cleanup_error_forbids_output_publication": True,
            "async_abort_and_input_seed_owner_qualified": False}
        self.kernels[name] = receipt
        return protected, receipt

    def receipt(self):
        self.check_sources()
        return {"schema": "trnm.hia.private-stack-build.v1", "status": "PASS",
            "source_inputs": {p: {"bytes": len(raw), "sha256": sha256(raw)} for p, raw in sorted(self.inputs.items())},
            "source_inputs_stable": True, "core": self.core, "emitter_sha256": sha256(self.emitter),
            "kernels": self.kernels, "runtime_hosted_code": False,
            "literal_isa_is_a_separate_trusted_boundary": True,
            "whole_key_owner_qualified": False}
