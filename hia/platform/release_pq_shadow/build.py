"""Bind real bounded HIA objects behind a test-only, single-call C bridge."""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from hia.platform.pq_auth.qualification.contract import check_platform_environment
from hia.tests.native_support import NativeModule
from hia.tools.toolchain import HIA_ROOT, build_native

HERE = Path(__file__).resolve().parent
ENTRY = "trnm_release_shadow_v1"
UNITS = {
    "unsigned": "unsigned_candidate", "identity": "pq_role_identity",
    "locator": "pq_signature_set", "message": "pq_signing_message",
    "quorum": "pq_bundle_callback_quorum", "state": "pq_bundle_checkpoint",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def command(args):
    return subprocess.run(args, check=True, capture_output=True, timeout=30,
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).stdout


def require_bridge_symbols(owner, expected, object_sha256, platform_tools):
    """Reject any other object surface, retaining only bounded symbol diagnostics."""
    exports = {ENTRY}
    allowed = expected | {"calloc", "free", "memcpy", "memset"}
    defined, undefined = owner["defined"], owner["undefined"]
    missing_phases, unexpected_imports = expected - undefined, undefined - allowed
    if defined == exports and not missing_phases and not unexpected_imports:
        return

    def preview(symbols):
        return {
            "count": len(symbols),
            "first": [name if re.fullmatch(r"[A-Za-z0-9_.$@-]{1,96}", name)
                      else "<noncanonical>" for name in sorted(symbols)[:8]],
        }

    details = {
        "expected_defined": sorted(exports), "expected_phases": sorted(expected),
        "observed_defined": preview(defined), "observed_undefined": preview(undefined),
        "missing_exports": preview(exports - defined),
        "unexpected_exports": preview(defined - exports),
        "missing_phases": preview(missing_phases),
        "unexpected_imports": preview(unexpected_imports),
        "bridge_object_sha256": object_sha256, "platform_tools": platform_tools,
    }
    raise ValueError("Bridge does not bind the exact private phases: " +
                     json.dumps(details, ensure_ascii=True, separators=(",", ":"), sort_keys=True))


class LinkedShadow(NativeModule):
    """Reuse the bounded disposable worker, never host-load the final image."""
    def __init__(self, backend):
        from hia.tools.toolchain import pinned_toolchain
        check_platform_environment(os.environ)
        pinned_toolchain()
        from hepta.elf_shared_abi import inspect_owned_shared_elf
        from hepta.object_symbols import inspect_object_symbols

        if backend not in ("direct", "selfhost"):
            raise ValueError("Unrecognized emission backend")
        self._temporary = tempfile.TemporaryDirectory(prefix="trnm-release-shadow-link-")
        out = Path(self._temporary.name)
        self.library = out / "linked-shadow.so"
        self.exports = frozenset({ENTRY})
        self.byte_exports = (ENTRY,)
        self.functions = {ENTRY: {"params": [{"type": "readbuf"}, {"type": "mutbuf"}],
                                  "returns": ["u32"]}}
        tools = {n: Path("/usr/bin", n).resolve(strict=True) for n in ("cc", "ld", "objcopy")}
        hashes = {n: sha(p.read_bytes()) for n, p in tools.items()}
        glue = HERE / "bridge.c"
        exports = HERE / "exports.map"
        source_hashes = {p.name: sha(p.read_bytes()) for p in (glue, exports)}
        try:
            entries, objects = {}, []
            for phase, stem in UNITS.items():
                source = HIA_ROOT / "src" / "release_bundle" / (stem + ".hepta")
                original, renamed = out / (phase + "-f0.o"), out / (phase + "-private.o")
                options = {}
                if backend == "selfhost":
                    options = {"compiler": os.environ.get("HIA_NATIVE_COMPILER"),
                               "compiler_sha256": os.environ.get("HIA_NATIVE_COMPILER_SHA256")}
                receipt, _ = build_native(source, original, kind="object", byte_exports=("f0",),
                                           backend=backend, **options)
                own = inspect_object_symbols(original.read_bytes(), "ELF64", 62)
                tag = "trnm_release_shadow_" + phase
                compiled_exports = frozenset(receipt["exports"])
                allowed = {"calloc", "free"} if backend == "selfhost" else {"abort", "memset", "memcpy"}
                if (own["defined"] != compiled_exports or "f0" not in compiled_exports
                        or (backend == "selfhost" and compiled_exports != {"f0"})
                        or not own["undefined"] <= allowed):
                    raise ValueError(f"Unexpected bare phase object surface {phase}: {own}")
                local = sorted(compiled_exports - {"f0"})
                command([tools["objcopy"], "--redefine-sym", "f0=" + tag,
                         *(f"--localize-symbol={name}" for name in local), original, renamed])
                new = inspect_object_symbols(renamed.read_bytes(), "ELF64", 62)
                if new != {**own, "defined": frozenset({tag})}:
                    raise ValueError("Unexpected bound phase object surface")
                original_text, renamed_text = out / (phase + "-raw.text"), out / (phase + "-private.text")
                command([tools["objcopy"], "--dump-section", ".text=" + str(original_text), original, out / "dump-raw.o"])
                command([tools["objcopy"], "--dump-section", ".text=" + str(renamed_text), renamed, out / "dump-private.o"])
                text = original_text.read_bytes()
                if not text or text != renamed_text.read_bytes():
                    raise ValueError("Private-symbol binding changed native machine bytes")
                entries[phase] = {"raw_sha256": receipt["artifact_sha256"], "text_sha256": sha(text),
                                  "linked_sha256": sha(renamed.read_bytes()), "symbol": tag,
                                  "local_scalar_exports": local,
                                  "source_sha256": receipt["chain_migration"]["source_sha256"],
                                  "compiler_wire_sha256": receipt.get("compiler_wire_sha256"),
                                  "fallback_used": receipt.get("claims", {}).get("fallback_used", False)}
                if entries[phase]["fallback_used"] or sha(original.read_bytes()) != entries[phase]["raw_sha256"]:
                    raise ValueError("Phase bytes drifted or used a fallback")
                objects.append(renamed)

            bridge = out / "bridge.o"
            command([tools["cc"], "-std=c17", "-O2", "-Wall", "-Wextra", "-Werror",
                     "-fPIC", "-fvisibility=hidden", "-fno-strict-aliasing",
                     "-fno-ident", "-c", glue, "-o", bridge])
            # The reviewed C stage bridge must import the actual six phase symbols.
            bridge_raw = bridge.read_bytes()
            bridge_sha256 = sha(bridge_raw)
            owner = inspect_object_symbols(bridge_raw, "ELF64", 62)
            expected = {item["symbol"] for item in entries.values()}
            require_bridge_symbols(owner, expected, bridge_sha256, hashes)

            command([tools["ld"], "-m", "elf_x86_64", "-shared", "-z", "defs", "-z", "noexecstack",
                     "-z", "relro", "-z", "now", "--build-id=none", "--hash-style=both",
                     "--version-script=" + str(exports), bridge, *objects, "-lc", "-o", self.library])
            image = self.library.read_bytes()
            dynamic = inspect_owned_shared_elf(image, (ENTRY,))
            if ({p.name: sha(p.read_bytes()) for p in (glue, exports)} != source_hashes
                    or {n: sha(p.read_bytes()) for n, p in tools.items()} != hashes):
                raise ValueError("Link inputs changed")
            self.artifact_sha256 = sha(image)
            self.receipt = {"schema": "trnm.hia.release-shadow-linked.v1", "scope": "qualification-only",
                            "backend": backend, "bridge_language": "C", "bridge_inputs": source_hashes,
                            "bridge_object_sha256": sha(bridge.read_bytes()), "platform_tools": hashes,
                            "units": entries, "artifact_sha256": self.artifact_sha256,
                            "exports": [ENTRY], "dynamic": dynamic, "production_authority": False,
                            "pure_hia_owner": False, "externally_reusable_token": False}
        except BaseException:
            self._temporary.cleanup()
            raise
