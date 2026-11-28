# Offline integer-model snapshot artifact

This named Linux x86-64 shared library exposes exactly
`trnm_integer_model_snapshot_load_v1`. It packages the existing pure HIA
[IMD2 entry](../../src/state/INTEGER_MODEL_MATERIAL.md) unchanged. It is not
installed into the Node, and no legacy production path selects it.

The [typed C header](integer_model_snapshot.h) describes the foreign ABI.
It passes three disjoint pointer/extent pairs for request, result and scratch.
The result packs the outer ABI status in its upper 32 bits and the component
status in its lower 32 bits. Output is only meaningful on a zero result:
computed content ID then the exact original ILM2 or ILM3 bytes.

From the repository root, after configuring the exact
[toolchain](../../toolchain.lock.json) and
[selfhost compiler](../../qualification/compiler-binding.json), use:

```sh
python -B -m hia.platform.integer_model_snapshot.build --output /path/to/private-parent/new-build
```

The output must be fresh, outside the checkout, under a private directory
owned by the caller. The build binds source and tool hashes, renames the
native object entry without changing its machine text, and independently
rechecks the final ELF. The strict artifact has one export, no imports or
dynamic library dependencies, no initialization callbacks or search-path
tags, and linked text equal to the emitted text. It uses neither a runtime
forwarder nor a host fallback. This named artifact is **selfhost only**.
A separate direct-compiler negative check observes actual `abort` and
`memset` imports and never links or installs that object. The existing
dual-emitter kernel differential is separate and is not a named-artifact
qualification.

The [offline caller differential](../../tests/test_integer_model_snapshot_caller.py)
links a fresh Rust test executable to the exact named artifact. Genuine
Rust/Serde produces one immutable `BTreeMap<String, Value>` carrying original
application keys and unrelated neighboring rows. The original
`ReadState::scan` and `prefix_rows` select the two namespaces for IMD2.
A bounded **Rust** projection prepares the private frame. There is no claim
of a native State adapter. Original `load_model` reads the same state and
provides the independent result for parity with a one-call HIA result.
Cases outside the private frame are explicitly reported as projection
refusals and are not treated as comparable native results.

The ELF surface and direct refusal tests always run with the pinned toolchain.
The genuine Rust caller requires a trusted matching
`HIA_M06_ORACLE_PREBUILT` target with the original locked Serde/Hex artifacts;
without that dependency configuration, it explicitly skips. No hosted
qualification, general State ownership, cross-target support, storage,
execution, verification, model adoption, Node integration or retirement
is claimed.
