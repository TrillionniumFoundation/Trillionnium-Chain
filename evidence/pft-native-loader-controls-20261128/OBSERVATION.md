# Native loader first controls

The first and only local engineering gate ran on 2026-11-28 from 02:50:22 to
02:50:30 UTC. All **9 new loader controls passed**, with the existing 11
standalone arithmetic controls explicitly filtered out. The one offline Cargo
compile-and-test command exited 0 after 7.654649710 seconds under a single
120-second deadline. This duration is an engineering observation, not a benchmark.

The core layer contains four controls; this layer adds five adversarial groups.
The combined frozen source was tested once before publishing either layer. The
base layer omits only this layer's test-module declaration; the complete test
source SHA in `FIRST_GATE_ORIGINAL.json` matches the final stacked source.
No controls were replayed to accommodate the split or formatting.

`FIRST_GATE_ORIGINAL.json` retains the exact native receipt bytes.
`FIRST_OUTPUTS.json` preserves original stdout/stderr as SHA-bound base64,
including whitespace. The effective Cargo fingerprint records `-D warnings`.
serde_json 1.0.149 resolved `arbitrary_precision`, `default`, and `std`.
`DEPENDENCY_PREPARATION.json` records the 21 dependency versions/checksums,
all equal to the upstream Chain lock; the harness used its own target, Cargo home
and vendor copies made from read-only verified cached archives, without network.
The first read-only cache probe had an iteration-type error before compilation;
`PREPARATION_FIRST_FAILURE.json` retains it separately from the successful gate.

The HARNESS files and `harness.rs` retain the minimal build inputs. Their original
layout and every source SHA are in the native receipt; `native_first_gate.py`
retains the executed bounded launcher. Preparation and control records remain
separate. The library's real module declaration is committed in the parent;
whole-crate Cargo/Clippy/graph/source checks remain distinct remote CI gates.

The numerical profile decodes JSON numbers to binary64 before checking LE pins.
A nonzero decimal too small for binary64 may decode to signed zero; this is not
a claim to reject every mathematical decimal underflow. Declared canonical JSON
strings are hashed verbatim, without reproving Python float canonicalization.
The expected output [2,-5,-4,10] is a fixed manual synthetic octet oracle.
Only public synthetic packets were used. No historical candidate/feature packet,
labels, DEV or final data were read, and no historical XW was rerun.

Passing means retained byte pins and bounded declared semantics matched. It
does not prove pin provenance/signatures, training or Gram truth, normal
equations, PSD, usefulness, real user B, permission, native adoption, int257/TMT1
compatibility, FinalUse, payment, reward, production or consensus.
