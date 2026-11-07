# W1 fixed binary, generated constraints, and encoding audit

Date: 2026-11-07. Base source: `7150d96a2112875b4afcf3023361a5cef4a0e4b1`.

This follow-up independently reconstructs the fixed v2 guest image and interprets
the generated constraint expressions. It closes three specific implementation
facts: the saved composite binary produces the configured image ID, its embedded
kernel equals the locked release binary, and the two generated constraint DAGs
have trace-variable degree at most five. It does not establish compiler
correctness, intended program semantics, valid trace reachability, or a complete
QROM theorem. The earlier
[implementation map](W1_QROM_IMPLEMENTATION_MAP_20261107.md) remains a fixed
historical record; its contract and scripts are unchanged.

The executable checks are in
[w1_qrom_semantics_audit.py](../../scripts/w1_qrom_semantics_audit.py), with
[22 regression tests](../../scripts/ci/test_w1_qrom_semantics_audit.py).
The full [result](../../evidence/pon-w1-qrom-semantics-20261107/report.json)
includes all loaded page digests, selected upstream member hashes, actual
encoding vectors, operation counts and qualification flags.

## 1. Source and artifact identities

The new [evidence directory](../../evidence/pon-w1-qrom-semantics-20261107/README.md)
carries six complete release `.crate` archives. The audit verifies each archive
against a hardcoded Cargo checksum, verifies its VCS identity, and compares its
package/checksum to the corresponding entries in the verifier, guest and prover
lockfiles. `risc0-build` is checked in the host prover lockfile only. This is a
targeted source check, not a claim that the entire Cargo graph was rebuilt.

| Package | Version | VCS commit | Checked contribution |
| --- | --- | --- | --- |
| `risc0-binfmt` | 3.0.5 | `8c215e2f4ccdd935f0517bf05d90f1ae032840a9` | Composite decoding, ELF loading, memory hashing, final tagged hash |
| `risc0-zkos-v1compat` | 2.2.3 | Same `8c215e2f…` commit | Published kernel ELF and associated source |
| `risc0-build` | 3.0.3 | `fba0c0179f0125afe23bd15eb4c34428aacf5705` | Source path assembling user ELF and kernel ELF into `ProgramBinary` |
| `risc0-zkp` | 3.0.5 | Same `8c215e2f…` commit | `PolyExtStep` executor and verifier context |
| `risc0-circuit-recursion` | 4.0.5 | Same `8c215e2f…` commit | Generated recursion constraint DAG, taps, public/challenge dimensions |
| `risc0-circuit-rv32im` | 4.0.5 | Same `8c215e2f…` commit | Generated RV32IM constraint DAG, taps, public/challenge dimensions |

Poseidon2 arithmetic comes from the earlier independently implemented
[control-tree helper](../../scripts/w1_control_tree_audit.py). This audit checks
the helper's complete source digest and compiles those exact bytes. It also
checks the complete compressed source snapshot digest and the helper's fixed
upstream source hashes. The memory-specific input/output conventions are
implemented separately. No upstream Rust prover or verifier is invoked by this
Python audit.

The saved `guest.bin` is 375,928 bytes, with SHA-256
`25718312ec3c6f5219d832e3516adfb5f82983156f669c5e7daa15bd22d1798f`.
The source of the configured v2 `IMAGE_ID` is independently pinned before its
eight words are compared with the reconstructed result.

## 2. Composite binary to initialized memory to image ID

The file is a version-1 **R0BF composite binary**, not a standalone ELF. Its
fixed header declares `V1Compat` ABI version `1.0.0`. The user ELF starts at byte
32 and occupies 343,504 bytes; the remaining 32,392 bytes are the kernel ELF.
The kernel bytes exactly equal `elfs/v1compat.elf` in the verified
`risc0-zkos-v1compat-2.2.3.crate`. Their SHA-256 is
`7ffd942e4e8babd771094f549ad080cfea8ecb2c05c986e275c011f41979d921`.
That equality identifies the shipped kernel binary; it is not a reproduction of
the kernel compilation.

The reconstruction follows `risc0-binfmt/src/elf.rs` and `src/image.rs`:

1. Decode the fixed composite header and separate the two ELFs.
2. Load their little-endian ELF32 RISC-V executable `PT_LOAD` segments in table
   order. Later segment words replace earlier words. Uninitialized memory is
   zero; partial words follow the source's four-byte loop.
3. Write the user entry point at `0x00010000`, merge user words over kernel
   words, then write the kernel entry point at `0xffff0210` and kernel mode `1`
   at `0xffff0214`.
4. Hash 1,024-byte memory pages and a sparse depth-22 binary tree covering the
   32-bit byte-address space.
5. Apply the SHA-256 tagged `risc0.SystemState` encoding to the resulting root,
   with the outer state PC equal to zero.

In the actual artifact, the user entry is `2168964` and the kernel entry is
`3221225472`. The two ELFs both load header words in the low address region;
the prescribed merge replaces 69 kernel words with user words. The complete
initialized image contains 51,507 loaded words in 208 pages. The resulting
normal-form memory root is:

```text
eaef1e2d046026053790dd77bdafe629eddf1a12c35190385eebf8417c7ae964
```

The final image ID is:

```text
7b8fb87437a9f1c308909d6b8e27655a3190ae04d2b11a2fa12ef111941c0dff
```

Its little-endian words exactly match the fixed verifier constant:

```text
[1958252411, 3287394615, 1805488136, 1516578702,
 78549041, 790278610, 301018785, 4279049364]
```

Before checking this artifact, the script reproduces the upstream zero-page,
zero-memory and nonzero kernel-memory known answers. The last vector exercises
address placement and suspend fields as well as hashing. This gives an
independent cross-check beyond merely comparing two copies of the configured
image constant.

The Python parser deliberately supports a bounded subset containing this
artifact: the fixed R0BF header, little-endian ELF32/RISC-V executable headers,
at least one load segment, and a limit on expanded words. Rejections outside
that subset are audit restrictions. They are not assertions about every input
accepted or rejected by the SDK ELF parser.

## 3. What the image ID commits to

The page and node encodings differ from the control-tree conventions:

| Boundary | Exact convention checked |
| --- | --- |
| Memory page | 512 little-endian 16-bit values; overwrite 16 rate cells and retain 8 capacity cells for each of 32 Poseidon2 permutations |
| Memory internal node | Right child normal-form field words, then left child normal-form field words, then eight zero cells |
| Memory digest output | First eight **normal-form** field elements, serialized as little-endian words |
| Control-tree node | Left then right **Montgomery-encoded** digest words, decoded to field elements before the shared permutation |
| Image ID | `SHA256(SHA256("risc0.SystemState") || memory_root || LE32(0) || LE16(1))` |

The final image ID commits to the initialized loaded memory. A separate file
digest is needed to fix the entire composite file. The audit constructs a
specific example: changing composite byte `190692` from `46` to `47` changes
the full binary SHA-256 to
`b46b55f891276e589e694fe3e09b2999f87868308a3a3e35dd8dd354ea53a954`.
The user entry, loaded word map and kernel bytes remain exactly equal, so the
memory-tree and image-ID inputs remain equal. The audit rejects the modified
file at its independent whole-file digest check. Conversely, flipping the first
byte of the fixed executable user segment changes both the recomputed memory
root and image ID.

The report also carries a concrete alias between two uses of the same
Poseidon2 permutation. Choose normal-form memory left words `1..8` and right
words `9..16`. Give the control hash the Montgomery encoding of `9..16` as its
left input and of `1..8` as its right input. Both operations then present this
same normal-form state to the permutation:

```text
[9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0]
```

The memory result is
`26aef03c2c56af3901843515515a910cb103766734bc58127459504de4c67974`.
The control result is
`7d8cfe153d59f01c8708c11a6550303dab80484b5f4cdc603e52106b1cbe8427`;
decoding its Montgomery words gives exactly the memory result. Thus a theorem
application must account for these shared permutation inputs and differing
serializations. These uses do not automatically supply independent random
oracle domains. This vector constructs neither a valid false receipt nor a
collision attack on the fixed proof profile.

## 4. Generated constraint degree: an arithmetic fact

The audit parses every operation in each fixed generated `PolyExtStepDef` and
abstractly executes its **separate field and mix register banks**. It rejects
unsupported syntax or operations, forward or wrong-bank references, out-of-range
taps/globals and inconsistent returned-register counts. It does not merely count
multiplication operators or trust a declared maximum degree.

The degree variables are trace-tap indeterminates over the extension field.
Public output values, transcript challenges and the constraint-mixing challenge
are fixed coefficients. Constants and global reads have degree bound zero;
trace reads have degree bound one. Addition/subtraction take the maximum of the
input bounds; multiplication adds them. Crucially, `AndCond` includes the degree
of its condition:

```text
AndEqz: tot = chain.tot + chain.mul * inner
AndCond: tot = chain.tot + condition * inner.tot * chain.mul
```

Every `MixState.mul` is independently tracked and remains a trace-constant
coefficient. The executor definitions are supplied by the complete checksum-
verified `risc0-zkp` archive. The arithmetic rules give a degree upper bound by
induction on the generated DAG. They allow cancellations to reduce degree but
never rely on a cancellation to justify a smaller upper bound.

| Generated circuit | Operations | Field registers | Mix registers | Fixed tap count | Returned mixed constraint degree bound |
| --- | ---: | ---: | ---: | ---: | ---: |
| Recursion | 12,359 | 11,130 | 1,229 | 643 | 5 |
| RV32IM | 20,202 | 13,736 | 6,466 | 790 | 5 |

The recursion field-expression bound reaches four; its conditionally mixed
constraints reach five. RV32IM already has field expressions of degree five.
Both complete DAGs have no inverse or division operation. Expansion of an
extension-field multiplication into base-field coordinates is bilinear, so the
extension degree four does not itself multiply these degree bounds by four.

A conditional univariate consequence can now be stated precisely. If every
committed trace polynomial has degree less than `N`, substitution at shifted
points preserves that bound and the mixed constraint numerator has degree at
most `5(N−1)`. **If additionally** that numerator is divisible by the degree-`N`
zerofier `(3X)^N−1`, its polynomial quotient has degree at most `4N−5`; each of
the four interleaved quotient polynomials then has degree less than `N`.

The audit does not prove that an actual trace satisfies that divisibility
premise, that the generated constraints implement the intended VM/program
semantics, or that later DEEP/FRI rational denominators are nonzero. It does not
instantiate an RBR error term. These qualifications remain explicit false
fields in the result. The syntactic degree bound is one usable input to that
remaining analysis.

## 5. Compiled ZKR byte streams and capacity

The companion [ZKR artifact audit](../../scripts/w1_zkr_artifact_audit.py) was
run against the complete official 59,768,781-byte ZIP on the authorized local
runtime. It independently verified SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`,
the value pinned by the checked recursion crate's `build.rs`. The compact
[32-program result](../../evidence/pon-w1-qrom-semantics-20261107/zkr-programs.json)
records each decompressed program's SHA-256, byte count, field-word checks,
row count, catalog control ID, and membership in the default 27-program list.
The large ZIP is supplied separately when reproducing this check.

Every program in the ZIP consists of canonical little-endian BabyBear input
words arranged into complete rows of 23 columns. At the recorded outer
receipt's `po2 = 18`, reserving the source's 1,024 ZK rows leaves 261,120 code
rows. All 27 default named programs satisfy that capacity inequality. Their
row counts range from 112,107 to 261,112. The largest, `join_povw.zkr`, leaves
only eight unused code rows. This is a byte-stream/capacity fact, not a proof
of execution or of an accepted trace at every size.

The artifact result labels its control IDs **declared**, because this stage
does not recompute interpolation, shifted LDE and the FRI code commitment.
Every program has a nonzero code stream; this does not prove that an arbitrary
valid code commitment cannot equal zero. The five extra named programs are
the two ordinary and two PoVW lifts with suffixes 23/24, plus
`test_recursion_circuit.zkr`; they are not added to the default allowlist.

A subsequent, separately recorded
[native reconstruction](W1_ZKR_CONTROL_ID_RECOMPUTATION_20261107.md) now computes
all 27 default byte streams' actual FRI control IDs and rebuilds the allowed
root from those results. All match. The artifact-shape report retains its
original qualification boundary; the later result does not establish compiler
correctness, intended execution semantics, or zero-root exclusion.

The [nine ZKR regressions](../../scripts/ci/test_w1_zkr_artifact_audit.py) check
source context, row/endian/canonical boundaries, over-capacity input, inventory
changes and the recorded observation's qualification flags. They do not
pretend to rehash a ZIP that is absent from the local checkout. Run the actual
full artifact audit explicitly with:

```sh
python scripts/w1_zkr_artifact_audit.py --zkr /path/to/verified.zip
python -m unittest scripts.ci.test_w1_zkr_artifact_audit -v
```

## 6. Remaining semantic obligations

The new conclusions have deliberately narrower scopes than the complete first
and third obligation groups:

| Sub-obligation | Result here |
| --- | --- |
| Fixed v2 composite bytes to configured image ID | Independently recomputed and matched |
| Embedded kernel to locked release kernel | Complete-archive and byte equality checked |
| Fixed generated DAG degree bound | Independently recomputed for recursion and RV32IM |
| Source program to compiled guest/kernel binary | No compiler reproduction or refinement proof |
| Complete ZKR release to 32 named byte streams and default-27 capacity | Full ZIP and per-program digest/shape/capacity checked |
| Recursion source to bytecode or bytecode to FRI control identities | Not established by the artifact-shape stage |
| Intended semantics of all 27 named recursion programs | Not proved by a catalog or uniform AIR degree bound |
| Every allowed/reachable trace | No universal reachability or soundness proof |
| Exclusion of executable control digest zero | Still unproved; the 229 zero padding leaves do not establish exclusion or a valid zero-root program |
| Joint hash/commitment extraction theorem | Shared-input vector recorded; theorem hypotheses still need a joint model |
| Full QROM bound and quantum work-to-chain-weight correspondence | Not established |

Reproduce the new checks from the repository root with:

```sh
python scripts/w1_qrom_semantics_audit.py
python -m unittest scripts.ci.test_w1_qrom_semantics_audit -v
```

`--out` only creates a new result path; it refuses to overwrite an existing
evidence file. Neither command performs network access or a Rust build.
