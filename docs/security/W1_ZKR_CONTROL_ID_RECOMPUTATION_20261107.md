# W1: all 27 compiled recursion programs to the fixed control root

Date: 2026-11-07. Frozen profile source: upstream RISC Zero
`8c215e2f4ccdd935f0517bf05d90f1ae032840a9`, with the repository baseline
`7150d96a2112875b4afcf3023361a5cef4a0e4b1`.

**All 27 default named ZKR byte streams have now been independently converted
to their FRI code commitments, and all 27 results match the fixed control-ID
catalog.** Rebuilding the depth-eight allowlist tree from those computed IDs
and its 229 zero-digest padding leaves gives:

```text
a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56
```

This closes the concrete **fixed compiled bytecode → code commitment → default
named-program control root** sub-obligation. It does not prove what those
programs mean, whether their constraints admit only intended execution traces,
or that no other valid code can have digest zero. Compiler correctness and the
complete QROM argument remain open.

## Evidence and scope

The computation is implemented by a new, independent
[C kernel](../../scripts/w1_zkr_control_id.c) and
[Python driver](../../scripts/w1_zkr_control_id_audit.py). It uses normal-form
BabyBear arithmetic and ordinary coefficient-order NTTs, rather than calling
the SDK's `Program::compute_control_id`. The earlier
[image/DAG/byte-stream audit](W1_QROM_SEMANTICS_AUDIT_20261107.md) and its
reports retain their original stage scopes.

| Record | What it records |
| --- | --- |
| [First bounded join run](../../evidence/pon-w1-qrom-semantics-20261107/control-id-join.json) | One actual program, seven arithmetic KATs, compiler identity, generated constants, native output and timing |
| [Complete 27-program run](../../evidence/pon-w1-qrom-semantics-20261107/control-ids-all27.json) | Every input digest, row shape, computed ID, exact native output, comparison and recomputed final tree root |
| [Execution identity](../../evidence/pon-w1-qrom-semantics-20261107/control-id-execution.json) | Native source/driver/header/binary hashes, the two completed runtime jobs, and result-file hashes |
| [Earlier complete ZIP inventory](../../evidence/pon-w1-qrom-semantics-20261107/zkr-programs.json) | All 32 named byte streams, including the five excluded from the default 27 |

The official ZIP is 59,768,781 bytes and has SHA-256
`744b999f0a35b3c86753311c7efb2a0054be21727095cf105af6ee7d3f4d8849`.
The same digest is fixed by the checksum-verified recursion crate's `build.rs`.
The driver reads the complete ZIP into an immutable byte buffer, verifies that
digest, rejects inventory differences, and only then extracts requested
programs. The large ZIP is an explicit external input when reproducing the
calculation; it is not silently substituted with a catalog or saved result.

The complete 27-program report's SHA-256 is
`48be4b4f4016e90adab07505e27f511232ec4164049c333073ded39a2f462aad`.
The first join report's SHA-256 is
`190841da4d23af81d17783238f403b6894ff1208fdbf5c130d118a28c1a17f0b`.

## Computation reproduced

For each program the matrix has 23 code columns. The run fixes
`N = 2^18 = 262144` rows, matching the recorded outer W1 receipt's size. The
artifact's own rows must fit within `N − 1024`; the remaining code rows are
zero, exactly as initialized in `Program::compute_control_id_inner`. Every
input u32 is checked to be a canonical normal-form BabyBear value.

For one column with values `a[j]`, the implementation computes natural-order
interpolation coefficients:

```text
c[k] = N^(-1) * sum_j a[j] * ROU_REV[18]^(j*k)
```

It multiplies coefficient `k` by `3^k`, pads the coefficient vector to length
`4N`, and evaluates using `ROU_FWD[20]`. Thus the low-degree extension at row
`r` equals the interpolated polynomial evaluated at
`3 * ROU_FWD[20]^r`. This is the same mathematical transform as the pinned
SDK's bit-reversed interpolation buffer, bit-reversed shift exponents,
fourfold repeated expansion, and forward butterfly with the first two levels
skipped. The implementations use different internal coefficient layouts.

At each of the `4N = 1048576` LDE rows, the code-column values are hashed in
their source order. The 23-value leaf hash absorbs the first 16 values, then
the remaining seven plus nine zero rate cells, retaining the eight capacity
cells between the two Poseidon2 permutations. Twenty binary Merkle levels then
hash left child followed by right child. All these operations keep field
elements in normal form internally. The final eight digest elements are
converted to raw Montgomery words and serialized little endian before
comparison with the SDK catalog.

The driver separately validates the returned normal-form root, its Montgomery
serialization, row count, trace exponent, LDE domain size, thread count,
sample shapes and finite timing observations. A native process must finish
successfully and its computed digest must equal the independently loaded,
source-pinned catalog entry. Exact requested-program ordering and counts are
checked after all programs complete.

For the full run, the driver then rebuilds the allowlist tree from the **newly
computed** digests, rather than copying the declared roots into the tree. The
previously pinned independent Poseidon2 control-tree helper supplies this final
depth-eight calculation. The resulting root matches the fixed profile.

The `geometry` object inside each native program record is the preceding
artifact-shape check. Its scope flags still say that geometry alone does not
recompute a control ID. The subsequent `computed_control_id`, native output
and final qualification fields record the stronger commitment reconstruction.

## Calibration and actual execution

Seven independent known-answer checks run before any full program:

1. A 24-element Poseidon2 permutation.
2. The 23-column leaf hash, including its incomplete final rate block.
3. A left/right internal-node hash.
4. An eight-point forward DFT against a direct quadratic-time Python reference.
5. An eight-point inverse DFT, including normalization.
6. A fourfold shifted LDE against that direct reference.
7. A complete nonzero, 23-column, small code commitment with row packing,
   interpolation, shift, leaf hashing and all Merkle levels included.

The first full `join.zkr` run completed with four threads in about 9.45 seconds
and produced:

```text
7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e
```

It matched the fixed join ID, so the same source, generated parameters and
algorithm were used for the full default roster. The full run completed all
27 programs without a control-ID mismatch or a per-program timeout. Each
program ran with four worker threads and a 120-second limit. The sum of the
observed native subprocess wall times was approximately 257.24 seconds. This
is a local reconstruction measurement, not a quantum cost model or a chain
weight calibration.

| Default family | Programs recomputed |
| --- | ---: |
| `identity.zkr` | 1 |
| `join`, `join_povw`, `join_unwrap_povw` | 3 |
| `resolve`, `resolve_povw`, `resolve_unwrap_povw` | 3 |
| `union.zkr`, `unwrap_povw.zkr` | 2 |
| Ordinary RV32IM lifts with suffixes 14 through 22 | 9 |
| PoVW RV32IM lifts with suffixes 14 through 22 | 9 |
| **Total** | **27** |

The actual build used GCC 13.3.0 with `-O3 -std=c11 -fopenmp -Wall -Wextra
-Werror`. The C template, Python driver and generated-header SHA-256 values
are respectively:

```text
b388eeea5ae14ae2595acb1c6c241141d435fca91f72285e43969554dd3d6813
876c262c5f8b0263f9fceb38a8df586d8d98756358e552135da68893b41c78ac
505d0ba904b6acb1e7e3aeb05378d8f5bc1a1fc5b24e54d39cd05baa7dcfee06
```

The resulting native binary's SHA-256 was
`35e645eac7f0681cefa8b98f068d89b9fc2c9dcafd3c994a97d0eccb6ed5adc5`.
These are identities of the observed reconstruction. They are not a formal
verification of the C compiler, generated binary, operating system, or hardware.

The [eight permanent regressions](../../scripts/ci/test_w1_zkr_control_id_audit.py)
compile the kernel and run the known answers, a `po2=11` all-zero code commitment
against an independently constructed constant Merkle tree, malformed input and
resource-limit checks, strict result-field/encoding checks, and a cross-check of
every saved 27-program result against the separate ZIP inventory and computed
final tree. They explicitly reject unavailable compilation rather than skipping
the native checks. CI's small calculations do not claim to repeat the entire
large ZIP computation.

## Qualification boundary

The stronger result establishes a finite, fixed-artifact binding. It supplies
no automatic upgrade for these distinct statements:

| Statement | Status after this computation |
| --- | --- |
| Each of the 27 fixed byte streams has the declared code commitment at `po2=18` | Recomputed and matched |
| The default named-program root is built from those computed commitments | Recomputed and matched |
| Each of those 27 computed commitments is nonzero | Checked for the enumerated artifacts |
| The compiler correctly translated intended recursion source to those bytes | Not proved or reproduced |
| The generated constraints enforce each named program's intended semantics | Not proved |
| Every accepted recursive proof has `po2=18` | Not proved by this run |
| Every satisfying or reachable recursive trace has been characterized | Not proved |
| A different valid code commitment cannot equal zero | Not proved |
| The 229 zero padding leaves cannot admit any valid zero-root code | Still requires a separate argument |
| Joint commitment extraction, RBR/state restoration, and the full QROM reduction apply | Remain open |
| Quantum resource usage corresponds to consensus work or chain weight | Remains a separate obligation |

The all-zero code regression is an arithmetic test vector. Its nonzero root
does not prove that all valid code roots are nonzero, nor does it demonstrate a
valid executable zero-code program. The fixed catalog's finite nonzero check
must not be promoted into a universal zero-root exclusion statement.

To reproduce, supply the exact digest-verified ZIP and a C compiler with OpenMP:

```sh
python scripts/w1_zkr_control_id_audit.py \
  --zkr /path/to/verified.zip --out-dir /tmp/w1-join-recompute \
  --program join.zkr --threads 4 --timeout 120

python scripts/w1_zkr_control_id_audit.py \
  --zkr /path/to/verified.zip --out-dir /tmp/w1-all27-recompute \
  --all-default --threads 4 --timeout 120

python -m unittest scripts.ci.test_w1_zkr_control_id_audit -v
```

Output directories must be new. Per-program observations and process output
are retained before acceptance checks; a failure or timeout cannot produce a
completed full-roster report. No Rust proof generation, recursive bytecode
execution, network fetch, deployment, or consensus activation is performed by
these commands.
