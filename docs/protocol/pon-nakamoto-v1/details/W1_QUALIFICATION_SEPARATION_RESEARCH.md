# W1 qualification separation and numerical boundary research

This isolated research entry implements bounded experiments for the
[sole development plan](../../../development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md).
It preserves [W1](WORK_PROFILE.md), its canonical bytes, target arithmetic and
all existing production-qualification flags. Baseline source is
`630f871293e48588e0a1ceae7ceb64973d3ec31d`; each generated report records the
hashes of the specific source and fixture files it reads. New source must be
re-executed and separately bound by the integrating owner.

## Executable scope

- [Qualification experiment](../../../../formal/pon-nakamoto-v1/experiments/qualification_separation.py)
  imports the retained Python PNH1/PNW1 wire/work oracles, strict Ed25519 verifier,
  required-target work function and actual SQLite contract ledger. An optional
  `pon_work_io` binary cross-checks the same work cases in native code. Without
  that explicit binary, native W1 verification is reported as not executed.
- [Numerical experiment](../../../../formal/pon-nakamoto-v1/experiments/numerical_boundary.py)
  compares an independent exact rational IEEE decoder/quantizer with a compiled
  source slice of the original private Rust quantizer. It also measures exact
  arithmetic error and finite-field rank on transformed historical maintenance
  matrices. These are operator experiments, not model training or convergence.
- [Qualification controls](../../../../formal/pon-nakamoto-v1/experiments/test_qualification_separation.py)
  and [numerical controls](../../../../formal/pon-nakamoto-v1/experiments/test_numerical_boundary.py)
  exercise the real interfaces and distinguish the observations below.

The programs do not grant model, installation, reward, hardness or public-network
authority. They do not join a maintenance proof and a historical Hepta report
into one fictional end-to-end job. They do not execute Groth16 or assert a
third-party Ed25519 rerandomization exploit.

## Statement binding, tickets and repeat effects

The qualification experiment first verifies the committed
[accepted-block vector](../../../../formal/pon-nakamoto-v1/vectors/accepted-block/expected.json),
then admits it through the original SQLite ledger. It checks:

1. The exact ticket is accepted at its inclusive threshold; a target one unit
   lower is rejected.
2. Extra/missing proof bytes, another profile magic and noncanonical A/B/product
   words are rejected. Canonical but wrong A/B values fail task binding; a wrong
   product with the original trace reaches the product check and is rejected.
3. A bounded search deliberately produces a fabricated trace that satisfies the
   real preliminary ticket target. The complete verifier and ledger reject its
   transcript, and retained chainwork is unchanged.
4. Every field of the actual header schema is changed individually: network,
   parameters, parent, height, timestamp, target, miner, transactions, state,
   receipts, work task and nonce. The old proof cannot establish the new
   statement, and ledger admission leaves stored blocks/chainwork unchanged.
5. Three repeated admissions of the identical accepted block return the original
   block identity. They do not create three additional units of credited work.

The relation-only header-mutation controls use a maximum verifier threshold to
reach transcript checking without an incidental early lottery rejection. This
does **not** make a mutated header a valid block: the separate SQLite admission
control uses that header's actual target and all original contextual checks.

### Legal signature variation is not a free W1 lottery

Using only the public development key-zero seed, the experiment constructs two
different, valid Ed25519 signatures for the same unsigned command. Both pass the
retained strict verifier. This requires the signing key; it is not public
signature malleability. The negative controls still reject `S + L` and a changed
message.

The two signed transactions have different transaction IDs and receipt roots,
but identical application state when executed independently from the same
parent. Because these roots enter the W1 header, the challenge changes and the
old proof is rejected with `TRANSCRIPT`. Attempting to execute both commands
against one account sequence is rejected with `NONCE`, both within one block
and after the first command has executed.

This is a useful regression for future proof envelopes: raw envelope identity
may differ while the logical command is unchanged. A successor must explicitly
specify which object controls the lottery and which object controls payment
deduplication. Hashing freely rerandomizable proof bytes can create extra cheap
lottery attempts; checking the proof's public statement alone does not remove
that freedom. Current W1 has a canonical exact transcript rather than such an
independently randomized proof wrapper.

## Four separate facts: settlement, usefulness, installation and chainwork

The experiment executes a real development `reserve_task -> record_receipt ->
accept_task` sequence, puts it into a newly proved W1 block and admits the block.
The receipt names a computed maintenance output. The service contract reaches
`settled`, its remaining escrow becomes zero, and no model contribution,
evaluation or release record appears. `model:current` remains the genesis
value. Credited work follows the required target, independently of service
payment. This is a ledger contract fixture, not an ordinary Hepta training run.

Separately, the program reads the retained
[five-control observation](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/five-controls.json)
and [original-owner observation](../../../../evidence/pon-upgrade-implementation-20261018/native-rounds/real-model-owner-controlled-20261025/original-native-owner-results.json).
It recomputes the gain from the recorded exact score fractions instead of
accepting a caller-supplied positive-gain flag. The historical candidate and
strongest evaluation controls both score `1/2`, so the gain is zero, despite
successful controlled process phases. The original owner reports a successful
signed neural read/unload over peer-fetched upstream weights; that progress is
preserved. The same evidence explicitly does not report a selected complete
Cell release installation or CURRENT update. The research program neither
reruns those external artifacts nor promotes their historical authority.

Consequently the research observation must retain separate answers to:

| Question | Evidence used here | Limit |
| --- | --- | --- |
| Is this W1 statement valid? | Full retained verifier and accepted vector | Correct relation does not prove cheapest production cost |
| Was a service contract settled? | Actual signed commands and SQLite state | A receipt/settlement does not establish learned utility |
| Did the model beat the controls? | Recomputed historical exact fractions | Zero gain remains zero; no new training or future-data evaluation |
| Was a selected model installed? | Historical original-owner report | Partial peer-weight use is not selected complete-release installation |
| How much chainwork was credited? | Actual ledger row and required-target arithmetic | Neither scores nor service fees replace the work predicate |

## Numerical experiment and source-slice boundary

The optional native probe extracts `require` and `quantize` exactly from
[checkpoint_tile_material_v1.rs](../../../../trillionnium/crates/trnm-mvcc-fee/src/checkpoint_tile_material_v1.rs)
and compiles those unchanged function bodies into a small, bounded stdin/stdout
driver. It records the complete original source hash, both slice hashes,
generated driver hash, compiler version, binary hash and all raw input/output.
It does **not** compile the complete crate or replay the complete checkpoint
policy, signed source admission, runtime or file/material ownership checks.
This probe cannot qualify FP8, Pearl or an arbitrary floating-point successor.

The independent oracle decodes BF16/FP32 bit patterns into exact rational
numbers, applies the selected power-of-two scale, rounds ties to even, then
clips symmetrically. The bounded corpus includes signed zeros, subnormals,
normal values, maximum finite values, both infinities, quiet/signaling NaN
patterns, one-ULP neighbors around ties/clipping thresholds, and deterministic
hash-selected patterns. It includes the original `(mantissa=7, scale=14,
clip=32767)` and `(23,4,128)` parameters plus explicitly isolated scale controls.

The scale grid transforms the committed `matrices.bin` into exactly representable
`A_integer / 4096` BF16 values and `B_integer / 64` FP32 values. These transforms
are declared experimental inputs. They are not claimed to be a neural
checkpoint or an activation trace. Exact unquantized contraction is compared
with the decoded integer contraction using rational errors, not an unspecified
floating tolerance. A separate transform `A_integer / 2`, `B_integer` exposes
clipping error. No statistical generalization or convergence conclusion is
drawn from these inputs.

Token-padding controls retain 1, 2, 8, 16, 32 or 64 columns and set the others to
zero. Rank is computed exactly over the W1 prime field. The rank cannot exceed
the number of retained columns, and padded product columns remain exactly zero.
This identifies source structure that a cost model must include. It is not a
measured speedup or proof that the complete challenge-bound transcript is free.

Finally, the experiment expands EL/ER from the real committed W1 challenge and
compares 32 exact eight-term field dot products with direct FP32 and FP64
multiply/accumulate substitutions. These controls demonstrate why a floating
kernel cannot silently replace the existing modular arithmetic while preserving
W1. They do not rule out exact integer limb algorithms or other valid producers.

### Signed decoding must be re-established for new ranges

The existing weight/activation clips have the worst-case integer bound
`64 * 32767 * 128 = 268427264`, below `floor(q/2) = 2147483645`.
This permits unambiguous centered signed decoding for that bounded contraction.
If both operands instead allow magnitude 32767, the bound becomes
`68715282496`; reducing that positive example modulo q and decoding it as a
centered signed integer yields `-4194160`. It remains a valid field residue but
is not the original integer contraction. Increasing scale/range therefore needs
a fresh overflow/quantization proof or a different arithmetic representation.

## Reproduction

Run the repository preflight before executing the research or building the probe:

```sh
bash scripts/project-preflight.sh
python formal/pon-nakamoto-v1/experiments/qualification_separation.py \
  --output /tmp/w1-qualification/separation.json
python formal/pon-nakamoto-v1/experiments/numerical_boundary.py \
  --output /tmp/w1-qualification/numerical.json \
  --rustc /absolute/path/to/rustc \
  --raw-directory /tmp/w1-qualification/quantizer-probe
python -m unittest discover -s formal/pon-nakamoto-v1/experiments \
  -p 'test_qualification_separation.py' -v
python -m unittest discover -s formal/pon-nakamoto-v1/experiments \
  -p 'test_numerical_boundary.py' -v
```

For optional native W1 verification, add `--native-work
/absolute/path/to/pon_work_io` to the qualification experiment. That executable
must be built from the exact reviewed source by the integration owner; the
report records its hash but a file hash alone is not source-build provenance.
The program refuses ambient `TRNM_NATIVE_WORK`, `TRNM_NATIVE_EXECUTOR` and
`TRNM_PON_EVALUATION_POLICY` overrides rather than silently changing the retained
fixture's meaning. Omitting `--rustc` records that the native quantizer was not
executed; it does not synthesize a passing native observation. Existing output
files/directories are not overwritten.

## Initial bounded observation

The initial local execution on the stated baseline observed 25 W1 relation cases
with the two intended positives and 23 intended rejections, all 12 header-field
admission negatives, unchanged work for three duplicate admissions, and the
expected signature/account-sequence separation. Native W1 execution was not
requested in that initial observation. The original quantizer source slice
compiled with Rust 1.95.0 and matched the independent oracle on all 735 cases.
The two regression suites passed 8 and 9 tests respectively.

On the declared maintenance transforms, the `(14,4)` scale pair has maximum
absolute contraction error `199/131072`; `(14,6)` is exact for these specially
representable inputs. These numbers are not predictions of LLM quality. Padded
column counts `1,2,8,16,32,64` yield ranks `1,2,8,16,32,37`; the underlying
maintenance A matrix has rank 31 in the evaluated grid. Both direct FP32 and
FP64 substitutions disagree with all 32 selected W1 field products. Complete
raw observations, including hashes and probe transcripts, belong in the
integrating owner's separate evidence capture; this document is not their
signed source-qualified acceptance receipt.

These results close a bounded correctness/interpretation regression only.
Minimum effective work cost, economic attack resistance, public-service
availability, full training convergence, independent model quality, ordinary
selected-release installation and production qualification remain separate.
