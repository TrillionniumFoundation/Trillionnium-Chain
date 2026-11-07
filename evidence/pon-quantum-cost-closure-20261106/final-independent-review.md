# Final independent review: physical schedule checks and preprocessing reuse

Review date: 2026-11-07. Reviewer: `quantum_paper_review`.

## Outcome and scope

No unresolved source blocker remains in the reviewed physical-resource validation changes or the new preprocessing-reuse diagnostic. The review did identify a material fixture-label and coverage error: the original case labeled `parent` changed PNH1 byte 66, which belongs to `parameters`, rather than a parent byte. That evidence could not establish parent coverage even though the resulting shared-prefix block count happened to be the same. The fixture and replay controls now change byte 70, independent wire-field decoding checks the intended field, and the affected evidence has been regenerated while the original artifacts remain preserved.

This review read the source, native encoders, existing targeted test logs, and before/after evidence. It did not modify repository source or repeat the long campaigns. A final repository read observed clean worktree HEAD `c7f0918da82041de62e693b4e6a814b4ca16fe4c`; the source hashes below bind the substantive review. This is not a claim that this reviewer ran the final committed-source integration gate. The root agent owns that replay and release decision.

## 1. Physical estimator: width and depth constraints

The three new necessary constraints in `_validate_count_shape` agree with the current schedule semantics:

| Constraint | Meaning |
| --- | --- |
| `gate_count + 2 * toffoli_count <= qubits * gate_depth` | Every gate occupies at least one wire in an all-gate layer; each Toffoli occupies three distinct wires. |
| `toffoli_count <= (qubits // 3) * toffoli_depth` | A Toffoli layer has capacity for at most `floor(qubits / 3)` disjoint three-wire gates. |
| `direct_t_count <= qubits * direct_t_depth` | A direct-T layer has capacity for at most one direct T operation per wire. |

These are deliberately permissive necessary conditions. The inputs do not separately report CNOT counts, so the first inequality does not invent a second-wire charge for unspecified gates. Passing the inequalities does not certify a realizable circuit, a surface-code layout, or optimal scheduling.

### Agreement with actual circuit metrics

`reversible_components.Circuit.metrics` updates the layer labels of every touched wire, including control wires. Its all-gate layer is one plus the largest incoming label; its Toffoli-depth label propagates the largest incoming label and increments it for a Toffoli. `Circuit.emit` rejects repeated or unknown wires. Consequently, gates with the same all-gate layer cannot share a wire, and Toffolis with the same Toffoli-layer label cannot share a wire. Clifford gates do not increment the Toffoli label, but do propagate dependencies. This distinction is essential: ignoring a gate's Toffoli cost does not erase its wire dependencies.

The current W1 circuit constructor has no direct T gates. Direct T accounting is a separate supported estimator input. The third bound is consistent with its declared wire-exclusive direct-T depth convention. An alternative depth measure that allows shared-wire simultaneous operations or counts a separately optimized decomposition would require a distinct contract, rather than silently reusing these fields.

`Primitive.report` includes the real copy CNOTs and a conservative serial copy depth. `OracleProgram.resources` accumulates wrapped gate counts and conservative leaf depths while its width includes persistent registers and peak reusable scratch. `resource_request` supplies that full logical width to the stages. Conservative upper bounds on the depth of the same declared schedule are compatible with the checks; independently chosen loose ceilings for both count and depth are not a concrete schedule description.

### Serial aggregation, empty schedules, and integer bounds

For stage multiplicities `m_i >= 0`, let `Q = max(Q_i)`. Summation preserves the constraints:

```text
sum(m_i * (G_i + 2 F_i)) <= Q * sum(m_i * D_i)
sum(m_i * F_i) <= floor(Q / 3) * sum(m_i * D_Fi)
sum(m_i * T_i) <= Q * sum(m_i * D_Ti)
```

Thus the checks do not assume all stages run simultaneously, and do not reject legal cumulative depths merely because several sequential stages reuse the same registers. Zero counts and zero depths remain valid. The direct estimator still accepts valid derived totals greater than uint64 up to its existing `MAX_DERIVED = 2**256 - 1`; stage-field validation and derived-total validation keep their different bounds.

The shared validator also closes the previously observed direct-entry bypass: inconsistent count/depth inputs could previously produce an estimate, including nonzero gate count with zero elapsed time. The physical audit's preserved before/after controls show the five inconsistent count shapes and five impossible width/depth shapes rejected after the fixes. This is input-consistency hardening, not physical calibration.

Evidence inspected:

- `physical-cost/report.md` and `physical-cost/width_depth_review.md`.
- `physical-cost/before_physical_counts.log` and `physical-cost/after_physical_counts.log`.
- `physical-cost/before_width_depth.log` and `physical-cost/after_width_depth.log`.
- `physical-cost/unittest-final-source.log`: 55 targeted tests pass, including empty stages, large serial totals, all estimator entry points, resource clocks, and candidate-check accounting.

## 2. Canonical template boundary

`compare_preprocessing` validates both inputs through `_canonical_template`, then calls `header_for` for each supplied nonce. The canonicalization boundary is sound for the declared diagnostic:

- It requires the exact `FixedTemplate` type and exact types for redundant metadata, header bytes, and matrix tuples. This prevents Python equality from accepting a boolean target as the equal-valued integer target, a float nonce offset as an integer offset, or a bytearray as canonical bytes.
- It reconstructs the template with `FixedTemplate.from_header` and compares the entire result. The underlying parser validates shape and nonce-bit types, matrix values and lengths, wire format, task commitment, and target; it canonicalizes the complete nonce field to zero. A forged metadata field or an input header with a nonzero nonce therefore does not pass canonical equality.
- Each `header_for` call rejects booleans, floats, negative nonces, and nonces outside the declared domain. Validation is symmetric between the left and right inputs.

The tests cover these boundary cases, task/matrix unbinding, and failure of the independent SHA continuation check. Native context eligibility, timestamp acceptance, and consensus admission are explicitly outside this helper's contract.

## 3. Native bytes and SHA checkpoint scope

The offsets were checked against `pon_wire.rs` header encoding and `pon_growth.rs` growth-header encoding, not inferred only from the Python fixtures. PNH1 has 318 bytes:

| PNH1 field | Byte interval, end exclusive |
| --- | --- |
| magic | `[0, 4)` |
| version | `[4, 6)` |
| network | `[6, 38)` |
| parameters | `[38, 70)` |
| parent | `[70, 102)` |
| height | `[102, 110)` |
| timestamp | `[110, 118)` |
| target | `[118, 150)` |
| miner | `[150, 182)` |
| transactions | `[182, 214)` |
| state | `[214, 246)` |
| receipts | `[246, 278)` |
| task | `[278, 310)` |
| nonce | `[310, 318)` |

PGH2 adds a four-byte prefix before the complete PNH1 header, then a 32-byte witness. Its ledger-field offsets are therefore the PNH1 offsets plus four; task is `[282, 314)`, nonce `[314, 322)`, and witness `[322, 354)`.

The challenge frames include the domain tag and length framing. PNH1 has 25 bytes before the header, so task starts at framed byte 303, and the first five SHA blocks include the first 17 task bytes. Its nonce starts at framed byte 335. PGH2 has 53 bytes before the header, so task starts at 335, nonce at 367, and witness at 375: all lie beyond the first 320 bytes. PNH1 and PGH2 require six and seven SHA compression blocks respectively after padding.

The helper compares actual framed bytes, counts only the uninterrupted equal leading blocks, selects the checkpoint exactly at that boundary, and resumes the right-hand message. It checks that result against an independent full `hashlib.sha256` evaluation. It does not infer safe reuse from equal digest fingerprints.

The corrected fixtures report the following counts. These are results for the specified concrete mutations, not a universal count for every possible change within a field:

| Mutation fixture | Equal leading fixed SHA blocks |
| --- | ---: |
| nonce | 5 |
| parent, byte 70 | 1 |
| target, byte 118 | 2 |
| timestamp, byte 110 | 2 |
| profile | 0 |
| growth witness, byte 322 | 5 |
| task, PNH1 | 4 |
| task, PGH2 | 5 |

All eight fixtures change the whole challenge input. In particular, reusing the five-block checkpoint for a PGH2 task or witness change does not reuse the remaining challenge compression, the full challenge, or subsequent W1 work.

`ab_inputs_equal` compares `(A, B, N, q)`. This correctly includes the field modulus and excludes noise/round parameters that do not enter that matrix product. `task_commitment_input_equal` compares the actual `h_bytes(b"task", A_bytes, B_bytes)` input; the native task commitment binds matrix bytes, not `q`. Equal whole challenge bytes across differing relation parameters similarly do not establish equal later W1 intermediates. The module states that distinction explicitly.

## 4. Finding R1: parent fixture correction verified

The original `changed_header(template, 66)` was labeled `parent`. PNH1 byte 66 is `parameters[28]`. Its prefix count of one happened to coincide with the corrected parent fixture's count, which concealed the coverage error from the old numeric assertion. The old evidence must not be cited as having exercised parent changes.

The corrected test uses byte 70 and adds an independent `struct.unpack` decode of all native header fields. Each of the existing eight cases now checks the complete changed-field set against its intended case name. The new assertion, run against the old fixture, fails with actual `parameters` and expected `parent`; this is preserved in `literal-budget/parent-field-label-before-fix.log`. The corrected run passes all seven tests. The replay now records exactly `[70]` as the differing byte offsets, `['parent']` as changed wire fields, and unchanged `parameters[38:70]`.

`literal-budget/parent-offset-correction.json` records the classification, corrected layout, current source hashes, regenerated evidence hashes, and nine preserved historical artifacts. `literal-budget/status.json` now records completion after the correction and the current test hash. The old artifacts remain under `literal-budget/parent-offset66-history/` with explicit `parent-offset66-mislabeled` filenames.

This was a test-fixture label and coverage defect. The core `w1_preprocessing_reuse.py` did not require modification. Separately, the stale-checkpoint negative controls deliberately call a private unguarded continuation primitive with an invalid five-block checkpoint. They demonstrate why checking the prefix matters; they do not demonstrate an existing production oracle cache vulnerability. The diagnostic computes its own checkpoints and does not implement a deployed cross-task cache.

## 5. Evidence and claim limits

`literal-budget/preprocessing-tests-final.log` records seven tests passing in 0.273 seconds. The tests construct reduced full and restricted HashPlans to compare checkpoints; they do not execute a complete quantum oracle, estimate physical resources for those fixtures, or invoke native admission. The SHA continuations and actual-byte comparisons establish correctness of the reported dependency scope only.

No reviewed result measures preprocessing frequency, CPU or QPU time saved, energy saved, whole-challenge amortization, equal-budget advantage, minimum attacker cost, or security of a DAA/fork-choice rule. Equality is a sufficient reuse condition for the tested computation; inequality does not rule out other caches or algorithms. The diagnostic's explicit qualification flags remain false.

### Reviewed source hashes

Paths in this table are relative to `formal/pon-nakamoto-v1/`.

| Source | SHA-256 |
| --- | --- |
| `quantum_oracle_resources.py` | `0ac636241697c728d64fc4a4f1bb77c53d52a625a6532dfb32631b3f33f20902` |
| `test_quantum_oracle_resources.py` | `9743ef8ecf1220c19435f5871dc8cf21ae8fcb4476959a575519ab89643a9c61` |
| `reversible_components.py` | `f518669b0b4ac41a442986ff779da618227b375ef69bdb17db0eacc505908fe0` |
| `w1_preprocessing_reuse.py` | `660cac37d0f3048f2a809b06e48fa3b24f171968cebf8f3493f3e2dc0ce17c3a` |
| `test_w1_preprocessing_reuse.py` | `d056548a1b217db06b1ece21595f107187ed9a9afeefd15aae97dc2770e2082c` |
| `w1_quantum_oracle.py` | `5a1a250680299561cb83b0b7d17ab57cf180e64277f981f5130cdf04e70aeb99` |
| `w1_quantum_primitives.py` | `1d1f0a800e24e1d82aab1794ec0cf207ed845e7a7080bacd41b0d0c575f98ac1` |
| `w1_quantum_restricted_oracle.py` | `b590ed91d491577c494a667a9271410b420dc35b7088705ef99982c2abd3b702` |

Corrected preprocessing replay SHA-256: `1c6e7c2f4e0b3458c1b2aa5b09e60c184518ecd30e32b5c49f6dc913c0e89d49` (`literal-budget/preprocessing-reuse-controls.json`). The complete correction manifest retains the original hashes as historical evidence; the old parent label is not retroactively validated.
