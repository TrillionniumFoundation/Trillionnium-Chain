# W1 closure: historical/current source repair and retained validation

Status: **HOLD / NO-GO**. This evidence child does not establish QROM security,
a lifetime failure bound, a new STARK proof, production admission or native
resource acceptance.

## Source identities

| Role | Exact commit | Tree |
|---|---|---|
| Base #850 | `3898582a321471fc2a6945b37ff4d0cd58c7a255` | Existing parent |
| First code, failed real semantics comparison | `35d57d41cc22ef7380da939f905ad171225eb484` | `844e00fb438917741f9cfc674afe742e713a7bbb` |
| Corrected code, final local validation | `d0b4b16268fc6338ecd77906f12097fbae58435e` | `853c847c9602f6515aded0084d8e04e2c5afd5e8` |

The correction is an actual child of the failed code, not an amendment.
Source observations before and after both committed-source campaigns are
clean and equal. This directory is an evidence-only child and must not
replace either executed code identity.

## Concrete repair and preserved boundaries

The historical lifetime reader rejected the changed current `store.rs`. Its
reader, 20 pins, original tests, original runner, 105-name roster and original
saved reports remain unchanged. The fixed original positive historical lane
checks out `1a14f7d4826363daefac9ec10131c66d7e70ece7`; that historical lane
was not executed in this local campaign, and no fresh positive result is claimed.

A separate current contract pins the same 20 paths. Exactly one pin differs:
the reviewed 382,866-byte store source. The current observer runs the old
source-observation function in an explicitly declared private current context;
it does not alter the historical module or pins. The old CLI still actually
exits 2 on current source, with stdout empty and a retained source-identity
refusal. The finite accounting evaluator and all unknown project bounds remain
unchanged; source observations do not prove semantics or full hash-use coverage.

The first real workflow-block campaign on `35d57d41` executed all 103 named
controls but correctly failed reproduction and final completion. Its semantics
report differed at only `/provenance/lock_checks/2/sha256`: the local guest
methods lock had gained `risc0-binfmt` and `sha2` dependency edges. The old
report lock hash is `af7ee60b8f9f95c200d3dddac41b70c037e2bb3395122fe67ab20885140f247f`;
the current lock hash is `ed6ea70f20cbe45bf0bdef7f841adbdaa7c3b2a9838ffdfed64fa88f129b707a`.

The child correction independently pins the original report and current lock,
permits exactly that reviewed provenance leaf, and refuses every other report
change, including scalar type changes. Five other reports remain byte-identical
comparisons. No historical output file is rewritten to disguise the mismatch.

## Final exact-source validation on d0b4b162

| Scope | Actual result |
|---|---|
| Current lifetime observer | 14/14 methods PASS |
| Current closure/comparison/workflow controls | 31/31 methods PASS |
| Original CI-contract suite plus registration regression | 167/167 methods PASS |
| Source-integrity controls | 43/43 methods PASS |
| PQ corpus controls | 57/57 methods PASS |
| New current named closure roster | 110/110 actual named controls PASS |
| Actual current workflow shell blocks | All eight executed blocks exit 0 |
| Repository/link, corpus and generated inventory checks | Exit 0; 927 exact corpus blob checks |
| Local Cargo metadata | Could not launch: Cargo executable absent |

The 110-name roster overlaps the separately reported observer and closure
control suites; the counts are not added into a distinct global total. Nine
standalone commands were recorded: eight exit 0 and one launch failure.
No local Rust graph, build, formatting, Clippy or native cryptographic execution
pass is claimed. Generated source inventory changed only to include the two new
configuration paths; cryptographic relation, proof-format and admission sources
and Cargo locks were not changed by this repair.

The actual current workflow run executed its literal reserve, source-before,
preflight, named-controls, historical-refusal, reproduce, source-after and
completion blocks against the clean corrected commit. Its checkout prerequisite
was the existing isolated local clone and committed source, verified by the
actual full-source identity blocks. It was **not** an Actions run or execution
of the `actions/checkout` service. The final local completion consumer records
all stages passed with every security qualification false and security bits null.

## Retained unsuccessful observations

`failed-35d57d41/` contains the real committed-source failure, full named result,
actual V1 refusal, reproduction difference and failed final completion. Its
source identity remains 35d57d41. It also retains decoded text of original
parent job 129256191854 from hosted run 42645116454, whose lifetime class ran
zero tests because setup rejected the current store identity.

`precommit-preparation/` preserves sparse-checkout setup failures: missing
semantics Cargo locks, then the historical guest binary, plus the CI-contract
run with a missing isolated fuzz lock. These observations occurred before the
committed-source campaign and are not relabelled as final-source failures or
successes. Their later successful reruns do not erase them. The retained
historical guest lock was fetched from exact original source and checked to its
reported hash; its narrow textual difference is separately documented.

`corrected-d0b4b162/` contains the complete final local command and workflow
observations. The original historical positive lane and prospective-merge lane
have not been executed locally. New-head hosted CI must be read separately.

All actual lifetime bounds remain null, complete QROM/FRI/shared-oracle and
recursive-composition obligations remain unproved, and consensus/production
qualification stays false. This component repair closes a source-scope CI
mismatch; it does not discharge a complete cryptographic security obligation.
