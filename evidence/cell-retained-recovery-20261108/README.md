# Exact retained Cell recovery — source-bound component evidence

Status: **component gates PASS; production / independent custody / WAN / ordinary
Hepta adoption remain HOLD_NO_GO**. The normative contract is
[Complete retained-version recovery V1](../../docs/development/specs/pon/CELL_RETAINED_RECOVERY_V1.md).
The [sole plan](../../docs/development/TRNM_AI_NATIVE_BLOCKCHAIN_DEVELOPMENT_PLAN.md)
retains the integration and operational obligations.

## Frozen source and executed result

| Item | Recorded identity / result |
| --- | --- |
| Parent Cell candidate | `0dc13a92cc49e9a751a2b6cf7cc96524f1244a2a` (#807) |
| Tested implementation commit | `9e37f42528c970230c192a10da81f882444c29af` |
| Tested tree | `cce7bfc83f9a2e712b68d0569d1a0b21d98f314c` |
| Whole tracked source before and after | 16,801 entries; 1,735,094,295 raw bytes verified against Git |
| Full default-feature DA native tests | **530 passed**, 0 failed, 0 ignored, 0 filtered |
| Compile-fail doctests | **11 passed** |
| New native tests, individually matched to log | **68 passed** |
| Complete command campaign | **18/18 passed** |
| Rust toolchain / host | Rust 1.95.0; Linux x86_64 |
| Build/test settings | 2 build jobs, 1 test thread, incremental off, debug info off |

The test command ran the entire `trnm-data-availability` package: 496 library
tests and 34 integration/CLI tests, followed by the 11 compile-fail doctests.
The original default feature set and all original test cases were retained.
Disabling compiler debug information saves build storage; this campaign makes
no performance or fixed public-Host resource qualification claim.

[Command summary](exact-source/summary.json),
[complete native output](exact-source/complete-cell-tests.log),
[source before](exact-source/source-before.json) and
[source after](exact-source/source-after.json) retain the actual record.
Source identity checking explicitly executes no tests; its result is distinct
from the native commands. [New test roster](new-test-roster.json) lists all 68
names actually observed as successful, rather than inferring execution from a
source scan or a zero-selected-test result.

The evidence-only commit adding this directory is distinct from the tested
implementation above. Any later exact delivery run or hosted prospective merge
must carry its own source receipt and must not inherit this commit's pass.

## What was exercised

| New group | Tests | Concrete controls |
| --- | ---: | --- |
| Declared placement | 21 | Mixed operator/admin/domain failure sets; duplicate indices; correlated identities; exact bounded work; 288 comparisons with an independent subset oracle |
| Verified retained RS recovery | 21 | Actual bytes for all 4 original manifests / 12 chunks; two compositions sharing objects; whole-file hashes; corrupt extras and replica copies; omissions; failure latch; nonrefundable budgets; maximum-manifest binding |
| Exact retained set | 14 | Exact owner roster, epoch, service windows and loader pins; shared-object accounting; missing/corrupt V2-only adapter; zero-I/O admission refusal; original cross-version TCP quotas |
| Complete-version network | 12 | Three real TCP providers holding different closure portions; all four existing transports; missing tokenizer/environment; partial replies; original cancellation/deadline and response/request accounting |

The retained-set TCP positive case restores two versions with five unique
manifests and fifteen chunks using exactly one persistent connection and twenty
request frames. The quota refusal cases do not replenish the budget at the next
version or model/environment boundary. In the split-closure test no one provider
has the entire version, yet the selected original closure is recovered.
These are controlled local TCP processes, not independent operators or WAN SLA
measurements. Warm-cache observations are explicitly identified as cache-only.

Four correct shares restore bytes but report the missing additional failure
margin. Six correct shares assigned to one common domain also restore bytes,
while retaining a deficit for every affected chunk. Distinct labels alone never
produce a physical-independence qualification.

## Other required gates

The campaign also passed:

- Locked, offline Cargo graphs for the default and all-feature workspace plus
  the separate fuzz manifest; both lockfiles remain unchanged.
- Workspace formatting and the unchanged independent Python TCV1 byte vector.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- 43 raw-source integrity negative controls, 37 PQ-source negative controls,
  and 108 CI contract controls.
- Repository/local-link checking (4,313 links), 594 exact source blob pins,
  distributed source inventory freshness, implementation-report freshness and
  final unchanged-worktree checking.

The optional native provider was prepared through the unchanged canonical CI
script: verified OpenSSL 3.5.9 source, static build, actual ML-DSA-65 correct
message verification and wrong-message rejection. [Provider receipt](provider.json)
records that setup. It does not convert default-feature tests into an executed
all-feature runtime campaign or a whole-system quantum-security proof.

[Source pin delta](source-pin-delta.json) records all eleven changed/new source
pins against the original #807 parent. [Files and SHA-256 values](files.json)
cover the captured data files; the index and this explanatory README are not
self-hashed by that index.

## Retained negative observations and fixes

[Failure ledger](failure-ledger.json) distinguishes development, storage and
publication bootstrap observations. No historical failure is relabeled as a
successful test on the frozen source.

The [first complete development library run](development-01/complete-cell-tests.log)
had 495 passes and one failed test assertion. The test incorrectly equated
client request frames with server read-slot admissions. The server reserves
before waiting, including a final EOF slot; the client had not retried. The
correction now requires exact client frame/byte counts and exact server completed
responses, permits at most one bounded EOF read slot, and still requires zero
payload acquisition when a version's manifest is missing. No networking quota,
deadline or implementation behavior was relaxed. The later complete frozen run
above passed the corrected stronger assertions.

An earlier targeted compile found two concurrently authored test modules absent
and executed no tests. Its [original excerpt](initial-targeted-compile-failure.txt)
is retained separately. The local promisor-clone bootstrap failure and original
240-second full-clone timeout affected only a publication relay; no existing
checkout or published ref was changed by either attempt.

Independent code review also found and corrected two bounded-cost issues before
the frozen campaign: repeated enumeration for the per-chunk cost estimate, and
revalidating/hashing a complete manifest on every chunk. Cost is now cached in
the immutable policy; an immutable borrowed manifest binding validates once and
selects each subsequent chunk in constant-size metadata work. The original
CRS1 bytes, original chunk hash and full payload checks remain mandatory.

## Remaining qualification

The exact current-set input must still come from the live durable owner. This
component does not enumerate funded duties, atomically register model and
environment obligations in TCA2, or authorize GC from returned reference lists.
The streaming CRS1 verifier receives bytes and declared provider identities;
it does not authenticate their network source, prove fresh custody or prove
physical/administrative independence. Actual restricted-loader dependencies,
supported tensor/quantization/ABI execution, independent WAN fault/churn/cold
recovery, renewal/repair funding and ordinary Hepta CURRENT/FinalUse remain open.

#812 at `7e044b65454f4c9ea505591727332acffb33e7e5` is a separate frozen source and
did not contain #807 at this continuation's start. This component's source/tests
must be integrated explicitly and rerun there. Main was not changed, no branch
protection was bypassed, and no deployment or production activation is asserted.
