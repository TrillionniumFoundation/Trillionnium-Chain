# 819309 original business gates — HOLD

This fixed read-only package records the real integration-branch push
819309fd312298e099642e1253b1d4ba07113e98, actual main
dd6e1c3cbeacbdc532b0679297835b3a0aac78f0 and ordered prospective merge
28df21f965e0348690836c9c854dab645827a03d. Both test trees are
f9d63abb9e2931fd78e26ccb87e3a7955068f267.

GATE_CORE.json is the compact outcome. ARTIFACT_INDEX.json binds all 14 core
native lanes to exact GitHub artifact IDs, original ZIP digests and sources.
metadata/ retains complete paginated GET results, including the final denominator:
37 workflow jobs = 26 success / 11 failure;
34 native lanes = 24 success / 10 failure.
All expected 136 materialization/source-before/source-after/context steps passed.

Four ordinary service and both fresh service lanes failed the unchanged business
target. All eight baseline reports confirmed 1/1; all eight pressure reports
confirmed 0/1 despite 7/7 honest Submit responses. Native process completion,
Host contract checks, cached rejection and accepted independent History pages
remain distinct from transaction confirmation.

Four State lanes passed six exact named controls and the main 40-test migration
suite. Two successful FIFO child summaries per lane do not make 42 main tests.
These are State controls, not a throughput qualification.

Four 4105 History lanes failed natively: exit 101, zero passed / one failed.
Confirmer successful import returns: x64 H 2791, x64 M 3386, ARM H 4104,
ARM M 4104. Non-genesis packet rows: 2791, 3386, 4105, 4105 respectively.
Every confirmer remained active at genesis. ARM cancellation cursors: 3782/3701.
x64 servers reached the original 1800-second lifetime before Connection refused.
ARM final import calls hit the original 30-second deadline; servers were stopped
before lifetime expiry. Eight databases were read mode=ro, immutable=1 and
query_only, with matching SHA256 before/after. No Node open or recovery ran.

The 14 original ZIP byte streams are retained in reachable Git history and
indexed by [ORIGINAL_ZIP_ARCHIVE.json](ORIGINAL_ZIP_ARCHIVE.json), including
their exact paths, blob IDs, byte counts and SHA-256 digests. They are absent
from the current checkout. Complete databases, large original reports and every
other supplied member remain in those exact ZIP objects; no member was rewritten.
artifacts/ additionally exposes original source/context/manifest/log records and
independent readbacks. pinned-readers/ retains exact-819 source blob identities.
readbacks/ preserves timing versions and scope. OBSERVER_NOTES.json retains
known observer preparation failures and corrections.

Original artifact 11531476198 remains unavailable: the real job reported
Found 0 artifact(s). Cause UNKNOWN; no substitute or expiry/deletion inference.
The 20 other W1 component jobs succeeded in GitHub metadata. Their separate
once-only archive-read coverage is outside this fixed core package and cannot
qualify the original service or History gates.

e70, d26 and 819 are separate captures, not a paired performance experiment.
No native rerun, CI dispatch, source mutation, budget relaxation, TPS, COW,
public-network or production-activation claim was made by this observer.

## Verify the original sealed observation

SEAL.json, SHA256SUMS, FILES.json, ARTIFACT_INDEX.json, GATE_CORE.json and
OBSERVER_NOTES.json remain byte-for-byte unchanged. Their paths and totals
describe the original sealed logical package, including its original README,
not the current physical layout. The archive index binds the original README
and controls to commit `893210a45b44742edfe2510fea1d92e9974b5f95` and tree
`a2d04b29621bb78504244471aacac3be3bc78d1d`. This README documents the storage
change; it does not add or replace any observation.

From the repository root, run:

```sh
python3 scripts/ci/check_sealed_ci_archive.py \
  --manifest evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json
```

The reader verifies all 810 original checksum entries, all 14 original GitHub
artifact bindings, the original 309,875,945-byte sealed payload and its HOLD
outcome. Only the indexed ZIPs and original README resolve from pinned Git
objects. Every other original file must still exist with its original bytes;
missing or changed retained evidence fails verification. The original seal and
checksum list are verified unchanged, rather than regenerated around missing
paths. Local history must contain the pinned objects; the reader does not fetch.

To retrieve an exact original ZIP, use the generic reader with an indexed path:

```sh
python3 scripts/ci/check_historical_archive.py \
  --manifest evidence/pon-business-gates-819309-final-20261107/ci-819/ORIGINAL_ZIP_ARCHIVE.json \
  --cat evidence/pon-business-gates-819309-final-20261107/ci-819/archives/13585963261.zip \
  > /tmp/13585963261.zip
```

The same `--cat` interface retrieves the original README or sealed controls
listed in `historical_manifests`. Both readers perform byte-integrity checks
only. They do not execute archived helpers, rerun native observations or change
the service, History, public-network or production qualification.
