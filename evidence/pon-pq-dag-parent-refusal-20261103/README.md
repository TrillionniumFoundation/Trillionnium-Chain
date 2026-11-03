# Original DAG runtime failure: fixed-parent refusal is now observable

This is a read-only examination of the original
[required baseline run 41628135442](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/41628135442).
It does not rerun a workload or waive its original acceptance gate.

| Lane | Tested commit | Original artifact | ZIP bytes |
| --- | --- | ---: | ---: |
| Head | `12fe5f2c1f19704fe7eb635dede6839ed8b1e91e` | 13229776793 | 2,584,782 |
| Actual prospective merge | `0357031364787574cb7058b05329aa2e2730f947` | 13228623338 | 2,584,573 |

Both tested trees are `c44112da731e3f958e55eb024e5762d6723ea2c9`.
The original ZIP lengths and official SHA-256 digests were checked before
extracting the selected records. Each retained runtime receipt has the same
before/after tracked source identity and an actual exit code of 101. Its
command hash matches the complete original `rust-shard.sh` bytes.

## Actual outcome

Each lane retains all 18 samples: three modes, two workloads, three repetitions,
with the original balanced ordering and identical signed packets. In every sample:

- All seven block submissions succeed.
- The first History response is downloaded successfully.
- The independent consumer returns `PUBLIC_HOST_KERNEL_PARENT`.
- No transaction is confirmed, and the native client state is unequal.
- The separate cold reopen equals the service's original state.

The unchanged test ends with one passing case and one failing case, no ignored
cases, and `retained native delivery/replay invariants failed`. The complete
workspace test log is retained; later tests skipped by this terminal command
failure are not counted as passed.

The source at this exact commit calls `receive_public_page_from` for the
independent consumer. Its kernel-parent constructor produces this error when
the fixed approved parent cannot be opened or fails the original path/ownership
requirements. The ordinary runtime command does not contain the dedicated
fixed-Host provisioning wrapper used by the separate from-zero job. Together,
the source and observations locate the refusal at the Host prerequisite. They
do not prove a particular filesystem condition because this artifact has no
matching kernel-parent snapshot. No resource check, deadline or invariant has
been bypassed, and successful execution after provisioning is not claimed.

## Preserved material and verification

Each payload contains the complete original DAG report, complete workspace
test log, source record, runtime receipt, runtime command script and provider
identity record. The corresponding manifest records exact lengths and SHA-256
digests for all retained members, plus every omitted original member. The
omissions are other runtime evidence outside this specific failure analysis;
the complete original ZIP is not claimed to be archived here.

Run `python3 verify_payloads.py` to check the retained bytes, source identities,
command hash, actual terminal failure and every sample. It reproduces
[observations.json](observations.json) without executing embedded commands.

The earlier change that retained `architecture-delivery-comparison.json` now
provides its intended diagnostic evidence. Runtime acceptance remains failed.
These observations do not qualify any DAG consensus design, independent WAN
operation, whole-chain PQ, or production activation.
