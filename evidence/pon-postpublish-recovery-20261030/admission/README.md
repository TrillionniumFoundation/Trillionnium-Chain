# Recovered original admission CI evidence

This is a new compact recovery from surviving GitHub CI artifacts after the local
workspace reset. It does not recreate or claim recovery of the lost local commit,
tree, evidence layout, or measurements. No native experiment was rerun.

## Original source and artifacts

- Repository: `TrillionniumFoundation/Trillionnium-Chain`.
- Tested commit: `1d11f875493f8125e36b9adceacb342df108e5e5`.
- Tested tree: `64b82137eebeb96b572abc62e5fce39af3593200`.
- [Workflow run 40988668819](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668819), attempt 1.
- x64 job: `123845534896`; ARM64 job: `123845534628`.
- [x64 artifact 12949190541](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668819/artifacts/12949190541):
  **98,015,214 bytes**, SHA-256
  `0cba4a65b534be04492764bd6ba0b67c81712e23e154c0e1643bebc40e4e4a37`.
- [ARM64 artifact 12947808903](https://github.com/TrillionniumFoundation/Trillionnium-Chain/actions/runs/40988668819/artifacts/12947808903):
  **28,003 bytes**, SHA-256
  `35bd0454c8f700e1488290ee03496bf28052e4716f6fb0218ef240c81bd73426`.

Both complete original ZIPs were downloaded again and checked against their
published sizes and hashes. The full x64 ZIP remains outside Git. Its new
`x64-selected-original-members.zip` retains **45 exact original members**; each
member's original byte length and SHA-256 are recorded in
[selection-manifest.json](selection-manifest.json). This selected ZIP is new
packaging, not the original full artifact. The ARM64 ZIP is retained unchanged.
Actual API metadata and connector-decoded logs are retained separately. The logs
are losslessly gzip-compressed, preserving original trailing spaces and newlines.
Their compressed and decoded hashes, encoding and recovery time are explicit in
[provenance.json](provenance.json).

All six original source records agree: **7,435 tracked entries /
960,706,544 tracked bytes**, at the tested source above. These records do not
qualify the later recovery commit or a subsequent workflow repair.

## x64: all three campaigns ran; finite service failed

Compiler setup, release builds, fixed Host setup, pinned reader environment,
strict Clippy, cleanup and final source verification succeeded. Original pressure,
receiver-owner supplement and fresh-caller pressure were all actually attempted
once, each exiting 101. Their process durations were respectively
112.343986905, 113.427210643 and 112.116150989 seconds. The driver continued
after the original failures and executed the supplemental campaign and readers.
It retained no driver exception or finalization failure.

Sixteen of 19 native gates passed; the three finite campaigns failed. All six
mandatory reader/environment gates were attempted. Original and fresh fixed Host
client readback passed. Failed service predicates remain failed.

The unchanged phase window was **30 seconds**. These are observed depth-six
confirmation endpoints relative to phase start:

| Campaign / phase | Endpoint | Original finite service predicate |
| --- | ---: | --- |
| Original no-attacker baseline | **31.786640876 s** | Failed |
| Fresh-caller no-attacker baseline | **32.189797667 s** | Failed |
| Fresh-caller from-zero attack | 34.270335206 s | Failed |
| Fresh-caller correct product / false trace | 34.852993307 s | Failed |
| Receiver-owner no-attacker baseline | 32.197815436 s | Failed |

The no-attacker baselines themselves failed. This is not evidence that attackers
alone caused the service failure. The original baseline's final strict History
import consumed **2.844300120 s process CPU / 11.406756045 s process wall**; its
seven imports totalled **7.257389532 s process CPU**. Nested costs are not added
to enclosing process or cgroup totals.

## Actual fresh identities and depletion

The original pinned CI reader used Python 3.12.3 and cryptography 50.0.2,
independently derived caller keys, and checked caller/body bindings. Its inputs
and output are retained, including all five fresh-reader input files.

| Fresh attack phase | Offered distinct identities | Actually authenticated distinct identities |
| --- | ---: | ---: |
| From-zero | 3,738 | **3,715** |
| Correct product / false trace | 2,834 | **2,834** |

Both exceeded the original minimum of 65. This recovery independently recounts
the actor/receiver caller-body joins from the original raw reports. It does not
rerun signature verification or independently derive the keys.

The fresh from-zero phase had **zero** depletion samples. Correct product /
false trace had **401 depletion samples**, paid depletion during its observed
round, **2,811 fresh challenges actually published**, and a passing original
**64-slot churn** predicate. These positive observations do not override failed
confirmation timing. Each fresh phase offered seven of 21 planned honest bodies;
all seven submitted calls succeeded within their original call deadlines, but
the finite multi-round confirmation condition remained unmet.

The retained native manifests preserve **24 attackers**, **480 calls per actor**,
three planned rounds, **30-second phases**, **2-second call deadlines**, and
`ticket_bits=0`. Fixed Host composition and resource records remain original.

## Receiver-owner terminal failure

The false-trace receiver-owner phase recorded
`RECEIVER_IPC_ABSOLUTE_DEADLINE` and had no complete receiver report. Its actual
failure record retained **24 actor observations and 24 parent wait4 records**,
each with one successful reap. The receiver was forcibly terminated and reaped
once (`raw_wait_status=9`, `exit_success=false`); its whole-lifetime observed CPU
was **10.837811000 s**.

The original and partial data remain distinct. No successful report is synthesized.
The missing third complete report leaves receiver-owner qualification and its
complete fixed Host reader failed.

## ARM64: setup failed before native execution

The pinned reader environment succeeded. Rustup then reported recovery from a
partially installed toolchain and a `bin/cargo-clippy` conflict while installing
the exact compiler. Fixed Host provisioning and the native driver were skipped.
All three native campaigns were therefore **not attempted on ARM64**. This is a
setup failure, not an observed ARM service or depletion result. Any later repair
requires its own execution evidence.

## Reproduce this recovery's readback

Run from the repository root:

```bash
python3 evidence/pon-postpublish-recovery-20261030/admission/readback.py
```

It verifies retained archive/member hashes, original source equality, original
terminals and limits; recounts caller/body joins; and checks the derived
[summary.json](summary.json). With the original complete x64 ZIP available,
`--original-x64 PATH` also verifies its exact original hash and compares all
45 retained members against it. The actual recovery check with that complete
archive and the later offline check are retained separately.

These checks do not authenticate the CI machine, remeasure time, execute native
code, prove global work hardness or certify arbitrary-Sybil fairness. All finite
qualification, production, work-hardness and quantum-security claims remain
unqualified. The original failed campaign outcomes are preserved.
