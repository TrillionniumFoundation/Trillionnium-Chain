# Procfs identity boundary for optional proving observations

This adds one fail-closed identity check to the optional sampler from
[the preceding sampler observation](../w1-proc-group-sampler-20261027/README.md).
The preceding six-control results, failures and hashes are preserved unchanged.
No guest, host, W1 relation, proof/security parameter or admission policy changes.

Before reading any numeric target PID resource file, the sampler reads only its
own `/proc/self/stat` and requires all three identity fields to match the
operating-system calls:

- PID equals `os.getpid()`.
- Process group equals `os.getpgid(0)`.
- Session equals `os.getsid(0)`.

If the self record is missing, invalid or inconsistent, the sampler stops target
resource discovery. JSON/JSONL report `proc_self_identity_verified: false`, the
reason for unavailable identity, no observed target identities and null CPU/RSS
costs. The command's actual exit result remains separate: an unavailable optional
resource observation does not invent command failure or proof success. No
command lines or process environments are read.

This check handles a procfs view from a different PID namespace even when a
numeric target PID, group or session could happen to match. It is an operational
self-identity consistency check, not a security attestation against a hostile
kernel or a forged procfs. Existing process-group/start-time filters and all
sampling lower-bound limitations still apply.

## Actual verification

| Retained observation | Result |
| --- | --- |
| `native-controls` | **7 controls pass**, 16.451287 seconds, on the authorized native process namespace. |
| `sandbox-control` | **1 actual refusal control passes**, 0.268654 seconds, in the default mismatched sandbox namespace. |

The native control set includes the prior parser, ownership, PID reuse, unavailable
identity, optional/default path and actual periodic grandchild timeout controls.
A new five-case control changes self PID, group or session independently, removes
the self record, or makes it malformed. A guarded numeric-target reader must not
be called for any of those cases. Synthetic test procfs fixtures explicitly write
a self record matching the real test process identity.

The separate actual sandbox command exits successfully after a short sleep;
its sampler reports `proc_self_identity_mismatch`, zero observed target identities
and null user CPU, system CPU and RSS. This records the real environment boundary
without claiming those unavailable costs are zero. Actual subprocess logs,
process reports, sampler JSONL, test logs and SHA256 source identity are retained.
The source observations ran before this commit and identify the exact files by
hash; no later commit is described as the original run-start HEAD.

Reproduce the full seven controls in a Linux environment where process IDs match
its mounted procfs:

```sh
cd trillionnium/crates/trnm-crypto-primitives/guests/w1-risc0
python -m unittest test_proc_group_sampler -v
```

The controls execute short CPU/sleep subprocesses and no cryptographic proving.
The existing long two-thread proof attempt and every previous proof observation
remain unchanged. No optional research or new proving attempt is launched here.
