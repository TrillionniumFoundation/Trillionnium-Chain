# Supplemental Colab profile and composition evidence

**Result: 82 / 82 tests passed on an actual Colab standard CPU runtime.**
The run covers the 45 profile tests and 37 composition tests from the four exact
project source files under source/. It reports zero errors, failures, skips,
expected failures, or unexpected successes. All four source hashes match before
and after execution. This is controlled-fixture evidence.

## Exact provider execution

- Task key: pon-profile-closure-89df-python-20261107-v1
- Provider job: 0d953d8a-81fa-40d8-ab90-8f4e23f5c909
- Provider state: succeeded; exit code: 0; submit attempts: 1
- Job wall limit: 300 seconds
- Source payload SHA-256: 0c0cef95c1d710138eccf20cd4a63734ace5b9f46e08b87f3279f433d6b2a7bf
- Adapter payload identity: 10b58751df2ec45d8383fbde35e65ba531a6e3d68a8c802ae16f89fbd065d58a
- Provider receipt says execution stopped and the process group is no longer alive.
- Runtime: Python 3.13.18, AMD EPYC 7B12, 2 logical CPUs,
  13,286,924 KiB memory, standard CPU with accelerator NONE.
- Test execution wall time: 1.348569677 seconds.
- Host controller elapsed time: 67.424082994 seconds.

These times cover different scopes and are not a physical cost meter.
Complete raw test output is retained in cloud/stdout.log and cloud/stderr.log
(the latter is empty). The complete test inventory, before/after source hashes,
runtime readback and process counters are in cloud/test-report.json.
These files and the payload are byte-exact retained artifacts. Their hashes
are bound to the provider manifest in observations/execution-public.json.

## Isolation and preparation failures

The existing account was already authorized. Readiness observed a free tier,
zero paid compute units and an eligible standard CPU assignment. No account,
subscription or global default profile was changed. The task used its own
durably keyed provisioning journal, private profile, job ledger and newly
created kernel on the existing CPU assignment.

The first setup attempt was rejected by the installed adapter with
AUTH_STATUS_PATH_UNSAFE (adapter exit 3). The ancestor work directory had mode
0775; the adapter's original path guard rejects group-writable ancestors.
Readback confirmed the proposed manager state directory was absent.
The rejection occurred when constructing the local journal, before runtime
allocation, kernel creation or test submission. The rejected-attempt receipt
and path observation are separately hash-bound in the public projections.
The task then used a fresh 0700 state/profile root directly under the verified
home. Shared directory permissions were left unchanged.

An earlier read-only source-interface probe failed with a Python regular
expression error (host exit 1). Local evidence packaging also retained an
argument-list limit rejection and a quoting error that occurred before process
creation. All remain in observations/preparation-failures.json; none reran the
cloud test job. Preparation and failed-attempt costs remain unknown.

## Runtime and kernel disposition

The pre-existing kernel e5b396bb-f180-4fe1-97bc-4e639259415c was never adopted,
restarted or deleted. The task created kernel
a2ec9817-d269-4a37-a134-dad4a584ba9e; post-run readback observed both kernels
idle. The task kernel remains **idle and retained, not released**. The shared
assignment remains present. No runtime release was attempted because this task
does not own the shared assignment. This is a bounded observation, not a claim
about future availability or freshness.

## Scope and limits

This finite run checks the project profile and composition implementations
against their existing controlled tests on the observed Colab Python runtime.
It supplies actual supplementary cloud execution evidence for the user's
preferred compute channel. It is separate from the parent campaign's native
Rust tests, 33-command validation and any wider workspace/runtime campaign.

This package does not establish independent external demand, customer budget,
issuer independence, public-network query attribution, target authorization,
current external consumer use, complete preparation/failure/machine/network
costs, a physical meter, or actual payer/beneficiary cost transfer.
Provider-reported consumption rate 0.08 and paid-unit balance 0 are observations,
not a settled invoice or proof of free physical resources.
Qualification flags remain false; chainwork weight remains zero.
No claim is made that each new ticket requires new neural computation.

## Public provenance and omissions

MANIFEST.json hashes every published file except itself. source-bindings.json
pins the four project sources, payload and installed adapter/runner hashes.
The adapter and SDK implementations are **not published**. No profile,
authentication configuration, credential store, tokens or cookies are included.

Observation files are explicitly labelled public projections where fields or
host paths were removed. Each records the original record's SHA-256 and byte
length, omitted fields and replacements; it is not represented as the original
bytes. The readiness projection omits authentication-storage/scope metadata.
The post-run projection omits installed SDK implementation excerpts.
Exact originals and private state remain with the runtime owner.

The archive is a review artifact. Unpacking it or rerunning the included payload
elsewhere does not reproduce the original provider identity or qualify a
consensus profile.
