# Cell producer to the ordinary Hepta host

`scripts/run_llm_cell_native_handoff.py --consumer-mode cell-host-v2` prepares the
existing eleven-file SmolLM byte plan, calls the actual `trnm-cell fetch-closure`,
then execs the existing `hepta-neural-agentd --host-format cell-v2`. Its default
`original-v1` mode retains the original unavailable-consumer failure.

This mode requires the Hepta Cell-v2 host and shared startup-deadline changes. It
does not merge the separate PQ source branch, operate an issuer, create a Fleet,
change CURRENT, qualify a product or claim feedback rounds. The original native
host replays those owners and rejects missing or ineligible configurations.

Execution profiles are explicit. The original handoff-v2 schema uses a sealed
anonymous ELF; it remains useful for the data/exec-contract controls, but the
paired native Cell-v2 daemon rejects that image before aliases or model owners.
Its path-based helpers and original sandbox PID namespace cannot reopen an
anonymous image. For the ordinary daemon, the distinct handoff-v3 schema below
selects a protected installed ELF. Neither profile falls back to the other.

## Inputs owned outside the transport

Supply `--handoff-config ABSOLUTE_JSON --handoff-config-sha256 HEX`, in addition
to the original absolute paths and cache caps. The new strict JSON schema is
`pon-smollm-cell-host-handoff-v2`, with these exact fields:

| Field | Original owner input |
| --- | --- |
| `schema` | `pon-smollm-cell-host-handoff-v2` |
| `host` | `{path, sha256}` of the independently authorized complete `hepta-smollm-cognitive-cell-host-v2` host file |
| `executable` | `{path, sha256}` of the deployed native ELF `hepta-neural-agentd` |
| `workspace` | Exact canonical workspace already registered for that Agentd |
| `generation` | Independently selected model generation, matching the parent |
| `loader_profile` | Original independently pinned execution-profile digest |
| `context` | Exact `family`, `base`, `parent`, `tokenizer`, `layout`, `runtime` Cell context |
| `authentication` | Explicit content-cache or existing PQ authentication policy below |

The installed-image configuration uses schema `pon-smollm-cell-host-handoff-v3`
and adds exactly `execution_profile: "protected-installed-elf-v1"` to these
fields. The `executable` object still contains its independent `{path, sha256}`;
the host/Cell schemas and their original owner inputs are unchanged. Supplying
the new field under handoff-v2, omitting it under v3, or selecting an unknown
profile is rejected. Successful transport reports retain the chosen handoff
schema and explicitly record its execution profile.

The host file itself is never rewritten. It must already include its original
product-qualified descriptor, resource grant, journal and FinalUse configuration.
Its `sidecar.path` must be `OUTPUT/consumer-cell-sidecar.json`;
`dependency_closure.path` must be `OUTPUT/consumer-release.tcd1`. Its worker's
materials and adapter inputs must point to `OUTPUT/consumer-materials` and
`OUTPUT/consumer-parent`. Their expected hashes and the TCD1 domain id must be
supplied independently before this run. Producer-calculated hashes are compared
with those pins; they are never substituted into the owner file.

The original `HEPTA_FLEET_ROOT`, `HEPTA_AGENT_ID`, `HEPTA_AGENT_GENERATION`,
`HEPTA_AGENT_HOME`, `HEPTA_AGENT_RUN_ROOT` and `CODEX_HOME` process environment
must be present. The handoff does not change these values. The ordinary daemon
validates the existing Fleet's Starting generation, workspace and writer lock.
Missing configuration, executable, descriptor, issuer configuration or required
environment returns `NOT_CONFIGURED` before creating the output/cache. Invalid
schemas, digests or path bindings return `REJECTED`; neither failure falls back.
Linux executable memfd and byte/size sealing support are required; their absence
also returns `NOT_CONFIGURED`, without executing the mutable source path.
That memfd requirement belongs only to the v2 sealed-image profile. The explicit
v3 installed profile instead requires the following deployment conditions:

- The caller has one nonzero real/effective/saved/filesystem UID, and
  `CapEff`, `CapPrm`, `CapAmb` and `CapInh` are all zero. A nonzero bounding set
  alone is not mistaken for an active or inheritable capability.
  The observation uses `/proc/thread-self/status`, so it covers the calling
  thread's actual credentials even when it is not the process leader.
- The canonical regular ELF has one link, is owned by root, and neither its mode
  nor effective-identity access grants the caller write permission. SUID, SGID
  and any `security.capability` attribute are rejected.
- Every canonical ancestor is root-owned, has no group/other write bits and
  denies effective-identity writes by the caller. A writable temporary directory
  is not a protected installation location.

The bounded ELF is checked against the independent SHA-256 pin while retaining
the original FD. Immediately before exec, process privilege and installed-path
checks are repeated; the original FD is used, and no source-path fallback is
attempted. The native Cell-v2 pre-alias gate then compares the loaded image and
its reopenable path by device/inode. Original helper dispatch remains first and
the sandbox/user/PID namespaces are unchanged. This profile does not set global
privilege flags or manufacture a deployment permission.

The root installer must create and keep this exact protected version inode and
its canonical path stable for the owner's lifetime. Reusing an inode that an
untrusted caller previously opened for writing, then only changing its owner or
mode, does not revoke that caller's old writable FD and is outside this profile's
trusted installation procedure. A current stat cannot prove that history.
Root installation/updates, system interpreter
and libraries, and the existing trusted `CODEX_HOME/.env` remain part of the
trusted deployment. These checks exclude the ordinary unprivileged caller from
changing the installation; they do not make claims against a privileged installer
or replace the original model/FinalUse qualification.
Any `LD_*` or `GLIBC_TUNABLES` environment key is rejected before owner inputs
are opened and again on the exact environment snapshot passed to `execve`.
Empty values are also rejected: glibc's `LD_TRACE_LOADED_OBJECTS=` can exit
successfully without executing the program's main function.
The original Fleet/HEPTA/CODEX environment is preserved, not silently sanitized.

`authentication` is either exactly `{ "profile": "content-cache-v1" }`, or
`cell-pq-v2` with `authorization` and `signer_spki` pinned-file objects plus
`signer_key_id`, `generation`, `sequence`, `network`, `parameters`,
`key_not_before`, `key_expires` and nullable `key_revoked_at`. These are the
existing native CPR2 verifier inputs. No key or CPR2 signature is generated.
The initial pin checks retain the exact CPR2/SPKI bytes. Preparation publishes
these bytes into this run's canonical `0700` output directory as create-only
`0600` files; the native verifier receives only these snapshot paths. Replacing
the original authorization or key file after its pin check cannot change the
bytes passed to native admission. The enclosing deployment directory tree must
be trusted against rename/replacement; a private leaf alone does not protect an
ancestor writable by another principal. This is a deployment boundary, not a
claim of protection against a compromised same-UID process.
Failed PQ admission is terminal. CPR2 authenticates the embedded TCR1; the
original owner separately pins TCD1. Selecting this data policy does not change
the Hepta host's FinalUse algorithm or make the whole pair PQ qualified.

## Actual data and time boundaries

The producer exports all eleven actual native TCM1 manifests from its verified
cache. It checks the same owner source/profile/context, builds the existing
controlled sidecar and exact TCD1 with the adapter root depending on the ten
remaining files, and compares all independently supplied pins. Manifest exports
consume the original 120-second release-preparation window; they do not get a
new per-member preparation allowance. Authorization snapshots and TCD1 publication,
including their fsync calls, consume that same window. A post-publication expiry
leaves the handoff unprepared; any late files remain failed-run evidence and do
not enable acquisition or native host entry.

The existing aggregate transfer window remains **35 seconds**, from listener
announcement through TCD1 acquisition, all cache-only materializations and final
consumer readbacks. Connection, response-byte and cache caps remain aggregate.
Only the native TCD1 completion marker and rehashed files qualify this data step.
The finite provider exits before host entry. The sidecar is then published with
create-only protected-file semantics.

In the sealed v2 profile, the bounded native ELF is copied into a Linux memfd, sealed against writes and
size changes, and only then checked against its independent SHA-256 pin. That
sealed descriptor survives into `execve`; replacing the source path or rewriting
the same source inode cannot change the executed ELF. This pins the ELF image,
not its system ELF interpreter or shared libraries. The initial Python process,
its startup environment and the protected host/deployment remain trusted inputs;
the later loader check cannot undo code run when Python originally started.
The process attempts the ordinary host with its original environment and workspace.
The current sealed-image profile does not preserve the ordinary Hepta helper
re-execution paths across its unchanged sandbox PID namespace. Hepta candidate
`b93b7c3fc58d088baad281389547264894e864ef` therefore rejects this anonymous image
at its explicit Cell-v2 entry, before dotenv, helper aliases or model owners.
This profile remains **HOLD for ordinary host use**; a successful ELF argv probe
does not establish the real daemon's usability. The explicit handoff-v3 protected-installed profile retains the original image
FD and stable installed paths, and requires its own admission and actual native
tests. Its presence does not upgrade the sealed profile or prove model use.

When an ordinary compatible image reaches the original host, Hepta applies its
existing **120-second startup window**, shared with Cell verification,
qualification, FinalUse and physical loading. Transport completion does not
start a parallel inference owner or manufacture a successful receipt.


`handoff.json` ends at `transport-complete-handoff-pending` / `EXEC_REQUESTED` /
`UNVERIFIED`, with installation and FinalUse observations false. It is an immutable
transport record, not a live daemon status. The existing external supervisor and
original owner readbacks observe the exec'd daemon's later admission, use and
termination. An exec syscall failure is separately recorded as failed. OS-blocked
reads retain their owners until returning; this is not hard preemption evidence.

## Validation

Run the new producer controls with a freshly built native binary:

```sh
TRNM_CELL_BIN=/absolute/path/trnm-cell python3 scripts/ci/test_llm_cell_host_handoff.py -v
python3 scripts/ci/test_llm_cell_handoff_deadline.py -v
```

Installed-image permission/CLI controls use actual root-installed test copies
and the original nonroot CI caller:

```sh
bash scripts/ci/run_llm_cell_installed_host_controls.sh /absolute/path/trnm-cell /absolute/path/hepta-neural-agentd
```

This CI-only runner creates one new random directory under `/opt` through
existing noninteractive sudo permission, copies only the harmless argv probe and
the actual compiled native daemon, and removes that exact directory on exit.
SUID/SGID/capability rejection fixtures contain inert non-loadable bytes. It does
not install a service, change a user or alter a running deployment. If the local
environment cannot supply a real protected installation, deployment positives
are skipped/`NOT_CONFIGURED`; parser or writable-file rejections do not substitute
for those positives. The CI runner requires all eight installed-image controls,
including an actual v3 TCP transport to the harmless installed argv probe and
actual installed Hepta CLI/helper dispatch. Neither is a model qualification.

The native positive uses synthetic eleven-file bytes, actual TCP, TCD1 validation,
cache-only materialization and an ELF argv probe. The probe only verifies process
handoff; it is explicitly not a real Hepta model or use admission. Production
acceptance still requires real protected owner inputs and the ordinary daemon's
actual original-owner observations. An absent native test binary is a skipped
control, never passing native evidence.

The PQ swap control signs two real ML-DSA CPR2 statements for the same release:
the independently pinned A is withdrawn and B is allowed. After initial pinning,
it replaces A's source with B and later replaces the source SPKI. Native admission
still rejects the retained A before creating a consumer cache; a separate actual
native B acquisition succeeds from the verified producer cache. The ELF control
rewrites an echo probe's original inode with a false probe: execution from the
sealed descriptor retains echo's argv/exit behavior, and actual writes/grow/shrink
attempts fail. These test-only keys and probes confer no production authority.
Separate controls reject loader overrides both initially and when inserted
after configuration loading, before the actual exec call can be reached.
The empty-value control first reproduces the real glibc trace-only exit-zero
behavior with a harmless ELF probe, then verifies that this setting cannot reach
the handoff's exec call.
