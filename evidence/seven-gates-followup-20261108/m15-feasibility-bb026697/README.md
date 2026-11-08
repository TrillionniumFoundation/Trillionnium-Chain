# M15 static native feasibility at bb026697

**Result: blocked before static compilation and before the original isolated Rust case.** Two independent prerequisite checks refused the current desktop setup. The source and the original 32-step / 180-second / RPC-2 contract remain unchanged. No debug executable was substituted, no host setting or permission was changed, and no new native success or deployment qualification is claimed.

## Fixed source and existing inputs

The desktop checkout is `/home/qian-qi/workspace/chain-seven-gates-20261108-3a20/source-exact` at:

- Commit: `bb026697a972521009bc133ae6ed2b653e18e931`.
- Tree: `18175756871bf341586fc37be1b17a00ef1dd099`.
- Branch: `fix/chain-seven-gates-followup-20261108-3a20`.
- Official repository origin and clean Git status were observed before the probe; the final runtime diagnostic again observed the same commit/tree and clean status.

The existing host is Linux x86_64 with outer UID/GID 1000. Rust and Cargo 1.95.0 were read back from their real toolchain paths. Python 3.12.3, unshare, mount, setpriv, newuidmap, newgidmap, chroot, and the native compiler/binutils tools were present and fingerprinted. The protected `/etc/subuid` and `/etc/subgid` each contain `qian-qi:100000:65536`, which includes the requested existing 2000-ID ranges.

`static-build-tools.json` pins the original OpenSSL 3.5.9 provider, all **142 installed provider headers**, both static archives, the actual OpenSSL executable, the existing provider-preparation receipt, and the eight build tools. The preparation reached and returned from the original `m15_static_native_build.input_tools()` check, then failed later at the isolated runtime input check. This is an accepted build-input contract observation, not a successful build.

| Input | SHA-256 |
| --- | --- |
| Static build tool manifest | `dbfaebf6b4e5874645d5458f67e32e4296a653e40a9b65dd7a9931689b74a1eb` |
| Isolated runtime manifest candidate, **rejected** | `0833b10590a1f96836027335e52f0ae43acf329a3b1d1d0cf32033f69fd4ebfc` |
| Original provider preparation receipt | `ceabed0dca2eb705ff1bd37222466c55bf1a7d3df32901075a1e2f2c5881230a` |
| Original provider OpenSSL executable | `8ff7dd91270fd4a8fc377031f0fd2f2cee1cd17a32ce30e4fd773a25730a120f` |

## Observed blockers

### 1. The original namespace mapping is refused

The probe used the same namespace and mapping flags as the original isolated runner, followed only by a small Python readback of namespace identities and UID/GID maps:

```text
/usr/bin/unshare --user --map-root-user
  --map-users=1:100000:2000 --map-groups=1:100000:2000
  --setgroups=allow --mount --pid --fork --kill-child=KILL
  --ipc --uts --net --propagation=private
  /usr/bin/python3.12 -I -B -c <read-only namespace readback>
```

The actual `unshare` command exited **1** with:

```text
unshare: cannot open /proc/self/setgroups: Permission denied
```

Its recorder exited 0 because it successfully retained this negative observation; that recorder status is **not namespace success**. The record explicitly says `namespace_ready: false`, `static_build_started: false`, and `native_case_executed: false`. No test-root tmpfs/proc/bind mount was attempted and no Node was run. The exact observation is retained in `remote-records/namespace-probe.json`, SHA-256 `be86fea5b59f729d606724c0f03e2c0081c208e132adc1ee3683e85632b13890`.

The diagnostic observer reported `NoNewPrivs: 0`, `Seccomp: 0`, and AppArmor context `unconfined`; the earlier readback reported `apparmor_restrict_unprivileged_userns=1`. These are observations, not a determination of the precise kernel-policy cause of the refusal. The probe did not change `--setgroups=allow`, reduce the namespaces, or alter host policy.

### 2. The existing setpriv runtime violates the original file-custody contract

The original `m15_isolated_native_support.pinned_file()` requires a single-linked, protected regular tool/runtime file. The current setpriv closure includes:

| Existing file | Link count | Original check |
| --- | ---: | --- |
| `/usr/lib/x86_64-linux-gnu/libc.so.6` | **2** | **Rejected** |
| `/usr/lib/x86_64-linux-gnu/libcap-ng.so.0.0.0` | 1 | Accepted |
| `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2` | 1 | Accepted |

The rejected libc has UID/GID 0, mode 0755, size 2,129,424 bytes, and SHA-256 `3a15d66867d83762c7f2f1e37359cb8f6c5743edb369c65285cb0b1c4f7498bf`. The preparation job exited **1** at the original input check with `ValueError: single-linked regular tool/source required`. The later read-only diagnostic called the original predicate on each actual closure file and retained the results. It did not copy, replace, relink, chmod, or chown any system file.

The exact diagnostic is `remote-records/runtime-files-diagnostic.json`, SHA-256 `b5b68b8af3c59e078af19fe00aedeec8899574c29b4ff26dacb9fe06a699d30a`.

## Original entry points and candidate commands

The only selected Rust case remains:

```text
release_owner::native_consumer_tests::isolated_fixed_root_static_node_claim_refresh_and_revocation
```

Its tracked `#[ignore]` is explicit: it requires reviewed static Node/libtest artifacts and fresh rootless user/mount/PID namespaces. An ordinary Node library run that leaves this case ignored does not execute it.

The exact static-build candidate below is recorded for review and **was not run**. The current overall sequence remains blocked by both observations above:

```sh
/usr/bin/python3.12 -I -B \
  /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/source-exact/scripts/m15_static_native_build.py \
  --repo /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/source-exact \
  --output /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/m15-static-bb026697-01 \
  --expected-head bb026697a972521009bc133ae6ed2b653e18e931 \
  --expected-tree 18175756871bf341586fc37be1b17a00ef1dd099 \
  --tool-inputs /home/qian-qi/workspace/chain-seven-gates-20261108-3a20/m15-feasibility-v1/static-build-tools.json \
  --tool-inputs-sha256 dbfaebf6b4e5874645d5458f67e32e4296a653e40a9b65dd7a9931689b74a1eb \
  --compile-timeout-seconds 14400
```

The original builder selects locked/offline release compilation, `--target x86_64-unknown-linux-gnu`, `pq-native-openssl`, `target-feature=+crt-static`, and **2 jobs**. It builds the real Node and compiles the libtest artifact without running tests. It verifies actual static ELF bytes, original source and dependency closure before/after, and retains artifact identities. It creates a fresh target under its own output directory. Its bounded compilation allowance is separate from the Rust case's 180-second execution contract.

The isolated runner template is fully specified in `execution-plan.json`, including the current rejected runtime-manifest candidate. It cannot be launched as a qualified attempt now: the namespace check failed, the runtime manifest was rejected, and there is **no newly built `artifacts.json` or valid artifact digest** to supply. A later legitimate attempt must bind the SHA-256 of its actual new artifact manifest, retain the current failures, and pass the unchanged original artifact/tool predicates. No prior debug binary or older branch's successful artifact can fill that identity.

The unchanged isolated runner enforces:

- Inner Rust case: **32 steps / 180 seconds / service RPC 2 seconds**.
- Explicit selector with `--exact`, `--ignored`, `--nocapture`, and `--test-threads=1`.
- A 195-second inner cleanup ceiling and 240-second outer setup/cleanup ceiling, neither of which changes the Rust acceptance budget.
- A bounded private tmpfs, with the actual artifact sizes checked before use. The plan records a 2048 MiB candidate; it is not a measured resource result.
- Actual static same-FD execution, a single authenticated claim, refresh and revocation controls, two fixture principals, signed Clock observations, owned-process cleanup, and retained fixture state.

## Durable jobs and retained evidence

| Operation | Job ID | Job exit | Interpretation |
| --- | --- | ---: | --- |
| Read-only prerequisite inventory | `1a1bc85bb06-138b0-309` | 0 | Inputs observed; no build or namespace |
| Namespace observation recorder | `1a1bc88e35c-138b0-31e` | 0 | Internal `unshare` exit **1** retained |
| Exact input preparation | `1a1bc8df7e2-138b0-335` | **1** | Original runtime-custody predicate refused libc |
| Read-only runtime diagnosis | `1a1bc9051aa-138b0-344` | 0 | Original refusal localized; no fix applied |

All four jobs reached terminal states, with complete, durable, untruncated stdout/stderr. Their original start arguments, stable request keys, status responses, read responses, raw streams, and exact retained files are included. `source/` contains the relevant unchanged source files; `execution-plan.json` carries their hashes and Git blobs. `SHA256SUMS` inventories the evidence directory.

The remote observations remain under `/home/qian-qi/workspace/chain-seven-gates-20261108-3a20/m15-feasibility-v1`. This is feasibility and negative-prerequisite evidence. **The M15 native case remains unexecuted, the original 32-command campaign is not replaced, and overall qualification remains HOLD.**
