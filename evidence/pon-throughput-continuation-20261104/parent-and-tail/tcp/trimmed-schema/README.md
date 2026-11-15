# TCP controls — trimmed-schema dirty 73ab candidate

This is a separate rerun of the same five TCP controls at **2026-11-04 08:03:44 UTC**. All five tests and all five required-selector readers passed. [summary.json](summary.json) and the untouched [receipt.json](receipt.json) record the scope and identities.

The actual source was **dirty `73ab6e9a83bcc836e261d93f9bb23ceafe556758`**, with native input map **`0e9dd2812f4ae9388e5bba175934ee71632c4e053f5f94906d0dd21a22209c88`** and ELF SHA256 **`65d283d519c942230a44b99db1b05308f226d5bca9706f8a1db059a7b852e144`**. These observations preceded the later fast-forward. They are **not test results for `b8116f65789a85148254f870c678a44f895316de`**, its dirty successor, or bare 73ab.

## Exact observation

The graph agent compiled the complete Node lib test executable with `--all-features --no-run` and the original profile. This run adopted that existing ELF by its actual hash and executed only the five named TCP controls. It did not invoke Cargo. The build's [command](build-origin/command.json), [result](build-origin/result.json), [raw stdout gzip](build-origin/stdout.jsonl.gz), [raw stderr](build-origin/stderr.txt), and [adoption receipt](adopted-build.json) are preserved.

| Control | Test stdout | Test stderr | Required-selector output |
|---|---|---|---|
| Complete body rejects tail; pending legal frame remains unread | [1](tests/test-1.stdout) | [1](tests/test-1.stderr) | [1](tests/test-1-required.stdout) |
| Legal early body survives waiting for Ready and submits | [2](tests/test-2.stdout) | [2](tests/test-2.stderr) | [2](tests/test-2-required.stdout) |
| Tail with write half open or half-closed cancels queued work and preserves accounting | [3](tests/test-3.stdout) | [3](tests/test-3.stderr) | [3](tests/test-3-required.stdout) |
| Existing signed-submit half-close/disconnect control | [4](tests/test-4.stdout) | [4](tests/test-4.stderr) | [4](tests/test-4-required.stdout) |
| Existing paid enqueue disconnect control | [5](tests/test-5.stdout) | [5](tests/test-5.stderr) | [5](tests/test-5-required.stdout) |

[Raw test-results.json](test-results.json) retains commands, times, exits, and stdout/stderr hashes. The controls use real localhost TCP and ordinary development classical V3 signed native submission. They do not qualify the PQ handshake, a complete Node test suite, hosted F0/campaign, the four-second SLO, or throughput. Queued cancellation observations do not establish rollback of a transaction already durably committed.

All **1,194 native input files** and the ELF remained unchanged across this rerun. [native-inputs.json.gz](native-inputs.json.gz) stores one manifest, and [source-observations.json](source-observations.json) preserves the identities of the repeated before/after observations. The scope covers recorded workspace source/fixtures and direct external includes; it does not claim all-repository immutability.

## Integrity and reconstruction

This directory has its own [SHA256SUMS](SHA256SUMS) and [copy verification](copy-verification.json). The parent historical f56/dd6a package and its checksum list were left byte-for-byte unchanged.

From this directory, integrity checking requires no build:

```bash
sha256sum --check SHA256SUMS
```

For a future manual reproduction, start with a separate clean checkout of `73ab6e9a83bcc836e261d93f9bb23ceafe556758`. Apply the [parent's frozen native patch](../native/tested-native-from-73ab.patch.gz), then the [three-file overlay](from-f56.patch.gz). The overlay was made from frozen source snapshots, applied in a disposable scratch tree, and every resulting changed-file hash was checked against the target manifest; see [patch-verification.json](patch-verification.json). Do not apply these patches over a checkout already containing them.

With `tcp_evidence` pointing to the parent evidence directory and the working directory at that clean checkout's root:

```bash
gzip -dc "$tcp_evidence/native/tested-native-from-73ab.patch.gz" | git apply -
gzip -dc "$tcp_evidence/trimmed-schema/from-f56.patch.gz" | git apply -
python3 - "$tcp_evidence/trimmed-schema/native-inputs.json.gz" <<'PY_REPRO'
import gzip, hashlib, json, pathlib, sys
manifest=json.loads(gzip.decompress(pathlib.Path(sys.argv[1]).read_bytes()))
for name, expected in manifest["native_input_files"].items():
    assert hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest()==expected, name
canonical=json.dumps(manifest["native_input_files"],sort_keys=True,separators=(",",":")).encode()
assert hashlib.sha256(canonical).hexdigest()==manifest["manifest_sha256"]
print(manifest["manifest_sha256"])
PY_REPRO
bash scripts/project-preflight.sh
```

Use the existing [parent build and five-selector instructions](../README.md), retaining the normal rustup shim, 1.95.0, original all-features profile, and repository PQ provider preparation. Those five selectors are unchanged and also appear in this directory's summary. Rebuilding at another path can change ELF bytes; record the new hash rather than claiming it equals the measured ELF. Original logs retain their historical absolute paths as provenance, while the repository-relative inputs and commands above provide the reproducible source.

This packaging operation ran only integrity, patch-application, and documentation checks. It did not compile or execute native tests, and it does not supersede any earlier failed observation.
