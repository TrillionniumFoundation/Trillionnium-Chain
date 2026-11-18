# Complete evidence archives

These are the nine current volume sets: eight complete archives and one compact
Work/Host development view with explicit Git and external-binary dependencies. Every part is a regular file of at most
six MiB. Its manifest binds order, offset, length and SHA256, together with the
complete reconstructed archive. Every original member was independently reopened
and every volume set physically reassembled before publication.

| Evidence | Manifest | Parts | Complete bytes | Complete SHA256 |
| --- | --- | ---: | ---: | --- |
| mempool-typed-development | [manifest](mempool-typed-development.parts/manifest.json) | 4 | 24888160 | `d58b3cf105271e7d76f332a59a9b95969c23d8e1b7d2edfd99c9981172db7ee0` |
| execution-application-ci | [manifest](execution-application-ci.parts/manifest.json) | 12 | 70656656 | `5720f3fd66aee750bf0b212c8ff6dd915e7dd6ad60a85c376e589506f7de3354` |
| work-owner-development | [manifest](work-owner-development.parts/manifest.json) | 8 | 50018340 | `b91bcd33a2cfa683cb158b2a98a43c56d06deddb85ce3cc3703bb1984455c325` |
| work-owner-ci | [manifest](work-owner-ci.parts/manifest.json) | 39 | 243515800 | `16c37259be4b1e0003d0569d2f96e28531bb4e2c1e77c152412f51576f1d2cd6` |
| execution-batch-development | [manifest](execution-batch-development.parts/manifest.json) | 18 | 107152632 | `2446b6d527a21e935be2bda8e4907feeabef28386f1ad16243deb9f05392d4ef` |
| governance-development | [manifest](governance-development.parts/manifest.json) | 2 | 10476388 | `463424d8dbbf64745e409f797d15b8bec8562717758fc0c912ad01e4e5944e8e` |
| control-guard-development | [manifest](control-guard-development.parts/manifest.json) | 3 | 13259644 | `92ee4be881e23483373019bef0987433239967de5737b0467329edafea080623` |
| peer-lease-development | [manifest](peer-lease-development.parts/manifest.json) | 15 | 92757028 | `dfbdf6ac0239898d94ee0494d818112485b6a20fdc050a0dd95d0a5ed3c0e23d` |
| work-handshake-development | [manifest](work-handshake-development.parts/manifest.json) | 7 | 38955024 | `8dfb55c4f9f7ff8c1198aca30670f606f1faf0593276105d57683662c44d11dd` |

Application includes complete c61 and 876 GitHub ZIPs. Work/Host CI includes
complete producer/consumer ZIPs, the full original executable and isolated
original source. Batch's original executables are explicitly external retained
objects; their full identities and locations are in
[the Batch record](execution-batch-development.json). Historical failed
observations remain alongside successful source-specific executions.

## Reconstruct and verify

Run this Python standard-library command from the repository root. It creates
a new private directory, validates each declared regular part, writes complete
archives and checks their final lengths and hashes. It never extracts members
or executes archived scripts.

```bash
python3 -B - <<'PY'
from pathlib import Path
import hashlib, json, os, stat, tempfile

names = (
    "mempool-typed-development", "execution-application-ci",
    "work-owner-development", "work-owner-ci", "execution-batch-development",
    "governance-development", "control-guard-development",
    "peer-lease-development", "work-handshake-development",
)
destination = Path(tempfile.mkdtemp(prefix="trnm-hia-evidence-"))
for name in names:
    base = Path("hia/qualification") / (name + ".parts")
    manifest = json.loads((base / "manifest.json").read_text())
    assert manifest["schema"] == "trnm.hia.contiguous-archive.v1"
    assert manifest["logical_name"] == name + ".tar.xz"
    total = 0
    digest = hashlib.sha256()
    target = destination / manifest["logical_name"]
    with target.open("xb") as output:
        for index, row in enumerate(manifest["parts"]):
            assert row["path"] == f"part-{index:03d}"
            assert type(row["offset"]) is int and row["offset"] == total
            assert type(row["bytes"]) is int and 0 < row["bytes"] <= 6 * 1024 * 1024
            path = base / row["path"]
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as source:
                before = os.fstat(source.fileno())
                assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                data = source.read(row["bytes"] + 1)
                after = os.fstat(source.fileno())
                assert (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) == (
                    after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
                )
            assert len(data) == row["bytes"]
            assert hashlib.sha256(data).hexdigest() == row["sha256"]
            output.write(data)
            digest.update(data)
            total += len(data)
    assert total == manifest["archive"]["bytes"]
    assert digest.hexdigest() == manifest["archive"]["sha256"]
    print(target, total, digest.hexdigest())
PY
```

## Read the compact Work/Host view

After reconstruction, provide the resulting archive and the exact retained original
executable to the reader. The executable must be the 574,468,200-byte object with
SHA256 `d7c7757bdb6409067f5be594c54b230f9ed30bae2d15664e1d1dce526059a2c4`,
a regular single-link file with mode `0500`. The Git repository must contain the
view's pinned commit `326837e4c5a8a6b3b99390063c08a47dc4f9d6a0` and its complete
referenced objects. The reader verifies every referenced blob using immutable
Git object semantics and reads the full external executable.

```bash
python3 -B -I -S hia/tools/read_work_owner_development.py \
  --archive /path/to/work-owner-development.tar.xz \
  --manifest hia/qualification/work-owner-development.view.json \
  --repository . \
  --original-binary /path/to/original-test-binary
```

The view covers 25,677 primary members and 194 supplements, using 20,178 content
objects and 4,004 Git objects for 4,675 logical references. It does not contain
the external executable. Its separately retained complete package is
261,160,948 bytes /`c651437b0b7666987a4cddedd038508ff3dfe8f84ce1cb72de1db7cff5e9375f`;
locations and actual readback receipts are in [the current record](work-owner-development.json).
The [history index](work-owner-development-history.json) binds the replaced
predecessor volumes and qualification record to complete byte-compared c390 Git
objects. The [integration record](work-host-integration.json) and its separate
`work-host-integration-controls.tar.xz` retain root's complete control reports,
raw observations and verified duplicate-copy cleanup proofs.

Embedded formats and complete content indexes remain unchanged. Reconstruction
verifies preserved bytes. It does not execute a runtime again, qualify a new
commit, close an open gate or authorize retirement.

## Work toolchain CI follow-up

The single `work-owner-toolchain-ci.tar.xz` archive and its
[complete member index and observations](work-owner-toolchain-ci.json) retain
the bd620 Work prerequisite failure, full local negative/corrected controls,
both job observations, and all three successful push component ZIPs plus
independent public readback. Tool-generated empty lock metadata is excluded
from the canonical archive; all observed source, failure and raw bytes remain.
This small archive is separate from the nine volume sets above. Its current
source correction requires fresh hosted execution and grants no retirement.

## Node/M05 successor report dossier

[node-owner-development.json](node-owner-development.json) binds the complete
[node-owner-development-reports.tar.xz](node-owner-development-reports.tar.xz)
report/receipt/source-fence dossier for the current finite local qualification.
This is a report archive, not another complete runtime evidence volume set.
All raw streams, native images, original source captures and both independent
original binaries remain explicitly retained at the external locations in the
record. Its local PASS does not replace commit-bound hosted execution.

## Node/Work CI correction dossier

[node-work-ci-corrections.json](node-work-ci-corrections.json) indexes
[node-work-ci-corrections-reports.tar.xz](node-work-ci-corrections-reports.tar.xz).
Every declared regular member was independently reopened and hashed. It retains
the complete old hosted job/API observations, both complete decoded Work
artifacts, local reader/control failures and corrected source-bound observations.
Large original ZIP containers and the separate complete 409,242,432-byte
controls transport remain at explicit external paths. This dossier does not
replace a new commit-bound hosted qualification or the full-chain retirement gates.

## Control-plane and escrow final development archives

These two single-volume archives retain the complete final native/original
executions and all executed binaries. Each has a MANIFEST.json identifying every
other regular member by size and SHA256. Both were independently decompressed
and every member rehashed; their histories retain failures with their own source
identities. Neither archive grants hosted qualification or old-stack retirement.

| Evidence | Record | Bytes | SHA256 | Regular members |
| --- | --- | ---: | --- | ---: |
| [control-plane-development.tar.xz](control-plane-development.tar.xz) | [record](control-plane-development.json) | 2762380 | `f687e83b64104c847319a232b93eb0268e117ad8c4a1882c7435840ef705a0b2` | 3933 |
| [escrow-development.tar.xz](escrow-development.tar.xz) | [record](escrow-vault-development.json) | 4366140 | `b3814f90f74e1f75991e3583cddf2617ef482e78a0ed4b7ef63b21a98e3b2356` | 1466 |

Control-plane's final run6 includes the allocation observer that was missing
from run5 retention. Escrow's partial one-of-seven negative execution remains
INCOMPLETE. The current source snapshots, raw streams and root readbacks are
inside these archives; v1/v2 or other parallel development trees are not active
production implementations.

The small [integration archive](native-owner-integration.tar.xz) and
[record](native-owner-integration.json) retain the whole-tree inventory,
migration/composition/partition and bootstrap raw logs, static source checks,
both complete archive readbacks, original offline-build failure and parent CI
observations. These controls do not substitute for fresh hosted runtime tests.

## Governance, local signature guard, peer values and Work race

These four volume sets retain one canonical final evidence package per current
implementation increment. All regular payloads, including actual native and
original binaries, are present in the archives. Their member indexes retain
size, SHA256 and mode. Historical observations keep their own source identity;
they are not additional active implementations.

| Record | Regular members | Scope of complete retained evidence |
| --- | ---: | --- |
| [Governance](governance-development.json) | 2341 | Final 10 tests, 94 comparisons, 48 retained original tests, actual allocator and process failures, complete final source snapshot |
| [Local plan guard](control-guard-development.json) | 2020 | Final 14 tests, original policy and real local Ed25519 profile, complete native/Rust/allocator observations and all 65 source inputs |
| [Peer lease values](peer-lease-development.json) | 1188 | Final 13 tests, complete 121-test original remote execution with all 16 binaries/libraries, complete 1700-file original source archive, final and reporter-control source snapshots |
| [Work handshake](work-handshake-development.json) | 821 | Complete 24-case scheduling archive, all 20842 full-regression artifacts, actual old/fixed builds, exact source snapshots and complete historical hosted failure ZIPs |

Peer's historical v1 did not retain the old test and README source bytes. Their
observed hashes and all available failed observations remain, but that historical
run cannot claim a complete source reproduction. The final source snapshot is
complete. Its small actual reporter-control driver is additionally retained at
`peer-lease/qualification-report-negative.py` in
[native-extension-integration.tar.xz](native-extension-integration.tar.xz).
Lossless recompression reduced the peer transport from 186317232 to 92757028
bytes; both complete decompressed tar streams were read and verified identical.
No observation, binary, source or member was removed by recompression.

The separate [original Work build](work-handshake-original-build.tar.xz) is a
147792-byte fixed regression input, SHA256
`137c4a0b3ea6b86ad67916ec0c35df512d63fb19405f9c6e4b83bccac0f33811`.
Its 64 regular members retain the actual old HIA build, emitter inputs/outputs
and native images. CI validates its exact identity and safely extracts it before
executing the old/new regression. It is required negative-test evidence, not a
second current production implementation.

The [integration record](native-extension-integration.json) and its archive
retain root's exact inventory, 33 integration tests, four bootstrap groups,
complete 457-test discovery, static workflow checks, full archive/volume
readbacks and precise duplicate/cache cleanup receipts. Initial local ENOSPC,
missing-toolchain setup and reader mistakes remain explicitly recorded. These
checks do not retire any package or replace new commit-bound hosted execution.
