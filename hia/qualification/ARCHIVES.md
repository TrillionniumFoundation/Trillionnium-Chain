# Complete evidence archives

These are the five current volume sets: four complete archives and one compact
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
