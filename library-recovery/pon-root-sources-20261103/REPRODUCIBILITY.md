# Code-only historical Library recovery (chain, 2026-11-03)

Original ChatGPT Library root records: **60**. Distinct original SHA-256 values: **53**. Duplicate records are mapped to canonical original filenames in `SOURCE_SHA256_MANIFEST.json`. The code-only ZIP packages intentionally omit raw experiment traces, weights, datasets, outputs and checkpoints.

These are historical PoN / DAA research fragments and diagnostics, not an activated consensus profile. Some files were separately preserved in a prior standalone research branch. They must not be linked into live consensus without independent qualification.

## Verify exact source bytes (Python standard library)

Run from this directory after downloading all ZIPs and the manifest:

```python
import pathlib,json,hashlib,zipfile
p=pathlib.Path('.')
j=json.loads((p/'SOURCE_SHA256_MANIFEST.json').read_text())
wanted={r['canonical']:r['sha256'] for r in j['entries']}
found={}
for package in j['packages']:
    zpath=p/package['filename']
    b=zpath.read_bytes()
    assert len(b)==package['bytes']
    assert hashlib.sha256(b).hexdigest()==package['sha256']
    with zipfile.ZipFile(zpath) as z:
        for entry in z.namelist():
            assert entry.startswith('source/') and '..' not in pathlib.PurePosixPath(entry).parts
            name=entry[len('source/'):]
            assert name not in found
            found[name]=hashlib.sha256(z.read(entry)).hexdigest()
            assert wanted[name]==found[name]
assert len(found)==j['unique']
assert all(found[r['canonical']]==r['sha256'] for r in j['entries'])
print('source byte integrity PASS')
```

The manifest additionally carries each original full Git Blob SHA-1 and original byte size. This is a source transport/integrity reproducibility statement—not a claim that tests can be executed outside their exact historical repository context or that security/production blockers are closed. GitHub archive ZIP Git Blob SHA objects were verified before the recovery tree was committed. Keep the original Library copies until the dot machine's unpushed commits and archive-contained source inventory have also been audited.
