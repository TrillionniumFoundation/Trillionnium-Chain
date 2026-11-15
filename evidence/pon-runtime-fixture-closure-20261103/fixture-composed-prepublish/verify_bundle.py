from pathlib import Path
import base64, gzip, hashlib, json, sys

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent
def sha(data): return hashlib.sha256(data).hexdigest()
index = json.loads((root / 'artifact-index.json').read_bytes())
for item in index['artifacts']:
    data = (root / item['path']).read_bytes()
    assert len(data) == item['bytes'] and sha(data) == item['sha256'], item['path']
summary = json.loads((root / 'source-bound-summary.json').read_bytes())
packed = (root / summary['raw_bundle']['path']).read_bytes()
assert int.from_bytes(packed[4:8], 'little') == 0
assert sha(packed) == summary['raw_bundle']['sha256']
raw = gzip.decompress(packed)
assert len(raw) == summary['raw_bundle']['uncompressed_bytes']
assert sha(raw) == summary['raw_bundle']['uncompressed_sha256']
bundle = json.loads(raw)
assert len(bundle['entries']) == len({row['path'] for row in bundle['entries']})
for row in bundle['entries']:
    blob = bundle['blobs'][row['blob']]
    data = base64.b64decode(blob['data'], validate=True)
    assert len(data) == row['bytes'] == blob['bytes']
    assert sha(data) == row['sha256'] == row['blob']
    assert not row['path'].endswith('/native.log')
assert len(bundle['entries']) == summary['raw_bundle']['original_entries']
manifest = (root / 'native-source-manifest.json').read_bytes()
assert sha(manifest) == summary['source']['native_manifest_sha256']
assert len(json.loads(manifest)) == summary['source']['native_manifest_paths'] == 1190
assert summary['full_registry']['status'] == bundle['full_registry_status'] == 'PENDING'
assert summary['full_registry']['observed_passed'] is None
assert summary['full_registry']['observed_failed'] is None
assert summary['full_registry']['observed_ignored'] is None
assert bundle['full_registry_log_or_terminal_result_included'] is False
assert summary['prior_diagnostics_only_run_is_separate']['counts_carried_forward'] is False
print(json.dumps({'status':'PASS_READ_ONLY_PACKAGE_VERIFICATION','artifacts':len(index['artifacts']),'raw_entries':len(bundle['entries']),'unique_raw_blobs':len(bundle['blobs']),'full_registry':'PENDING','index_sha256':sha((root/'artifact-index.json').read_bytes())},sort_keys=True))
