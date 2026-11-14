import pathlib,sys,json,hashlib
E=pathlib.Path('/private/tmp/chain-public-policy-prefix-cache-evidence-20261114-v1');O=E/'linux-closed-originals-v1'
data=json.loads(sys.argv[1]);assert not O.exists() and not O.is_symlink();O.mkdir(mode=0o700);P=O/'payloads';P.mkdir(mode=0o700)
assert O.resolve()==O
for row in data['files']:
 q=pathlib.PurePosixPath(row['path']);assert not q.is_absolute() and all(x not in ('','.','..')for x in q.parts)
 (P/q).parent.mkdir(parents=True,exist_ok=True)
b=(json.dumps(data,indent=2)+'\n').encode()
(O/'source-roster.json').write_bytes(b)
print(json.dumps({'status':'CREATE_ONLY_DESTINATIONS_PREPARED','files':len(data['files']),'bytes':sum(x['bytes']for x in data['files']),'source_roster_sha256':hashlib.sha256(b).hexdigest()}))
