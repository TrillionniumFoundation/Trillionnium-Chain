from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import json
import os
import ssl
import subprocess
import time
import urllib.request

ROOT = Path('/home/qian-qi/chain-credit-envelope-20261108-f7e62')
OUT = Path('/home/qian-qi/credit-envelope-f7e62-provider2')
EXPECTED = '603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a'
SIZE = 53279637
CHUNK = 4*1024*1024
URLS = (
    'https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz',
    'https://api.github.com/repos/openssl/openssl/releases/assets/598377651',
)
head = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
assert head == '57511355b9dfb1fc02c90eb0713fd8e95263a662'
OUT.mkdir(exist_ok=False)
(OUT/'transport').mkdir()
context = ssl.create_default_context()
context.minimum_version = ssl.TLSVersion.TLSv1_2

def download(index):
    start = index*CHUNK
    end = min(SIZE, start+CHUNK)-1
    attempts = []
    for number in range(3):
        url = URLS[number % len(URLS)]
        tick = time.monotonic()
        try:
            request = urllib.request.Request(url, headers={
                'Range': f'bytes={start}-{end}', 'Accept': 'application/octet-stream',
                'User-Agent': 'Trillionnium-fixed-provider-validation',
            })
            with urllib.request.urlopen(request, timeout=60, context=context) as response:
                content_range = response.headers.get('Content-Range')
                if response.status != 206 or content_range != f'bytes {start}-{end}/{SIZE}':
                    raise ValueError('unexpected status or content range')
                content = response.read(end-start+2)
                if len(content) != end-start+1:
                    raise ValueError('incomplete or oversized range')
            target = OUT/'transport'/f'part-{index:03d}'
            with target.open('xb') as stream:
                stream.write(content)
            attempts.append({'attempt': number+1,'transport_url': url,'elapsed_seconds': time.monotonic()-tick,
                             'http_status': 206,'content_range': content_range,'bytes': len(content),
                             'sha256': hashlib.sha256(content).hexdigest(),'passed': True})
            record = {'part': index,'start': start,'end': end,'attempts': attempts,'passed': True}
            (OUT/'transport'/f'part-{index:03d}.json').write_text(json.dumps(record,indent=2)+'\n')
            print(json.dumps({'part': index,'bytes': len(content),'passed': True}),flush=True)
            return record
        except Exception as error:
            attempts.append({'attempt': number+1,'transport_url': url,'elapsed_seconds': time.monotonic()-tick,
                             'error_type': type(error).__name__,'http_status': getattr(error,'code',None),
                             'passed': False})
    record = {'part': index,'start': start,'end': end,'attempts': attempts,'passed': False}
    (OUT/'transport'/f'part-{index:03d}.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'part': index,'passed': False}),flush=True)
    return record

with ThreadPoolExecutor(max_workers=4) as pool:
    futures = [pool.submit(download,i) for i in range((SIZE+CHUNK-1)//CHUNK)]
    records = sorted((future.result() for future in as_completed(futures)),key=lambda row:row['part'])
transport = {'schema':'pon-fixed-provider-range-transport-v1','source_commit':head,
             'official_release_asset_id':598377651,'expected_bytes':SIZE,'expected_sha256':EXPECTED,
             'parts':records,'all_parts_complete':all(row['passed'] for row in records)}
(OUT/'transport-summary.json').write_text(json.dumps(transport,indent=2)+'\n')
if not transport['all_parts_complete']:
    raise SystemExit('range transport incomplete; all observations retained')
archive = OUT/'openssl-3.5.9.tar.gz'
with archive.open('xb') as stream:
    for row in records:
        stream.write((OUT/'transport'/f"part-{row['part']:03d}").read_bytes())
actual = hashlib.sha256(archive.read_bytes()).hexdigest()
(OUT/'archive-verification.json').write_text(json.dumps({'bytes':archive.stat().st_size,'sha256':actual,
                                                        'expected_sha256':EXPECTED,'passed':actual==EXPECTED},indent=2)+'\n')
assert archive.stat().st_size == SIZE and actual == EXPECTED
(OUT/'runner').mkdir()
(OUT/'github.env').touch(exist_ok=False)
env = dict(os.environ)
env.update(RUNNER_TEMP=str(OUT/'runner'),GITHUB_ENV=str(OUT/'github.env'),
           TRNM_CI_RECEIPT_DIR=str(OUT/'observations'),CARGO_BUILD_JOBS='2',
           PYTHONDONTWRITEBYTECODE='1',TRNM_PQ_SOURCE_ARCHIVE=str(archive))
subprocess.run(['bash','scripts/project-preflight.sh','--audit'],cwd=ROOT,env=env,check=True)
started = datetime.datetime.now(datetime.timezone.utc).isoformat()
tick = time.monotonic()
with (OUT/'setup.stdout.log').open('xb') as stdout,(OUT/'setup.stderr.log').open('xb') as stderr:
    result = subprocess.run(['bash','scripts/ci/prepare_pq_provider.sh'],cwd=ROOT,env=env,stdout=stdout,stderr=stderr)
ending = subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
record = {'source_commit':head,'source_unchanged':ending==head,
          'command':['bash','scripts/ci/prepare_pq_provider.sh'],'started_utc':started,
          'elapsed_seconds':time.monotonic()-tick,'exit_code':result.returncode,'source_modified':False}
(OUT/'setup-result.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
print(json.dumps(record),flush=True)
raise SystemExit(result.returncode if ending==head else 2)
