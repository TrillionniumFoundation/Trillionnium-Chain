set -euo pipefail
python3 -B hia/tools/bootstrap.py --output "$RUNNER_TEMP/hia-bootstrap"
python3 - "$RUNNER_TEMP/hia-bootstrap/bootstrap.json" "$GITHUB_ENV" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
if value.get('status') != 'PASS':
    raise SystemExit('HIA compiler bootstrap did not pass')
if value.get('compiler_sha256') != '87c247e4d1c3c9a449d2947fd4227fdc186d519bffd203a04cafce7861a4ed54':
    raise SystemExit('HIA compiler identity differs from the pinned native compiler')
if not value.get('compiler'):
    raise SystemExit('HIA native compiler path is absent')
with open(sys.argv[2], 'a') as out:
    out.write('HIA_NATIVE_COMPILER=' + value['compiler'] + '\n')
    out.write('HIA_NATIVE_COMPILER_SHA256=' + value['compiler_sha256'] + '\n')
PY
