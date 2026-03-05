#!/usr/bin/env bash
set -euo pipefail

npm run lint
npm run typecheck
npm run test
npm run test:contract

if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
  npm run --if-present test:e2e
else
  echo "[ci-check] skipping e2e (set CI_RUN_E2E=1 to enable)"
fi

if [[ -d .next ]]; then
  echo "[ci-check] cleaning previous .next artifacts"
  rm -rf .next
fi

npm run build

echo "[ci-check] PASS: lint + typecheck + test + contract + build"
