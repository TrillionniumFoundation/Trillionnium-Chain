#!/usr/bin/env bash
set -euo pipefail

npm run lint
npm run typecheck
npm run --if-present test

if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
  npm run --if-present test:e2e
else
  echo "[ci-check] skipping e2e (set CI_RUN_E2E=1 to enable)"
fi

npm run build
