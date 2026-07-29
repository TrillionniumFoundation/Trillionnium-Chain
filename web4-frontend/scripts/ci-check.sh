#!/usr/bin/env bash
set -euo pipefail

# Stabilize locale/time-sensitive snapshots and logs across developer/CI hosts.
export TZ=UTC
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

npm run dependency:compat
npm run lint
npm run typecheck
npm run test
npm run test:contract

if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
  npm run test:e2e
else
  echo "[ci-check] skipping e2e (set CI_RUN_E2E=1 to enable)"
fi

if [[ -d .next ]]; then
  echo "[ci-check] cleaning previous .next artifacts"
  rm -rf .next
fi

npm run build

if [[ "${CI_RUN_E2E:-0}" == "1" ]]; then
  echo "[ci-check] PASS: lint + typecheck + test + contract + e2e + build"
else
  echo "[ci-check] PASS: lint + typecheck + test + contract + build"
fi
