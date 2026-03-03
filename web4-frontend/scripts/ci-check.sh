#!/usr/bin/env bash
set -euo pipefail

npm run lint
npm run typecheck
npm run --if-present test
npm run build
