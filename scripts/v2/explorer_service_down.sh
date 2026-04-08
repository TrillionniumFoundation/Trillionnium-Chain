#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
exec "$ROOT/trillionnium/scripts/v2/explorer_service_down.sh" "$@"
