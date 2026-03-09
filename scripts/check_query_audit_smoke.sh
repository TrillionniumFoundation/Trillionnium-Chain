#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/trillionnium-rust/scripts/check_query_audit_smoke.sh" "$@"
