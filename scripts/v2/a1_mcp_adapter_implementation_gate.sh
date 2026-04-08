#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

echo "[A1] MCP adapter implementation gate: runtime fail-closed + provenance canonicalization"

cargo test -p trnm-worker-agent enterprise_audit_export_flattens_v2_provenance_for_agent_and_compliance
cargo test -p trnm-worker-agent enterprise_audit_export_normalizes_mcp_streamable_http_aliases_for_v2_schema
cargo test -p trnm-worker-agent enterprise_audit_export_normalizes_mcp_websocket_aliases_for_v2_schema
cargo test -p trnm-worker-agent enterprise_audit_export_normalizes_mcp_sse_aliases_for_v2_schema
cargo test -p trnm-worker-agent enterprise_audit_export_fail_closed_on_noncanonical_schema_tag
cargo test -p trnm-worker-agent export_audit_markdown_contains_provenance_fingerprint_fields

echo "[A1][PASS] MCP adapter implementation gate"
