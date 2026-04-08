#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/trillionnium"

echo "[A2] A2A adapter implementation gate: protocol alias normalization + fail-closed filtering"

cargo test -p trnm-worker-agent attach_llm_provenance_accepts_agent_protocol_aliases
cargo test -p trnm-worker-agent attach_llm_provenance_drops_unsupported_agent_protocol
cargo test -p trnm-worker-agent attach_llm_provenance_normalizes_agent_protocol_casing
cargo test -p trnm-worker-agent attach_llm_provenance_rejects_non_ascii_or_invisible_agent_protocol_aliases
cargo test -p trnm-worker-agent export_audit_index_normalizes_agent_protocol_aliases_to_canonical_keys
cargo test -p trnm-worker-agent normalized_agent_protocol_accepts_future_version_suffixes
cargo test -p trnm-worker-agent normalized_agent_protocol_accepts_punctuation_variants_for_aliases
cargo test -p trnm-worker-agent normalized_agent_protocol_accepts_websocket_aliases

echo "[A2][PASS] A2A adapter implementation gate"
