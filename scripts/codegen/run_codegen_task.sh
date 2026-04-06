#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TASK="${1:-}"
if [[ -z "$TASK" ]]; then
  echo "usage: $0 <task-id>" >&2
  exit 2
fi

case "$TASK" in
  A1)
    # Placeholder: wire A1 metric hooks scaffolding marker file (safe incremental step)
    mkdir -p "$ROOT/trillionnium/run/codegen"
    echo "task=A1 metric hooks scaffold $(date '+%F %T')" > "$ROOT/trillionnium/run/codegen/A1.txt"
    ;;
  A2)
    mkdir -p "$ROOT/trillionnium/scripts"
    if [[ ! -f "$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh" ]]; then
      cat > "$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[TODO] consensus fault matrix scaffold"
EOF
      chmod +x "$ROOT/trillionnium/scripts/run_consensus_fault_matrix.sh"
    fi
    ;;
  A3)
    mkdir -p "$ROOT/docs/protocol"
    if [[ ! -f "$ROOT/docs/protocol/consensus-v1-freeze.md" ]]; then
      cat > "$ROOT/docs/protocol/consensus-v1-freeze.md" <<'EOF'
# Consensus v1 Freeze (Scaffold)

- status: draft
- scope: finality, recovery, fault behavior
EOF
    fi
    ;;
  B1|B2|B3|C1|C2|C3)
    mkdir -p "$ROOT/trillionnium/run/codegen"
    echo "task=$TASK scaffold $(date '+%F %T')" > "$ROOT/trillionnium/run/codegen/${TASK}.txt"
    ;;
  *)
    echo "unknown task: $TASK" >&2
    exit 3
    ;;
esac

echo "[OK] codegen task $TASK"
