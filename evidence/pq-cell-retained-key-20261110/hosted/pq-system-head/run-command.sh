set -euo pipefail
label="$1"
shift
source_args=(--kind "$SOURCE_KIND" --candidate "$EXPECTED_HEAD" --tested "$EXPECTED_TESTED")
if test "$SOURCE_KIND" = prospective-merge; then
  source_args+=(--base "$EXPECTED_BASE")
fi
command_status=0
python3 scripts/ci/record_pq_native_command.py "${source_args[@]}" --label "$label" --output "$PQ_OUT" -- "$@" || command_status=$?
if test -f "$PQ_OUT/$label.log"; then
  if test "$command_status" -ne 0; then
    tail -n 200 "$PQ_OUT/$label.log"
  else
    case "$label" in
      node-lib) sed -n '/test result:/p; /trnm-state-delta-walk-observation-v1/p; /trnm-current-account-.*observation-v1/p' "$PQ_OUT/$label.log" ;;
      cost-*) cat "$PQ_OUT/$label.log" ;;
    esac
  fi
fi
exit "$command_status"
