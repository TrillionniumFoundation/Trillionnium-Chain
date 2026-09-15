#!/usr/bin/env bash
# Execute independent commands without losing the family's aggregate failure.
# Source this file, call trnm_gate for each command, then trnm_gate_finish.
# This collects execution outcomes only; it is not independent acceptance.
TRNM_GATE_COMMAND_COUNT=0
TRNM_GATE_FAILURE_COUNT=0

trnm_gate() {
  local rc=0 seconds="${TRNM_GATE_TIMEOUT_SECONDS:-900}"
  TRNM_GATE_COMMAND_COUNT=$((TRNM_GATE_COMMAND_COUNT + 1))
  printf 'gate_command=%s argv=' "$TRNM_GATE_COMMAND_COUNT"
  printf '%q ' "$@"
  printf '\n'
  if [[ $# -eq 0 || ! "$seconds" =~ ^[1-9][0-9]{0,4}$ ]]; then
    printf 'gate_command_error=invalid-command-or-timeout\n' >&2
    rc=2
  elif timeout --signal=TERM --kill-after=5s -- "${seconds}s" "$@"; then
    rc=0
  else
    rc=$?
  fi
  if [[ "$rc" -ne 0 ]]; then
    TRNM_GATE_FAILURE_COUNT=$((TRNM_GATE_FAILURE_COUNT + 1))
  fi
  printf 'gate_command=%s exit=%s\n' "$TRNM_GATE_COMMAND_COUNT" "$rc"
  # The collector continues, but trnm_gate_finish must return the family result.
  return 0
}

trnm_gate_finish() {
  printf 'gate_commands=%s gate_failures=%s\n' \
    "$TRNM_GATE_COMMAND_COUNT" "$TRNM_GATE_FAILURE_COUNT"
  if [[ "$TRNM_GATE_COMMAND_COUNT" -eq 0 ]]; then
    printf 'gate_error=no-commands-executed\n' >&2
    return 2
  fi
  [[ "$TRNM_GATE_FAILURE_COUNT" -eq 0 ]]
}
