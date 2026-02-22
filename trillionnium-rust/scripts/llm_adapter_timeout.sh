#!/usr/bin/env bash
set -euo pipefail
sleep "${LLM_TIMEOUT_SLEEP_SECONDS:-5}"
printf '{"output_text":"late","provider_request_id":"timeout-mock"}\n'
