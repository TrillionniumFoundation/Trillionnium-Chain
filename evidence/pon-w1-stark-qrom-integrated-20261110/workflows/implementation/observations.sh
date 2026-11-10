set -euo pipefail
w1_qrom_current_out="$RUNNER_TEMP/pon-w1-qrom-current-v2-$SOURCE_KIND-x64-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
mkdir "$w1_qrom_current_out"
printf 'W1_QROM_CURRENT_OUT=%s\n' "$w1_qrom_current_out" >> "$GITHUB_ENV"
printf 'Current V2 source mapping and original V1 source-pin refusal. Historical V1 positive replay is a separate fixed-source job. All cryptographic, native-execution and production qualifications remain false.\n' > "$w1_qrom_current_out/SCOPE.txt"
python3 --version > "$w1_qrom_current_out/python-version.txt" 2>&1
