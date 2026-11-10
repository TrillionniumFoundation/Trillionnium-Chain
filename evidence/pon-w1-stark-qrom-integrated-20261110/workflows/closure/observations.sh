set -euo pipefail
out="$RUNNER_TEMP/w1-qrom-current-closure-$SOURCE_KIND-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"
mkdir "$out"
printf 'W1_CLOSURE_OUT=%s\n' "$out" >> "$GITHUB_ENV"
printf 'Current selected-source lifetime observation, explicit V1 refusal and separate current named roster only. Original historical positives execute in their own fixed checkout. No complete QROM theorem, adversary budget or qualification is granted.\n' > "$out/SCOPE.txt"
