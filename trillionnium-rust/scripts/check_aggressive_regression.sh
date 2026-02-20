#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CSV="${CSV:-$(ls -1dt run/bench/bench-regression-matrix-*.csv | head -n 1)}"
MAX_RATIO="${AGGRESSIVE_MAX_RATIO:-2.2}"
MAX_RATIO_CLASSIC="${AGGRESSIVE_MAX_RATIO_CLASSIC:-$MAX_RATIO}"
MAX_RATIO_MIXED="${AGGRESSIVE_MAX_RATIO_MIXED:-2.0}"
MAX_RATIO_HOT_STREAK="${AGGRESSIVE_MAX_RATIO_HOT_STREAK:-2.1}"
MODE="${MODE:-hard}" # hard|warn

echo "Using CSV: $CSV"
echo "MODE=$MODE"
echo "AGGRESSIVE_MAX_RATIO_CLASSIC=$MAX_RATIO_CLASSIC"
echo "AGGRESSIVE_MAX_RATIO_MIXED=$MAX_RATIO_MIXED"
echo "AGGRESSIVE_MAX_RATIO_HOT_STREAK=$MAX_RATIO_HOT_STREAK"

awk -F, -v max_ratio_classic="$MAX_RATIO_CLASSIC" -v max_ratio_mixed="$MAX_RATIO_MIXED" -v max_ratio_hot_streak="$MAX_RATIO_HOT_STREAK" -v mode="$MODE" '
  NR==1 { next }
  {
    workload=$1; txs=$2; keys=$3; strategy=$4; elapsed=$6+0;
    k=workload"|"txs"|"keys;
    if (strategy=="original") orig[k]=elapsed;
    if (strategy=="aggressive-greedy") aggr[k]=elapsed;
  }
  END {
    bad=0;
    for (k in orig) {
      if (!(k in aggr)) {
        printf("missing aggressive-greedy row for %s\n", k) > "/dev/stderr";
        bad=1;
        continue;
      }
      o=orig[k]; a=aggr[k];
      ratio=(o==0)?9999:(a/o);

      split(k, parts, "|");
      wl=parts[1];
      threshold=max_ratio_classic;
      if (wl=="mixed") threshold=max_ratio_mixed;
      else if (wl=="hot-streak") threshold=max_ratio_hot_streak;

      printf("case=%s original=%dms aggressive=%dms ratio=%.3f threshold=%.3f\n", k, o, a, ratio, threshold);
      if (ratio > threshold) {
        printf("regression ratio above threshold: %s ratio=%.3f > %.3f\n", k, ratio, threshold) > "/dev/stderr";
        bad=1;
      }
    }

    if (bad && mode=="hard") exit 31;
    if (bad && mode=="warn") {
      printf("aggressive regression check WARN-only mode\n") > "/dev/stderr";
      exit 0;
    }
  }
' "$CSV"

echo "aggressive regression check: PASS"
