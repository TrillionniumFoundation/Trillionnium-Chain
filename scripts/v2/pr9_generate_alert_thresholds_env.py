#!/usr/bin/env python3
"""PR9: generate alert-thresholds.env from PR7 threshold advisor output."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate PR9 env from PR7 threshold-advice.json")
    ap.add_argument(
        "--advice-json",
        default="",
        help="path to PR7 threshold-advice.json (default: latest under run/pr7-threshold-advisor/*)",
    )
    ap.add_argument(
        "--out-env",
        default="run/pr9/alert-thresholds.env",
        help="output env path (default: run/pr9/alert-thresholds.env)",
    )
    args = ap.parse_args()

    root = Path(__file__).resolve().parents[2]

    if args.advice_json:
        advice_path = (root / args.advice_json).resolve() if not Path(args.advice_json).is_absolute() else Path(args.advice_json)
    else:
        candidates = sorted((root / "run" / "pr7-threshold-advisor").glob("*/threshold-advice.json"))
        if not candidates:
            raise SystemExit("No threshold-advice.json found under run/pr7-threshold-advisor")
        advice_path = candidates[-1]

    out_env = (root / args.out_env).resolve() if not Path(args.out_env).is_absolute() else Path(args.out_env)
    out_env.parent.mkdir(parents=True, exist_ok=True)

    data = json.loads(advice_path.read_text(encoding="utf-8"))
    sug = data["suggestions"]

    rows = {
        "WARN_UNRESOLVED_CHALLENGES": int(round(float(sug["unresolved_challenges"]["warn"]))),
        "FAIL_UNRESOLVED_CHALLENGES": int(round(float(sug["unresolved_challenges"]["fail"]))),
        "WARN_FORFEITS_DAILY_INCREASE": int(round(float(sug["forfeits_daily_increase"]["warn"]))),
        "FAIL_FORFEITS_DAILY_INCREASE": int(round(float(sug["forfeits_daily_increase"]["fail"]))),
        "WARN_ESCROW_NONZERO_HOURS": f"{float(sug['escrow_nonzero_hours']['warn']):.2f}",
        "FAIL_ESCROW_NONZERO_HOURS": f"{float(sug['escrow_nonzero_hours']['fail']):.2f}",
    }

    generated_at = datetime.now(timezone.utc).isoformat()
    lines = [
        "# PR9 alert thresholds generated from PR7 advisor",
        f"# source={advice_path}",
        f"# generated_at_utc={generated_at}",
        "",
    ]
    lines.extend(f"{k}={v}" for k, v in rows.items())
    lines.append("")

    out_env.write_text("\n".join(lines), encoding="utf-8")
    print(f"WROTE {out_env}")
    for k, v in rows.items():
        print(f"{k}={v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
