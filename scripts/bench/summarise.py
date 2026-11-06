#!/usr/bin/env python3
"""Renders the per-scenario k6 result files as a markdown table."""

import glob
import json
import os
import sys

COLUMNS = [
    ("scenario", "场景"),
    ("vus", "VUs"),
    ("duration", "时长"),
    ("requests", "请求数"),
    ("qps", "QPS"),
    ("p50_ms", "P50 (ms)"),
    ("p95_ms", "P95 (ms)"),
    ("p99_ms", "P99 (ms)"),
    ("failed_pct", "失败率"),
    ("status_429", "429 次数"),
]

# Keep the table in the order run.sh executes, not in glob order.
ORDER = ["context", "me", "admin", "org", "login"]


def load(directory):
    rows = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        with open(path, encoding="utf-8") as handle:
            try:
                rows.append(json.load(handle))
            except json.JSONDecodeError as err:
                print(f"skipping {path}: {err}", file=sys.stderr)
    rows.sort(key=lambda row: ORDER.index(row["scenario"]) if row.get("scenario") in ORDER else len(ORDER))
    return rows


def main():
    if len(sys.argv) != 2:
        print("usage: summarise.py RESULT_DIR", file=sys.stderr)
        return 2
    rows = load(sys.argv[1])
    if not rows:
        print("no scenario results found", file=sys.stderr)
        return 1

    print("| " + " | ".join(label for _, label in COLUMNS) + " |")
    print("|" + "|".join("---" for _ in COLUMNS) + "|")
    for row in rows:
        cells = []
        for key, _ in COLUMNS:
            value = row.get(key, "")
            if key == "failed_pct":
                value = f"{value}%"
            cells.append(str(value))
        print("| " + " | ".join(cells) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
