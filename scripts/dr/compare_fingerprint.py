#!/usr/bin/env python3
"""Compare two row-count fingerprints produced by scripts/dr/lib.sh.

Two modes, because the two drills ask opposite questions:

    strict    nothing may change            (restore: the dump is the reference)
    no-loss   nothing may shrink            (upgrade: the drill's own smoke test
                                             legitimately adds rows)

Fingerprint lines are "table<TAB>rows<TAB>max_id". schema_migrations is always
ignored: it is the one table a migration is supposed to change.
"""
import sys

IGNORED = {"schema_migrations"}


def load(path: str) -> dict[str, int]:
    out: dict[str, int] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            out[parts[0]] = int(parts[1])
    return out


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compare_fingerprint.py <strict|no-loss> <before> <after>", file=sys.stderr)
        return 2
    mode, before_path, after_path = sys.argv[1], sys.argv[2], sys.argv[3]
    before, after = load(before_path), load(after_path)

    problems: list[str] = []
    for table, rows in before.items():
        if table in IGNORED:
            continue
        now = after.get(table)
        if now is None:
            problems.append(f"{table}: present before ({rows} rows), missing after")
        elif mode == "strict" and now != rows:
            problems.append(f"{table}: {rows} -> {now}")
        elif mode == "no-loss" and now < rows:
            problems.append(f"{table}: lost rows {rows} -> {now}")

    if problems:
        print("fingerprint mismatch:", *problems, sep="\n  ", file=sys.stderr)
        return 1

    counted = len([t for t in before if t not in IGNORED])
    if mode == "strict":
        print(f"   fingerprint identical across {counted} tables")
    else:
        grew = len([t for t, r in before.items() if t not in IGNORED and after.get(t, 0) > r])
        print(f"   {counted} tables preserved, {grew} grew from the drill's own writes (expected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
