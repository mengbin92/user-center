#!/usr/bin/env python3
"""Compare two row-count fingerprints produced by scripts/dr/lib.sh.

Two modes, because the two drills ask opposite questions:

    strict    nothing may change            (restore: the dump is the reference)
    no-loss   nothing may shrink            (upgrade: the drill's own smoke test
                                             legitimately adds rows)

Fingerprint lines are "table<TAB>rows<TAB>max_id". schema_migrations is always
ignored: it is the one table a migration is supposed to change.

Both components are compared. Row counts alone are not a restore check: a
restore that kept 3 rows but restarted the auto-increment produced "3 -> 3" and
passed, while every later insert would have collided with an id that already
existed. max_id is the high-water mark, so it has to be part of both modes ---
strict as equality, no-loss as "may not go backwards".
"""
import sys

IGNORED = {"schema_migrations"}


def load(path: str) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            # A fingerprint without the high-water mark cannot be verified, so
            # a malformed line is a failure rather than a skipped table. The
            # earlier version silently dropped it and then reported "identical".
            if len(parts) != 3:
                raise ValueError(
                    f"{path}:{lineno}: expected table<TAB>rows<TAB>max_id, got {line!r}"
                )
            out[parts[0]] = (int(parts[1]), int(parts[2]))
    return out


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: compare_fingerprint.py <strict|no-loss> <before> <after>", file=sys.stderr)
        return 2
    mode, before_path, after_path = sys.argv[1], sys.argv[2], sys.argv[3]
    if mode not in ("strict", "no-loss"):
        print(f"unknown mode: {mode}", file=sys.stderr)
        return 2
    try:
        before, after = load(before_path), load(after_path)
    except (OSError, ValueError) as exc:
        print(f"fingerprint unreadable: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []
    for table, (rows, max_id) in before.items():
        if table in IGNORED:
            continue
        now = after.get(table)
        if now is None:
            problems.append(f"{table}: present before ({rows} rows, max_id {max_id}), missing after")
            continue
        now_rows, now_max = now
        if mode == "strict":
            if now_rows != rows:
                problems.append(f"{table}: rows {rows} -> {now_rows}")
            if now_max != max_id:
                problems.append(f"{table}: max_id {max_id} -> {now_max}")
        else:
            # Compared per component, never as a tuple: (5, 90) -> (6, 80) has
            # more rows and a lower high-water mark, and tuple ordering would
            # call that "grew".
            if now_rows < rows:
                problems.append(f"{table}: lost rows {rows} -> {now_rows}")
            if now_max < max_id:
                problems.append(f"{table}: high-water mark went backwards {max_id} -> {now_max}")

    if problems:
        print("fingerprint mismatch:", *problems, sep="\n  ", file=sys.stderr)
        return 1

    counted = len([t for t in before if t not in IGNORED])
    if mode == "strict":
        print(f"   fingerprint identical across {counted} tables (rows and max_id)")
    else:
        grew = len(
            [t for t, (r, m) in before.items() if t not in IGNORED and after[t][0] > r]
        )
        print(f"   {counted} tables preserved (rows and max_id), {grew} grew from the drill's own writes (expected)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
