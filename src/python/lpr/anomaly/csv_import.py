"""Reads login CSVs with user_id, timestamp, location and success columns."""
from __future__ import annotations

import re

from ..jsutil import R, date_parse, is_nan, iso_string, trim

MAX_CSV_ROWS = 50_000

_HAS_OFFSET = R(r"[zZ]|[+-]\d\d:?\d\d$")
_LINE_SPLIT = re.compile(r"\r?\n")

TRUE_VALUES = {"true", "1", "yes", "success", "ok"}
FALSE_VALUES = {"false", "0", "no", "fail", "failed", "failure"}


class LoginImportError(Exception):
    """The file is not a usable login CSV; the message explains why."""


def parse_line(line: str) -> list[str]:
    out: list[str] = []
    cur: list[str] = []
    quoted = False
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quoted:
            if ch == '"' and i + 1 < n and line[i + 1] == '"':
                cur.append('"')
                i += 1
            elif ch == '"':
                quoted = False
            else:
                cur.append(ch)
        elif ch == '"':
            quoted = True
        elif ch == ",":
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
        i += 1
    out.append("".join(cur))
    return [trim(c) for c in out]


def parse_login_csv(text: str) -> list[dict]:
    """Parses CSV with columns user_id, timestamp, location, success. Raises a readable error on bad input."""
    lines = [line for line in _LINE_SPLIT.split(text) if len(trim(line)) > 0]
    if len(lines) < 2:
        raise LoginImportError("The CSV needs a header row and at least one login.")
    header = [h.lower() for h in parse_line(lines[0])]

    def col(name):
        return header.index(name) if name in header else -1

    iu, it, il, is_ = col("user_id"), col("timestamp"), col("location"), col("success")
    if any(i < 0 for i in (iu, it, il, is_)):
        raise LoginImportError("CSV header must include: user_id, timestamp, location, success")
    if len(lines) - 1 > MAX_CSV_ROWS:
        raise LoginImportError(f"CSV is limited to {MAX_CSV_ROWS:,} rows.")

    def cell(cells, i):
        return cells[i] if i < len(cells) else ""

    events: list[dict] = []
    for n in range(1, len(lines)):
        cells = parse_line(lines[n])
        user_id = cell(cells, iu)
        ts = cell(cells, it)
        location = cell(cells, il)
        success_raw = cell(cells, is_).lower()
        parsed = date_parse(ts if _HAS_OFFSET.search(ts) else ts.replace(" ", "T", 1) + "Z")
        if not user_id or is_nan(parsed):
            raise LoginImportError(f"Row {n + 1}: missing user_id or unreadable timestamp.")
        if success_raw not in TRUE_VALUES and success_raw not in FALSE_VALUES:
            raise LoginImportError(f'Row {n + 1}: success must be true/false (got "{cell(cells, is_)}").')
        events.append({
            "id": f"row_{n}",
            "userId": user_id[:120],
            "timestamp": iso_string(parsed),
            "location": (location or "unknown")[:120],
            "success": success_raw in TRUE_VALUES,
            "label": None,
        })
    if not any(e["success"] for e in events):
        raise LoginImportError("The CSV has no successful logins to score.")
    return events
