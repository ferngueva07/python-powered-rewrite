"""Reads exported log text (JSON, JSONL, CSV, Windows XML, plain lines) into records."""
from __future__ import annotations

import re

from ..jsutil import R, js_entries, js_string, json_parse, trim, trim_start

_CSV_SPECIAL = re.compile(r'[",\r\n]')


def parse_csv_rows(text: str) -> list[list[str]]:
    """Splits CSV records, including quoted commas and newlines."""
    rows: list[list[str]] = []
    row: list[str] = []
    cur: list[str] = []
    quoted = False
    i = 0
    n = len(text)
    while i < n:
        if quoted:
            j = text.find('"', i)
            if j < 0:
                cur.append(text[i:])
                i = n
                break
            cur.append(text[i:j])
            if j + 1 < n and text[j + 1] == '"':
                cur.append('"')
                i = j + 2
            else:
                quoted = False
                i = j + 1
            continue
        m = _CSV_SPECIAL.search(text, i)
        if m is None:
            cur.append(text[i:])
            i = n
            break
        j = m.start()
        cur.append(text[i:j])
        ch = text[j]
        i = j + 1
        if ch == '"':
            quoted = True
        elif ch == ",":
            row.append(trim("".join(cur)))
            cur = []
        else:
            if ch == "\r" and i < n and text[i] == "\n":
                i += 1
            row.append(trim("".join(cur)))
            if any(row):
                rows.append(row)
            row = []
            cur = []
    row.append(trim("".join(cur)))
    if any(row):
        rows.append(row)
    return rows


_KEY_STRIP = re.compile(r"[^a-z0-9.]")


def key_name(key: str) -> str:
    return _KEY_STRIP.sub("", key.lower())


def field(record: dict, *keys: str) -> str:
    fields = record["fields"]
    for key in keys:
        value = fields.get(key_name(key))
        if value is not None and value != "":
            return value
    return ""


_JSONISH = R(r"^\s*[{[]")


def _flatten(value, fields: dict, path: str = "", depth: int = 0) -> None:
    if depth > 20 or value is None:
        return
    if not isinstance(value, (dict, list)):
        fields[key_name(path)] = js_string(value)
        # Cloud audit APIs often serialize policy documents and request bodies as JSON strings.
        if isinstance(value, str) and _JSONISH.search(value):
            try:
                _flatten(json_parse(value), fields, path, depth + 1)
            except Exception:
                pass  # Keep the original string.
        return
    for key, child in js_entries(value):
        _flatten(child, fields, f"{path}.{key}" if path else key, depth + 1)


def _record_text(fields: dict) -> str:
    return "\n".join(f"{k}={v}" for k, v in js_entries(fields))


def _structured(value, record: int) -> dict:
    fields: dict = {}
    _flatten(value, fields)
    return {"fields": fields, "text": _record_text(fields), "record": record}


_ENTITIES = {"&lt;": "<", "&gt;": ">", "&amp;": "&", "&quot;": '"', "&apos;": "'"}
_ENTITY_RE = re.compile(r"&(?:lt|gt|amp|quot|apos);")


def _xml_text(s: str) -> str:
    return _ENTITY_RE.sub(lambda m: _ENTITIES.get(m.group(0), m.group(0)), s)


_STARTS_JSON = R(r"^[{[]")
_HAS_EVENT = R(r"<Event(?:\s|>)")
_EVENT_BLOCK = R(r"<Event(?:\s[^>]*)?>[\s\S]*?<\/Event>")
_DATA = R(r"""<Data\s+Name=["']([^"']+)["'][^>]*>([\s\S]*?)<\/Data>""")
_EVENT_ID = R(r"<EventID[^>]*>(\d+)<\/EventID>")
_TIME_CREATED = R(r"""<TimeCreated[^>]*SystemTime=["']([^"']+)""")
_PROVIDER = R(r"""<Provider[^>]*Name=["']([^"']+)""")
_LINES = re.compile(r"\r?\n")
_CSV_FIRST_BAD = R(r"^[\d[{<]")
_CSV_HEADER_HINT = R(r"timestamp|user|status|ip.address", "i")
_AUDIT_TYPE = R(r"\btype=USER_\w+")
_AUDIT_MSG = R(r"\bmsg='([^']*)'")
_KV = R(r"""\b([\w.]+)=(?:"([^"]*)"|'([^']*)'|([^\s,]+))""")
_WRAPPERS = ["Records", "records", "value", "items", "entries", "findings", "Findings", "configurationItems"]


def read_log_records(text: str) -> list[dict]:
    """Reads exported text, not native binary EVTX. Locations refer to the original upload."""
    trimmed = trim_start(text)
    if _STARTS_JSON.search(trimmed):
        try:
            value = json_parse(trimmed)
            if isinstance(value, list):
                return [_structured(v, i + 1) for i, v in enumerate(value)]
            if isinstance(value, dict):
                for key in _WRAPPERS:
                    records = value.get(key)
                    if isinstance(records, list):
                        return [_structured(v, i + 1) for i, v in enumerate(records)]
                return [_structured(value, 1)]
        except Exception:
            pass  # Try JSONL or other text exports below.

    if _HAS_EVENT.search(text):
        records = []
        offset = 0
        line = 1
        for match in _EVENT_BLOCK.finditer(text):
            line += text.count("\n", offset, match.start())
            offset = match.start()
            block = match.group(0)
            fields: dict = {}
            for data in _DATA.finditer(block):
                fields[key_name(data.group(1))] = _xml_text(data.group(2))
            m = _EVENT_ID.search(block)
            fields["eventid"] = m.group(1) if m else ""
            m = _TIME_CREATED.search(block)
            fields["timestamp"] = m.group(1) if m else ""
            m = _PROVIDER.search(block)
            fields["provider"] = m.group(1) if m else ""
            records.append({"fields": fields, "text": _record_text(fields), "line": line})
        return records

    lines = _LINES.split(text)
    first = next((ln for ln in lines if trim(ln)), "")
    if "," in first and not _CSV_FIRST_BAD.search(first) and _CSV_HEADER_HINT.search(first):
        rows = parse_csv_rows(text)
        header = rows.pop(0) if rows else []
        # A logical CSV record may span several physical lines; report its record number.
        out = []
        for i, row in enumerate(rows):
            fields = {}
            for j, v in enumerate(row):
                fields[key_name(header[j] if j < len(header) else f"column{j}")] = v
            out.append({"fields": fields, "text": " ".join(row), "record": i + 2})
        return out

    out = []
    for i, line in enumerate(lines):
        if not trim(line) or line.startswith("#"):
            continue
        if trim_start(line).startswith("{"):
            try:
                rec = _structured(json_parse(line), i + 1)
                rec["line"] = i + 1
                out.append(rec)
                continue
            except Exception:
                pass  # Retain malformed lines for text checks.
        fields = {}
        audit_message = None
        if _AUDIT_TYPE.search(line):
            m = _AUDIT_MSG.search(line)
            audit_message = m.group(1) if m else None
        for source in ([line, audit_message] if audit_message else [line]):
            for match in _KV.finditer(source):
                value = match.group(2)
                if value is None:
                    value = match.group(3)
                if value is None:
                    value = match.group(4)
                fields[key_name(match.group(1))] = "" if value is None else value
        out.append({"fields": fields, "text": line, "line": i + 1})
    return out
