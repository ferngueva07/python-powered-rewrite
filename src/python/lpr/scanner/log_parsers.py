"""Detects login-log formats and extracts login events from them."""
from __future__ import annotations

import re

from ..jsutil import (NAN, R, current_utc_year, date_parse, date_utc, is_finite, is_nan, is_number,
                      iso_string, js_keys, js_number, js_string, js_values, json_parse, trim, trim_start)
from .log_records import field, parse_csv_rows, read_log_records

MAX_EVENTS = 50_000

_NORM = re.compile(r"[^a-z0-9]")


def norm(s: str) -> str:
    return _NORM.sub("", s.lower())


USER_KEYS = ["userid", "user", "username", "accountname", "account", "targetusername", "login", "email", "upn", "userprincipalname"]
TIME_KEYS = ["timestamp", "time", "datetime", "dateandtime", "date", "eventtime", "createddatetime", "ts", "timecreated", "logintime"]
LOCATION_KEYS = ["location", "sourcenetworkaddress", "ipaddress", "ip", "sourceip", "srcip", "clientip", "remoteip", "src", "country", "city", "workstationname"]
SUCCESS_KEYS = ["success", "status", "result", "outcome", "loginresult", "succeeded", "keywords", "eventtype"]
EVENT_ID_KEYS = ["eventid", "eventcode", "id"]

TRUE_VALUES = {"true", "1", "yes", "success", "succeeded", "ok", "accepted", "allow", "allowed", "auditsuccess", "pass", "passed"}
FALSE_VALUES = {"false", "0", "no", "fail", "failed", "failure", "denied", "deny", "rejected", "auditfailure", "blocked", "error"}

FORMAT_LABELS = {
    "login-csv": "Login CSV",
    "windows-security": "Windows Security log",
    "json": "JSON / JSONL log",
    "auth-log": "Linux auth.log (sshd)",
    "auditd": "Linux auditd",
}


def find_key(keys: list[str], candidates: list[str]):
    normalized = [norm(k) for k in keys]
    for c in candidates:
        if c in normalized:
            return keys[normalized.index(c)]
    return None


_EPOCH_DIGITS = R(r"^\d{10,13}$")
_HAS_OFFSET = R(r"[zZ]|[+-]\d\d:?\d\d$")


def parse_time(raw) -> float:
    if is_number(raw):
        return raw * 1000 if raw < 1e12 else float(raw)
    if not isinstance(raw, str) or not trim(raw):
        return NAN
    s = trim(raw)
    if _EPOCH_DIGITS.search(s):
        return parse_time(js_number(s))
    iso = s if _HAS_OFFSET.search(s) else s.replace(" ", "T", 1) + "Z"
    t = date_parse(iso)
    return date_parse(s) if is_nan(t) else t


def parse_success(raw):
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return None
    v = norm(js_string(raw))
    if v in TRUE_VALUES:
        return True
    if v in FALSE_VALUES:
        return False
    return None


def success_from_event_id(raw):
    """Windows Security logon event IDs: 4624/4648 successful, 4625/4771 failed."""
    ident = trim(js_string("" if raw is None else raw))
    if ident in ("4624", "4648"):
        return True
    if ident in ("4625", "4771"):
        return False
    return None


_LABEL_RES = {}


def _label_re(label: str):
    if label not in _LABEL_RES:
        _LABEL_RES[label] = R(label + r":[ \t]*([^\r\n\t]+)", "i")
    return _LABEL_RES[label]


def from_windows_message(message: str) -> dict:
    """Pulls Account Name / Source Network Address out of a Windows event message (last non-machine value wins)."""
    def pick(label):
        values = [trim(m.group(1)) for m in _label_re(label).finditer(message)]
        values = [v for v in values if v and v != "-" and not v.endswith("$")]
        return values[-1] if values else None

    location = pick("Source Network Address")
    if location is None:
        location = pick("Workstation Name")
    return {"user": pick("Account Name"), "location": location}


def make_event(n: int, prefix: str, user: str, time: float, location: str, success: bool) -> dict:
    return {
        "id": f"{prefix}_{n}",
        "userId": user[:120],
        "timestamp": iso_string(time),
        "location": (location or "unknown")[:120],
        "success": success,
        "label": None,
    }


def _str(v) -> str:
    return "" if v is None else trim(js_string(v))


_ACCOUNT_NAME = R(r"Account Name:", "i")


def records_to_events(records: list[dict], prefix: str) -> dict:
    events: list[dict] = []
    skipped = max(0, len(records) - MAX_EVENTS)
    windows = False
    for n, rec in enumerate(records[:MAX_EVENTS]):
        keys = js_keys(rec)
        uk = find_key(keys, USER_KEYS)
        tk = find_key(keys, TIME_KEYS)
        lk = find_key(keys, LOCATION_KEYS)
        sk = find_key(keys, SUCCESS_KEYS)
        ek = find_key(keys, EVENT_ID_KEYS)
        message_key = next((k for k in keys if isinstance(rec[k], str) and _ACCOUNT_NAME.search(rec[k])), None)
        win = from_windows_message(rec[message_key]) if message_key else {}
        ev_success = success_from_event_id(rec[ek]) if ek else None
        if ev_success is not None or message_key:
            windows = True
        user = (_str(rec[uk]) if uk else "") or win.get("user") or ""
        location = (_str(rec[lk]) if lk else "") or win.get("location") or ""
        time = parse_time(rec[tk] if tk else None)
        success = ev_success if ev_success is not None else (parse_success(rec[sk]) if sk else None)
        if not user or user == "-" or is_nan(time) or success is None:
            skipped += 1
            continue
        events.append(make_event(n + 1, prefix, user, time, "" if location == "-" else location, success))
    return {"events": events, "skipped": skipped, "windows": windows}


MONTHS = {"jan": 0, "feb": 1, "mar": 2, "apr": 3, "may": 4, "jun": 5, "jul": 6, "aug": 7, "sep": 8, "oct": 9, "nov": 10, "dec": 11}
SSH_RE = R(r"(Accepted|Failed) (?:password|publickey|keyboard-interactive(?:\/pam)?|none) for (?:invalid user )?(\S+) from (\S+)")
SSH_INVALID_RE = R(r"Invalid user (\S+) from (\S+)")
_ISO_PREFIX = R(r"^(\d{4}-\d\d-\d\dT\S+)")
_CLASSIC_PREFIX = R(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d):(\d\d):(\d\d)")
_LINES = re.compile(r"\r?\n")


def parse_auth_log(text: str, prefix: str, reference_year: int):
    """Parses sshd lines from auth.log / secure / journalctl output (classic or ISO-8601 syslog timestamps)."""
    events: list[dict] = []
    skipped = 0
    for n, line in enumerate(_LINES.split(text)):
        ssh = SSH_RE.search(line)
        invalid = None if ssh else SSH_INVALID_RE.search(line)
        if not ssh and not invalid:
            continue
        if len(events) >= MAX_EVENTS:
            skipped += 1
            continue
        time = NAN
        iso = _ISO_PREFIX.search(line)
        classic = _CLASSIC_PREFIX.search(line)
        if iso:
            time = date_parse(iso.group(1))
        elif classic:
            month = MONTHS.get(classic.group(1).lower())
            if month is not None:
                time = date_utc(reference_year, month, int(classic.group(2)), int(classic.group(3)),
                                int(classic.group(4)), int(classic.group(5)))
        if is_nan(time):
            skipped += 1
            continue
        if ssh:
            events.append(make_event(n + 1, prefix, ssh.group(2), time, ssh.group(3), ssh.group(1) == "Accepted"))
        else:
            events.append(make_event(n + 1, prefix, invalid.group(1), time, invalid.group(2), False))
    return {"format": "auth-log", "events": events, "skipped": skipped} if events or skipped else None


def try_json(text: str):
    records = None
    try:
        parsed = json_parse(text)
        if isinstance(parsed, list):
            records = parsed
        elif isinstance(parsed, dict):
            found = next((v for v in js_values(parsed) if isinstance(v, list)), None)
            records = found if found is not None else [parsed]
    except Exception:
        lines = [ln for ln in _LINES.split(text) if trim(ln)]
        parsed_lines = []
        for ln in lines:
            try:
                parsed_lines.append(json_parse(ln))
            except Exception:
                pass  # not a JSON line
        if parsed_lines and len(parsed_lines) >= len(lines) / 2:
            records = parsed_lines
    if records is None:
        return None
    return [r for r in records if isinstance(r, dict)]


_PREFIX_STRIP = R(r"[^a-z0-9]+", "i")
_AUDIT_LOGIN = R(r"\btype=USER_(?:AUTH|LOGIN)\b")
_STARTS_STRUCTURED = R(r"^[{[<]")
_AUTH_EVENT_TYPE = R(r"(?:login|auth|session)", "i")
_USER_TYPE = R(r"^USER_")
_AUDIT_TIME = R(r"msg=audit\(([\d.]+):")


def parse_login_log(text: str, file_name: str, reference_year: int | None = None):
    """Detects the log format and extracts login events.

    Returns None when the file does not look like a login log (content scanning still applies to it).
    """
    if reference_year is None:
        reference_year = current_utc_year()
    prefix = _PREFIX_STRIP.sub("_", file_name)[:40] or "file"
    trimmed = trim_start(text)
    audit_file = bool(_AUDIT_LOGIN.search(text))

    if _STARTS_STRUCTURED.search(trimmed) or audit_file:
        records = read_log_records(text)
        events: list[dict] = []
        skipped = 0
        windows = False
        auditd = False
        for i, record in enumerate(records):
            category = field(record, "event.category", "event.category.0")
            if category and category != "authentication":
                continue
            event_type = field(record, "eventtype")
            if event_type and not _AUTH_EVENT_TYPE.search(event_type):
                continue
            event_id = field(record, "eventid")
            windows = windows or (bool(event_id) and bool(field(record, "provider")))
            if event_id and field(record, "provider") and success_from_event_id(event_id) is None:
                continue
            audit = bool(_AUDIT_LOGIN.search(record["text"]))
            auditd = auditd or audit
            if audit_file and not audit:
                continue
            message = next((v for v in js_values(record["fields"]) if _ACCOUNT_NAME.search(v)), None)
            win = from_windows_message(message) if message else {}
            user = field(record, "userprincipalname", "targetusername", "actor.alternateid", "user.name",
                         "resource.email", "initiatedby.username", "acct", *USER_KEYS) or win.get("user") or ""
            location = field(record, "ipaddress", "client.ipaddress", "accessdevice.ip", "clientip", "source.ip",
                             "addr", *LOCATION_KEYS) or win.get("location") or ""
            success = success_from_event_id(event_id)
            error_code = field(record, "status.errorcode")
            if error_code:
                success = error_code == "0"
            if success is None:
                success = parse_success(field(record, "success", "outcome.result", "result", "status",
                                              "event.outcome", "res", *SUCCESS_KEYS))
            # USER_ERR and syscall audit records are not additional login attempts.
            record_type = field(record, "type")
            if record_type and _USER_TYPE.search(record_type) and not audit:
                continue
            if audit:
                m = _AUDIT_TIME.search(record["text"])
                time = js_number(m.group(1) if m else None) * 1000
            else:
                time = parse_time(field(record, "createddatetime", "timestamp", "published", "time", "eventtime",
                                        "@timestamp", *TIME_KEYS))
            if success is None or not user or not is_finite(time):
                skipped += 1
                continue
            if len(events) >= MAX_EVENTS:
                skipped += 1
                continue
            events.append(make_event(i + 1, prefix, user, time, location, success))
        if events:
            fmt = "windows-security" if windows else "auditd" if auditd else "json"
            return {"format": fmt, "events": events, "skipped": skipped}

    if trimmed.startswith("[") or trimmed.startswith("{"):
        records = try_json(trimmed)
        if records is not None:
            result = records_to_events(records, prefix)
            if result["events"]:
                return {"format": "json", "events": result["events"], "skipped": result["skipped"]}

    auth = parse_auth_log(text, prefix, reference_year)
    if auth and auth["events"]:
        return auth

    first_line = _LINES.split(trimmed, maxsplit=1)[0]
    if "," in first_line:
        rows = parse_csv_rows(trimmed)
        if len(rows) >= 2:
            header = rows[0]
            # Event Viewer exports leave the message column without a header, so keep extra cells too.
            records = []
            for cells in rows[1:]:
                rec = {}
                for i, c in enumerate(cells):
                    name = header[i] if i < len(header) and header[i] else f"column_{i + 1}"
                    rec[name] = c
                records.append(rec)
            result = records_to_events(records, prefix)
            if result["events"]:
                fmt = "windows-security" if result["windows"] else "login-csv"
                return {"format": fmt, "events": result["events"], "skipped": result["skipped"]}
    return None
