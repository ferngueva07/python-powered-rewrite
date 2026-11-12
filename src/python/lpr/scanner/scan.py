"""Scans uploaded files: content rules, security-log rules, login heuristics, and the anomaly model."""
from __future__ import annotations

import hashlib

from ..anomaly.pipeline import analyze
from ..jsutil import R, date_parse
from .content_scan import MAX_SCAN_BYTES, scan_content, severity_rank
from .log_parsers import parse_login_log
from .security_log import scan_security_log

BRUTE_FORCE_FAILURES = 10
SPRAY_USERS = 5
FAILURE_WINDOW_MS = 10 * 60_000
IP_RE = R(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]+)(?::\d+)?$", "i")
PRIVILEGED_USERS = {"root", "admin", "administrator", "sa", "oracle", "postgres"}


def login_heuristics(events: list[dict]) -> list[dict]:
    """Rule-based login checks that do not depend on the anomaly model."""
    findings: list[dict] = []
    by_source: dict[str, dict] = {}
    privileged: list[dict] = []
    spray_success: list[dict] = []
    ordered = sorted(((date_parse(e["timestamp"]), e) for e in events), key=lambda p: p[0])
    for now, e in ordered:
        key = e["location"] or "unknown"
        s = by_source.get(key) or {"failures": 0, "users": 0, "sampleUsers": [], "successAfter": [],
                                   "recent": [], "start": 0, "userCounts": {}}
        while s["start"] < len(s["recent"]) and now - s["recent"][s["start"]]["time"] > FAILURE_WINDOW_MS:
            user = s["recent"][s["start"]]["user"]
            s["start"] += 1
            count = s["userCounts"][user] - 1
            if count:
                s["userCounts"][user] = count
            else:
                del s["userCounts"][user]
        if not e["success"]:
            s["recent"].append({"user": e["userId"], "time": now})
            s["userCounts"][e["userId"]] = s["userCounts"].get(e["userId"], 0) + 1
            s["failures"] = max(s["failures"], len(s["recent"]) - s["start"])
            if len(s["userCounts"]) > s["users"]:
                s["users"] = len(s["userCounts"])
                s["sampleUsers"] = list(s["userCounts"].keys())[:4]
        else:
            failures = len(s["recent"]) - s["start"]
            if failures >= BRUTE_FORCE_FAILURES and len(s["successAfter"]) < 5:
                s["successAfter"].append(f"{e['userId']} at {e['timestamp']} ({failures} preceding failures)")
            if IP_RE.search(key) and len(s["userCounts"]) >= SPRAY_USERS:
                spray_success.append(e)
            if IP_RE.search(key) and failures >= 5 and e["userId"].lower() in PRIVILEGED_USERS:
                privileged.append(e)
        by_source[key] = s

    # Only IP sources identify a single attacker; city-level locations are shared by many users.
    ranked = [(k, s) for k, s in by_source.items() if IP_RE.search(k)]

    compromised = [(k, s) for k, s in ranked if s["successAfter"]]
    if compromised:
        findings.append({
            "ruleId": "brute-force-success", "title": "Successful login after brute force", "severity": "critical", "category": "login",
            "description": f"A source with {BRUTE_FORCE_FAILURES}+ failed attempts in the preceding 10 minutes logged in successfully. Investigate possible compromise.",
            "count": len(compromised),
            "samples": [{"text": f"{src}: {s['failures']} failures, then success as {s['successAfter'][0]}"} for src, s in compromised[:5]],
        })
    brute = sorted([(k, s) for k, s in ranked if s["failures"] >= BRUTE_FORCE_FAILURES], key=lambda p: -p[1]["failures"])
    if brute:
        findings.append({
            "ruleId": "brute-force", "title": "Brute-force source", "severity": "high", "category": "login",
            "description": f"Sources with {BRUTE_FORCE_FAILURES} or more failed login attempts within 10 minutes.",
            "count": len(brute),
            "samples": [{"text": f"{src}: peak of {s['failures']} failures within 10 minutes; up to {s['users']} account(s) targeted in a window"} for src, s in brute[:5]],
        })
    spray = sorted([(k, s) for k, s in ranked if s["users"] >= SPRAY_USERS], key=lambda p: -p[1]["users"])
    if spray:
        findings.append({
            "ruleId": "password-spray", "title": "Password spraying / user enumeration", "severity": "high", "category": "login",
            "description": f"A single source failed against {SPRAY_USERS} or more different usernames within 10 minutes.",
            "count": len(spray),
            "samples": [{"text": f"{src}: tried {s['users']} usernames within 10 minutes ({', '.join(s['sampleUsers'])}{', …' if s['users'] > 4 else ''})"} for src, s in spray[:5]],
        })
    if spray_success:
        findings.append({
            "ruleId": "password-spray-success", "title": "Successful login after password spraying", "severity": "critical", "category": "login",
            "description": f"A source that failed against {SPRAY_USERS}+ usernames within the preceding 10 minutes recorded a successful login. Check MFA and session issuance before concluding compromise.",
            "count": len(spray_success),
            "samples": [{"text": f"{e['userId']} from {e['location']} at {e['timestamp']}"} for e in spray_success[:5]],
        })
    if privileged:
        findings.append({
            "ruleId": "privileged-login", "title": "Privileged-account login after repeated failures", "severity": "high", "category": "login",
            "description": "A root/administrator-style account logged in from a source with at least 5 failures in the preceding 10 minutes. A privileged login alone is not treated as an attack.",
            "count": len(privileged),
            "samples": [{"text": f"{e['userId']} from {e['location']} at {e['timestamp']}"} for e in privileged[:5]],
        })
    return findings


def _sha256(data: bytes):
    try:
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return None


def _worst(findings: list[dict]):
    worst = None
    for f in findings:
        if worst is None or severity_rank(f["severity"]) < severity_rank(worst):
            worst = f["severity"]
    return worst


def scan_file(name: str, size: int, data: bytes | None = None, read_error: str | None = None) -> dict:
    """Scans one file. `data` holds at most the first MAX_SCAN_BYTES bytes."""
    truncated = size > MAX_SCAN_BYTES
    base = {"name": name, "size": size, "sha256": None, "kind": None, "logFormat": None, "loginEvents": 0,
            "skippedLogRecords": 0, "truncated": truncated, "error": None, "findings": [], "worst": None}
    try:
        if read_error is not None:
            raise RuntimeError(read_error)
        data = bytes(data or b"")[:MAX_SCAN_BYTES]
        digest = None if truncated else _sha256(data)
        content = scan_content(name, data)
        text = content["text"]
        log = parse_login_log(text, name) if text else None
        events = log["events"] if log else []
        findings = content["findings"] + (scan_security_log(text) if text else []) + login_heuristics(events)
        findings.sort(key=lambda f: severity_rank(f["severity"]))
        return {
            "report": {**base, "sha256": digest, "kind": content["kind"], "logFormat": log["format"] if log else None,
                       "loginEvents": len(events), "skippedLogRecords": log["skipped"] if log else 0,
                       "findings": findings, "worst": _worst(findings)},
            "events": events,
        }
    except Exception as err:  # Report the problem instead of claiming the file is clean.
        return {"report": {**base, "error": str(err) or "The file could not be read."}, "events": []}


def scan_uploads(files: list[dict], params: dict) -> dict:
    """files: [{name, size, data?, error?}]"""
    reports: list[dict] = []
    events: list[dict] = []
    file_of: dict[str, str] = {}
    for f in files:
        result = scan_file(f["name"], f["size"], f.get("data"), f.get("error"))
        reports.append(result["report"])
        for e in result["events"]:
            # Same-named files would otherwise collide on event ids.
            new_id = f"{len(reports)}_{e['id']}"
            file_of[new_id] = f["name"]
            events.append({**e, "id": new_id})

    analysis = None
    analysis_error = None
    if any(e["success"] for e in events):
        try:
            analysis = analyze(events, params)
        except Exception as err:
            analysis_error = str(err) or "Login analysis could not be completed."
    flagged = sorted([r for r in (analysis["rows"] if analysis else []) if r["isAnomaly"]], key=lambda r: -r["score"])
    flagged = [{**r, "file": file_of.get(r["eventId"], "")} for r in flagged]

    totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for r in reports:
        for f in r["findings"]:
            totals[f["severity"]] += 1
    return {"files": reports, "events": events, "flaggedLogins": flagged, "analysis": analysis,
            "analysisError": analysis_error, "totals": totals}
