"""Rule-based detections for security logs (cloud, identity, network, web, endpoint)."""
from __future__ import annotations

import math
import re

from ..jsutil import (NAN, R, current_utc_year, date_parse, is_finite, iso_string, js_entries, js_number,
                      js_round, js_values, to_fixed)
from .log_records import field, read_log_records


def _r(id_, title, severity, description):
    return {"id": id_, "title": title, "severity": severity, "description": description}


RULES = {
    "recon": _r("sensitive-path-probe", "Sensitive file / admin endpoint probing", "high", "Requests or access errors reference configuration files, credentials, or exposed administration tools. A probe does not prove access succeeded."),
    "tool": _r("attack-tool-agent", "Offensive scanner user agent", "medium", "The request identifies a known offensive scanning tool. This may be an authorized security test."),
    "sql": _r("log-sql-attack", "SQL injection or sensitive database operation", "high", "A request or query contains injection syntax, reads credential tables, or drops audit data. Review authorization and the recorded response."),
    "injection": _r("log-prompt-injection", "Instructions embedded in log data", "medium", "A log field attempts to instruct an automated analyzer to hide findings. These strings are treated only as data and do not control this scanner."),
    "admin": _r("cloud-privilege-change", "Privileged cloud / SaaS permission change", "high", "An audit event requests powerful permissions or an administrator role. Confirm the actor, scope, outcome, and approved change record."),
    "controls": _r("security-control-change", "Security control disabled or deleted", "high", "An audit record reports removal of MFA, logging, encryption, or a security policy. This is a review lead, not proof of unauthorized change."),
    "risk": _r("risky-signin", "Identity provider reports a risky sign-in", "high", "The identity provider recorded medium/high sign-in risk or a suspicious-login event."),
    "legacy": _r("legacy-auth-no-mfa", "Successful legacy authentication without MFA", "high", "A successful sign-in uses a legacy authentication client without recorded MFA. Verify whether the account should permit this flow."),
    "access": _r("conditional-access-bypass", "Successful sign-in with failed access policy", "high", "The sign-in succeeded even though a conditional-access policy recorded failure. Verify policy enforcement and the authentication flow."),
    "travel": _r("impossible-travel", "Geographically implausible sign-in travel", "high", "Consecutive successful sign-ins for one user are over 500 km apart and imply travel above 900 km/h within 24 hours. VPNs, proxies, and inaccurate IP geolocation can cause false positives."),
    "mfa": _r("mfa-fraud-bypass", "MFA fraud, anomalous push, or bypass", "high", "The identity provider reports a fraudulent/anomalous push or a successful bypass-code authentication."),
    "secrets": _r("k8s-secret-access", "Kubernetes secret access / container execution", "high", "The audit record requests secrets or executes commands in a pod. Verify the service account and authorization; routine automation can also do this."),
    "mail": _r("mail-forwarding-rule", "Mailbox forwarding or message-hiding rule", "high", "An Exchange audit event changes forwarding or creates a rule that forwards/deletes messages. Check destinations and approval for possible mailbox compromise."),
    "alert": _r("security-product-alert", "Security product reports a threat", "high", "An IDS, WAF, EDR, firewall, or cloud security product recorded a threat finding. A blocked or mitigated alert is not proof of a successful attack."),
    "vulnerability": _r("active-high-vulnerability", "Active high / critical vulnerability", "high", "The vulnerability scanner reports an active HIGH or CRITICAL package vulnerability. This indicates exposure, not evidence that exploitation occurred."),
    "lsass": _r("lsass-access", "Process injection or high-access handle to LSASS", "critical", "Sysmon reports a remote thread or a high-access process handle targeting LSASS, a credential theft technique. Validate the source process."),
    "roasting": _r("kerberos-roasting", "RC4 Kerberos ticket / missing pre-authentication", "high", "A successful Kerberos event uses RC4 for a service ticket or issues an RC4 TGT without pre-authentication. These enable offline password guessing, but legacy configurations can also cause them."),
    "anonymous": _r("s3-anonymous-read", "Anonymous S3 object download", "high", "S3 recorded a successful object read without an authenticated requester. Confirm that the bucket and object are intended to be public."),
    "scrape": _r("rapid-api-enumeration", "Rapid automated API enumeration", "medium", "One source using a scripting client requested at least 10 distinct API URLs in a minute. Legitimate integrations may do this too."),
    "aliases": _r("mailbox-alias-burst", "Burst of signups sharing one mailbox", "medium", "At least 10 distinct plus-addressed email aliases for one mailbox appear within 10 minutes, consistent with automated account farming."),
    "scan": _r("network-port-scan", "Rapid multi-port connection attempts", "high", "One source contacted at least 5 destination ports within 10 minutes. This can indicate a port scan; check whether it was authorized."),
    "denied": _r("repeated-network-denials", "Repeated firewall-denied connections", "medium", "A firewall denied at least 5 connections from one source within 10 minutes. This indicates repeated blocked attempts, not a confirmed intrusion."),
    "failures": _r("repeated-auth-failures", "Repeated authentication failures", "high", "One source has at least 5 authentication failures within 10 minutes. Review the accounts and subsequent successful logins."),
}

_URL_ESCAPE = re.compile(r"%([0-9a-f]{2})", re.IGNORECASE)


def _decode_escape(m):
    code = int(m.group(1), 16)
    return chr(code) if 32 <= code < 127 else m.group(0)


def decoded(text: str) -> str:
    """Decode URL escapes for inspection, preserving physical line numbers and malformed escapes."""
    for _ in range(2):
        text = _URL_ESCAPE.sub(_decode_escape, text)
    return text


_SRC_CLIENT = R(r"(?:client[: ]+|from\s+)(\d{1,3}(?:\.\d{1,3}){3})")
_SRC_LEAD = R(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})")


def source(record: dict) -> str:
    value = field(record, "ipaddress", "client.ipaddress", "srcip", "src", "source.ip", "clienthost", "ip_address", "addr")
    if value:
        return value
    m = _SRC_CLIENT.search(record["text"])
    if m and m.group(1):
        return m.group(1)
    m = _SRC_LEAD.search(record["text"])
    if m and m.group(1):
        return m.group(1)
    return ""


_NUMERIC = R(r"^\d+(?:\.\d+)?$")
_ISO_IN_TEXT = R(r"\b\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?")
_HAS_ZONE = R(r"[Z+-]\d\d:|Z$")
_COMBINED = R(r"\[(\d\d)\/([A-Za-z]{3})\/(\d{4}):(\d\d:\d\d:\d\d) ([+-]\d{4})\]")
_AUDIT = R(r"\baudit\(([\d.]+):")


def timestamp(record: dict) -> float:
    raw = field(record, "timestamp", "time", "createddatetime", "published", "startutc")
    if _NUMERIC.search(raw):
        n = js_number(raw)
        return n * (1000 if n < 1e12 else 1)
    if raw:
        return date_parse(raw)
    m = _ISO_IN_TEXT.search(record["text"])
    if m:
        iso = m.group(0)
        return date_parse(iso if _HAS_ZONE.search(iso) else iso.replace(" ", "T", 1) + "Z")
    m = _COMBINED.search(record["text"])
    if m:
        return date_parse(f"{m.group(1)} {m.group(2)} {m.group(3)} {m.group(4)} {m.group(5)}")
    m = _AUDIT.search(record["text"])
    return js_number(m.group(1)) * 1000 if m else NAN


def bursts(rows: list[dict], minimum: int, window_ms: float, distinct: bool) -> list[list[dict]]:
    groups: dict[str, list[dict]] = {}
    for row in rows:
        if not row["key"] or not is_finite(row["time"]):
            continue
        groups.setdefault(row["key"], []).append(row)
    found = []
    for group in groups.values():
        group.sort(key=lambda r: r["time"])
        start = 0
        counts: dict[str, int] = {}
        for end, row in enumerate(group):
            counts[row["value"]] = counts.get(row["value"], 0) + 1
            while row["time"] - group[start]["time"] > window_ms:
                key = group[start]["value"]
                start += 1
                c = counts[key] - 1
                if c:
                    counts[key] = c
                else:
                    del counts[key]
            if (len(counts) if distinct else end - start + 1) >= minimum:
                found.append(group[start:end + 1])
                break
    return found


P_RECON = R(r"""(?:\/|\\)(?:\.env(?:[.\w-]*)|\.git\/config|\.aws\/credentials|(?:admin\/)?web\.config|wp-config\.php|phpmyadmin(?:\/\S*)?)(?=[\s?"',]|$)""", "i")
P_TOOL = R(r"\b(?:sqlmap|nikto|nmap|nuclei|masscan|gobuster|acunetix)(?:[\/ ][\w.#-]+)?", "i")
P_SQL = R(r"""\bunion(?:\s|\+)+(?:all\s+)?select\b|'\s*(?:or|and)\s+'?\d+'?\s*=\s*'?\d+|\b(?:sleep|benchmark)\s*\(|\bselect\b[^\r\n]{0,160}\b(?:pg_shadow|mysql\.user)\b|\bdrop\s+table\s+(?:audit\w*|user_sessions)\b""", "i")
P_INJECTION = R(r"\bignore (?:all |any )?previous instructions\b|\b(?:set|mark|output)[^\r\n]{0,60}(?:severity|severities|analysis)[^\r\n]{0,50}(?:LOW|benign)\b", "i")

A_POLICY = R(r"^(?:CreatePolicy|PutUserPolicy|PutRolePolicy|AttachUserPolicy|AttachRolePolicy)$")
A_POLICY_VALUES = R(r'(?:AdministratorAccess|FullAdminAccess|"Action"\s*:\s*"\*")')
A_ROLE_ASSIGN = R(r"roleAssignments\/write$", "i")
A_ROLE_IDS = R(r"8e3af657-a8ff-443c-a75c-2fe8c4bcb635|b24988ac-6180-42a0-ab88-20f7382dd24c", "i")
A_GCP = R(r"SetIamPolicy$|CreateRole$")
A_GCP_VALUES = R(r"iam\.serviceAccounts\.actAs|resourcemanager\.projects\.setIamPolicy|roles\/(?:owner|editor)")
A_GRANT = R(r"^(?:role_change_to_admin|GRANT_ADMIN_PRIVILEGE)$")
EVENT_NAME_KEY = R(r"events\.\d+\.name$")
C_ACTIONS = R(r"^(?:two_factor_authentication\.disabled|admin_totp_disable|TURN_OFF_2_STEP_VERIFICATION|ekm_unenrolled|StopLogging|DeleteTrail|DeleteAccountPasswordPolicy)$")
C_RESOURCES = R(r"AWS::(?:CloudTrail::Trail|IAM::Policy)")
RISK_LEVEL = R(r"^(?:medium|high)$", "i")
LEGACY_CLIENT = R(r"^(?:IMAP4?|POP3?|SMTP|Authenticated SMTP|Other clients|Exchange ActiveSync)$", "i")
CA_RESULT_KEY = R(r"^appliedconditionalaccesspolicies\.\d+\.result$")
MFA_REASON = R(r"^(?:FRAUD|user_marked_fraud|anomalous_push)$", "i")
K8S_READ = R(r"^(?:get|list|watch)$")
MAIL_ACTION = R(r"^(?:New-InboxRule|Set-InboxRule|Set-Mailbox)$")
MAIL_VALUES = R(r"ForwardTo|ForwardingSmtpAddress|RedirectTo|DeleteMessage", "i")
MAIL_PARAM_KEY = R(r"parameters\.\d+\.(?:name|value)$")
INACTIVE = R(r"^(?:RESOLVED|SUPPRESSED|ARCHIVED|CLOSED)$", "i")
HIGH_CRIT = R(r"^(?:HIGH|CRITICAL)$")
HIGH_CRIT_I = R(r"^(?:HIGH|CRITICAL)$", "i")
P_ALERT = R(r"""%ASA-\d-33800[56]:[^\r\n]+|(?:CEF:\d\|[^\r\n]{0,100}\|THREAT\|[7-9]\||\btype="utm"\s+subtype="(?:ips|virus)"[^\r\n]+)|,\s*THREAT,\s*(?:vulnerability|virus|spyware),[^\r\n]+|\[Priority:\s*[12]\]""", "i")
SYSMON_ID = R(r"^(?:8|10)$")
LSASS = R(r"\\lsass\.exe$", "i")
LSASS_ACCESS = R(r"^(?:0x1fffff|0x1f0fff|0x1010|0x1410)$", "i")
P_ANONYMOUS = R(r'\b\d{1,3}(?:\.\d{1,3}){3}\s+-\s+\S+\s+REST\.GET\.OBJECT\s+\S+\s+"GET [^"]+"\s+200\b')
REQUEST_URL = R(r'"(?:GET|POST|PUT|DELETE) (\S+) HTTP\/')
API_PATH = R(r"^\/api\/")
SCRIPT_CLIENT = R(r"python-requests|Go-http-client|curl\/|axios", "i")
ALIAS = R(r"^([^,\s+]+)\+([^,@\s]+)@([^,\s]+),[^,]+,[^,]+,([^,]+)")
FAILURE_TEXT = R(r"(?:Failed password|authentication fail(?:ed|ure)|password mismatch|user .*? not found|res=failed)", "i")
LOGIN_EVENT_TYPE = R(r"\b(?:login|auth)", "i")
LOGIN_REQUEST = R(r"""\b(?:POST|GET)\b.*\/[^\s"]*(?:login|auth)""", "i")
DENIED_STATUS = R(r"\b(?:401|403)\b")
AUDIT_LOGIN_TYPE = R(r"^(?:USER_AUTH|USER_LOGIN)$")
DPT = R(r"\bDPT=(\d+)")
VPC = R(r"^\d\s+\d+\s+eni-\S+\s+(\S+)\s+\S+\s+\d+\s+(\d+)\s+\d+\s+\d+\s+\d+\s+(\d{10})\s+")
SRX = R(r"RT_FLOW_SESSION_DENY:[^\r\n]*?(\d+(?:\.\d+){3})\/\d+->\S+\/(\d+)")
CLASSIC_TIME = R(r"^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)")
FLOW_TUPLE_KEY = R(r"flowtuples\.\d+$")


def scan_security_log(text: str) -> list[dict]:
    findings: dict[str, dict] = {}

    def add(rule, record, evidence):
        finding = findings.get(rule["id"]) or {
            "ruleId": rule["id"], "title": rule["title"], "severity": rule["severity"], "category": "attack",
            "description": rule["description"], "count": 0, "samples": [],
        }
        finding["count"] += 1
        if len(finding["samples"]) < 5:
            context = source(record)
            sample = {}
            if record.get("line") is not None:
                sample["line"] = record["line"]
            if record.get("record") is not None:
                sample["record"] = record["record"]
            sample["text"] = f"{context + ' | ' if context else ''}{evidence}"[:360]
            finding["samples"].append(sample)
        findings[rule["id"]] = finding

    api, aliases, ports, failures, denials = [], [], [], [], []
    travel: dict[str, list[dict]] = {}
    year = current_utc_year()

    for record in read_log_records(text):
        inspected = decoded(record["text"])

        def match(rule, pattern):
            found = pattern.search(inspected)
            if found:
                add(rule, record, found.group(0))

        match(RULES["recon"], P_RECON)
        match(RULES["tool"], P_TOOL)
        match(RULES["sql"], P_SQL)
        match(RULES["injection"], P_INJECTION)

        fields = record["fields"]
        entries = js_entries(fields)
        action = field(record, "eventname", "action", "eventtype", "operation", "operationname", "protopayload.methodname")
        values = "\n".join(js_values(fields))
        if (
            (A_POLICY.search(action) and A_POLICY_VALUES.search(values))
            or (A_ROLE_ASSIGN.search(action) and A_ROLE_IDS.search(values))
            or (A_GCP.search(action) and A_GCP_VALUES.search(values))
            or A_GRANT.search(action)
            or any(EVENT_NAME_KEY.search(k) and v == "GRANT_ADMIN_PRIVILEGE" for k, v in entries)
        ):
            actor = field(record, "caller", "useridentity.arn", "protopayload.authenticationinfo.principalemail", "actor.user.email", "actor.email")
            add(RULES["admin"], record, f"{action or 'GRANT_ADMIN_PRIVILEGE'} | {actor}")

        if (
            C_ACTIONS.search(action)
            or (field(record, "configurationitemstatus") == "ResourceDeleted" and C_RESOURCES.search(field(record, "resourcetype")))
            or any(EVENT_NAME_KEY.search(k) and v == "TURN_OFF_2_STEP_VERIFICATION" for k, v in entries)
        ):
            add(RULES["controls"], record,
                f"{action or field(record, 'resourcetype')} | {field(record, 'configurationitemstatus', 'eventtype', 'action')}")

        risk = field(record, "risklevelaggregated", "risklevelduringsignin")
        if RISK_LEVEL.search(risk) or any(EVENT_NAME_KEY.search(k) and v == "suspicious_login" for k, v in entries):
            add(RULES["risk"], record,
                f"risk={risk or 'suspicious_login'} | user={field(record, 'userprincipalname', 'actor.email')} | outcome={field(record, 'status.errorcode')}")
        if (field(record, "status.errorcode") == "0" and LEGACY_CLIENT.search(field(record, "clientappused"))
                and not field(record, "mfadetail.authmethod")):
            add(RULES["legacy"], record,
                f"{field(record, 'userprincipalname')} | client={field(record, 'clientappused')} | errorCode=0 | no MFA detail")
        if field(record, "status.errorcode") == "0" and (
            field(record, "conditionalaccessstatus") == "failure"
            or any(CA_RESULT_KEY.search(k) and v == "failure" for k, v in entries)
        ):
            add(RULES["access"], record, f"user={field(record, 'userprincipalname')} | errorCode=0 | conditional-access policy=failure")
        if MFA_REASON.search(field(record, "reason", "result")) or (
            field(record, "factor") == "bypass_code" and field(record, "result") == "SUCCESS"
        ):
            add(RULES["mfa"], record,
                f"user={field(record, 'user.name')} | {field(record, 'result')} | {field(record, 'reason')} | factor={field(record, 'factor')}")
        if field(record, "apiversion").startswith("audit.k8s.io/") and (
            (K8S_READ.search(field(record, "verb")) and field(record, "objectref.resource") == "secrets")
            or field(record, "objectref.subresource") == "exec"
        ):
            add(RULES["secrets"], record,
                f"{field(record, 'verb')} {field(record, 'requesturi')} | user={field(record, 'user.username')} | response={field(record, 'responsestatus.code')}")
        if MAIL_ACTION.search(action) and MAIL_VALUES.search(values):
            params = " ".join(v for k, v in entries if MAIL_PARAM_KEY.search(k))
            add(RULES["mail"], record, f"{action} | user={field(record, 'userid')} | {params}")

        severity = field(record, "severity.label", "severity")
        inactive = (
            INACTIVE.search(field(record, "workflow.status", "recordstate", "status"))
            or field(record, "service.archived") == "true"
            or field(record, "mitigationstatus", "threatinfo.mitigationstatus") == "marked_as_benign"
        )
        if not inactive:
            if field(record, "type") == "PACKAGE_VULNERABILITY" and field(record, "status") == "ACTIVE" and HIGH_CRIT.search(severity):
                add(RULES["vulnerability"], record, f"{field(record, 'title')} | severity={severity} | status=ACTIVE")
            elif (
                (field(record, "productarn", "detectionsource") and HIGH_CRIT_I.search(severity))
                or (":guardduty:" in field(record, "arn") and js_number(severity) >= 4)
                or (field(record, "eventtype") == "alert" and js_number(field(record, "alert.severity")) > 0
                    and js_number(field(record, "alert.severity")) <= 2)
                or field(record, "threatinfo.confidencelevel") == "malicious"
                or js_number(field(record, "rule.level")) >= 7
            ):
                name = field(record, "title", "alert.signature", "threatinfo.threatname", "rule.description")
                add(RULES["alert"], record, f"{name} | severity={severity or field(record, 'alert.severity', 'rule.level')}")
        match(RULES["alert"], P_ALERT)
        if ("Sysmon" in field(record, "provider") and SYSMON_ID.search(field(record, "eventid"))
                and LSASS.search(field(record, "targetimage"))
                and (field(record, "eventid") == "8" or LSASS_ACCESS.search(field(record, "grantedaccess")))):
            add(RULES["lsass"], record,
                f"{field(record, 'sourceimage')} -> {field(record, 'targetimage')} | EventID={field(record, 'eventid')} | access={field(record, 'grantedaccess')}")
        if ("Security-Auditing" in field(record, "provider") and field(record, "status") == "0x0"
                and field(record, "ticketencryptiontype").lower() == "0x17"
                and (field(record, "eventid") == "4769" or (field(record, "eventid") == "4768" and field(record, "preauthtype") == "0"))):
            add(RULES["roasting"], record,
                f"EventID={field(record, 'eventid')} | user={field(record, 'targetusername')} | service={field(record, 'servicename')} | RC4=0x17 | preAuth={field(record, 'preauthtype')}")
        match(RULES["anonymous"], P_ANONYMOUS)

        time = timestamp(record)
        src = source(record)
        lat = field(record, "location.geocoordinates.latitude")
        lon = field(record, "location.geocoordinates.longitude")
        user = field(record, "userprincipalname")
        if (user and field(record, "status.errorcode") == "0" and lat and lon and is_finite(time)
                and is_finite(js_number(lat)) and is_finite(js_number(lon))
                and abs(js_number(lat)) <= 90 and abs(js_number(lon)) <= 180):
            travel.setdefault(user, []).append({"record": record, "time": time, "lat": js_number(lat), "lon": js_number(lon)})
        url = field(record, "path", "requestpath")
        if not url:
            m = REQUEST_URL.search(inspected)
            url = m.group(1) if m else ""
        if API_PATH.search(url) and SCRIPT_CLIENT.search(inspected):
            api.append({"key": src, "value": url, "time": time, "record": record})
        alias = ALIAS.search(record["text"])
        if alias:
            aliases.append({"key": f"{alias.group(1)}@{alias.group(3)}".lower(), "value": alias.group(2),
                            "time": date_parse(alias.group(4).replace(" ", "T", 1) + "Z"), "record": record})

        failure = (
            FAILURE_TEXT.search(record["text"])
            or (field(record, "status.errorcode") != "" and field(record, "status.errorcode") != "0")
            or field(record, "eventid") == "4625"
            or field(record, "outcome.result") == "FAILURE"
            or (LOGIN_EVENT_TYPE.search(field(record, "eventtype")) and field(record, "success") == "false")
            or (LOGIN_REQUEST.search(inspected) and DENIED_STATUS.search(inspected))
        )
        if failure and (not field(record, "type").startswith("USER_") or AUDIT_LOGIN_TYPE.search(field(record, "type"))):
            failures.append({"key": src, "value": field(record, "userprincipalname", "targetusername", "actor.alternateid", "acct"),
                             "time": time, "record": record})

        port = field(record, "dpt", "dstport")
        if not port:
            m = DPT.search(record["text"])
            port = m.group(1) if m else None
        if src and port:
            ports.append({"key": src, "value": port, "time": time, "record": record})
        vpc = VPC.search(record["text"])
        if vpc:
            ports.append({"key": vpc.group(1), "value": vpc.group(2), "time": js_number(vpc.group(3)) * 1000, "record": record})
        srx = SRX.search(record["text"])
        if srx:
            # RFC3164 exports omit the year; use the same reference year for every record.
            classic = CLASSIC_TIME.search(record["text"])
            evidence = {"key": srx.group(1), "value": srx.group(2),
                        "time": date_parse(f"{classic.group(1)} {year} UTC") if classic else NAN, "record": record}
            ports.append(evidence)
            denials.append(evidence)
        for key, tuple_ in entries:
            if not FLOW_TUPLE_KEY.search(key):
                continue
            cells = tuple_.split(",")
            if len(cells) >= 8:
                ports.append({"key": cells[1], "value": cells[4], "time": js_number(cells[0]) * 1000, "record": record})

    for rows, minimum, window_ms, distinct, rule in (
        (api, 10, 60_000, True, RULES["scrape"]),
        (aliases, 10, 600_000, True, RULES["aliases"]),
        (ports, 5, 600_000, True, RULES["scan"]),
        (failures, 5, 600_000, False, RULES["failures"]),
        (denials, 5, 600_000, False, RULES["denied"]),
    ):
        for group in bursts(rows, minimum, window_ms, distinct):
            first, last = group[0], group[-1]
            amount = len({r["value"] for r in group}) if distinct else len(group)
            label = "distinct values" if distinct else "events"
            examples = ", ".join(r["value"] for r in group[:5])
            add(rule, first["record"],
                f"{first['key']}: {amount} {label} between {iso_string(first['time'])} and {iso_string(last['time'])} | {examples}")

    for user, history in travel.items():
        history.sort(key=lambda h: h["time"])
        for i in range(1, len(history)):
            prev, nxt = history[i - 1], history[i]
            def rad(n):
                return n * math.pi / 180
            a = (math.sin(rad(nxt["lat"] - prev["lat"]) / 2) ** 2
                 + math.cos(rad(prev["lat"])) * math.cos(rad(nxt["lat"])) * math.sin(rad(nxt["lon"] - prev["lon"]) / 2) ** 2)
            km = 6371 * 2 * math.asin(math.sqrt(min(1, a)))
            hours = (nxt["time"] - prev["time"]) / 3_600_000
            if 0 <= hours <= 24 and km > 500 and (hours == 0 or km / hours > 900):
                add(RULES["travel"], nxt["record"],
                    f"{user}: {js_round(km)} km in {to_fixed(hours * 60, 1)} minutes | {source(prev['record'])} at {iso_string(prev['time'])} -> {source(nxt['record'])} at {iso_string(nxt['time'])}")
    return list(findings.values())
