"""Inspects a file's name, type signature and text for dangerous material."""
from __future__ import annotations

import bisect
import codecs
import re

from ..jsutil import R

MAX_SAMPLES = 5
MAX_SCAN_BYTES = 20 * 1024 * 1024
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def severity_rank(s: str) -> int:
    return SEVERITY_ORDER.index(s)


def _rule(id_, title, severity, category, description, pattern, flags="", redact=False):
    return {"id": id_, "title": title, "severity": severity, "category": category,
            "description": description, "pattern": R(pattern, flags), "redact": redact}


TEXT_RULES = [
    # Secrets / credentials
    _rule("private-key", "Private key", "critical", "secret", "A private key is embedded in the file. Anyone with this file can impersonate the key owner.",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----", redact=True),
    _rule("aws-key", "AWS access key", "high", "secret", "Looks like an AWS access key ID.",
          r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", redact=True),
    _rule("github-token", "GitHub token", "high", "secret", "Looks like a GitHub personal access or app token.",
          r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b", redact=True),
    _rule("slack-token", "Slack token", "high", "secret", "Looks like a Slack API token.",
          r"\bxox[abprs]-[A-Za-z0-9-]{10,}", redact=True),
    _rule("stripe-key", "Stripe live secret key", "high", "secret", "Looks like a Stripe live secret key.",
          r"\b[rs]k_live_[0-9a-zA-Z]{20,}", redact=True),
    _rule("google-api-key", "Google API key", "medium", "secret", "Looks like a Google API key.",
          r"\bAIza[0-9A-Za-z_-]{35}\b", redact=True),
    _rule("jwt", "JSON Web Token", "medium", "secret", "A bearer token (JWT) that may grant access until it expires.",
          r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", redact=True),
    _rule("credential-url", "Credentials in URL", "medium", "secret", "A connection string or URL with an embedded username and password.",
          r"""\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@"']+:[^\s@/"']{3,}@[^\s"']+""", "i", redact=True),
    _rule("password-assignment", "Hard-coded password or secret", "medium", "secret", "A password, secret, or API key assigned to a literal value.",
          r"""\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?(?!\$\{|<|\*{3}|changeme|null|none|true|false)[^\x00\s"',;]{6,}""", "i", redact=True),

    # Malware / attacker tooling
    _rule("eicar", "EICAR antivirus test file", "critical", "malware", "The industry-standard antivirus test signature. Harmless, but every scanner treats it as malware.",
          r"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*"),
    _rule("mimikatz", "Credential dumping tool (Mimikatz)", "critical", "malware", "References Mimikatz modules used to steal Windows passwords and hashes.",
          r"\bmimikatz\b|\bsekurlsa::\w+|\blsadump::\w+", "i"),
    _rule("reverse-shell", "Reverse shell", "critical", "malware", "A command that hands a remote attacker an interactive shell.",
          r"\/dev\/tcp\/\d{1,3}(?:\.\d{1,3}){3}\/\d+|\bnc(?:at)?(?:\.exe)?\b[^\n]{0,80}\s-[ec]\s+(?:\/bin\/(?:ba)?sh|cmd(?:\.exe)?)|socket\.socket\([^\n]{0,200}\bdup2\b", "i"),
    _rule("webshell", "Web shell", "critical", "malware", "Server-side code that runs commands taken straight from a web request.",
          r"\b(?:eval|assert|system|exec|passthru|shell_exec|popen)\s*\(\s*(?:base64_decode\s*\(\s*)?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b", "i"),
    _rule("ransomware-shadow", "Shadow copy deletion", "critical", "malware", "Deleting Volume Shadow Copies is a hallmark of ransomware preparing to encrypt files.",
          r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|\bbcdedit(?:\.exe)?\s+\/set\s+\S*\s*recoveryenabled\s+no\b", "i"),
    _rule("ps-encoded", "Encoded PowerShell command", "high", "malware", "PowerShell launched with a Base64-encoded command, commonly used to hide malicious scripts.",
          r"\bpowershell(?:\.exe)?\b[^\n]{0,120}\s-(?:e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}", "i"),
    _rule("ps-download-cradle", "PowerShell download-and-run", "high", "malware", "Downloads code from the internet and executes it in memory.",
          r"\b(?:IEX|Invoke-Expression)\b[^\n]{0,200}\b(?:DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|iwr|irm|Invoke-RestMethod)\b|\b(?:DownloadString|Invoke-WebRequest|iwr|irm)\b[^\n]{0,200}\|\s*(?:IEX|Invoke-Expression)\b", "i"),
    _rule("lolbin", "Living-off-the-land binary abuse", "high", "malware", "A built-in Windows tool used in a way attackers rely on to download or run payloads.",
          r"""\bcertutil(?:\.exe)?\s[^\n]{0,80}-urlcache\b[^\n]{0,80}\s-f\b|\bregsvr32(?:\.exe)?\s[^\n]{0,80}\/i:\s*https?:|\bmshta(?:\.exe)?\s+["']?(?:https?:|vbscript:|javascript:)|\bbitsadmin(?:\.exe)?\s[^\n]{0,80}\/transfer\b|\brundll32(?:\.exe)?\s[^\n]{0,80}javascript:""", "i"),
    _rule("defense-evasion", "Security tooling disabled or logs cleared", "high", "malware", "Disables Microsoft Defender or wipes event logs to cover tracks.",
          r"\bSet-MpPreference\b[^\n]{0,80}-Disable(?:RealtimeMonitoring|IOAVProtection|BehaviorMonitoring)\b|\bwevtutil(?:\.exe)?\s+cl\b|\bClear-EventLog\b", "i"),
    _rule("js-obfuscated-eval", "Obfuscated JavaScript execution", "high", "malware", "Decodes hidden text and immediately executes it.",
          r"\beval\s*\(\s*(?:atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(|\bdocument\.write\s*\(\s*unescape\s*\(", "i"),
    _rule("py-exec-encoded", "Python executes encoded payload", "high", "malware", "Decodes Base64/zlib data and executes it.",
          r"""\bexec\s*\(\s*(?:base64\.b64decode|zlib\.decompress|marshal\.loads|__import__\(\s*["'](?:base64|zlib|marshal)["']\))"""),
    _rule("pipe-to-shell", "Download piped into a shell", "medium", "malware", "Runs a remote script without inspecting it first.",
          r"\b(?:curl|wget)\s[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"),
    _rule("vba-shell", "Office macro spawns programs", "medium", "malware", "Macro code that creates a shell object or auto-runs when the document opens.",
          r"""CreateObject\(\s*["'](?:WScript\.Shell|Shell\.Application|MSXML2\.XMLHTTP)["']\s*\)|\b(?:AutoOpen|Auto_Open|Document_Open|Workbook_Open)\b""", "i"),

    # Attack payloads (typically found in web/app logs)
    _rule("log4shell", "Log4Shell exploit attempt", "critical", "attack", "A JNDI lookup string used to exploit CVE-2021-44228.",
          r"\$\{(?:jndi|\$\{(?:lower|upper|::-j)[^}]*\})[^}]{0,40}:(?:ldaps?|rmi|dns|iiop|nis|corba)?", "i"),
    _rule("sql-injection", "SQL injection attempt", "medium", "attack", "Input that tries to alter a database query.",
          r"\bunion(?:\s|\+|%20|\/\*\*\/)+(?:all(?:\s|\+|%20)+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|;\s*drop\s+table\b|\bsleep\(\s*\d+\s*\)\s*--|\bxp_cmdshell\b", "i"),
    _rule("path-traversal", "Path traversal attempt", "medium", "attack", "Tries to escape a web root to read system files.",
          r"(?:\.\.[/\\]){2,}|(?:%2e%2e(?:%2f|%5c|\/)){2,}|\/etc\/passwd\b|\bwin\.ini\b", "i"),
    _rule("xss", "Cross-site scripting attempt", "medium", "attack", "Script injection aimed at a browser.",
          r"""<script\b[^>]*>[^<]{0,200}(?:document\.cookie|alert\(|fetch\()|\bjavascript:\s*alert\(|\bon(?:error|load)\s*=\s*["']?alert\(""", "i"),

    _rule("large-encoded-blob", "Large encoded blob", "low", "malware", "A long Base64 string. Often benign (images, certificates) but also used to hide payloads.",
          r"[A-Za-z0-9+/]{600,}={0,2}"),
]

EXECUTABLE_EXT = R(r"\.(?:exe|dll|scr|com|pif|sys|cpl|msi|msp|elf|so|dylib|bin|out|app)$", "i")
RISKY_EXT = R(r"\.(?:exe|scr|com|pif|cpl|msi|hta|vbs|vbe|js|jse|wsf|wsh|ps1|psm1|bat|cmd|lnk|iso|img|jar|reg|docm|xlsm|pptm|dotm)$", "i")
DOUBLE_EXT = R(r"\.(?:pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|csv|zip|mp[34])\.(?:exe|scr|com|pif|bat|cmd|js|jse|vbs|vbe|ps1|hta|lnk|wsf|jar)$", "i")
_LNK_EXT = R(r"\.lnk$", "i")
_EXEC_KIND = R(r"executable|shortcut", "i")
_WS_RUN = R(r"\s+")
_REDACT_TAIL = R(r"""([:=]\s*["']?|^)(\S+)$""")
_PWD_SUDO = R(r"^PWD=\/")
_PWD_JSON = R(r"""^pwd["']\s*:\s*["']\/""", "i")
_COMMAND_KEY = R(r'"command"\s*:')
_VBA_ZIP = R(r"vbaProject\.bin")
_VBA_OLE = R(r"_VBA_PROJECT|\bVBA\b")
_PDF_ACTIVE = R(r"\/(?:JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b")


def redact(value: str) -> str:
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "•" * min(12, len(value) - 6) + value[-2:]


def detect_file_kind(data: bytes):
    if data.startswith(b"\x4d\x5a"):
        return "Windows executable (PE)"
    if data.startswith(b"\x7fELF"):
        return "Linux executable (ELF)"
    if data.startswith(b"\xcf\xfa\xed\xfe") or data.startswith(b"\xce\xfa\xed\xfe"):
        return "macOS executable (Mach-O)"
    if data.startswith(b"\x4c\x00\x00\x00\x01\x14\x02\x00"):
        return "Windows shortcut (LNK)"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive / Office document"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "Legacy Office document (OLE)"
    if data.startswith(b"%PDF"):
        return "PDF document"
    return None


def _c1_passthrough(err):
    # Browsers decode the five bytes windows-1252 leaves undefined as the matching C1 control.
    return chr(err.object[err.start]), err.start + 1


codecs.register_error("lpr-c1", _c1_passthrough)


def _strip_bom(text: str) -> str:
    return text[1:] if text.startswith("\ufeff") else text


def decode_text(data: bytes) -> tuple[str, bool]:
    """Decodes bytes as text, honouring UTF-16 BOMs (common in Windows exports)."""
    if data.startswith(b"\xff\xfe"):
        return _strip_bom(data[2:].decode("utf-16-le", errors="replace")), False
    if data.startswith(b"\xfe\xff"):
        return _strip_bom(data[2:].decode("utf-16-be", errors="replace")), False
    head = data[:8192]
    nulls = head.count(0)
    binary = nulls > len(head) * 0.01
    if binary:
        # A single-byte decoding keeps every byte so signatures inside binaries still match.
        return data.decode("cp1252", errors="lpr-c1"), True
    return _strip_bom(data.decode("utf-8", errors="replace")), False


def _line_at(line_starts: list[int], index: int) -> int:
    return bisect.bisect_right(line_starts, index)


def scan_text(text: str, binary: bool = False) -> list[dict]:
    findings: list[dict] = []
    line_starts = [0]
    if not binary:
        line_starts.extend(m.end() for m in re.finditer("\n", text))
    for rule in TEXT_RULES:
        if binary and rule["id"] == "large-encoded-blob":
            continue
        count = 0
        samples: list[dict] = []
        for m in rule["pattern"].finditer(text):
            m0 = m.group(0)
            # sudo logs use PWD for the working directory, not a password.
            if rule["id"] == "password-assignment" and _PWD_SUDO.search(m0):
                continue
            if rule["id"] == "password-assignment" and _PWD_JSON.search(m0):
                index = m.start()
                end = text.find("\n", index)
                line = text[text.rfind("\n", 0, index + 1) + 1: len(text) if end < 0 else end]
                if _COMMAND_KEY.search(line):
                    continue
            count += 1
            if len(samples) < MAX_SAMPLES:
                raw = _WS_RUN.sub(" ", m0)[:160]
                if not rule["redact"] or rule["id"] == "private-key":
                    shown = raw
                else:
                    shown = _REDACT_TAIL.sub(lambda g: g.group(1) + redact(g.group(2)), raw, count=1)
                sample = {"text": shown}
                if not binary:
                    sample = {"line": _line_at(line_starts, m.start()), "text": shown}
                samples.append(sample)
        if count:
            findings.append({"ruleId": rule["id"], "title": rule["title"], "severity": rule["severity"],
                             "category": rule["category"], "description": rule["description"],
                             "count": count, "samples": samples})
    return findings


def scan_content(name: str, data: bytes) -> dict:
    findings: list[dict] = []
    kind = detect_file_kind(data)

    def add(rule_id, title, severity, category, description, sample=None):
        finding = {"ruleId": rule_id, "title": title, "severity": severity, "category": category,
                   "description": description}
        if sample is not None:
            finding["sample"] = sample
        finding["count"] = 1
        finding["samples"] = [{"text": sample}] if sample else []
        findings.append(finding)

    if DOUBLE_EXT.search(name):
        add("double-extension", "Disguised file extension", "high", "file-type",
            "The name pretends to be a document but actually ends in an executable or script extension.", name)
    elif RISKY_EXT.search(name):
        add("risky-extension", "Executable or script file", "medium", "file-type",
            "This file type can run code when opened. Only open it if you trust the source.", name)
    if kind and _EXEC_KIND.search(kind) and not EXECUTABLE_EXT.search(name) and not _LNK_EXT.search(name):
        add("extension-mismatch", "Hidden executable", "high", "file-type",
            f"The content is a {kind}, but the file name does not say so.", f"{name} → {kind}")

    truncated = len(data) > MAX_SCAN_BYTES
    text, binary = decode_text(data[:MAX_SCAN_BYTES] if truncated else data)
    if kind == "ZIP archive / Office document" and _VBA_ZIP.search(text):
        add("office-macro", "Office document with macros", "medium", "malware",
            "The document contains a VBA macro project, a common malware delivery method.")
    if kind == "Legacy Office document (OLE)" and _VBA_OLE.search(text):
        add("office-macro", "Office document with macros", "medium", "malware",
            "The document contains a VBA macro project, a common malware delivery method.")
    if kind == "PDF document" and _PDF_ACTIVE.search(text):
        add("pdf-active-content", "PDF with active content", "medium", "malware",
            "The PDF contains JavaScript, auto-open actions, launch actions, or embedded files.")
    findings.extend(scan_text(text, binary))
    return {"findings": findings, "text": None if binary else text, "kind": kind, "truncated": truncated}
