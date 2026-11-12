"""JavaScript-compatible helpers.

The original app ran in JavaScript. These helpers reproduce the few JavaScript
behaviours the analysis depends on (Date.parse, toISOString, Math.round,
toFixed, String(number), regex semantics, the mulberry32 generator) so the
Python engine produces the same numbers, timestamps and wording.
"""
from __future__ import annotations

import json
import math
import re
import time as _time
from decimal import ROUND_HALF_UP, Decimal

NAN = float("nan")
MS_PER_DAY = 86_400_000
MAX_TIME = 8.64e15

# JavaScript's whitespace + line terminators (String.prototype.trim, regex \s).
JS_WS = (
    "\t\n\x0b\x0c\r \xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
    "\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_JS_WS_SET = frozenset(JS_WS)


def trim(s: str) -> str:
    return s.strip(JS_WS)


def trim_start(s: str) -> str:
    return s.lstrip(JS_WS)


def is_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def is_finite(x) -> bool:
    return is_number(x) and math.isfinite(x)


def is_nan(x) -> bool:
    return x != x


# ---------------------------------------------------------------- regexes

_RE_WS_CLASS = "\\t\\n\\x0b\\x0c\\r \\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff"


def _translate(src: str) -> str:
    """Rewrite a JavaScript regex source so Python's `re` matches the same way."""
    out: list[str] = []
    i = 0
    in_class = False
    n = len(src)
    while i < n:
        c = src[i]
        if c == "\\" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "s":
                out.append(_RE_WS_CLASS if in_class else "[" + _RE_WS_CLASS + "]")
            elif nxt == "S" and not in_class:
                out.append("[^" + _RE_WS_CLASS + "]")
            else:
                out.append(c + nxt)
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
                out.append(c)
            elif c == "[":
                out.append("\\[")
            else:
                out.append(c)
            i += 1
            continue
        if c == "[":
            in_class = True
            out.append(c)
            i += 1
            if i < n and src[i] == "^":
                out.append("^")
                i += 1
            continue
        if c == ".":
            out.append("[^\\n\\r\\u2028\\u2029]")
        elif c == "$":
            out.append("\\Z")
        else:
            out.append(c)
        i += 1
    return "".join(out)


def R(source: str, flags: str = "") -> re.Pattern:
    """Compile a JavaScript regular expression (flags: 'i' supported, 'g' ignored)."""
    f = re.ASCII
    if "i" in flags:
        f |= re.IGNORECASE
    return re.compile(_translate(source), f)


# ---------------------------------------------------------------- numbers

def js_round(x):
    """Math.round: halves round toward +Infinity."""
    if not math.isfinite(x):
        return x
    r = math.floor(x)
    return r + 1 if x - r >= 0.5 else r


def round_to(n: float, d: int = 4) -> float:
    f = 10 ** d
    return js_round(n * f) / f


def number_to_string(x) -> str:
    """Number.prototype.toString() for finite and special values."""
    if isinstance(x, bool):
        return "true" if x else "false"
    x = float(x)
    if x != x:
        return "NaN"
    if x == math.inf:
        return "Infinity"
    if x == -math.inf:
        return "-Infinity"
    if x == 0:
        return "0"
    sign = "-" if x < 0 else ""
    r = repr(abs(x))
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    digits = (ip + fp).lstrip("0")
    lead_zeros = len(ip + fp) - len((ip + fp).lstrip("0"))
    point = len(ip) + exp - lead_zeros  # decimal point position relative to digits
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    nn = point
    if k <= nn <= 21:
        s = digits + "0" * (nn - k)
    elif 0 < nn <= 21:
        s = digits[:nn] + "." + digits[nn:]
    elif -6 < nn <= 0:
        s = "0." + "0" * (-nn) + digits
    else:
        e = nn - 1
        s = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + s


def to_fixed(x: float, d: int) -> str:
    """Number.prototype.toFixed()."""
    if x != x:
        return "NaN"
    if abs(x) >= 1e21:
        return number_to_string(x)
    q = Decimal(x).quantize(Decimal(1).scaleb(-d), rounding=ROUND_HALF_UP)
    s = format(q, "f")
    if x == 0 and s.startswith("-"):
        s = s[1:]
    return s


_NUM_RE = re.compile(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?\Z", re.ASCII)


def js_number(v) -> float:
    """Number(value) for the value types the analysis passes."""
    if v is None:
        return NAN
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if is_number(v):
        return float(v)
    if not isinstance(v, str):
        return NAN
    s = trim(v)
    if not s:
        return 0.0
    if _NUM_RE.match(s):
        return float(s)
    low = s.lower()
    if low.startswith("0x") and re.fullmatch(r"[0-9a-fA-F]+", s[2:]):
        return float(int(s[2:], 16))
    if low.startswith("0o") and re.fullmatch(r"[0-7]+", s[2:]):
        return float(int(s[2:], 8))
    if low.startswith("0b") and re.fullmatch(r"[01]+", s[2:]):
        return float(int(s[2:], 2))
    if s in ("Infinity", "+Infinity"):
        return math.inf
    if s == "-Infinity":
        return -math.inf
    return NAN


def js_string(v) -> str:
    """String(value) for JSON values."""
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if is_number(v):
        return number_to_string(v)
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        return ",".join("" if e is None else js_string(e) for e in v)
    return "[object Object]"


def to_uint32(x) -> int:
    if not is_finite(x):
        return 0
    return int(math.trunc(x)) % 4294967296


# ---------------------------------------------------------------- objects

_INDEX_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)


def _is_index(k: str) -> bool:
    return bool(_INDEX_RE.match(k)) and int(k) < 4294967295


def js_keys(obj) -> list:
    """Object.keys() order: array-index keys ascending, then insertion order."""
    if isinstance(obj, list):
        return [str(i) for i in range(len(obj))]
    keys = list(obj.keys())
    idx = [k for k in keys if isinstance(k, str) and _is_index(k)]
    if not idx:
        return keys
    rest = [k for k in keys if not (isinstance(k, str) and _is_index(k))]
    return sorted(idx, key=int) + rest


def js_entries(obj) -> list:
    if isinstance(obj, list):
        return [(str(i), v) for i, v in enumerate(obj)]
    return [(k, obj[k]) for k in js_keys(obj)]


def js_values(obj) -> list:
    if isinstance(obj, list):
        return list(obj)
    return [obj[k] for k in js_keys(obj)]


def _bad_constant(name):
    raise ValueError(f"Unexpected token {name} in JSON")


def json_parse(text: str):
    """JSON.parse: every number is a double, NaN/Infinity literals are rejected."""
    return json.loads(text, parse_int=float, parse_constant=_bad_constant)


# ---------------------------------------------------------------- random

def mulberry32(seed):
    a = to_uint32(seed)

    def rng() -> float:
        nonlocal a
        a = (a + 0x6D2B79F5) & 0xFFFFFFFF
        t = ((a ^ (a >> 15)) * (1 | a)) & 0xFFFFFFFF
        t = ((t + (((t ^ (t >> 7)) * (61 | t)) & 0xFFFFFFFF)) & 0xFFFFFFFF) ^ t
        return ((t ^ (t >> 14)) & 0xFFFFFFFF) / 4294967296

    return rng


# ---------------------------------------------------------------- dates

def days_from_civil(y: int, m: int, d: int) -> int:
    y -= m <= 2
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (m + (-3 if m > 2 else 9)) + 2) // 5 + d - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def civil_from_days(z: int):
    z += 719468
    era = z // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return y + (m <= 2), m, d


def make_day(year: int, month0: int, date: int) -> int:
    ym = year + month0 // 12
    mn = month0 % 12
    return days_from_civil(ym, mn + 1, 1) + date - 1


def date_utc(year, month0, day=1, h=0, mi=0, s=0, ms=0) -> float:
    """Date.UTC()."""
    year = int(year)
    if 0 <= year <= 99:
        year += 1900
    return float(make_day(year, int(month0), int(day)) * MS_PER_DAY + ((int(h) * 60 + int(mi)) * 60 + int(s)) * 1000 + int(ms))


def _clip(t: float) -> int:
    if not is_finite(t) or abs(t) > MAX_TIME:
        raise ValueError("Invalid time value")
    return int(math.trunc(t))


def iso_string(t) -> str:
    """new Date(t).toISOString()."""
    t = _clip(t)
    days, rem = divmod(t, MS_PER_DAY)
    y, m, d = civil_from_days(days)
    h, rem = divmod(rem, 3_600_000)
    mi, rem = divmod(rem, 60_000)
    s, ms = divmod(rem, 1000)
    ys = f"{y:04d}" if 0 <= y <= 9999 else ("+" if y > 0 else "-") + f"{abs(y):06d}"
    return f"{ys}-{m:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"


def utc_hours(t) -> float:
    """new Date(t).getUTCHours()."""
    if not is_finite(t) or abs(t) > MAX_TIME:
        return NAN
    return (int(math.trunc(t)) // 3_600_000) % 24


def current_utc_year() -> int:
    return _time.gmtime().tm_year


def _local_to_utc(ms_local: float) -> float:
    """Interpret a wall-clock time in the device's time zone (like the browser does)."""
    try:
        secs = math.floor(ms_local / 1000)
        days, rem = divmod(int(secs), 86400)
        y, m, d = civil_from_days(days)
        h, rem = divmod(rem, 3600)
        mi, s = divmod(rem, 60)
        utc_secs = _time.mktime((y, m, d, h, mi, s, 0, 0, -1))
        return utc_secs * 1000 + (ms_local - secs * 1000)
    except (OverflowError, ValueError, OSError):
        return ms_local


# Date.parse() — a port of V8's date parser (ES ISO format + legacy formats).

_KEYWORDS = [
    ("jan", "M", 1), ("feb", "M", 2), ("mar", "M", 3), ("apr", "M", 4),
    ("may", "M", 5), ("jun", "M", 6), ("jul", "M", 7), ("aug", "M", 8),
    ("sep", "M", 9), ("oct", "M", 10), ("nov", "M", 11), ("dec", "M", 12),
    ("am", "AMPM", 0), ("pm", "AMPM", 12),
    ("ut", "TZ", 0), ("utc", "TZ", 0), ("z", "TZ", 0), ("gmt", "TZ", 0),
    ("cdt", "TZ", -5), ("cst", "TZ", -6), ("edt", "TZ", -4), ("est", "TZ", -5),
    ("mdt", "TZ", -6), ("mst", "TZ", -7), ("pdt", "TZ", -7), ("pst", "TZ", -8),
    ("t", "T", 0),
]


class _Tok:
    __slots__ = ("kind", "value", "length", "type")

    def __init__(self, kind, value=None, length=0, type_=None):
        self.kind = kind  # num, sym, kw, ws, unk, end, invalid
        self.value = value
        self.length = length
        self.type = type_

    def is_symbol(self, c):
        return self.kind == "sym" and self.value == c

    def is_sign(self):
        return self.kind == "sym" and self.value in "+-"

    def is_fixed(self, n):
        return self.kind == "num" and self.length == n

    def is_kw_z(self):
        return self.kind == "kw" and self.type == "TZ" and self.length == 1 and self.value == 0


_END = _Tok("end")
_INVALID = _Tok("invalid")


class _Scanner:
    def __init__(self, s: str):
        self.s = s
        self.i = 0
        self._next = self._scan()

    def _scan(self) -> _Tok:
        s, i, n = self.s, self.i, len(self.s)
        if i >= n:
            return _END
        c = s[i]
        if "0" <= c <= "9":
            j = i
            val = 0
            while j < n and "0" <= s[j] <= "9":
                if j - i < 9:
                    val = val * 10 + (ord(s[j]) - 48)
                j += 1
            self.i = j
            return _Tok("num", val, j - i)
        if c in ":-+.)":
            self.i = i + 1
            return _Tok("sym", c)
        if ord(c) >= 65 and c not in _JS_WS_SET:
            j = i
            prefix = []
            while j < n and ord(s[j]) >= 65 and s[j] not in _JS_WS_SET:
                if j - i < 3:
                    prefix.append(chr(ord(s[j]) | 0x20))
                j += 1
            self.i = j
            length = j - i
            word = "".join(prefix)
            for name, typ, value in _KEYWORDS:
                if name == word and (length <= 3 or typ == "M"):
                    return _Tok("kw", value, length, typ)
                if typ == "M" and len(word) == 3 and name == word:
                    return _Tok("kw", value, length, typ)
            return _Tok("kw", None, length, "UNKNOWN")
        if c in _JS_WS_SET:
            j = i
            while j < n and s[j] in _JS_WS_SET:
                j += 1
            self.i = j
            return _Tok("ws", None, j - i)
        if c == "(":
            balance = 0
            j = i
            while True:
                ch = s[j] if j < n else ""
                if ch == ")":
                    balance -= 1
                elif ch == "(":
                    balance += 1
                j += 1
                if not (balance > 0 and j < n):
                    break
            self.i = min(j, n)
            return _Tok("unk")
        self.i = i + 1
        return _Tok("unk")

    def next(self) -> _Tok:
        tok = self._next
        self._next = self._scan()
        return tok

    def peek(self) -> _Tok:
        return self._next

    def skip_symbol(self, c) -> bool:
        if self._next.is_symbol(c):
            self.next()
            return True
        return False


class _Day:
    def __init__(self):
        self.comp = []
        self.named_month = None
        self.iso = False

    def empty(self):
        return not self.comp

    def add(self, n):
        if len(self.comp) < 3:
            self.comp.append(n)
            return True
        return False

    def write(self):
        if len(self.comp) < 1:
            return None
        comp = self.comp + [1] * (3 - len(self.comp))
        year = 0
        if self.named_month is None:
            if self.iso or not (1 <= comp[0] <= 31):
                year, month, day = comp[0], comp[1], comp[2]
            else:
                month, day, year = comp[0], comp[1], comp[2]
        else:
            month = self.named_month
            if len(self.comp) == 1 and False:
                day = comp[0]
            elif not (1 <= comp[0] <= 31):
                year, day = comp[0], comp[1]
            else:
                day, year = comp[0], comp[1]
        if not self.iso:
            if 0 <= year <= 49:
                year += 2000
            elif 50 <= year <= 99:
                year += 1900
        if not (-(2 ** 30) <= year < 2 ** 30) or not (1 <= month <= 12) or not (1 <= day <= 31):
            return None
        return year, month - 1, day


class _Time:
    def __init__(self):
        self.comp = []
        self.hour_offset = None

    def empty(self):
        return not self.comp

    def is_expecting(self, n):
        k = len(self.comp)
        return (k == 1 and 0 <= n <= 59) or (k == 2 and 0 <= n <= 59) or (k == 3 and 0 <= n <= 999)

    def add(self, n):
        if len(self.comp) < 4:
            self.comp.append(n)
            return True
        return False

    def add_final(self, n):
        if not self.add(n):
            return False
        while len(self.comp) < 4:
            self.comp.append(0)
        return True

    def write(self):
        comp = self.comp + [0] * (4 - len(self.comp))
        hour, minute, second, ms = comp
        if self.hour_offset is not None:
            if not (0 <= hour <= 12):
                return None
            hour = hour % 12 + self.hour_offset
        if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59 and 0 <= ms <= 999):
            if hour != 24 or minute != 0 or second != 0 or ms != 0:
                return None
        return hour, minute, second, ms


class _Zone:
    def __init__(self):
        self.sign = None
        self.hour = None
        self.minute = None

    def set(self, offset_hours):
        self.sign = -1 if offset_hours < 0 else 1
        self.hour = abs(offset_hours)
        self.minute = 0

    def empty(self):
        return self.hour is None

    def is_utc(self):
        return self.hour == 0 and self.minute == 0

    def is_expecting(self, n):
        return self.hour is not None and self.minute is None and 0 <= n <= 59

    def offset_seconds(self):
        if self.sign is None:
            return None
        h = self.hour or 0
        m = self.minute or 0
        return self.sign * (h * 3600 + m * 60)


def _read_ms(tok: _Tok) -> int:
    number, length = tok.value, tok.length
    if length == 1:
        number *= 100
    elif length == 2:
        number *= 10
    elif length > 3:
        length = min(length, 9)
        factor = 1
        while length > 3:
            factor *= 10
            length -= 1
        number //= factor
    return number


def _es5(sc: _Scanner, day: _Day, tm: _Time, tz: _Zone) -> _Tok:
    if sc.peek().is_sign():
        sign_tok = sc.next()
        if not sc.peek().is_fixed(6):
            return sign_tok
        sign = 1 if sign_tok.value == "+" else -1
        year = sc.next().value
        if sign < 0 and year == 0:
            return sign_tok
        day.add(sign * year)
    elif sc.peek().is_fixed(4):
        day.add(sc.next().value)
    else:
        return sc.next()
    if sc.skip_symbol("-"):
        p = sc.peek()
        if not p.is_fixed(2) or not (1 <= p.value <= 12):
            return sc.next()
        day.add(sc.next().value)
        if sc.skip_symbol("-"):
            p = sc.peek()
            if not p.is_fixed(2) or not (1 <= p.value <= 31):
                return sc.next()
            day.add(sc.next().value)
    p = sc.peek()
    if not (p.kind == "kw" and p.type == "T"):
        if p.kind != "end":
            return sc.next()
    else:
        sc.next()
        p = sc.peek()
        if not p.is_fixed(2) or not (0 <= p.value <= 24):
            return _INVALID
        hour_is_24 = p.value == 24
        tm.add(sc.next().value)
        if not sc.skip_symbol(":"):
            return _INVALID
        p = sc.peek()
        if not p.is_fixed(2) or not (0 <= p.value <= 59) or (hour_is_24 and p.value > 0):
            return _INVALID
        tm.add(sc.next().value)
        if sc.skip_symbol(":"):
            p = sc.peek()
            if not p.is_fixed(2) or not (0 <= p.value <= 59) or (hour_is_24 and p.value > 0):
                return _INVALID
            tm.add(sc.next().value)
            if sc.skip_symbol("."):
                p = sc.peek()
                if p.kind != "num" or (hour_is_24 and p.value > 0):
                    return _INVALID
                tm.add(_read_ms(sc.next()))
        p = sc.peek()
        if p.is_kw_z():
            sc.next()
            tz.set(0)
        elif p.is_sign():
            tz.sign = 1 if sc.next().value == "+" else -1
            p = sc.peek()
            if p.is_fixed(4):
                hm = sc.next().value
                h, mi = hm // 100, hm % 100
                if not (0 <= h <= 23) or not (0 <= mi <= 59):
                    return _INVALID
                tz.hour, tz.minute = h, mi
            else:
                if not p.is_fixed(2) or not (0 <= p.value <= 23):
                    return _INVALID
                tz.hour = sc.next().value
                if not sc.skip_symbol(":"):
                    return _INVALID
                p = sc.peek()
                if not p.is_fixed(2) or not (0 <= p.value <= 59):
                    return _INVALID
                tz.minute = sc.next().value
        if sc.peek().kind != "end":
            return _INVALID
    if tz.empty() and tm.empty():
        tz.set(0)
    day.iso = True
    return _END


_FAST_ISO = re.compile(r"(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z\Z", re.ASCII)


def date_parse(s) -> float:
    """Date.parse(s): milliseconds since the epoch, or NaN."""
    if not isinstance(s, str):
        s = js_string(s)
    m = _FAST_ISO.match(s)
    if m:
        y, mo, d, h, mi, sec = (int(g) for g in m.groups()[:6])
        frac = m.group(7)
        ms = int((frac + "00")[:3]) if frac else 0
        if 1 <= mo <= 12 and 1 <= d <= 31 and mi <= 59 and sec <= 59 and (h <= 23 or (h == 24 and mi == 0 and sec == 0 and ms == 0)):
            return float(make_day(y, mo - 1, d) * MS_PER_DAY + ((h * 60 + mi) * 60 + sec) * 1000 + ms)
    sc = _Scanner(s)
    day, tm, tz = _Day(), _Time(), _Zone()
    tok = _es5(sc, day, tm, tz)
    if tok.kind == "invalid":
        return NAN
    has_read_number = not day.empty()
    while tok.kind != "end":
        if tok.kind == "num":
            has_read_number = True
            n = tok.value
            if sc.skip_symbol(":"):
                if sc.skip_symbol(":"):
                    if not tm.empty():
                        return NAN
                    tm.add(n)
                    tm.add(0)
                else:
                    if not tm.add(n):
                        return NAN
                    if sc.peek().is_symbol("."):
                        sc.next()
            elif sc.skip_symbol(".") and tm.is_expecting(n):
                tm.add(n)
                if sc.peek().kind != "num":
                    return NAN
                ms = _read_ms(sc.next())
                if ms < 0:
                    return NAN
                tm.add_final(ms)
            elif tz.is_expecting(n):
                tz.minute = n
            elif tm.is_expecting(n):
                tm.add_final(n)
                p = sc.peek()
                if not (p.kind == "end" or p.kind == "ws" or p.is_kw_z() or p.is_sign()):
                    return NAN
            else:
                if not day.add(n):
                    return NAN
                sc.skip_symbol("-")
        elif tok.kind == "kw":
            if tok.type == "AMPM" and not tm.empty():
                tm.hour_offset = tok.value
            elif tok.type == "M":
                day.named_month = tok.value
                sc.skip_symbol("-")
            elif tok.type == "TZ" and has_read_number:
                tz.set(tok.value)
            else:
                if has_read_number:
                    return NAN
                if sc.peek().kind == "num":
                    return NAN
        elif tok.is_sign() and (tz.is_utc() or not tm.empty()):
            tz.sign = 1 if tok.value == "+" else -1
            n = 0
            length = 0
            if sc.peek().kind == "num":
                t2 = sc.next()
                length, n = t2.length, t2.value
            has_read_number = True
            if sc.peek().is_symbol(":"):
                tz.hour = n
                tz.minute = None
            elif length in (1, 2):
                tz.hour = n
                tz.minute = 0
            elif length in (3, 4):
                tz.hour = n // 100
                tz.minute = n % 100
            else:
                return NAN
        elif (tok.is_sign() or tok.is_symbol(")")) and has_read_number:
            return NAN
        tok = sc.next()
    dw = day.write()
    tw = tm.write()
    if dw is None or tw is None:
        return NAN
    year, month0, d = dw
    h, mi, sec, ms = tw
    date = make_day(year, month0, d) * MS_PER_DAY + ((h * 60 + mi) * 60 + sec) * 1000 + ms
    offset = tz.offset_seconds()
    if offset is None:
        if abs(date) > MAX_TIME + 864_000_000:
            return NAN
        date = _local_to_utc(date)
    else:
        date -= offset * 1000
        if abs(date) > MAX_TIME:
            return NAN
    if abs(date) > MAX_TIME:
        return NAN
    return float(date)
