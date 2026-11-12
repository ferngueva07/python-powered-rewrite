"""Deterministic demo dataset with a few planted unusual logins."""
from __future__ import annotations

import math
import re

from ..jsutil import date_utc, iso_string, js_round, mulberry32

HOME_CITIES = [
    "Chicago, US", "Austin, US", "Denver, US", "Toronto, CA",
    "London, UK", "Madrid, ES", "Mexico City, MX", "Berlin, DE",
]
FOREIGN_CITIES = [
    "Lagos, NG", "Bucharest, RO", "Shenzhen, CN", "São Paulo, BR",
    "Minsk, BY", "Jakarta, ID", "Hanoi, VN",
]
NAMES = [
    "ana.ruiz", "ben.okafor", "chloe.park", "dev.patel", "elena.rossi", "farid.haddad",
    "grace.kim", "hugo.martin", "isla.nguyen", "jonah.weiss", "kara.singh", "liam.obrien",
    "maya.cohen", "nico.silva", "olivia.berg", "pablo.diaz", "quinn.taylor", "rosa.lopez",
    "sam.ito", "tara.walsh", "uma.reddy", "victor.hale", "wren.adams", "xavier.cruz",
    "yara.nasser", "zoe.fischer", "aiden.moore", "bea.santos",
]

# Fixed end date keeps the sample deterministic for a given seed.
SAMPLE_END = date_utc(2026, 10, 10)
DAYS = 90
DAY_MS = 86_400_000


def generate_sample_events(seed=7) -> list[dict]:
    rng = mulberry32(seed * 7919 + 13)

    def pick(arr):
        return arr[math.floor(rng() * len(arr))]

    def gauss():
        u = 1 - rng()
        v = rng()
        return math.sqrt(-2 * math.log(u)) * math.cos(2 * math.pi * v)

    start = SAMPLE_END - DAYS * DAY_MS
    raw: list[tuple[float, dict]] = []

    def push(user_id, t, location, success, label):
        raw.append((t, {"userId": user_id, "timestamp": iso_string(t), "location": location,
                        "success": success, "label": label}))

    profiles = []
    for i, user_id in enumerate(NAMES):
        r = rng()
        if r < 0.6:
            peak = 7.5 + rng() * 2.5
        elif r < 0.9:
            peak = 12 + rng() * 4
        else:
            peak = 18 + rng() * 3
        home = pick(HOME_CITIES)
        second = None
        if rng() < 0.35:
            second = pick(HOME_CITIES)
            if second == home:
                second = None
        dormant = i in (3, 17)
        sd = 0.7 + rng() * 1.1
        p_daily = 0.97 if dormant else 0.55 + rng() * 0.4
        gap = {"from": 18, "to": 18 + 55 + math.floor(rng() * 12)} if dormant else None
        profiles.append({"userId": user_id, "home": home, "second": second, "peak": peak,
                         "sd": sd, "pDaily": p_daily, "gap": gap})

    for p in profiles:
        mark_return = False
        for d in range(DAYS):
            gap = p["gap"]
            if gap and gap["from"] <= d < gap["to"]:
                mark_return = True
                continue
            if rng() >= p["pDaily"]:
                continue
            sessions = 2 if rng() < 0.2 else 1
            for s in range(sessions):
                hour = min(22, max(6, js_round(p["peak"] + gauss() * p["sd"] + s * 4)))
                t = start + d * DAY_MS + hour * 3_600_000 + math.floor(rng() * 60) * 60_000
                loc = p["second"] if (p["second"] and rng() < 0.12) else p["home"]
                if rng() < 0.03:
                    typos = 1 if rng() < 0.85 else 2
                    for k in range(typos, 0, -1):
                        push(p["userId"], t - k * 45_000, loc, False, None)
                push(p["userId"], t, loc, True, "dormant_return" if mark_return else None)
                mark_return = False

    def random_day_time(hour):
        day = 30 + math.floor(rng() * (DAYS - 31))
        minute = math.floor(rng() * 60)
        return start + day * DAY_MS + hour * 3_600_000 + minute * 60_000

    for _ in range(6):
        p = pick(profiles)
        hour = 1 + math.floor(rng() * 4)
        push(p["userId"], random_day_time(hour), p["home"], True, "odd_hour")
    for _ in range(5):
        p = pick(profiles)
        t = random_day_time(js_round(p["peak"]))
        push(p["userId"], t, pick(FOREIGN_CITIES), True, "new_location")
    for _ in range(5):
        p = pick(profiles)
        loc = pick(FOREIGN_CITIES)
        t = random_day_time(math.floor(rng() * 24))
        attempts = 6 + math.floor(rng() * 9)
        for k in range(attempts, 0, -1):
            push(p["userId"], t - k * (20_000 + math.floor(rng() * 40_000)), loc, False, None)
        push(p["userId"], t, loc, True, "brute_force")

    raw.sort(key=lambda pair: pair[0])
    return [{**e, "id": f"evt_{i + 1:05d}"} for i, (_, e) in enumerate(raw)]


_NEEDS_QUOTES = re.compile(r'[",\n]')


def _csv_cell(value: str) -> str:
    return '"' + value.replace('"', '""') + '"' if _NEEDS_QUOTES.search(value) else value


def events_to_csv(events: list[dict]) -> str:
    lines = ["user_id,timestamp,location,success"]
    for e in events:
        lines.append(",".join(_csv_cell(v) for v in (e["userId"], e["timestamp"], e["location"],
                                                      "true" if e["success"] else "false")))
    return "\n".join(lines)
