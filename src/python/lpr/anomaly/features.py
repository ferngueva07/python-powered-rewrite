"""Turns raw login attempts into the four model features."""
from __future__ import annotations

from bisect import bisect_left, bisect_right

from ..jsutil import date_parse, js_round, trim, utc_hours

DAY_MS = 86_400_000
MINUTE_MS = 60_000


def hour_of_day(t_ms: float, tz_offset_min: float = 0) -> int:
    """Feature 1: hour of day (0-23) on the user's own clock (UTC when no offset is known)."""
    return utc_hours(t_ms - tz_offset_min * MINUTE_MS)


def normalize_location(location: str) -> str:
    return trim(location).lower()


def count_in_window(sorted_times: list[float], start: float, end: float) -> int:
    """Number of values in a sorted list that fall within [start, end]."""
    return bisect_right(sorted_times, end) - bisect_left(sorted_times, start)


def compute_features(events: list[dict], window_minutes: float = 30) -> list[dict]:
    """One feature row per successful login.

    - hourOfDay: hour of the login on the user's own clock.
    - daysSinceLastLogin: days since the same user's previous successful login.
    - locationChangeFlag: 1 if the user never logged in successfully from this location.
    - failedAttemptCount: same-user failed attempts within +/- window minutes.
    """
    window_ms = window_minutes * MINUTE_MS
    by_user: dict[str, list] = {}
    for e in events:
        by_user.setdefault(e["userId"], []).append((date_parse(e["timestamp"]), e))

    rows: list[tuple[float, dict]] = []
    for user_id, items in by_user.items():
        items.sort(key=lambda p: p[0])
        fail_times = [t for t, e in items if not e["success"]]
        last_success = None
        seen: set[str] = set()
        for t, e in items:
            if not e["success"]:
                continue
            loc = normalize_location(e["location"])
            days = None if last_success is None else js_round(((t - last_success) / DAY_MS) * 100) / 100
            flag = 1 if seen and loc not in seen else 0
            tz = e.get("tzOffsetMin")
            tz = 0 if tz is None else tz
            rows.append((t, {
                "eventId": e["id"],
                "userId": user_id,
                "timestamp": e["timestamp"],
                "location": e["location"],
                "label": e.get("label"),
                "tzOffsetMin": tz,
                "hourOfDay": hour_of_day(t, tz),
                "daysSinceLastLogin": days,
                "locationChangeFlag": flag,
                "failedAttemptCount": count_in_window(fail_times, t - window_ms, t + window_ms),
            }))
            last_success = t
            seen.add(loc)

    rows.sort(key=lambda p: p[0])
    return [r for _, r in rows]
