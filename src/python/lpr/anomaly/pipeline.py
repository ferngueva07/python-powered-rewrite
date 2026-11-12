"""Anomaly scoring pipeline: train, score, explain, and summarise logins."""
from __future__ import annotations

import math

import numpy as np

from ..jsutil import date_parse, iso_string, is_nan, js_round, number_to_string, round_to, to_fixed
from .features import compute_features
from .isolation_forest import IsolationForest

SIGNALS = ("hour", "days", "location", "failed")


class AnalysisError(Exception):
    """A readable problem with the data being analysed."""


def quantile(values, q: float) -> float:
    if len(values) == 0:
        return 1
    s = sorted(values)
    pos = min(len(s) - 1, max(0, math.ceil(q * len(s)) - 1))
    return s[pos]


def median(values) -> float:
    return quantile(values, 0.5)


def population_stats(rows: list[dict]) -> dict:
    counts = [0] * 24
    for r in rows:
        counts[r["hourOfDay"]] += 1
    n = max(1, len(rows))
    hour_share = [c / n for c in counts]
    # Hour of day encoded as rarity (-log smoothed share), so 03:00 sits far from 09:00 on one axis.
    hour_rarity = [-math.log((c + 1) / (n + 24)) for c in counts]
    mode_hour = hour_share.index(max(hour_share))
    days = [0 if r["daysSinceLastLogin"] is None else r["daysSinceLastLogin"] for r in rows]
    return {
        "hourShare": hour_share,
        "hourRarity": hour_rarity,
        "daysP95": quantile(days, 0.95),
        "baseline": [hour_rarity[mode_hour], median(days), 0, 0],
    }


def to_vector(row: dict, stats: dict) -> list[float]:
    """Model input built from the four features (first login counts as 0 days)."""
    days = row["daysSinceLastLogin"]
    return [
        stats["hourRarity"][row["hourOfDay"]],
        0 if days is None else days,
        row["locationChangeFlag"],
        row["failedAttemptCount"],
    ]


def explain(row: dict, stats: dict, window_minutes) -> tuple[list[str], dict]:
    reasons: list[str] = []
    share = stats["hourShare"][row["hourOfDay"]]
    days = row["daysSinceLastLogin"]
    flags = {
        "hour": share < 0.02,
        "days": days is not None and days >= max(7, stats["daysP95"]),
        "location": row["locationChangeFlag"] == 1,
        "failed": row["failedAttemptCount"] >= 3,
    }
    if flags["hour"]:
        how = "almost no logins happen then" if share < 0.001 else f"only {to_fixed(share * 100, 1)}% of logins"
        reasons.append(f"Unusual hour: {row['hourOfDay']:02d}:00 UTC ({how})")
    if flags["days"] and days is not None:
        reasons.append(f"Returned after {js_round(days)} days away")
    if flags["location"]:
        reasons.append(f"First login ever from {row['location']}")
    if flags["failed"]:
        reasons.append(
            f"{row['failedAttemptCount']} failed attempts within ±{number_to_string(window_minutes)} min — possible brute force"
        )
    return reasons, flags


class TrainedModel:
    def __init__(self, features, forest, matrix, scores, threshold, stats):
        self.features = features
        self.forest = forest
        self.matrix = matrix
        self.scores = scores
        self.threshold = threshold
        self.stats = stats


def train(events: list[dict], params: dict) -> TrainedModel:
    features = compute_features(events, params["windowMinutes"])
    if len(features) == 0:
        raise AnalysisError("No successful logins to analyze.")
    if len(features) == 1:
        raise AnalysisError("At least two successful logins are needed to calculate an anomaly score.")
    stats = population_stats(features)
    X = [to_vector(f, stats) for f in features]
    forest = IsolationForest(n_trees=150, sample_size=256, seed=params["seed"]).fit(X)
    matrix = np.asarray(X, dtype=np.float64)
    scores = [float(s) for s in forest.score_matrix(matrix)]
    return TrainedModel(features, forest, matrix, scores, quantile(scores, 1 - params["contamination"]), stats)


def train_and_score(events: list[dict], params: dict) -> tuple[TrainedModel, list[dict]]:
    """train() plus every row's signal contributions, scored in a single batched pass."""
    features = compute_features(events, params["windowMinutes"])
    if len(features) == 0:
        raise AnalysisError("No successful logins to analyze.")
    if len(features) == 1:
        raise AnalysisError("At least two successful logins are needed to calculate an anomaly score.")
    stats = population_stats(features)
    X = [to_vector(f, stats) for f in features]
    forest = IsolationForest(n_trees=150, sample_size=256, seed=params["seed"]).fit(X)
    matrix = np.asarray(X, dtype=np.float64)
    n = matrix.shape[0]
    blocks = [matrix]
    for d in range(len(SIGNALS)):
        ablated = matrix.copy()
        ablated[:, d] = stats["baseline"][d]
        blocks.append(ablated)
    all_scores = forest.score_matrix(np.vstack(blocks))
    base = all_scores[:n]
    scores = [float(v) for v in base]
    contributions = [dict() for _ in range(n)]
    for d, key in enumerate(SIGNALS):
        drop = (base - all_scores[(d + 1) * n:(d + 2) * n]).tolist()
        for i, v in enumerate(drop):
            contributions[i][key] = round_to(max(0.0, v))
    model = TrainedModel(features, forest, matrix, scores, quantile(scores, 1 - params["contamination"]), stats)
    return model, contributions


def with_threshold(model: TrainedModel, contamination: float) -> TrainedModel:
    """Same trained forest, new contamination threshold."""
    return TrainedModel(model.features, model.forest, model.matrix, model.scores,
                        quantile(model.scores, 1 - contamination), model.stats)


def contributions_matrix(model: TrainedModel, matrix: np.ndarray, scores) -> list[dict]:
    """Ablation: how much each score drops when one feature is reset to a typical value."""
    scores = np.asarray(scores, dtype=np.float64)
    out = [dict() for _ in range(matrix.shape[0])]
    for d, key in enumerate(SIGNALS):
        ablated = matrix.copy()
        ablated[:, d] = model.stats["baseline"][d]
        drop = scores - model.forest.score_matrix(ablated)
        for i, v in enumerate(drop.tolist()):
            out[i][key] = round_to(max(0.0, v))
    return out


def score_row(model: TrainedModel, row: dict, window_minutes, score=None, contributions=None) -> dict:
    vec = to_vector(row, model.stats)
    s = model.forest.score(vec) if score is None else score
    if contributions is None:
        contributions = contributions_matrix(model, np.asarray([vec], dtype=np.float64), [s])[0]
    reasons, flags = explain(row, model.stats, window_minutes)
    return {
        **row,
        "score": round_to(s),
        "isAnomaly": s >= model.threshold,
        "contributions": contributions,
        "reasons": reasons,
        "flags": flags,
    }


def _locale_key(s: str):
    """Approximates String.prototype.localeCompare ordering for user names."""
    folded = s.casefold()
    primary = tuple((0 if not c.isalnum() else 1 if c.isdigit() else 2, c) for c in folded)
    return primary, tuple(c.isupper() for c in s), s


def build_profiles(rows: list[dict]) -> list[dict]:
    by_user: dict[str, list[dict]] = {}
    for r in rows:
        by_user.setdefault(r["userId"], []).append(r)
    profiles = [
        {
            "userId": user_id,
            "logins": len(items),
            "knownLocations": list(dict.fromkeys(r["location"] for r in items)),
            "typicalHour": median([r["hourOfDay"] for r in items]),
            "lastLogin": items[-1]["timestamp"],
        }
        for user_id, items in by_user.items()
    ]
    profiles.sort(key=lambda p: _locale_key(p["userId"]))
    return profiles


def _bucketize(rows, labels, key_of):
    buckets = {b: {"bucket": b, "normal": 0, "flagged": 0} for b in labels}
    for r in rows:
        b = buckets.get(key_of(r))
        if b is None:
            continue
        if r["isAnomaly"]:
            b["flagged"] += 1
        else:
            b["normal"] += 1
    return [buckets[label] for label in labels]


DAY_BUCKETS = ["first", "<1", "1-2", "3-7", "8-14", "15-30", "31-60", "60+"]


def _day_bucket(d):
    if d is None:
        return "first"
    if d < 1:
        return "<1"
    if d < 3:
        return "1-2"
    if d < 8:
        return "3-7"
    if d < 15:
        return "8-14"
    if d < 31:
        return "15-30"
    if d <= 60:
        return "31-60"
    return "60+"


FAILED_BUCKETS = ["0", "1", "2", "3-5", "6-10", "11+"]


def _failed_bucket(n):
    if n <= 2:
        return str(n)
    if n <= 5:
        return "3-5"
    if n <= 10:
        return "6-10"
    return "11+"


def score_all(model: TrainedModel) -> list[dict]:
    return contributions_matrix(model, model.matrix, model.scores)


def analyze(events: list[dict], params: dict, model: TrainedModel | None = None, contributions=None) -> dict:
    if model is None:
        model, contributions = train_and_score(events, params)
    elif contributions is None:
        contributions = score_all(model)
    window = params["windowMinutes"]
    rows = [score_row(model, f, window, model.scores[i], contributions[i]) for i, f in enumerate(model.features)]

    by_label: dict[str, dict] = {}
    injected_total = 0
    injected_caught = 0
    for r in rows:
        if not r["label"]:
            continue
        entry = by_label.setdefault(r["label"], {"total": 0, "caught": 0})
        entry["total"] += 1
        injected_total += 1
        if r["isAnomaly"]:
            entry["caught"] += 1
            injected_caught += 1

    return {
        "summary": {
            "totalEvents": len(events),
            "successfulLogins": len(rows),
            "failedAttempts": sum(1 for e in events if not e["success"]),
            "users": len({r["userId"] for r in rows}),
            "flagged": sum(1 for r in rows if r["isAnomaly"]),
            "threshold": round_to(model.threshold),
            "newLocationLogins": sum(1 for r in rows if r["locationChangeFlag"] == 1),
            "burstLogins": sum(1 for r in rows if r["failedAttemptCount"] >= 3),
            "injected": {"total": injected_total, "caught": injected_caught},
            "byLabel": by_label,
        },
        "rows": rows,
        "users": build_profiles(model.features),
        "distributions": {
            "hours": _bucketize(rows, [str(h) for h in range(24)], lambda r: str(r["hourOfDay"])),
            "days": _bucketize(rows, DAY_BUCKETS, lambda r: _day_bucket(r["daysSinceLastLogin"])),
            "failed": _bucketize(rows, FAILED_BUCKETS, lambda r: _failed_bucket(r["failedAttemptCount"])),
            "location": _bucketize(rows, ["Known location", "New location"],
                                   lambda r: "New location" if r["locationChangeFlag"] else "Known location"),
        },
        "params": params,
    }


def _probe_events(probe: dict, window_minutes, t: float, tz_offset=None) -> list[dict]:
    spacing = min(20_000, (window_minutes * 60_000) / (probe["failedAttempts"] + 1))
    extra = []
    for i in range(int(probe["failedAttempts"])):
        e = {
            "id": f"probe_fail_{i}",
            "userId": probe["userId"],
            "timestamp": iso_string(t - (i + 1) * spacing),
            "location": probe["location"],
            "success": False,
            "label": None,
        }
        if tz_offset is not None:
            e["tzOffsetMin"] = tz_offset
        extra.append(e)
    last = {
        "id": "probe",
        "userId": probe["userId"],
        "timestamp": iso_string(t),
        "location": probe["location"],
        "success": True,
        "label": None,
    }
    if tz_offset is not None:
        last["tzOffsetMin"] = tz_offset
    extra.append(last)
    return extra


def score_probe(events: list[dict], params: dict, probe: dict, model: TrainedModel | None = None) -> dict:
    """Scores a hypothetical login against the model trained on `events`, using the user's real history."""
    if model is None:
        model = train(events, params)
    t = date_parse(probe["timestamp"])
    if is_nan(t):
        raise AnalysisError("Invalid timestamp")
    user_events = [e for e in events if e["userId"] == probe["userId"]]
    extra = _probe_events(probe, params["windowMinutes"], t)
    feat = next((r for r in compute_features(user_events + extra, params["windowMinutes"]) if r["eventId"] == "probe"), None)
    if feat is None:
        raise AnalysisError("Could not compute features for this login")
    row = score_row(model, feat, params["windowMinutes"])
    below = sum(1 for s in model.scores if s < row["score"])
    profiles = build_profiles([f for f in model.features if f["userId"] == probe["userId"]])
    return {
        "row": row,
        "threshold": round_to(model.threshold),
        "profile": profiles[0] if profiles else None,
        "scorePercentile": round_to((below / len(model.scores)) * 100, 1),
    }


MIN_HISTORY = 3


def _with_status(row: dict, prior_logins: int) -> dict:
    if row["flags"]["failed"]:
        status = "suspicious"
    elif prior_logins < MIN_HISTORY:
        status = "learning"
    elif row["isAnomaly"]:
        status = "suspicious"
    else:
        status = "normal"
    return {**row, "priorLogins": prior_logins, "status": status}


def score_user_history(model: TrainedModel, user_events: list[dict], window_minutes) -> list[dict]:
    """Scores every successful login in one user's history against an already-trained model."""
    return [_with_status(score_row(model, f, window_minutes), i)
            for i, f in enumerate(compute_features(user_events, window_minutes))]


def score_hypothetical(model: TrainedModel, user_events: list[dict], probe: dict, window_minutes) -> dict:
    """Scores a hypothetical login (with failed attempts just before it) against a user's real history."""
    t = date_parse(probe["timestamp"])
    if is_nan(t):
        raise AnalysisError("Invalid timestamp")
    extra = _probe_events(probe, window_minutes, t, probe.get("tzOffsetMin"))
    hit = next((r for r in score_user_history(model, user_events + extra, window_minutes) if r["eventId"] == "probe"), None)
    if hit is None:
        raise AnalysisError("Could not compute features for this login")
    return hit
