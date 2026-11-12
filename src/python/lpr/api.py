"""Entry points the web page calls. Inputs and outputs are JSON text."""
from __future__ import annotations

import json

from .anomaly import pipeline
from .anomaly.csv_import import parse_login_csv
from .anomaly.sample_data import events_to_csv, generate_sample_events
from .scanner.log_parsers import parse_login_log
from .scanner.scan import scan_uploads as _scan_uploads


def _ok(value) -> str:
    return json.dumps({"ok": True, "value": value}, separators=(",", ":"), allow_nan=False)


def _fail(err: Exception) -> str:
    return json.dumps({"ok": False, "error": str(err) or "Analysis could not be completed."})


def _guard(fn):
    def wrapper(*args):
        try:
            return _ok(fn(*args))
        except Exception as err:  # noqa: BLE001 - surfaced to the page as a readable message
            return _fail(err)
    wrapper.__name__ = fn.__name__
    return wrapper


class _ModelCache:
    """Reuses the trained forest while only the contamination slider changes."""

    def __init__(self):
        self.key = None
        self.model = None
        self.contributions = None

    def get(self, events_json: str, events: list, params: dict):
        key = (events_json, params["windowMinutes"], params["seed"])
        if self.key != key:
            self.model, self.contributions = pipeline.train_and_score(events, params)
            self.key = key
        return pipeline.with_threshold(self.model, params["contamination"]), self.contributions


_cache = _ModelCache()


@_guard
def sample_events(seed):
    return generate_sample_events(seed)


@_guard
def to_csv(events_json: str):
    return events_to_csv(json.loads(events_json))


@_guard
def analyze(events_json: str, params_json: str):
    events = json.loads(events_json)
    params = json.loads(params_json)
    if not events:
        return None
    model, contributions = _cache.get(events_json, events, params)
    return pipeline.analyze(events, params, model, contributions)


@_guard
def score_probe(events_json: str, params_json: str, probe_json: str):
    events = json.loads(events_json)
    params = json.loads(params_json)
    model, _ = _cache.get(events_json, events, params)
    return pipeline.score_probe(events, params, json.loads(probe_json), model)


def import_login_events(text: str, file_name: str) -> list:
    """The overview's Import log button: a login CSV first, then any supported login log."""
    try:
        return parse_login_csv(text)
    except Exception as csv_err:
        log = parse_login_log(text, file_name)
        if not log or not any(e["success"] for e in log["events"]):
            raise csv_err
        return log["events"]


@_guard
def import_login_text(text: str, file_name: str):
    return import_login_events(text, file_name)


def _js_value(v):
    """JavaScript null arrives as pyodide.ffi.jsnull; treat it like undefined."""
    try:
        from pyodide.ffi import jsnull
    except ImportError:
        return v
    return None if v is jsnull else v


@_guard
def scan_uploads(files_proxy, params_json: str):
    files = []
    for f in files_proxy:
        data = _js_value(getattr(f, "data", None))
        error = _js_value(getattr(f, "error", None))
        files.append({
            "name": str(f.name),
            "size": int(f.size),
            "data": data.to_bytes() if data is not None else None,
            "error": None if error is None else str(error),
        })
    return _scan_uploads(files, json.loads(params_json))
