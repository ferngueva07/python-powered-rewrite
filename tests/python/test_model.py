"""Model and demo-data rules: values pinned to the original JavaScript app's output."""
import unittest

import _paths  # noqa: F401
from lpr import api
from lpr.anomaly.csv_import import LoginImportError, parse_login_csv
from lpr.anomaly.pipeline import analyze, score_probe
from lpr.anomaly.sample_data import events_to_csv, generate_sample_events
from lpr.jsutil import date_parse, iso_string, js_round, mulberry32, to_fixed

PARAMS = {"contamination": 0.08, "windowMinutes": 30, "seed": 7}


class Model(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.events = generate_sample_events(7)
        cls.result = analyze(cls.events, PARAMS)

    def test_demo_dataset_is_the_same_as_the_original(self):
        self.assertEqual(len(self.events), 2498)
        self.assertEqual(self.events[0]["timestamp"], "2026-08-12T08:12:00.000Z")
        self.assertEqual(self.events[-1]["id"], "evt_02498")

    def test_default_settings_flag_the_same_logins(self):
        s = self.result["summary"]
        self.assertEqual((s["successfulLogins"], s["failedAttempts"], s["users"]), (2388, 110, 28))
        self.assertEqual(s["flagged"], 192)
        self.assertEqual(s["threshold"], 0.5269)
        self.assertEqual(s["injected"], {"total": 18, "caught": 18})

    def test_contamination_sets_the_share_flagged(self):
        low = analyze(self.events, {**PARAMS, "contamination": 0.02})["summary"]["flagged"]
        high = analyze(self.events, {**PARAMS, "contamination": 0.2})["summary"]["flagged"]
        self.assertLess(low, 192)
        self.assertGreater(high, 192)

    def test_password_burst_preset_is_flagged_as_brute_force(self):
        probe = score_probe(self.events, PARAMS, {"userId": "chloe.park", "timestamp": "2026-11-10T09:00:00.000Z",
                                                  "location": "Chicago, US", "failedAttempts": 7})
        self.assertTrue(probe["row"]["flags"]["failed"])
        self.assertTrue(any("7 failed attempts within ±30 min" in r for r in probe["row"]["reasons"]))

    def test_csv_round_trip(self):
        back = parse_login_csv(events_to_csv(self.events))
        self.assertEqual([e["timestamp"] for e in back], [e["timestamp"] for e in self.events])

    def test_csv_import_errors(self):
        with self.assertRaisesRegex(LoginImportError, "header row"):
            parse_login_csv("user_id,timestamp,location,success\n")
        with self.assertRaisesRegex(LoginImportError, "limited to 50,000 rows"):
            parse_login_csv("user_id,timestamp,location,success\n" + "a,2026-01-01T00:00:00Z,x,true\n" * 50_001)

    def test_import_falls_back_to_login_logs(self):
        text = "Jan 15 03:00:01 h sshd[1]: Accepted password for alice from 203.0.113.9 port 22 ssh2\n"
        self.assertEqual(api.import_login_events(text, "auth.log")[0]["userId"], "alice")
        with self.assertRaisesRegex(LoginImportError, "CSV header must include"):
            api.import_login_events("hello,world\n1,2", "x.csv")

    def test_javascript_compatible_helpers(self):
        self.assertEqual(js_round(2.5), 3)
        self.assertEqual(js_round(-2.5), -2)
        self.assertEqual(to_fixed(1.25, 1), "1.3")
        self.assertEqual(iso_string(0), "1970-01-01T00:00:00.000Z")
        self.assertEqual(date_parse("10 Nov 2026 10:00:00 +0000"), 1794304800000.0)
        self.assertEqual(date_parse("2026-01-01"), 1767225600000.0)
        rng = mulberry32(7)
        self.assertEqual(rng(), 0.011704753153026104)  # same as the JavaScript generator


if __name__ == "__main__":
    unittest.main()
