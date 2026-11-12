"""Scanner and model rules (ported from the original scripts/tests/scanner.test.ts)."""
import json
import unittest

import _paths  # noqa: F401
from lpr.anomaly.pipeline import AnalysisError, analyze
from lpr.scanner.content_scan import MAX_SCAN_BYTES, scan_content
from lpr.scanner.log_parsers import parse_login_log
from lpr.scanner.log_records import read_log_records
from lpr.scanner.scan import login_heuristics, scan_file, scan_uploads
from lpr.scanner.security_log import scan_security_log

PARAMS = {"contamination": 0.08, "windowMinutes": 30, "seed": 7}


def ids(findings):
    return [f["ruleId"] for f in findings]


class ScannerRules(unittest.TestCase):
    def test_scans_large_files_using_only_the_bounded_prefix(self):
        report = scan_file("unknown.ext", 150 * 1024 * 1024, b"password=examplepassword")["report"]
        self.assertIsNone(report["error"])
        self.assertTrue(report["truncated"])
        self.assertIsNone(report["sha256"])
        self.assertIn("password-assignment", ids(report["findings"]))

    def test_only_first_20_mib_are_read(self):
        self.assertEqual(MAX_SCAN_BYTES, 20 * 1024 * 1024)
        data = b"x" * MAX_SCAN_BYTES + b"\npassword=examplepassword"
        report = scan_file("big.txt", len(data), data)["report"]
        self.assertNotIn("password-assignment", ids(report["findings"]))

    def test_surfaces_read_errors_instead_of_claiming_files_are_clean(self):
        report = scan_file("broken.bin", 1, read_error="Read denied")["report"]
        self.assertEqual(report["error"], "Read denied")

    def test_scans_binary_data_with_a_credential_followed_by_null_bytes(self):
        data = b"password=examplepassword" + b"\x00" * (1024 * 1024 - 24)
        self.assertIn("password-assignment", ids(scan_content("unknown.bin", data)["findings"]))

    def test_reports_records_skipped_after_the_parser_limit(self):
        row = '{"user":"alice","timestamp":"2026-01-01T00:00:00Z","success":true}'
        parsed = parse_login_log("\n".join([row] * 50_001), "log.jsonl")
        self.assertEqual(len(parsed["events"]), 50_000)
        self.assertEqual(parsed["skipped"], 1)

    def test_one_successful_login_cannot_be_scored(self):
        events = [{"id": "1", "userId": "alice", "timestamp": "2026-01-01T00:00:00Z", "location": "here", "success": True, "label": None}]
        with self.assertRaisesRegex(AnalysisError, "At least two successful logins"):
            analyze(events, PARAMS)

    def test_reports_analysis_failure_for_a_single_parsed_login(self):
        data = b"user_id,timestamp,location,success\nalice,2026-01-01T00:00:00Z,here,true"
        scan = scan_uploads([{"name": "log.csv", "size": len(data), "data": data}], PARAMS)
        self.assertRegex(scan["analysisError"] or "", "At least two successful logins")
        self.assertIsNone(scan["analysis"])
        self.assertEqual(scan["flaggedLogins"], [])

    def test_parses_nested_identity_outcomes_without_turning_network_telemetry_into_logins(self):
        record = {"createdDateTime": "2026-01-01T00:00:00Z", "userPrincipalName": "person@example.test",
                  "ipAddress": "192.0.2.1", "status": {"errorCode": 0}}
        log = parse_login_log(json.dumps({"value": [record, {**record, "status": {"errorCode": 50126}}]}), "renamed.data")
        self.assertEqual([[e["userId"], e["location"], e["success"]] for e in log["events"]],
                         [["person@example.test", "192.0.2.1", True], ["person@example.test", "192.0.2.1", False]])
        network = {"@timestamp": record["createdDateTime"], "event": {"category": "network", "outcome": "success"},
                   "user": {"name": "person"}, "source": {"ip": "192.0.2.1"}}
        self.assertIsNone(parse_login_log(json.dumps(network), "network.json"))

    def test_counts_only_auditd_login_records_not_duplicate_user_err_messages(self):
        log = parse_login_log("\n".join([
            "type=USER_LOGIN msg=audit(1705329003.100:1): msg='op=login acct=\"someone\" addr=192.0.2.7 res=failed'",
            "type=USER_ERR msg=audit(1705329003.300:2): msg='op=PAM:bad_ident acct=\"someone\" addr=192.0.2.7 res=failed'",
        ]), "audit.data")
        self.assertEqual(log["format"], "auditd")
        self.assertEqual(len(log["events"]), 1)
        self.assertEqual(log["events"][0]["userId"], "someone")
        self.assertEqual(log["events"][0]["location"], "192.0.2.7")
        self.assertEqual(log["skipped"], 0)

    def test_preserves_existing_field_aliases_alongside_nested_identity_records(self):
        records = [
            {"userPrincipalName": "nested", "createdDateTime": "2026-01-01T00:00:00Z", "status": {"errorCode": 0}, "ipAddress": "192.0.2.1"},
            {"email": "legacy", "dateandtime": "2026-01-01T00:00:01Z", "outcome": "success", "country": "elsewhere"},
            {"EventID": 4625, "TimeCreated": "2026-01-01T00:00:02Z", "Message": "Account Name: windows-user\nSource Network Address: 192.0.2.2"},
        ]
        log = parse_login_log(json.dumps(records), "mixed.json")
        self.assertEqual([[e["userId"], e["location"], e["success"]] for e in log["events"]],
                         [["nested", "192.0.2.1", True], ["legacy", "elsewhere", True], ["windows-user", "192.0.2.2", False]])
        self.assertEqual(log["skipped"], 0)

    def test_finds_sign_in_travel_from_coordinates(self):
        records = [
            {"createdDateTime": "2026-01-01T00:00:00Z", "userPrincipalName": "traveler", "status": {"errorCode": 0},
             "location": {"geoCoordinates": {"latitude": 0, "longitude": 0}}},
            {"createdDateTime": "2026-01-01T00:10:00Z", "userPrincipalName": "traveler", "status": {"errorCode": 0},
             "location": {"geoCoordinates": {"latitude": 50, "longitude": 50}}},
        ]
        finding = next(f for f in scan_security_log(json.dumps(records)) if f["ruleId"] == "impossible-travel")
        self.assertEqual(finding["count"], 1)
        self.assertEqual(len(finding["samples"]), 1)
        records[1]["createdDateTime"] = "2026-01-05T00:00:00Z"
        self.assertEqual(scan_security_log(json.dumps(records)), [])
        records[1]["createdDateTime"] = "2026-01-01T00:10:00Z"
        records[1]["status"]["errorCode"] = 50126
        self.assertEqual(scan_security_log(json.dumps(records)), [])

    def test_burst_detection_is_source_specific_time_bounded_and_counts_distinct_ports(self):
        def make(ports, spaced=False, mixed=False):
            return "\n".join(
                f"<134>1 2026-01-01T00:{(i * 11 if spaced else i):02d}:00Z fw kernel SRC=192.0.2.{i if mixed else 1} DST=10.0.0.1 DPT={p}"
                for i, p in enumerate(ports))
        self.assertIn("network-port-scan", ids(scan_security_log(make([22, 23, 80, 443, 445]))))
        self.assertEqual(scan_security_log(make([22, 22, 22, 22, 22])), [])
        self.assertEqual(scan_security_log(make([22, 23, 80, 443, 445], spaced=True)), [])
        self.assertEqual(scan_security_log(make([22, 23, 80, 443, 445], mixed=True)), [])

    def test_does_not_correlate_old_failures_or_flag_a_privileged_login_alone(self):
        failed = [{"id": str(i), "userId": f"person{i}", "timestamp": f"2026-01-01T00:00:{i:02d}Z",
                   "location": "192.0.2.1", "success": False, "label": None} for i in range(10)]
        success = {**failed[0], "id": "success", "userId": "root", "timestamp": "2026-01-01T00:10:09.000Z", "success": True}
        self.assertNotIn("brute-force-success", ids(login_heuristics(failed + [success])))
        self.assertNotIn("privileged-login", ids(login_heuristics(failed + [success])))
        self.assertEqual(login_heuristics([success]), [])
        success["timestamp"] = "2026-01-01T00:05:00Z"
        self.assertIn("brute-force-success", ids(login_heuristics(failed + [success])))

    def test_decodes_escaped_payloads_and_reports_the_original_record(self):
        record = {"request": "/?id=1%2520UNION%2520SELECT%25201", "client": {"ipAddress": "192.0.2.44"}}
        findings = scan_security_log(json.dumps({"Records": [record]}, indent=2))
        sql = next(f for f in findings if f["ruleId"] == "log-sql-attack")
        self.assertEqual(sql["samples"][0]["record"], 1)
        self.assertRegex(sql["samples"][0]["text"], r"(?i)192\.0\.2\.44.*UNION SELECT")

    def test_does_not_promote_resolved_or_low_priority_product_findings(self):
        findings = [
            {"ProductArn": "securityhub", "Severity": {"Label": "HIGH"}, "Title": "Historic alert", "Workflow": {"Status": "RESOLVED"}},
            {"arn": "arn:aws:guardduty:region:account:finding/1", "severity": 2, "title": "Routine probe"},
            {"threatInfo": {"confidenceLevel": "malicious", "mitigationStatus": "marked_as_benign"}},
            {"type": "PACKAGE_VULNERABILITY", "severity": "LOW", "status": "ACTIVE", "title": "Low risk vulnerability"},
        ]
        self.assertEqual(scan_security_log(json.dumps(findings)), [])

    def test_retains_csv_multiline_records_and_xml_evidence_locations(self):
        csv = read_log_records('timestamp,user,message\n2026-01-01,person,"line one,\nline two"\n')
        self.assertEqual(len(csv), 1)
        self.assertEqual(csv[0]["fields"]["message"], "line one,\nline two")
        self.assertEqual(csv[0]["record"], 2)
        xml = read_log_records('<Events>\n<Event><System><EventID>4625</EventID></System><EventData><Data Name="TargetUserName">a&amp;b</Data></EventData></Event>\n</Events>')
        self.assertEqual(xml[0]["line"], 2)
        self.assertEqual(xml[0]["fields"]["targetusername"], "a&b")


if __name__ == "__main__":
    unittest.main()
