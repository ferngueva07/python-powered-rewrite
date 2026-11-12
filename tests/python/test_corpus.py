"""Regression checks against the LogTriage security-log sample corpus (ported from corpus.test.ts).

Fixtures: LogTriage (https://logtriage.app), CC BY 4.0, pinned to commit 7418e5d.
"""
import hashlib
import json
import unittest

from _paths import FIXTURES
from lpr.scanner.scan import scan_file

EXPECTED_BY_FORMAT = {
    "aws-alb": ["attack-tool-agent"], "apache-error": ["sensitive-path-probe"], "auditd": ["brute-force-success"],
    "auth-log": ["brute-force", "password-spray"], "aws-config": ["security-control-change"],
    "aws-waf": ["log4shell", "log-sql-attack"], "azure-activity": ["cloud-privilege-change"],
    "azure-ad-signin": ["risky-signin"], "carbonblack": ["mimikatz", "ps-encoded"],
    "cef": ["security-product-alert", "log-sql-attack"], "cisco-asa": ["security-product-alert"],
    "cloudflare": ["sensitive-path-probe", "log-sql-attack"], "cloudtrail": ["cloud-privilege-change"],
    "crowdstrike": ["mimikatz"], "duo": ["mfa-fraud-bypass"], "ecs": ["mimikatz"], "f5-asm": ["log-sql-attack"],
    "fortigate": ["security-product-alert"], "gcp-audit": ["cloud-privilege-change"],
    "github-audit": ["security-control-change"], "google-workspace": ["cloud-privilege-change", "security-control-change"],
    "guardduty": ["security-product-alert"], "haproxy": ["sensitive-path-probe"], "iis": ["path-traversal"],
    "aws-inspector": ["active-high-vulnerability"], "jumpcloud": ["security-control-change"],
    "juniper-srx": ["repeated-network-denials"], "k8s-audit": ["k8s-secret-access"], "leef": ["log-sql-attack"],
    "m365": ["mail-forwarding-rule"], "mdatp": ["security-product-alert"], "mysql": ["log-sql-attack"],
    "nginx-error": ["sensitive-path-probe"], "azure-nsg": ["network-port-scan"],
    "okta": ["password-spray", "password-spray-success"], "panos": ["security-product-alert"],
    "postgresql": ["log-sql-attack"], "aws-s3-access": ["s3-anonymous-read"],
    "aws-securityhub": ["security-product-alert"], "sentinelone": ["security-product-alert"],
    "slack-audit": ["cloud-privilege-change"], "snort": ["security-product-alert"],
    "suricata": ["security-product-alert"], "syslog": ["network-port-scan"], "sysmon": ["lsass-access", "ps-encoded"],
    "traefik": ["attack-tool-agent"], "vpc-flow": ["network-port-scan"], "wazuh": ["security-product-alert"],
    "zeek": ["log-sql-attack"],
}
EXPECTED_BY_FILE = {
    "azure_impossible_travel.json": ["impossible-travel", "conditional-access-bypass"],
    "azure_injection_downgrade.json": ["legacy-auth-no-mfa", "log-prompt-injection"],
    "generic_api_scraper.csv": ["rapid-api-enumeration"],
    "generic_signup_mailbox_aliases.csv": ["mailbox-alias-burst"],
    "nginx_credential_stuffing.log": ["repeated-auth-failures"],
    "nginx_prompt_injection.log": ["log-prompt-injection", "repeated-auth-failures"],
    "nginx_recon_sweep.log": ["sensitive-path-probe"],
    "nginx_sqli_exfiltration.log": ["log-sql-attack"],
    "windows_brute_force.xml": ["brute-force", "password-spray"],
    "windows_kerberoasting.xml": ["kerberos-roasting"],
}


class Corpus(unittest.TestCase):
    def test_corpus(self):
        manifest = json.loads((FIXTURES / "manifest.json").read_text())
        self.assertEqual(len(manifest), 114)
        self.assertEqual(sum(1 for s in manifest if s["label"] == "malicious"), 60)
        for sample in manifest:
            with self.subTest(sample=sample["path"]):
                data = (FIXTURES / sample["path"]).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), sample["sha256"], "Fixture differs from upstream")
                # Neither the upstream path nor its malicious/benign label reaches the scanner.
                report = scan_file("upload.log", len(data), data)["report"]
                self.assertIsNone(report["error"])
                self.assertFalse(report["truncated"])
                found = [f["ruleId"] for f in report["findings"]]
                if sample["label"] == "malicious":
                    expected = EXPECTED_BY_FILE.get(sample["path"].split("/")[-1]) or EXPECTED_BY_FORMAT.get(sample["format"])
                    self.assertTrue(expected, f"Missing test expectations for {sample['path']}")
                    for rule_id in expected:
                        self.assertIn(rule_id, found, f"Missing expected detection: {rule_id}")
                    for finding in report["findings"]:
                        self.assertTrue(finding["samples"], f"Missing evidence: {finding['ruleId']}")
                        self.assertTrue(all(s["text"].strip() for s in finding["samples"]), f"Empty evidence: {finding['ruleId']}")
                else:
                    self.assertEqual(found, [], "Benign sample produced findings")


if __name__ == "__main__":
    unittest.main()
