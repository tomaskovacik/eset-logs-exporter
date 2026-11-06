# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for graylog/setup_graylog.py query/rule generation."""

import json
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "graylog"))
import setup_graylog as s  # noqa: E402

DEVICE_ALERT = "ESET - device online outside home country"
MALWARE_ALERT = "ESET - malware cleaned or deleted"


def queries(exc):
    return {t: q for t, q, *_ in s.apply_exceptions(s.ALERTS, exc)}


class TestExceptions(unittest.TestCase):
    def test_no_exceptions_leaves_queries_unchanged(self):
        self.assertEqual(queries({}), {a[0]: a[1] for a in s.ALERTS})

    def test_device_home_countries(self):
        q = queries({"device_home_countries": {
            "laptop-01": {"countries": ["EE"]},
            "laptop-02": {"countries": ["AT", "CH"]},
            "_disabled": {"countries": ["US"]}}})[DEVICE_ALERT]
        self.assertIn('NOT (device_name:"laptop-01" AND public_ip_country_code:EE)', q)
        self.assertIn('NOT (device_name:"laptop-02" AND public_ip_country_code:(AT OR CH))', q)
        self.assertNotIn("_disabled", q)

    def test_alert_exclusions(self):
        q = queries({"alert_exclusions": {
            MALWARE_ALERT: [{"query": 'hostname:"BUILD01"'}]}})
        self.assertTrue(q[MALWARE_ALERT].endswith(' AND NOT (hostname:"BUILD01")'))
        self.assertNotIn("BUILD01", q[DEVICE_ALERT])

    def test_unknown_alert_title_is_rejected(self):
        with self.assertRaises(SystemExit):
            queries({"alert_exclusions": {"ESET - typo": []}})

    def test_quote_escapes(self):
        self.assertEqual(s.quote('a"b\\c'), '"a\\"b\\\\c"')

    def test_example_file_is_valid(self):
        with open(os.path.join(ROOT, "graylog", "exceptions.example.json")) as f:
            q = queries(json.load(f))
        self.assertIn("laptop-01", q[DEVICE_ALERT])


class TestPipelineRules(unittest.TestCase):
    def test_outside_home_rule_trusted_egress(self):
        rule = s.outside_home_rule("SK", ["198.51.100.7/32", "203.0.113.0/24"])
        self.assertIn('!= "SK"', rule)
        self.assertIn('!cidr_match("198.51.100.7/32", to_ip($message.public_ip))', rule)
        self.assertIn('!cidr_match("203.0.113.0/24", to_ip($message.public_ip))', rule)

    def test_geoip_rule_uses_production_table_names(self):
        rule = s.geoip_rule("public_ip")
        self.assertIn('lookup_value("geoip-country"', rule)
        self.assertIn('lookup("geoip-asn"', rule)
        self.assertIn('set_field("public_ip_country_code"', rule)


if __name__ == "__main__":
    unittest.main()
