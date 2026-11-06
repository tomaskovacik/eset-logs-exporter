# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests: no ESET API or Graylog needed."""

import json
import os
import socket
import sys
import tempfile
import unittest
import zlib
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import eset_to_graylog as m  # noqa: E402

NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)

DEVICE = {
    "uuid": "dev-1",
    "displayName": "bocko11",
    "systemHostname": "BOCKO11",
    "primaryLocalIpAddress": "192.168.100.99",
    "publicIpAddress": "203.0.113.10",
    "parentGroupUuid": "grp-1",
    "operatingSystem": {"displayName": "Microsoft Windows 11 Pro",
                        "version": {"name": "10.0.26200.9457"}},
    "deployedComponents": [
        {"displayName": "ESET Management Agent", "version": {"name": "13.3.1192.0"}},
        {"displayName": "ESET Endpoint Security", "version": {"name": "13.1.2036.0"}},
    ],
    "tags": [""],
    "description": "",
    "lastSyncTime": "2026-10-26T00:00:00Z",
    "functionalityStatus": "DEVICE_FUNCTIONALITY_STATUS_ATTENTION_REQUIRED",
    "functionalityProblemCount": 2,
    "isMuted": False,
    "isMobile": False,
    "hardwareProfiles": [{
        "model": "HP EliteBook",
        "bios": {"serialNumber": "SERIAL123"},
        "networkAdapters": [{"macAddress": "AA-AA-AA-AA-AA-01"}, {"macAddress": ""},
                            {"macAddress": "AA-AA-AA-AA-AA-02"},
                            {"macAddress": "AA-AA-AA-AA-AA-01"}],
        "hardDrives": [{"serialNumber": "DISK1"}],
    }],
}
DEVICES = {"dev-1": DEVICE}
GROUPS = {"grp-1": "WINPC"}
LOOKBACK = 24 * 365 * 20   # first-run window wide enough for the fixed test dates


def indicator(uuid, ts, risk=40):
    return {
        "@timestamp": ts,
        "uuid": uuid,
        "event": {"type": "denied", "risk_score": risk, "reason": "PUA blocked"},
        "host": {"id": "dev-1", "hostname": "BOCKO11", "ip": "192.168.100.99"},
        "process": {"user": {"name": "bocko"}, "pid": 42},
        "rule": {"name": "Win32/Test.A"},
    }


class FakeClient:
    """Stands in for EsetClient; serves fixed lists per path."""

    def __init__(self, data):
        self.data = data
        self.calls = []

    def paginate(self, service, path, key, params=None, page_size=100):
        self.calls.append((path, params))
        since = m.parse_ts((params or {}).get("startTime"))
        for item in self.data.get(path, []):
            ts = m.parse_ts(item.get("@timestamp"))
            if since and ts and ts < since:     # same as the API's startTime filter
                continue
            yield item


class FakeSender:
    def __init__(self):
        self.sent = []

    def send(self, msg):
        self.sent.append(msg)


class TestHelpers(unittest.TestCase):
    def test_unique_drops_empty_and_duplicates_keeps_order(self):
        self.assertEqual(m.unique(["b", "", None, "a", "b"]), ["b", "a"])

    def test_parse_ts(self):
        self.assertEqual(m.parse_ts("2026-11-05T12:30:58Z"),
                         datetime(2026, 11, 5, 12, 30, 58, tzinfo=timezone.utc))
        self.assertIsNotNone(m.parse_ts("2026-10-07T09:49:22.456589Z"))
        self.assertIsNone(m.parse_ts(""))
        self.assertIsNone(m.parse_ts("garbage"))

    def test_flatten(self):
        out = m.flatten({"context": {"deviceUuid": "x", "userName": ""},
                         "tags": ["a", "", "b"], "items": [{"k": 1}], "empty": None})
        self.assertEqual(out, {"context_device_uuid": "x", "tags": "a,b", "items_0_k": 1})

    def test_risk_level(self):
        self.assertEqual(m.risk_level(10), m.SYSLOG_LEVEL["notice"])
        self.assertEqual(m.risk_level(40), m.SYSLOG_LEVEL["warning"])
        self.assertEqual(m.risk_level(60), m.SYSLOG_LEVEL["err"])
        self.assertEqual(m.risk_level(90), m.SYSLOG_LEVEL["crit"])
        self.assertEqual(m.risk_level(None), m.SYSLOG_LEVEL["warning"])

    def test_device_level(self):
        self.assertEqual(m.device_level("DEVICE_FUNCTIONALITY_STATUS_OK"), 6)
        self.assertEqual(m.device_level("DEVICE_FUNCTIONALITY_STATUS_ATTENTION_RECOMMENDED"), 5)
        self.assertEqual(m.device_level("DEVICE_FUNCTIONALITY_STATUS_ATTENTION_REQUIRED"), 4)


class TestShaping(unittest.TestCase):
    def test_device_fields(self):
        short, level, f = m.device_fields(DEVICE, GROUPS, NOW)
        self.assertEqual(level, m.SYSLOG_LEVEL["warning"])
        self.assertIn("bocko11", short)
        self.assertEqual(f["eset_type"], "device")
        self.assertEqual(f["group_name"], "WINPC")
        self.assertEqual(f["eset_security_product"], "ESET Endpoint Security")
        self.assertEqual(f["eset_security_version"], "13.1.2036.0")
        self.assertEqual(f["eset_agent_version"], "13.3.1192.0")
        self.assertEqual(f["bios_serial"], "SERIAL123")
        self.assertEqual(f["mac_addresses"], "AA-AA-AA-AA-AA-01,AA-AA-AA-AA-AA-02")
        self.assertEqual(f["days_since_sync"], 10.0)
        self.assertEqual(f["functionality_status"], "ATTENTION_REQUIRED")
        # other hardware details are not exported
        self.assertFalse(any("disk" in k or "model" in k for k in f))

    def test_indicator_fields(self):
        short, level, f = m.indicator_fields(
            indicator("i1", "2026-11-05T10:00:00.123456Z"), DEVICES, GROUPS)
        self.assertEqual(short, "ESET indicator: Win32/Test.A on bocko11")
        self.assertEqual(level, m.SYSLOG_LEVEL["warning"])
        self.assertEqual(f["eset_type"], "indicator")
        self.assertEqual(f["event_type"], "denied")        # ECS field kept as-is
        self.assertEqual(f["user_name"], "bocko")
        self.assertEqual(f["host_ip"], "192.168.100.99")
        self.assertEqual(f["device_name"], "bocko11")
        self.assertEqual(f["group_name"], "WINPC")
        self.assertNotIn("@timestamp", f)

    def test_indicator_unknown_device(self):
        ind = indicator("i1", "2026-11-05T10:00:00Z")
        ind["host"]["id"] = "unknown"
        short, _, f = m.indicator_fields(ind, DEVICES, GROUPS)
        self.assertIn("BOCKO11", short)
        self.assertNotIn("device_name", f)

    def test_incident_fields(self):
        inc = {"uuid": "inc-1", "displayName": "LSA dump",
               "severity": "INCIDENT_SEVERITY_LEVEL_HIGH", "status": "INCIDENT_STATUS_OPEN",
               "affectedAssets": [{"deviceUuid": "dev-1"}, {"deviceUuid": "gone"}],
               "mitreTechniqueIds": ["T1003", "T1055"]}
        short, level, f = m.incident_fields(inc, DEVICES)
        self.assertEqual(short, "ESET incident [OPEN/HIGH]: LSA dump")
        self.assertEqual(level, m.SYSLOG_LEVEL["err"])
        self.assertEqual(f["affected_devices"], "bocko11")
        self.assertEqual(f["mitre_technique_ids"], "T1003,T1055")


class TestGelf(unittest.TestCase):
    def test_build(self):
        msg = m.GelfSender.build("hello", 6, {"id": 5, "flag": True, "skip": "", "n": None,
                                              "bad key!": "x", "obj": {"a": 1}}, timestamp=1.5)
        self.assertEqual(msg["version"], "1.1")
        self.assertEqual(msg["timestamp"], 1.5)
        self.assertEqual(msg["_eset_id"], 5)               # _id is reserved
        self.assertEqual(msg["_flag"], "true")
        self.assertEqual(msg["_bad_key_"], "x")
        self.assertIsInstance(msg["_obj"], str)
        self.assertNotIn("_skip", msg)
        self.assertNotIn("_n", msg)

    def test_udp_plain_and_chunked(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as rx:
            rx.bind(("127.0.0.1", 0))
            rx.settimeout(5)
            sender = m.GelfSender("127.0.0.1", rx.getsockname()[1], "udp")
            try:
                small = m.GelfSender.build("small", 6, {})
                sender.send(small)
                self.assertEqual(json.loads(zlib.decompress(rx.recv(9000))), small)

                big = m.GelfSender.build("big", 6, {"blob": os.urandom(20000).hex()})
                sender.send(big)
                parts, total = {}, None
                while total is None or len(parts) < total:
                    d = rx.recv(9000)
                    self.assertEqual(d[:2], b"\x1e\x0f")
                    parts[d[10]], total = d[12:], d[11]
                self.assertGreater(total, 1)
                data = b"".join(parts[i] for i in range(total))
                self.assertEqual(json.loads(zlib.decompress(data)), big)
            finally:
                sender.close()

    def test_tcp_null_delimited(self):
        with socket.socket() as srv:
            srv.bind(("127.0.0.1", 0))
            srv.listen()
            sender = m.GelfSender("127.0.0.1", srv.getsockname()[1], "tcp")
            conn, _ = srv.accept()
            with conn:
                sender.send(m.GelfSender.build("one", 6, {}))
                sender.send(m.GelfSender.build("two", 6, {}))
                sender.close()
                data = b""
                while chunk := conn.recv(65536):
                    data += chunk
        frames = [json.loads(f) for f in data.split(b"\0") if f]
        self.assertEqual([f["short_message"] for f in frames], ["one", "two"])


class TestShipping(unittest.TestCase):
    def test_indicators_dedup_and_overlap(self):
        state = {}
        client = FakeClient({"/v3/indicators": [indicator("a", "2026-11-05T10:00:00Z"),
                                                indicator("b", "2026-11-05T11:00:00Z")]})
        sender = FakeSender()
        m.ship_indicators(client, sender, DEVICES, GROUPS, state, LOOKBACK, 60)
        self.assertEqual([s["_uuid"] for s in sender.sent], ["a", "b"])
        self.assertEqual(state["indicators_last_time"], "2026-11-05T11:00:00Z")
        # event time is used as GELF timestamp
        self.assertEqual(sender.sent[1]["timestamp"],
                         datetime(2026, 11, 5, 11, tzinfo=timezone.utc).timestamp())

        # second run: API returns the overlap again plus one late and one new
        client.data["/v3/indicators"] = [indicator("b", "2026-11-05T11:00:00Z"),
                                         indicator("late", "2026-11-05T10:30:00Z"),
                                         indicator("c", "2026-11-05T12:00:00Z")]
        sender = FakeSender()
        m.ship_indicators(client, sender, DEVICES, GROUPS, state, LOOKBACK, 60)
        self.assertEqual([s["_uuid"] for s in sender.sent], ["late", "c"])
        path, params = client.calls[-1]
        self.assertEqual(params["startTime"], "2026-11-05T10:00:00Z")   # last - overlap
        self.assertEqual(params["view"], "INDICATOR_VIEW_FULL")
        # UUIDs older than the next overlap window are forgotten
        self.assertNotIn("a", state["indicators_seen"])
        self.assertIn("c", state["indicators_seen"])

    def test_incidents_only_new_or_changed(self):
        state = {}
        inc = {"uuid": "i1", "displayName": "x", "status": "INCIDENT_STATUS_OPEN",
               "updateTime": "2026-11-01T00:00:00Z"}
        client = FakeClient({"/v3/incidents": [inc]})
        sender = FakeSender()
        m.ship_incidents(client, sender, DEVICES, state)
        m.ship_incidents(client, sender, DEVICES, state)
        self.assertEqual(len(sender.sent), 1)
        client.data["/v3/incidents"] = [dict(inc, status="INCIDENT_STATUS_CLOSED",
                                             updateTime="2026-11-02T00:00:00Z")]
        m.ship_incidents(client, sender, DEVICES, state)
        self.assertEqual(len(sender.sent), 2)
        self.assertEqual(sender.sent[1]["_status"], "CLOSED")

    def test_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "state.json")
            self.assertEqual(m.load_state(path), {})
            m.save_state(path, {"a": 1})
            self.assertEqual(m.load_state(path), {"a": 1})


if __name__ == "__main__":
    unittest.main()
