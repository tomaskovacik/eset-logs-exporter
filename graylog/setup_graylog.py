#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Create or update the Graylog side of eset-logs-exporter. Safe to re-run.

  index set   "ESET PROTECT" (copy of the default index set's settings, prefix "eset")
  stream      "ESET PROTECT", everything from the exporter's GELF input
  pipeline    "eset-protect": GeoIP country/ASN for public_ip and destination_ip,
              and outside_home_country=true on devices seen online abroad
  alerts      event definitions, see ALERTS below
  dashboard   "ESET PROTECT" (created once; --replace-dashboard rebuilds it)

Objects are matched by title: existing ones are updated, missing ones created.

Known exceptions live in a local JSON file (--exceptions, default
graylog/exceptions.json, git-ignored because it names people, devices and
company IPs). See graylog/exceptions.example.json:

  home_country            ISO code devices are expected in
  trusted_egress          public IPs/ranges never treated as abroad (VPN exits)
  device_home_countries   per-device countries that are not "abroad"
                          (people based abroad); trips stay alerting
  alert_exclusions        per-alert extra "AND NOT (...)" query clauses

Requires lookup tables named "geoip-country" (single value = ISO country code)
and "geoip-asn" (single value = AS number, multi value has as_organization),
e.g. MaxMind GeoLite2 or DB-IP Lite with Graylog's "Geo IP - MaxMind" adapter.

  ./setup_graylog.py --url http://localhost:9000 --token-file ~/.gltok \\
      --input-id 6aecf17592b40618ee4e3c55 --exceptions graylog/exceptions.json

Standard library only.
"""

import argparse
import base64
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

TITLE = "ESET PROTECT"
PREFIX = "eset-protect"

MIN = 60_000
HOUR = 3_600_000
DAY = 86_400_000


# --------------------------------------------------------------------------
# Graylog API
# --------------------------------------------------------------------------

class Graylog:
    def __init__(self, url, token, dry_run=False):
        self.base = url.rstrip("/") + "/api"
        self.auth = "Basic " + base64.b64encode(f"{token}:token".encode()).decode()
        self.dry_run = dry_run

    def req(self, method, path, body=None):
        if self.dry_run and method != "GET":
            print(f"  [dry-run] {method} {path}")
            return {"id": f"dry-run-{uuid.uuid4().hex[:8]}", "stream_id": "dry-run"}
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(self.base + path, data=data, method=method, headers={
            "Authorization": self.auth, "Accept": "application/json",
            "Content-Type": "application/json", "X-Requested-By": "eset-logs-exporter"})
        try:
            with urllib.request.urlopen(r, timeout=60) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raise SystemExit(f"{method} {path} -> HTTP {e.code}: "
                             f"{e.read().decode(errors='replace')[:800]}") from None

    def get(self, path):
        return self.req("GET", path)

    # Graylog 6+ wraps entity creation in CreateEntityRequest {"entity": ...};
    # updates take the plain object (some versions want the wrapper there too).
    def create(self, path, body):
        return self.req("POST", path, {"entity": body})

    def update(self, path, body):
        try:
            return self.req("PUT", path, body)
        except SystemExit as e:
            if "entity" not in str(e):
                raise
            return self.req("PUT", path, {"entity": body})


def find(items, title, key="title"):
    return next((i for i in items if i.get(key) == title), None)


# --------------------------------------------------------------------------
# Index set, stream
# --------------------------------------------------------------------------

def ensure_index_set(gl):
    sets = gl.get("/system/indices/index_sets?skip=0&limit=0")["index_sets"]
    existing = find(sets, TITLE)
    if existing:
        print(f"index set  '{TITLE}' exists ({existing['id']})")
        return existing["id"]
    default = next(s for s in sets if s.get("default"))
    body = {k: v for k, v in default.items() if k not in ("id", "default", "can_be_default")}
    body.update(title=TITLE, description="ESET PROTECT Cloud via eset-logs-exporter",
                index_prefix="eset", writable=True)
    res = gl.req("POST", "/system/indices/index_sets", body)
    print(f"index set  '{TITLE}' created ({res['id']}), settings copied from "
          f"'{default['title']}'")
    return res["id"]


def stream_rules(input_id):
    # both must match, so a GELF input shared with other feeds works too
    return [{"field": "gl2_source_input", "type": 1, "value": input_id,
             "inverted": False, "description": "exporter GELF input"},
            {"field": "source", "type": 1, "value": "eset-protect",
             "inverted": False, "description": "GELF host set by the exporter"}]


def ensure_stream(gl, index_set_id, input_id):
    streams = gl.get("/streams")["streams"]
    existing = find(streams, TITLE)
    if existing:
        have = {(r["field"], r["value"]) for r in existing.get("rules", [])}
        for rule in stream_rules(input_id):
            if (rule["field"], rule["value"]) not in have:
                gl.req("POST", f"/streams/{existing['id']}/rules", rule)
                print(f"stream     rule {rule['field']}={rule['value']} added")
        print(f"stream     '{TITLE}' exists ({existing['id']})")
        return existing["id"]
    res = gl.create("/streams", {
        "title": TITLE,
        "description": "Devices, indicators and incidents from eset-logs-exporter",
        "index_set_id": index_set_id,
        "remove_matches_from_default_stream": True,
        "matching_type": "AND",
        "rules": stream_rules(input_id),
    })
    sid = res["stream_id"]
    gl.req("POST", f"/streams/{sid}/resume")
    print(f"stream     '{TITLE}' created ({sid})")
    return sid


def check_lookup_tables(gl):
    tables = {t["name"] for t in gl.get("/system/lookup/tables?per_page=500")["lookup_tables"]}
    missing = {"geoip-country", "geoip-asn"} - tables
    if missing:
        raise SystemExit(f"missing lookup tables: {', '.join(sorted(missing))} "
                         "(see the docstring)")


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def geoip_rule(field):
    return f'''rule "{PREFIX} geoip {field}"
when
  has_field("{field}")
  && is_not_null(lookup_value("geoip-country", to_string($message.{field})))
then
  let ip = to_string($message.{field});
  set_field("{field}_country_code", lookup_value("geoip-country", ip));
  let asn = lookup("geoip-asn", ip);
  set_field("{field}_asn", to_string(asn.as_number, ""));
  set_field("{field}_as_org", to_string(asn.as_organization, ""));
end'''


def outside_home_rule(home, trusted):
    # trusted egress (company VPN, hosted sites) is not "abroad" even if it
    # geolocates elsewhere
    excl = "".join(f'\n  && !cidr_match("{n}", to_ip($message.public_ip))' for n in trusted)
    return f'''rule "{PREFIX} device outside home country"
when
  to_string($message.eset_type) == "device"
  && has_field("public_ip_country_code")
  && to_string($message.public_ip_country_code) != "{home}"
  // only devices that synced recently; a stale record says nothing about today
  && to_double($message.days_since_sync, 999.0) < 1.0{excl}
then
  set_field("outside_home_country", true);
end'''


def ensure_pipeline(gl, stream_id, home, trusted):
    rules = {
        f"{PREFIX} geoip public_ip": geoip_rule("public_ip"),
        f"{PREFIX} geoip destination_ip": geoip_rule("destination_ip"),
        f"{PREFIX} device outside home country": outside_home_rule(home, trusted),
    }
    existing = gl.get("/system/pipelines/rule")
    for title, source in rules.items():
        old = find(existing, title)
        body = {"title": title, "description": "managed by eset-logs-exporter", "source": source}
        if old:
            gl.req("PUT", f"/system/pipelines/rule/{old['id']}", dict(body, id=old["id"]))
            print(f"rule       '{title}' updated")
        else:
            gl.req("POST", "/system/pipelines/rule", body)
            print(f"rule       '{title}' created")

    source = f'''pipeline "{PREFIX}"
stage 0 match either
  rule "{PREFIX} geoip public_ip"
  rule "{PREFIX} geoip destination_ip"
stage 1 match either
  rule "{PREFIX} device outside home country"
end'''
    pipelines = gl.get("/system/pipelines/pipeline")
    old = find(pipelines, PREFIX)
    body = {"title": PREFIX, "description": "managed by eset-logs-exporter", "source": source}
    if old:
        pid = old["id"]
        gl.req("PUT", f"/system/pipelines/pipeline/{pid}", dict(body, id=pid))
        print(f"pipeline   '{PREFIX}' updated")
    else:
        pid = gl.req("POST", "/system/pipelines/pipeline", body)["id"]
        print(f"pipeline   '{PREFIX}' created")

    conns = gl.get("/system/pipelines/connections")
    current = next((c["pipeline_ids"] for c in conns if c["stream_id"] == stream_id), [])
    if pid not in current:
        gl.req("POST", "/system/pipelines/connections/to_stream",
               {"stream_id": stream_id, "pipeline_ids": current + [pid]})
        print(f"pipeline   '{PREFIX}' connected to stream")


# --------------------------------------------------------------------------
# Alerts
# --------------------------------------------------------------------------

# (title, query, priority 1-3, group_by, window, grace, note)
# Volumes measured on 30 days of real data from a 56-device ESET PROTECT Entry
# tenant before choosing queries and grace periods.
ALERTS = [
    ("ESET - device online outside home country",
     "eset_type:device AND outside_home_country:true", 2,
     ["device_name", "public_ip_country_code"], 30 * MIN, DAY,
     "Device records arrive every exporter run, so one alert per device per country per "
     "day. Trusted egress IPs (company VPN, hosted sites) are excluded in the pipeline."),
    ("ESET - malware cleaned or deleted",
     "eset_type:indicator AND event_category:malware", 2,
     ["hostname", "rule_name"], 30 * MIN, HOUR,
     "~1.8/day measured; mostly 'Potentially unsafe application' deleted, a few Trojans."),
    ("ESET - ARP cache poisoning",
     'eset_type:indicator AND rule_name:"ARP/CachePoisoningAttack"', 3,
     ["hostname"], 30 * MIN, HOUR,
     "11 in 30 days. ARP/DuplicateIPAddresses (61/30d) is left to the dashboard."),
    ("ESET - high risk indicator",
     "eset_type:indicator AND event_risk_score:>=48", 3,
     ["hostname", "rule_name"], 30 * MIN, HOUR,
     "ECS high/critical risk (>=48). 0 in 30 days - every indicator so far scored 40."),
    ("ESET - incident opened or changed",
     "eset_type:incident", 3,
     ["display_name", "status"], 30 * MIN, HOUR,
     "The exporter only ships incidents that are new or whose updateTime changed."),
    ("ESET - device protection needs attention",
     "eset_type:device AND NOT functionality_status:(OK OR ATTENTION_RECOMMENDED)", 2,
     ["device_name", "functionality_status"], 30 * MIN, DAY,
     "ATTENTION_REQUIRED, SECURITY_RISK or anything new ESET adds. 1 device measured."),
]


def alert_definition(stream_id, title, query, priority, group_by, window, grace, note,
                     notification_id):
    return {
        "title": title,
        "description": note,
        "remediation_steps": "",
        "priority": priority,
        "alert": True,
        "config": {
            "type": "aggregation-v1",
            "query": query,
            "query_parameters": [],
            "filters": [],
            "streams": [stream_id],
            "stream_categories": [],
            "group_by": group_by,
            "series": [{"type": "count", "id": "count-0", "field": group_by[0]}],
            "conditions": {"expression": {
                "expr": ">",
                "left": {"expr": "number-ref", "ref": "count-0"},
                "right": {"expr": "number", "value": 0.0}}},
            "search_within_ms": window,
            "execute_every_ms": 15 * MIN,
            "use_cron_scheduling": False,
            "cron_expression": None,
            "cron_timezone": None,
            "event_limit": 100,
        },
        "field_spec": {
            g: {"data_type": "string",
                "providers": [{"type": "template-v1", "template": "${source." + g + "}",
                               "require_values": g == group_by[0]}]}
            for g in group_by
        },
        "key_spec": group_by,
        "notification_settings": {"grace_period_ms": grace, "backlog_size": 5},
        "notifications": ([{"notification_id": notification_id,
                            "notification_parameters": None}] if notification_id else []),
        "storage": [{"type": "persist-to-streams-v1",
                     "streams": ["000000000000000000000002"]}],
        "state": "ENABLED",
    }


def liveness_definition(stream_id, notification_id):
    """No device records for 1 hour = exporter, ESET API or input is down."""
    d = alert_definition(stream_id, "ESET - exporter feed stopped", "eset_type:device", 3,
                         ["device_name"], HOUR, 6 * HOUR,
                         "Devices are shipped on every run (default every 15 min), so an "
                         "empty hour means the feed is broken.", notification_id)
    d["config"].update(group_by=[], series=[{"type": "count", "id": "count-0"}],
                       conditions={"expression": {
                           "expr": "<",
                           "left": {"expr": "number-ref", "ref": "count-0"},
                           "right": {"expr": "number", "value": 1.0}}})
    d.update(field_spec={}, key_spec=[])
    d["notification_settings"]["backlog_size"] = 0
    return d


def quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def apply_exceptions(alerts, exc):
    """Append known exceptions to alert queries, MS365-alerts style."""
    titles = {a[0] for a in alerts}
    # keys starting with "_" are comments / disabled entries
    exclusions = {k: v for k, v in exc.get("alert_exclusions", {}).items() if not k.startswith("_")}
    devices = {k: v for k, v in exc.get("device_home_countries", {}).items()
               if not k.startswith("_")}
    unknown = set(exclusions) - titles
    if unknown:
        raise SystemExit(f"alert_exclusions for unknown alerts: {', '.join(sorted(unknown))}")
    out = []
    for title, query, *rest in alerts:
        parts = [query]
        if title == "ESET - device online outside home country":
            for device, entry in devices.items():
                ccs = entry["countries"]
                cc = ccs[0] if len(ccs) == 1 else "(" + " OR ".join(ccs) + ")"
                parts.append(f"NOT (device_name:{quote(device)} AND public_ip_country_code:{cc})")
        for e in exclusions.get(title, []):
            parts.append(f"NOT ({e['query']})")
        out.append((title, " AND ".join(parts), *rest))
    return out


def ensure_alerts(gl, stream_id, notification_id, exc):
    existing = gl.get("/events/definitions?per_page=500")["event_definitions"]
    defs = [alert_definition(stream_id, *a, notification_id)
            for a in apply_exceptions(ALERTS, exc)]
    defs.append(liveness_definition(stream_id, notification_id))
    for d in defs:
        old = find(existing, d["title"])
        if old:
            gl.update(f"/events/definitions/{old['id']}?schedule=true", dict(d, id=old["id"]))
            print(f"alert      '{d['title']}' updated")
        else:
            gl.create("/events/definitions?schedule=true", d)
            print(f"alert      '{d['title']}' created")


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

def rel(seconds):
    return {"from": seconds, "type": "relative"}


LATEST = rel(1200)   # last 20 min = the latest device snapshot (one per run)
D7, D30, D90 = rel(7 * 86400), rel(30 * 86400), rel(90 * 86400)


def uid():
    return str(uuid.uuid4())


def widget(streams, title, q, rows, vis, tr=D30, cols=None, limit=15, desc="", width=6):
    sid, wid = uid(), uid()
    series = [{"type": "count", "id": "count()", "field": None}]
    rg = [{"type": "time", "fields": ["timestamp"], "interval": {"type": "auto", "scaling": 1.0}}
          if r == "timestamp" else
          {"type": "values", "fields": [r], "limit": limit, "skip_empty_values": True}
          for r in rows]
    cg = [{"type": "values", "fields": [c], "limit": 10, "skip_empty_values": True}
          for c in (cols or [])]
    query = {"type": "elasticsearch", "query_string": q}
    st = {"timerange": tr, "query": query, "streams": streams, "stream_categories": [],
          "id": sid, "name": "chart", "series": series, "sort": [], "rollup": True,
          "type": "pivot", "row_groups": rg, "column_groups": cg,
          "filter": None, "filters": []}
    w = {"id": wid, "type": "aggregation", "filter": None, "filters": [], "timerange": tr,
         "query": query, "streams": streams, "stream_categories": [],
         "config": {
             "row_pivots": [{"type": "time" if r == "timestamp" else "values", "fields": [r],
                             "config": ({"interval": {"type": "auto", "scaling": 1.0}}
                                        if r == "timestamp"
                                        else {"limit": limit, "skip_empty_values": True})}
                            for r in rows],
             "column_pivots": [{"type": "values", "fields": [c],
                                "config": {"limit": 10, "skip_empty_values": True}}
                               for c in (cols or [])],
             "series": [{"config": {"name": None, "thresholds": []}, "function": "count()"}],
             "sort": [], "visualization": vis, "rollup": True, "event_annotation": False,
             "units": {}, "visualization_config": None, "formatting_settings": None,
             "row_limit": limit, "column_limit": None},
         "description": desc, "context": None}
    return w, st, sid, title, width


def mtable(streams, title, q, fields, tr=D30, desc="", width=12):
    sid, wid = uid(), uid()
    query = {"type": "elasticsearch", "query_string": q}
    st = {"timerange": tr, "query": query, "streams": streams, "stream_categories": [],
          "type": "messages", "id": sid, "name": None, "limit": 150, "offset": 0,
          "sort": [{"field": "timestamp", "order": "DESC"}], "fields": [],
          "decorators": [], "filter": None, "filters": []}
    w = {"id": wid, "type": "messages", "filter": None, "filters": [], "timerange": tr,
         "query": query, "streams": streams, "stream_categories": [],
         "config": {"fields": fields, "units": {}, "show_message_row": False,
                    "show_summary": False, "decorators": [],
                    "sort": [{"type": "pivot", "field": "timestamp",
                              "direction": "Descending"}]},
         "description": desc or None, "context": None}
    return w, st, sid, title, width


def dashboard_tabs(s):
    dev, ind, inc = "eset_type:device", "eset_type:indicator", "eset_type:incident"
    return [
        ("Security events", [
            widget(s, "Indicators per day by category", ind, ["timestamp"], "bar",
                   cols=["event_category"]),
            widget(s, "Top detections", ind, ["rule_name"], "table"),
            widget(s, "Devices with most indicators", ind, ["hostname"], "table"),
            widget(s, "Users with most indicators", ind, ["user_name"], "table"),
            mtable(s, "Malware cleaned or deleted", f"{ind} AND event_category:malware",
                   ["timestamp", "hostname", "user_name", "rule_category", "rule_name",
                    "event_action", "file_path"]),
            mtable(s, "Incidents", inc,
                   ["timestamp", "status", "severity", "display_name", "affected_devices",
                    "mitre_technique_ids"], tr=D90),
        ]),
        ("Devices", [
            widget(s, "Devices by group", dev, ["group_name"], "pie", tr=LATEST,
                   desc="Latest snapshot (last 20 minutes)."),
            widget(s, "Protection status", dev, ["functionality_status"], "pie", tr=LATEST),
            widget(s, "Operating systems", dev, ["os_name"], "table", tr=LATEST),
            widget(s, "ESET security product versions", dev, ["eset_security_version"],
                   "table", tr=LATEST),
            widget(s, "Public IP country", dev, ["public_ip_country_code"], "pie",
                   tr=LATEST),
            widget(s, "Public IP network", dev, ["public_ip_as_org"], "table", tr=LATEST),
            mtable(s, "Devices online outside home country",
                   f"{dev} AND outside_home_country:true",
                   ["timestamp", "device_name", "public_ip", "public_ip_country_code",
                    "public_ip_as_org", "group_name"], tr=LATEST),
            mtable(s, "Devices not synced for over 30 days",
                   f"{dev} AND days_since_sync:>30",
                   ["device_name", "hostname", "group_name", "last_sync_time",
                    "days_since_sync", "eset_security_version"], tr=LATEST),
        ]),
        ("Web and network", [
            widget(s, "Blocked web domains", f"{ind} AND event_category:web", ["url_domain"],
                   "table", limit=25),
            widget(s, "Blocked destinations by country", f"{ind} AND event_category:web",
                   ["destination_ip_country_code"], "pie"),
            widget(s, "Network attacks by type", f'{ind} AND event_category:intrusion*',
                   ["rule_name"], "table"),
            widget(s, "Network attacks by device", f'{ind} AND event_category:intrusion*',
                   ["hostname"], "table"),
        ]),
        ("Feed health", [
            widget(s, "Messages per hour by type", "*", ["timestamp"], "bar",
                   cols=["eset_type"], tr=D7,
                   desc="Device records arrive on every exporter run; a gap means the "
                        "feed stopped (there is an alert for that)."),
            widget(s, "Devices per snapshot", dev, ["timestamp"], "line", tr=D7),
        ]),
    ]


def ensure_dashboard(gl, stream_id, replace):
    views = gl.get("/views?per_page=500").get("views", [])
    old = next((v for v in views if v.get("title") == TITLE and v.get("type") == "DASHBOARD"),
               None)
    if old and not replace:
        print(f"dashboard  '{TITLE}' exists ({old['id']}), --replace-dashboard to rebuild")
        return
    queries, state = [], {}
    for tab, built in dashboard_tabs([stream_id]):
        qid = uid()
        sts, widgets, mapping, positions, titles = [], [], {}, {}, {}
        row, col = 1, 1
        for w, st, sid, title, width in built:
            sts.append(st)
            widgets.append(w)
            mapping[w["id"]] = [sid]
            titles[w["id"]] = title
            if width >= 12:
                if col != 1:
                    row, col = row + 4, 1
                positions[w["id"]] = {"col": 1, "row": row, "height": 5, "width": 12}
                row += 5
            else:
                positions[w["id"]] = {"col": col, "row": row, "height": 4, "width": 6}
                row, col = (row, 7) if col == 1 else (row + 4, 1)
        queries.append({"id": qid, "timerange": D30, "filter": None, "filters": [],
                        "query": {"type": "elasticsearch", "query_string": ""},
                        "search_types": sts})
        state[qid] = {"selected_fields": None, "static_message_list_id": None,
                      "titles": {"widget": titles, "tab": {"title": tab}},
                      "widgets": widgets, "widget_mapping": mapping, "positions": positions,
                      "formatting": {}, "display_mode_settings": {"positions": {}}}
    search = gl.req("POST", "/views/search", {"queries": queries, "parameters": []})
    view = gl.create("/views", {
        "type": "DASHBOARD", "title": TITLE,
        "summary": "Security events, device inventory and feed health from ESET PROTECT",
        "description": "Managed by eset-logs-exporter graylog/setup_graylog.py",
        "search_id": search["id"], "properties": [], "requires": {}, "state": state})
    if old:
        gl.req("DELETE", f"/views/{old['id']}")
    print(f"dashboard  '{TITLE}' {'rebuilt' if old else 'created'} ({view['id']})")


# --------------------------------------------------------------------------

DEFAULT_EXCEPTIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exceptions.json")


def load_exceptions(path):
    if not os.path.exists(path):
        if path != DEFAULT_EXCEPTIONS:
            raise SystemExit(f"exceptions file not found: {path}")
        return {}
    with open(path) as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", required=True, help="Graylog base URL")
    ap.add_argument("--token-file", required=True, help="file with a Graylog API token")
    ap.add_argument("--input-id", required=True, help="ID of the exporter's GELF input")
    ap.add_argument("--exceptions", default=DEFAULT_EXCEPTIONS,
                    help="known exceptions JSON (default: graylog/exceptions.json if present)")
    ap.add_argument("--home-country", help="ISO code, overrides the exceptions file "
                                           "(default: SK)")
    ap.add_argument("--trusted-egress", action="append", default=[], metavar="IP/CIDR",
                    help="public IP or range never treated as abroad (repeatable, added "
                         "to the exceptions file)")
    ap.add_argument("--notification-id", help="attach this notification to all alerts")
    ap.add_argument("--replace-dashboard", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="read only, print what changes")
    args = ap.parse_args()

    exc = load_exceptions(args.exceptions)
    home = (args.home_country or exc.get("home_country") or "SK").upper()
    trusted = [str(ipaddress.ip_network(n, strict=False)) for n in
               [e["cidr"] for e in exc.get("trusted_egress", [])] + args.trusted_egress]
    print(f"exceptions home={home} trusted_egress={len(trusted)} "
          f"device_home_countries={len(exc.get('device_home_countries', {}))} "
          f"alert_exclusions={sum(map(len, exc.get('alert_exclusions', {}).values()))}")
    with open(args.token_file) as f:
        gl = Graylog(args.url, f.read().strip(), args.dry_run)

    check_lookup_tables(gl)
    index_set = ensure_index_set(gl)
    stream = ensure_stream(gl, index_set, args.input_id)
    ensure_pipeline(gl, stream, home, trusted)
    ensure_alerts(gl, stream, args.notification_id, exc)
    ensure_dashboard(gl, stream, args.replace_dashboard)


if __name__ == "__main__":
    sys.exit(main())
