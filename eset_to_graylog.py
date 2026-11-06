#!/usr/bin/env python3
"""Ship ESET PROTECT Cloud data (ESET Connect API) to Graylog as GELF.

Message types (field `eset_type`):
  device     one per device on every run (name, hostname, IPs, OS, ESET
             versions, status, last sync, BIOS serial, MAC addresses)
  indicator  new detection indicators (Incident Management v3, ECS format)
  incident   incidents that are new or changed since the last run (v3)

Config via environment:
  ESET_USER, ESET_PASS     API user credentials (required)
  ESET_PASS_FILE           read the password from this file instead of ESET_PASS
  ESET_REGION              eu | us | de | ca | jpn (default: eu)
  ESET_TIMEOUT             API request timeout in seconds (default: 120)
  GRAYLOG_HOST             Graylog GELF input host (default: 127.0.0.1)
  GRAYLOG_PORT             GELF input port (default: 12201)
  GRAYLOG_PROTO            udp | tcp (default: udp)

Examples:
  ./eset_to_graylog.py                           # devices only
  ./eset_to_graylog.py --indicators --incidents  # devices + security events
  ./eset_to_graylog.py --dry-run                 # print GELF JSON, send nothing

Only the standard library is used.
"""

import argparse
import json
import logging
import os
import re
import socket
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone

__version__ = "0.2"

log = logging.getLogger("eset2graylog")

SOURCE = "eset-protect"
TS_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SYSLOG_LEVEL = {"emerg": 0, "alert": 1, "crit": 2, "err": 3,
                "warning": 4, "notice": 5, "info": 6, "debug": 7}


# --------------------------------------------------------------------------
# ESET Connect API
# --------------------------------------------------------------------------

class EsetClient:
    def __init__(self, user, password, region="eu", timeout=120):
        self.user = user
        self.password = password
        self.region = region
        self.timeout = timeout
        self.token = None
        self.token_expiry = 0.0

    def _url(self, service, path):
        return f"https://{self.region}.{service}.eset.systems{path}"

    def _authenticate(self):
        url = f"https://{self.region}.business-account.iam.eset.systems/oauth/token"
        body = urllib.parse.urlencode({
            "grant_type": "password",
            "username": self.user,
            "password": self.password,
        }).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers={
            "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.load(resp)
        self.token = data["access_token"]
        # refresh a minute early
        self.token_expiry = time.time() + int(data.get("expires_in", 3600)) - 60
        log.info("authenticated as %s", self.user)

    def get(self, service, path, params=None):
        if not self.token or time.time() >= self.token_expiry:
            self._authenticate()
        url = self._url(service, path)
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": f"eset-logs-exporter/{__version__}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.load(resp)

    def paginate(self, service, path, key, params=None, page_size=100):
        params = dict(params or {}, pageSize=page_size)
        while True:
            data = self.get(service, path, params)
            yield from data.get(key, [])
            token = data.get("nextPageToken")
            if not token:
                return
            params["pageToken"] = token


# --------------------------------------------------------------------------
# Data shaping
# --------------------------------------------------------------------------

def parse_ts(value):
    """Parse an RFC 3339 timestamp from the API; None if empty/invalid."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def unique(values):
    """Non-empty values, duplicates removed, order kept."""
    return list(dict.fromkeys(v for v in values if v))


def device_level(status):
    if status.endswith("_OK"):
        return SYSLOG_LEVEL["info"]
    if "ATTENTION_RECOMMENDED" in status:
        return SYSLOG_LEVEL["notice"]
    if "ATTENTION" in status or "RISK" in status or "PROBLEM" in status:
        return SYSLOG_LEVEL["warning"]
    return SYSLOG_LEVEL["info"]


def device_fields(dev, group_names, now):
    os_info = dev.get("operatingSystem") or {}
    components = {c.get("displayName", ""): (c.get("version") or {}).get("name", "")
                  for c in dev.get("deployedComponents") or []}
    profiles = dev.get("hardwareProfiles") or []
    serials = unique((p.get("bios") or {}).get("serialNumber") for p in profiles)
    macs = unique(a.get("macAddress") for p in profiles
                  for a in p.get("networkAdapters") or [])
    last_sync = parse_ts(dev.get("lastSyncTime"))
    status = dev.get("functionalityStatus", "")
    group_uuid = dev.get("parentGroupUuid", "")

    fields = {
        "eset_type": "device",
        "device_uuid": dev.get("uuid"),
        "device_name": dev.get("displayName"),
        "hostname": dev.get("systemHostname"),
        "local_ip": dev.get("primaryLocalIpAddress"),
        "public_ip": dev.get("publicIpAddress"),
        "bios_serial": ",".join(serials),
        "mac_addresses": ",".join(macs),
        "os_name": os_info.get("displayName"),
        "os_version": (os_info.get("version") or {}).get("name"),
        "group_uuid": group_uuid,
        "group_name": group_names.get(group_uuid),
        "functionality_status": status.replace("DEVICE_FUNCTIONALITY_STATUS_", ""),
        "functionality_problem_count": dev.get("functionalityProblemCount", 0),
        "is_muted": dev.get("isMuted", False),
        "is_mobile": dev.get("isMobile", False),
        "description": dev.get("description"),
        "tags": ",".join(t for t in dev.get("tags") or [] if t),
        "eset_security_product": next(
            (n for n in components if n and "Management Agent" not in n), None),
        "eset_security_version": next(
            (v for n, v in components.items() if n and "Management Agent" not in n), None),
        "eset_agent_version": components.get("ESET Management Agent"),
        "last_sync_time": dev.get("lastSyncTime"),
        "days_since_sync": round((now - last_sync).total_seconds() / 86400, 1)
                           if last_sync else None,
    }
    short = (f"ESET device {fields['device_name']} ({fields['hostname']}) "
             f"{fields['local_ip']} status={fields['functionality_status']}")
    return short, device_level(status), fields


def flatten(obj, prefix=""):
    """Flatten nested dicts/lists into dotless snake keys for GELF."""
    out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()
            out.update(flatten(v, f"{prefix}{key}_" if prefix or key else ""))
    elif isinstance(obj, list):
        if all(not isinstance(i, (dict, list)) for i in obj):
            joined = ",".join(str(i) for i in obj if i not in ("", None))
            if joined:
                out[prefix.rstrip("_")] = joined
        else:
            for i, v in enumerate(obj):
                out.update(flatten(v, f"{prefix}{i}_"))
    elif obj not in ("", None):
        out[prefix.rstrip("_")] = obj
    return out


def add_device_identity(fields, dev, group_names):
    """Add our device fields so all message types are searchable the same way."""
    if not dev:
        return
    fields.setdefault("device_name", dev.get("displayName"))
    fields.setdefault("hostname", dev.get("systemHostname"))
    fields.setdefault("local_ip", dev.get("primaryLocalIpAddress"))
    fields.setdefault("public_ip", dev.get("publicIpAddress"))
    fields.setdefault("group_name", group_names.get(dev.get("parentGroupUuid")))


def risk_level(score):
    """ECS event.risk_score (0-100) to syslog level."""
    try:
        score = float(score)
    except (TypeError, ValueError):
        return SYSLOG_LEVEL["warning"]
    if score >= 74:
        return SYSLOG_LEVEL["crit"]
    if score >= 48:
        return SYSLOG_LEVEL["err"]
    if score >= 22:
        return SYSLOG_LEVEL["warning"]
    return SYSLOG_LEVEL["notice"]


def indicator_fields(ind, devices_by_uuid, group_names):
    """Indicators are ECS documents; nested keys become host_ip, process_user_name..."""
    body = {k: v for k, v in ind.items() if k != "@timestamp"}
    fields = flatten(body)
    fields["eset_type"] = "indicator"
    fields["indicator_time"] = ind.get("@timestamp")
    host = ind.get("host") or {}
    event = ind.get("event") or {}
    rule = ind.get("rule") or {}
    user = (ind.get("process") or {}).get("user") or ind.get("user") or {}
    fields["user_name"] = user.get("name")
    add_device_identity(fields, devices_by_uuid.get(host.get("id")), group_names)
    name = rule.get("name") or event.get("reason") or event.get("action") or "indicator"
    where = fields.get("device_name") or host.get("hostname") or host.get("id")
    short = f"ESET indicator: {name} on {where}"
    return short, risk_level(event.get("risk_score")), fields


def incident_level(severity):
    s = str(severity).upper()
    if "CRITICAL" in s:
        return SYSLOG_LEVEL["crit"]
    if "HIGH" in s:
        return SYSLOG_LEVEL["err"]
    if "MEDIUM" in s:
        return SYSLOG_LEVEL["warning"]
    return SYSLOG_LEVEL["notice"]


def incident_fields(inc, devices_by_uuid):
    fields = flatten(inc)
    fields["eset_type"] = "incident"
    fields["status"] = str(inc.get("status", "")).replace("INCIDENT_STATUS_", "")
    fields["severity"] = str(inc.get("severity", "")).replace("INCIDENT_SEVERITY_LEVEL_", "")
    devices = [devices_by_uuid.get(a.get("deviceUuid")) for a in inc.get("affectedAssets") or []]
    fields["affected_devices"] = ",".join(unique(d.get("displayName") for d in devices if d))
    fields["affected_hostnames"] = ",".join(unique(d.get("systemHostname") for d in devices if d))
    short = f"ESET incident [{fields['status']}/{fields['severity']}]: {inc.get('displayName')}"
    return short, incident_level(inc.get("severity")), fields


# --------------------------------------------------------------------------
# GELF output
# --------------------------------------------------------------------------

class GelfSender:
    UDP_CHUNK = 8154          # 8192 - 12 byte header, minus some headroom
    MAX_CHUNKS = 128

    def __init__(self, host, port, proto="udp", dry_run=False):
        self.host, self.port, self.proto, self.dry_run = host, port, proto, dry_run
        self.sock = None
        if dry_run:
            return
        if proto == "tcp":
            self.sock = socket.create_connection((host, port), timeout=10)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    @staticmethod
    def build(short, level, fields, timestamp=None, host=SOURCE):
        msg = {
            "version": "1.1",
            "host": host,
            "short_message": short,
            "timestamp": round(timestamp or time.time(), 3),
            "level": level,
        }
        for k, v in fields.items():
            if v is None or v == "":
                continue
            k = re.sub(r"[^\w.\-]", "_", k)
            if k == "id":
                k = "eset_id"       # _id is reserved in GELF
            if isinstance(v, bool):
                v = str(v).lower()
            msg[f"_{k}"] = v if isinstance(v, (int, float, str)) else str(v)
        return msg

    def send(self, msg):
        payload = json.dumps(msg, separators=(",", ":")).encode()
        if self.dry_run:
            print(json.dumps(msg, indent=2))
            return
        if self.proto == "tcp":
            self.sock.sendall(payload + b"\0")
            return
        data = zlib.compress(payload)
        if len(data) <= self.UDP_CHUNK:
            self.sock.sendto(data, (self.host, self.port))
            return
        chunks = [data[i:i + self.UDP_CHUNK] for i in range(0, len(data), self.UDP_CHUNK)]
        if len(chunks) > self.MAX_CHUNKS:
            log.warning("message too large for GELF UDP, dropped: %s", msg["short_message"])
            return
        msg_id = os.urandom(8)
        for seq, chunk in enumerate(chunks):
            header = b"\x1e\x0f" + msg_id + struct.pack("BB", seq, len(chunks))
            self.sock.sendto(header + chunk, (self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()


# --------------------------------------------------------------------------
# State (last shipped detection time)
# --------------------------------------------------------------------------

def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path, state):
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def env_flag(name):
    return os.environ.get(name, "").lower() in ("1", "true", "yes")


def fetch_group_names(client):
    try:
        return {g.get("uuid"): g.get("displayName") or g.get("name")
                for g in client.paginate("device-management", "/v1/device_groups",
                                         "deviceGroups")}
    except urllib.error.HTTPError as e:
        log.warning("could not list device groups (HTTP %s), group_name omitted", e.code)
        return {}


def ship_devices(sender, devices, groups, now):
    for dev in devices.values():
        sender.send(GelfSender.build(*device_fields(dev, groups, now)))
    log.info("sent %d device messages", len(devices))


def ship_indicators(client, sender, devices, groups, state, lookback_hours, overlap_minutes):
    """Ship indicators not sent before.

    ESET can register an indicator minutes after its @timestamp, so every run
    re-reads an overlap window and skips UUIDs already shipped within it.
    """
    now = datetime.now(timezone.utc)
    last = parse_ts(state.get("indicators_last_time"))
    since = (last - timedelta(minutes=overlap_minutes)) if last \
        else now - timedelta(hours=lookback_hours)
    seen = state.setdefault("indicators_seen", {})   # uuid -> @timestamp, updated as we go
    params = {"startTime": since.strftime(TS_FORMAT), "view": "INDICATOR_VIEW_FULL"}
    newest, count = last or since, 0
    for ind in client.paginate("incident-management", "/v3/indicators", "indicators", params):
        uuid = ind.get("uuid")
        if uuid in seen:
            continue
        occurred = parse_ts(ind.get("@timestamp"))
        short, level, fields = indicator_fields(ind, devices, groups)
        sender.send(GelfSender.build(short, level, fields,
                                     timestamp=occurred.timestamp() if occurred else None))
        count += 1
        seen[uuid] = ind.get("@timestamp")
        if occurred and occurred > newest:
            newest = occurred
    # forget UUIDs that can no longer fall inside the next overlap window
    cutoff = newest - timedelta(minutes=overlap_minutes)
    state["indicators_seen"] = {u: t for u, t in seen.items()
                                if (parse_ts(t) or now) >= cutoff}
    state["indicators_last_time"] = newest.strftime(TS_FORMAT)
    log.info("sent %d indicator messages (since %s)", count, params["startTime"])


def ship_incidents(client, sender, devices, state):
    """Ship incidents that are new or whose updateTime changed."""
    known = state.setdefault("incidents", {})         # uuid -> updateTime, updated as we go
    count = 0
    for inc in client.paginate("incident-management", "/v3/incidents", "incidents"):
        uuid, updated = inc.get("uuid"), inc.get("updateTime") or inc.get("createTime")
        if known.get(uuid) == updated:
            continue
        short, level, fields = incident_fields(inc, devices)
        ts = parse_ts(updated)
        sender.send(GelfSender.build(short, level, fields,
                                     timestamp=ts.timestamp() if ts else None))
        known[uuid] = updated
        count += 1
    log.info("sent %d incident messages", count)


def ship_optional(name, func, *args):
    """Run an optional data source; a 403/404 (license tier) must not stop the rest."""
    try:
        func(*args)
    except urllib.error.HTTPError as e:
        log.error("%s request failed (HTTP %s): %s", name, e.code,
                  e.read().decode(errors="replace")[:500])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--indicators", action="store_true", default=env_flag("SHIP_INDICATORS"),
                    help="also ship detection indicators newer than the last run")
    ap.add_argument("--incidents", action="store_true", default=env_flag("SHIP_INCIDENTS"),
                    help="also ship new or changed incidents")
    ap.add_argument("--no-devices", action="store_true", default=env_flag("SKIP_DEVICES"),
                    help="skip device inventory messages")
    ap.add_argument("--lookback-hours", type=int,
                    default=int(os.environ.get("LOOKBACK_HOURS", "24")),
                    help="indicators window on first run (default: 24, ESET keeps ~30 days)")
    ap.add_argument("--overlap-minutes", type=int,
                    default=int(os.environ.get("OVERLAP_MINUTES", "60")),
                    help="re-read window for late-arriving indicators (default: 60)")
    ap.add_argument("--state-file", default=os.environ.get("STATE_FILE", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".eset_to_graylog_state.json")))
    ap.add_argument("--dry-run", action="store_true",
                    help="print GELF messages instead of sending them")
    ap.add_argument("--interval", type=int,
                    default=int(os.environ.get("INTERVAL_SECONDS", "0")),
                    help="run forever, syncing every N seconds (default: once)")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    user, password = os.environ.get("ESET_USER"), os.environ.get("ESET_PASS")
    pass_file = os.environ.get("ESET_PASS_FILE")
    if not password and pass_file:
        with open(pass_file) as f:
            password = f.read().strip()
    if not user or not password:
        sys.exit("ESET_USER and ESET_PASS (or ESET_PASS_FILE) must be set")

    client = EsetClient(user, password, os.environ.get("ESET_REGION", "eu"),
                        timeout=int(os.environ.get("ESET_TIMEOUT", "120")))

    if args.interval <= 0:
        sys.exit(run_once(client, args))
    log.info("running every %ds", args.interval)
    while True:
        err = run_once(client, args)
        if err:
            log.error("%s", err)
        time.sleep(args.interval)


def run_once(client, args):
    """One sync cycle. Returns an error string on failure, None on success."""
    state = load_state(args.state_file)
    now = datetime.now(timezone.utc)
    try:
        sender = GelfSender(os.environ.get("GRAYLOG_HOST", "127.0.0.1"),
                            int(os.environ.get("GRAYLOG_PORT", "12201")),
                            os.environ.get("GRAYLOG_PROTO", "udp").lower(),
                            dry_run=args.dry_run)
    except OSError as e:
        return f"cannot connect to Graylog: {e}"

    try:
        # the device list is also used to enrich indicators/incidents with PC name/IP
        devices = {d.get("uuid"): d for d in client.paginate(
            "device-management", "/v1/devices", "devices")}
        groups = fetch_group_names(client)
        if not args.no_devices:
            ship_devices(sender, devices, groups, now)
        if args.indicators:
            ship_optional("indicators", ship_indicators, client, sender, devices, groups,
                          state, args.lookback_hours, args.overlap_minutes)
        if args.incidents:
            ship_optional("incidents", ship_incidents, client, sender, devices, state)
    except urllib.error.HTTPError as e:
        return (f"ESET API error HTTP {e.code} at {e.url}: "
                f"{e.read().decode(errors='replace')[:500]}")
    except urllib.error.URLError as e:
        return f"connection error: {e.reason}"
    except OSError as e:
        return f"I/O error: {e}"
    finally:
        sender.close()
        # saved even after a partial run, so already shipped items aren't resent
        if not args.dry_run:
            save_state(args.state_file, state)
    return None


if __name__ == "__main__":
    main()
