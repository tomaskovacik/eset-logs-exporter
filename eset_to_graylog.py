#!/usr/bin/env python3
"""Ship ESET PROTECT Cloud data (ESET Connect API) to Graylog as GELF.

Sends one message per device (name, hostname, IPs, OS, ESET versions,
status, last sync) and, optionally, new detections since the last run.
Hardware details are dropped except BIOS serial and MAC addresses
(kept for correlation with asset inventory and network logs).

Config via environment:
  ESET_USER, ESET_PASS     API user credentials (required)
  ESET_PASS_FILE           read the password from this file instead of ESET_PASS
  ESET_REGION              eu | us | de | ca | jpn (default: eu)
  GRAYLOG_HOST             Graylog GELF input host (default: 127.0.0.1)
  GRAYLOG_PORT             GELF input port (default: 12201)
  GRAYLOG_PROTO            udp | tcp (default: udp)

Examples:
  ./eset_to_graylog.py                       # devices only
  ./eset_to_graylog.py --detections          # devices + new detections
  ./eset_to_graylog.py --dry-run             # print GELF JSON, send nothing

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

log = logging.getLogger("eset2graylog")

SOURCE = "eset-protect"
SYSLOG_LEVEL = {"emerg": 0, "alert": 1, "crit": 2, "err": 3,
                "warning": 4, "notice": 5, "info": 6, "debug": 7}


# --------------------------------------------------------------------------
# ESET Connect API
# --------------------------------------------------------------------------

class EsetClient:
    def __init__(self, user, password, region="eu", timeout=30):
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
            "Accept": "application/json"})
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
        "event_type": "device_inventory",
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


def detection_level(severity):
    s = str(severity).upper()
    if "HIGH" in s or "CRITICAL" in s:
        return SYSLOG_LEVEL["err"]
    if "MEDIUM" in s:
        return SYSLOG_LEVEL["warning"]
    return SYSLOG_LEVEL["notice"]


def detection_fields(det, devices_by_uuid):
    fields = flatten(det)
    fields["event_type"] = "detection"
    # enrich with device identity so detections are searchable by PC/IP
    # v1: context.deviceUuid, v2: device.uuid
    dev_uuid = (det.get("context") or {}).get("deviceUuid") or (det.get("device") or {}).get("uuid")
    dev = devices_by_uuid.get(dev_uuid)
    if dev:
        fields.setdefault("device_name", dev.get("displayName"))
        fields.setdefault("hostname", dev.get("systemHostname"))
        fields.setdefault("local_ip", dev.get("primaryLocalIpAddress"))
        fields.setdefault("public_ip", dev.get("publicIpAddress"))
    name = det.get("displayName") or det.get("typeName") or det.get("category") or "detection"
    short = f"ESET detection: {name} on {fields.get('device_name', dev_uuid)}"
    return short, detection_level(det.get("severityLevel", "")), fields


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

def fetch_group_names(client):
    try:
        return {g.get("uuid"): g.get("displayName") or g.get("name")
                for g in client.paginate("device-management", "/v1/device_groups",
                                         "deviceGroups")}
    except urllib.error.HTTPError as e:
        log.warning("could not list device groups (HTTP %s), group_name omitted", e.code)
        return {}


def ship_devices(client, sender, now):
    devices = list(client.paginate("device-management", "/v1/devices", "devices"))
    groups = fetch_group_names(client)
    for dev in devices:
        sender.send(GelfSender.build(*device_fields(dev, groups, now)))
    log.info("sent %d device messages", len(devices))
    return {d.get("uuid"): d for d in devices}


def ship_detections(client, sender, devices_by_uuid, state, lookback_hours):
    since = parse_ts(state.get("last_detection_time")) or \
        datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
    params = {"startTime": since.strftime("%Y-%m-%dT%H:%M:%SZ")}
    newest = since
    count = 0
    try:
        # v2 needs a higher license tier (403 on PROTECT Complete); v1 works
        for det in client.paginate("incident-management", "/v1/detections",
                                   "detections", params):
            occurred = parse_ts(det.get("occurTime"))
            if occurred and occurred <= since:
                continue
            short, level, fields = detection_fields(det, devices_by_uuid)
            ts = occurred.timestamp() if occurred else None
            sender.send(GelfSender.build(short, level, fields, timestamp=ts))
            count += 1
            if occurred and occurred > newest:
                newest = occurred
    except urllib.error.HTTPError as e:
        log.error("detections request failed (HTTP %s): %s", e.code,
                  e.read().decode(errors="replace")[:500])
        return
    state["last_detection_time"] = newest.strftime("%Y-%m-%dT%H:%M:%SZ")
    log.info("sent %d detection messages (since %s)", count, params["startTime"])


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--detections", action="store_true",
                    default=os.environ.get("SHIP_DETECTIONS", "").lower() in ("1", "true", "yes"),
                    help="also ship detections newer than the last run")
    ap.add_argument("--no-devices", action="store_true",
                    help="skip device inventory messages")
    ap.add_argument("--lookback-hours", type=int, default=24,
                    help="detections window on first run (default: 24)")
    ap.add_argument("--state-file", default=os.environ.get("STATE_FILE", os.path.join(
        os.path.dirname(os.path.abspath(__file__)), ".eset_to_graylog_state.json")))
    ap.add_argument("--dry-run", action="store_true",
                    help="print GELF messages instead of sending them")
    ap.add_argument("--interval", type=int,
                    default=int(os.environ.get("INTERVAL_SECONDS", "0")),
                    help="run forever, syncing every N seconds (default: once)")
    ap.add_argument("-v", "--verbose", action="store_true")
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

    client = EsetClient(user, password, os.environ.get("ESET_REGION", "eu"))

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
        devices_by_uuid = {}
        if not args.no_devices or args.detections:
            # device list is also used to enrich detections with PC name/IP
            if args.no_devices:
                devices_by_uuid = {d.get("uuid"): d for d in client.paginate(
                    "device-management", "/v1/devices", "devices")}
            else:
                devices_by_uuid = ship_devices(client, sender, now)
        if args.detections:
            ship_detections(client, sender, devices_by_uuid, state, args.lookback_hours)
            if not args.dry_run:
                save_state(args.state_file, state)
    except urllib.error.HTTPError as e:
        return (f"ESET API error HTTP {e.code} at {e.url}: "
                f"{e.read().decode(errors='replace')[:500]}")
    except urllib.error.URLError as e:
        return f"connection error: {e.reason}"
    except OSError as e:
        return f"send error: {e}"
    finally:
        sender.close()
    return None


if __name__ == "__main__":
    main()
