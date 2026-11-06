# eset-logs-exporter

[![CI](https://github.com/tomaskovacik/eset-logs-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/tomaskovacik/eset-logs-exporter/actions/workflows/ci.yml)

Ships data from ESET PROTECT Cloud (via the [ESET Connect](https://help.eset.com/eset_connect/en-US/) REST API) to Graylog as GELF.

Every message has an `eset_type` field:

| `eset_type` | Source | Content |
|---|---|---|
| `device` | Device Management v1 | One message per device on every run: name, hostname, local/public IP, OS, group, ESET product and agent versions, functionality status, last sync, days since sync, BIOS serial, MAC addresses |
| `indicator` | Incident Management v3 `/v3/indicators` | Detection events in ECS format (full view), flattened to `host_ip`, `process_user_name`, `rule_name`, `url_full`, `file_hash_sha256`, … Only new ones are sent. |
| `incident` | Incident Management v3 `/v3/incidents` | Incidents that are new or changed since the last run: status, severity, MITRE technique IDs, affected devices |

Indicators and incidents are enriched with `device_name`, `hostname`, `local_ip`, `public_ip` and `group_name` from the device list, so all message types can be searched the same way. The GELF level follows ECS `event.risk_score` for indicators and severity for incidents.

Python standard library only, no dependencies.

## Setup

1. In ESET PROTECT Hub / ESET Business Account, create a dedicated API user with **Integrations** enabled and read access to ESET PROTECT.
2. In Graylog, create a GELF TCP (or UDP) input.
3. Configure:

   ```bash
   cp .env.example .env              # set ESET_USER, ESET_REGION, GRAYLOG_*
   printf '%s' 'api-password' > .pwd # mounted as a Docker secret
   ```

4. Run the published image (`linux/amd64`, `linux/arm64`):

   ```bash
   docker compose pull && docker compose up -d
   docker compose logs -f
   ```

   or build it locally with `docker compose up -d --build`.

### On a server (published image only)

[`examples/docker-compose.yml`](examples/docker-compose.yml) is self-contained: copy it and a password file to the server, set `ESET_USER` and `GRAYLOG_HOST`, and run `docker compose up -d`. Instructions are in the file header.

## Graylog setup

[`graylog/setup_graylog.py`](graylog/setup_graylog.py) creates (or updates, by title) everything on the Graylog side. Re-running it is safe.

- **Index set and stream** "ESET PROTECT", fed from the exporter's GELF input and removed from the Default Stream.
- **Pipeline** `eset-protect`: GeoIP country, ASN and AS organisation for `public_ip` (devices) and `destination_ip` (blocked web destinations), and `outside_home_country=true` on devices that synced in the last day from a public IP outside your country.
- **Alerts**: device online outside home country, malware cleaned or deleted, ARP cache poisoning, high-risk indicator, incident opened or changed, device protection needs attention, exporter feed stopped.
- **Dashboard** "ESET PROTECT" with Security events, Devices, Web and network, and Feed health tabs.

It needs lookup tables named `geoip-country` and `geoip-asn` (MaxMind GeoLite2 or DB-IP Lite with the *Geo IP - MaxMind* adapter).

```bash
cp graylog/exceptions.example.json graylog/exceptions.json   # git-ignored, edit it
graylog/setup_graylog.py --url https://graylog.example.com --token-file ~/.gltok \
    --input-id <GELF input id> [--notification-id <id>] [--dry-run]
```

### Known exceptions

`graylog/exceptions.json` holds what is expected in your environment. It names people, devices and company IPs, so it is git-ignored; [`exceptions.example.json`](graylog/exceptions.example.json) is an anonymised copy of a real deployment's file.

| Key | Effect |
|---|---|
| `home_country` | country devices are expected in (default `SK`) |
| `trusted_egress` | public IPs/ranges never treated as abroad. Matters for VPNs or hosted sites whose exit IP geolocates elsewhere: without it every device behind them alerts |
| `device_home_countries` | per-device countries that are not "abroad", for people based abroad. Only list home countries: trips are what the alert is for |
| `alert_exclusions` | per-alert extra `AND NOT (...)` clauses, keyed by exact alert title |

Keys starting with `_` and every `note` are ignored, so entries can carry their reasoning. Unknown alert titles are rejected. Edit the file and re-run the script.

Graylog grace periods suppress repeat *notifications*, not events, so without `--notification-id` the event list shows every evaluation.

ESET PROTECT console logins are not in the ESET Connect API. They are only available through ESET PROTECT's own syslog export (Audit category), which needs a syslog receiver reachable from the internet.

## Running without Docker

```bash
export ESET_USER=api-user@example.com ESET_PASS_FILE=.pwd ESET_REGION=eu
export GRAYLOG_HOST=127.0.0.1 GRAYLOG_PORT=12201 GRAYLOG_PROTO=udp
./eset_to_graylog.py --dry-run --indicators --incidents  # print GELF, send nothing
./eset_to_graylog.py --indicators --incidents            # one sync
./eset_to_graylog.py --interval 900 --indicators         # sync every 15 minutes
```

`eset_api_test.sh` is a small curl/jq script to check that API credentials work.

## Configuration

| Variable | Option | Default | |
|---|---|---|---|
| `ESET_USER` | | | API user email |
| `ESET_PASS` / `ESET_PASS_FILE` | | | password, or file containing it |
| `ESET_REGION` | | `eu` | `eu`, `us`, `de`, `ca`, `jpn` |
| `ESET_TIMEOUT` | | `120` | API request timeout, seconds |
| `GRAYLOG_HOST` | | `127.0.0.1` | |
| `GRAYLOG_PORT` | | `12201` | |
| `GRAYLOG_PROTO` | | `udp` | `udp` or `tcp` |
| `INTERVAL_SECONDS` | `--interval` | `0` | `0` = run once |
| `SHIP_INDICATORS` | `--indicators` | `false` | |
| `SHIP_INCIDENTS` | `--incidents` | `false` | |
| `SKIP_DEVICES` | `--no-devices` | `false` | |
| `LOOKBACK_HOURS` | `--lookback-hours` | `24` | indicators window on the first run (ESET keeps ~30 days) |
| `OVERLAP_MINUTES` | `--overlap-minutes` | `60` | re-read window for indicators ESET registers late |
| `STATE_FILE` | `--state-file` | next to script | what was already shipped |

## API availability

What the API returns depends on your ESET subscription. Tested with **ESET PROTECT Entry**:

| Endpoint | Result |
|---|---|
| `device-management /v1/devices`, `/v1/device_groups` | ✅ |
| `incident-management /v3/indicators`, `/v3/incidents` | ✅ |
| `incident-management /v1/detections` | ✅ (ESET plans to retire v1/v2) |
| `incident-management /v2/detections`, quarantine, user management | 403, ESET Cloud Office Security only |
| `vulnerability-management` | empty without V&PM |

If an optional source fails (403/404), the error is logged and the other sources are still shipped.

## Changelog

- **0.2**: unit tests, GitHub Actions CI and image release to ghcr.io; detections switched to v3 indicators (ECS, full view); v3 incidents added; message type field renamed `event_type` → `eset_type` (ECS uses `event.type`); late-arriving indicators handled with an overlap window; state saved after partial runs.
- **0.1**: device inventory and v1 detections.

## Development

```bash
python3 -m unittest discover -s tests -v   # offline tests, no API access needed
ruff check .
shellcheck eset_api_test.sh
```

CI (`.github/workflows/ci.yml`) runs lint, the tests on Python 3.10–3.13 and a Docker build on every push and pull request.

### Releasing

1. Bump `__version__` in `eset_to_graylog.py` and add a changelog entry.
2. Tag the commit with the same version and push it: `git tag -s 0.3 -m 0.3 && git push origin 0.3`.
3. `.github/workflows/release.yml` runs CI, checks the tag matches `__version__`, pushes `ghcr.io/tomaskovacik/eset-logs-exporter:<version>` and `:latest`, and creates the GitHub release.

## License

GNU General Public License v3.0 or later, see [LICENSE](LICENSE).
