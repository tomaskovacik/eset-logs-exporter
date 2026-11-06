# eset-logs-exporter

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

4. Run:

   ```bash
   docker compose up -d --build
   docker compose logs -f
   ```

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

- **0.2**: detections switched to v3 indicators (ECS, full view); v3 incidents added; message type field renamed `event_type` → `eset_type` (ECS uses `event.type`); late-arriving indicators handled with an overlap window; state saved after partial runs.
- **0.1**: device inventory and v1 detections.
