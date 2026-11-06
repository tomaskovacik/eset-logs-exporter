# eset-logs-exporter

Ships data from ESET PROTECT Cloud (via the [ESET Connect](https://help.eset.com/eset_connect/en-US/) REST API) to Graylog as GELF.

- **Device inventory**: name, hostname, local/public IP, OS, group, ESET product and agent versions, functionality status, last sync, BIOS serial, MAC addresses.
- **Detections** (optional): new detections since the last run, enriched with device name and IP.

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
./eset_to_graylog.py --dry-run        # print GELF messages, send nothing
./eset_to_graylog.py --detections     # one sync
./eset_to_graylog.py --interval 900   # sync every 15 minutes
```

`eset_api_test.sh` is a small curl/jq script to check that API credentials work.

## Configuration

| Variable | Default | |
|---|---|---|
| `ESET_USER` | | API user email |
| `ESET_PASS` / `ESET_PASS_FILE` | | password, or file containing it |
| `ESET_REGION` | `eu` | `eu`, `us`, `de`, `ca`, `jpn` |
| `GRAYLOG_HOST` | `127.0.0.1` | |
| `GRAYLOG_PORT` | `12201` | |
| `GRAYLOG_PROTO` | `udp` | `udp` or `tcp` |
| `INTERVAL_SECONDS` | `0` | `0` = run once |
| `SHIP_DETECTIONS` | `false` | |
| `STATE_FILE` | next to script | remembers the last shipped detection |
