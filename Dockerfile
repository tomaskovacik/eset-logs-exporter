FROM python:3.13-alpine

RUN apk add --no-cache tzdata \
 && addgroup -S exporter && adduser -S -G exporter -h /app exporter \
 && mkdir /data && chown exporter:exporter /data

WORKDIR /app
COPY --chown=exporter:exporter eset_to_graylog.py /app/eset_to_graylog.py

USER exporter
ENV PYTHONUNBUFFERED=1 \
    STATE_FILE=/data/state.json
VOLUME ["/data"]

ENTRYPOINT ["python", "/app/eset_to_graylog.py"]
