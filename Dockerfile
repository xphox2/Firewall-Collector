# Firewall Collector - Lightweight probe for remote sites
FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o firewall-collector ./cmd/collector

# alpine 3.21 — 3.19 reached end-of-life ~Nov 2025 (2026-06-23 audit, M13). This
# runtime only needs ca-certificates + bash (no bundled packages to re-pin).
FROM alpine:3.21

RUN apk add --no-cache ca-certificates bash

WORKDIR /app

COPY --from=builder /build/firewall-collector .

# Defense in depth (AUDIT-047): drop root in the runtime stage. Alpine ships
# the `nobody` user/group at uid/gid 65534. The binary is copied as root, then
# we explicitly strip the write bit and switch to the unprivileged user. A
# future RCE in the syslog/sFlow/TFTP/SNMP-trap parsers no longer grants a
# root shell on the management LAN.
#
# Rootless privileged-port binding: the probe binds 69/162/514 (all < 1024)
# but runs as 'nobody'. `cap_add` in compose only adds caps to the container's
# BOUNDING set; a non-root process needs the capability in its EFFECTIVE set,
# which Docker does NOT guarantee for a non-root USER (no ambient-capability
# promotion on some runtimes — notably Synology Container Manager), so the bind
# fails with EACCES. File capabilities fix this: `setcap +ep` makes the binary
# acquire the caps on exec regardless of uid/ambient state. cap_net_raw also
# covers ICMP ping. The compose must still list NET_RAW + NET_BIND_SERVICE in
# cap_add so the bounding set permits them (file caps can't exceed it). setcap
# runs LAST so the preceding chown can't drop the capability xattr.
RUN chmod 555 /app/firewall-collector && \
    mkdir -p /queue && \
    chown 65534:65534 /app /queue && \
    apk add --no-cache --virtual .setcap libcap && \
    setcap 'cap_net_bind_service=+ep cap_net_raw=+ep' /app/firewall-collector && \
    apk del .setcap
USER 65534:65534

# Server connection
ENV PROBE_REGISTRATION_KEY=""
ENV PROBE_SERVER_URL="https://stats.technicallabs.org"

# Intervals (in seconds)
ENV PROBE_HEARTBEAT_INTERVAL="60"
ENV PROBE_SYNC_INTERVAL="30"
ENV PROBE_POLL_INTERVAL="60"
ENV PROBE_DEVICE_REFRESH_INTERVAL="300"
ENV PROBE_PING_INTERVAL="60"
ENV PROBE_PING_TIMEOUT="5"
ENV PROBE_PING_COUNT="4"

# Listener configuration
ENV PROBE_LISTEN_ADDR="0.0.0.0"
ENV PROBE_SNMP_TRAP_PORT="162"
ENV PROBE_SYSLOG_PORT="514"
ENV PROBE_SFLOW_PORT="6343"
ENV PROBE_SNMP_TRAP_COMMUNITY=""

# Disk-spillover queue (AUDIT-058): buffers telemetry to disk when the central
# server is unreachable so nothing is lost during an outage or restart. /queue
# is created and chowned to the rootless uid above; mount a volume there for
# durability across container recreation. Set to "" to disable spillover.
ENV PROBE_QUEUE_DISK_PATH="/queue"

# Feature toggles (set to "false" to disable)
ENV PROBE_SNMP_TRAP_ENABLED="true"
ENV PROBE_SYSLOG_ENABLED="true"
ENV PROBE_SFLOW_ENABLED="true"
ENV PROBE_PING_ENABLED="true"

# TFTP config fetch enabled by default (uses PROBE_LISTEN_ADDR + PROBE_TFTP_PORT=69)

# SNMP Trap receiver
EXPOSE 162/udp
# Syslog receiver (TCP + UDP)
EXPOSE 514/tcp
EXPOSE 514/udp
# sFlow receiver
EXPOSE 6343/udp
# TFTP config backup receiver
EXPOSE 69/udp

ARG BUILD_VERSION=dev
LABEL org.opencontainers.image.title="Firewall Collector" \
      org.opencontainers.image.version="${BUILD_VERSION}" \
      org.opencontainers.image.description="Lightweight probe for collecting firewall stats" \
      com.technicallabs.ports.snmp="162/udp - SNMP Trap receiver" \
      com.technicallabs.ports.syslog="514/tcp+udp - Syslog receiver" \
      com.technicallabs.ports.sflow="6343/udp - sFlow receiver" \
      com.technicallabs.ports.tftp="69/udp - TFTP config backup receiver"

STOPSIGNAL SIGTERM

ENTRYPOINT ["./firewall-collector"]
