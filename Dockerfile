# Firewall Collector - Lightweight probe for remote sites
FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o firewall-collector ./cmd/collector

FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash

WORKDIR /app

COPY --from=builder /build/firewall-collector .

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

# Feature toggles (set to "false" to disable)
ENV PROBE_SNMP_TRAP_ENABLED="true"
ENV PROBE_SYSLOG_ENABLED="true"
ENV PROBE_SFLOW_ENABLED="true"
ENV PROBE_PING_ENABLED="true"

# SNMP Trap receiver
EXPOSE 162/udp
# Syslog receiver (TCP + UDP)
EXPOSE 514/tcp
EXPOSE 514/udp
# sFlow receiver
EXPOSE 6343/udp

LABEL org.opencontainers.image.title="Firewall Collector" \
      org.opencontainers.image.description="Lightweight probe for collecting firewall stats" \
      com.technicallabs.ports.snmp="162/udp - SNMP Trap receiver" \
      com.technicallabs.ports.syslog="514/tcp+udp - Syslog receiver" \
      com.technicallabs.ports.sflow="6343/udp - sFlow receiver"

ENTRYPOINT ["./firewall-collector"]
