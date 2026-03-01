# Firewall Collector - Lightweight probe for remote sites
FROM golang:1.21-alpine AS builder

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

ENV PROBE_REGISTRATION_KEY=""
ENV PROBE_SERVER_URL="https://stats.technicallabs.org"

EXPOSE 162/udp 514/udp 6343/udp

ENTRYPOINT ["./firewall-collector"]
