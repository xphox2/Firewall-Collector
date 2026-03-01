# Firewall Collector - Lightweight probe for remote sites
FROM alpine:3.19 AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /build

COPY go.mod go.sum ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o firewall-collector ./cmd/collector

FROM alpine:3.19

RUN apk add --no-cache ca-certificates bash

WORKDIR /app

COPY --from=builder /build/firewall-collector .

EXPOSE 162/udp 514/udp 6343/udp

ENTRYPOINT ["./firewall-collector"]
