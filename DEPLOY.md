# Deploying the collector

The collector ships as a container image on Docker Hub:
`xphox/firewall-collector`. Each release is tagged with its exact version
(e.g. `:1.3.45`), plus the moving `:1.3`, `:stable` and `:latest` aliases.

## Run it

You need a registration key from the server's admin UI (Probes page) and
the base URL of your Firewall-Mon server. Both are required; the collector
exits at startup if either is missing.

```bash
docker run -d --name firewall-collector \
  --network host \
  --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
  -v firewall-collector-queue:/queue \
  -e PROBE_REGISTRATION_KEY=your-key \
  -e PROBE_SERVER_URL=https://your-server.example.com \
  xphox/firewall-collector:1.3.45
```

Or use the repository's `docker-compose.yml`: fill in
`PROBE_REGISTRATION_KEY` and `PROBE_SERVER_URL`, then
`docker compose up -d`.

> **Upgrading to 1.3.45 or later:** `PROBE_SERVER_URL` no longer has a
> built-in default. If your container relied on the old image default, set
> the variable explicitly before pulling the new image.

Pin an exact patch tag (e.g. `:1.3.45`) for reproducible deployments. See
**README.md > Upgrading** for the upgrade and rollback procedure, and
[docs/ENV-VARS.md](docs/ENV-VARS.md) for every setting.

## Building your own image

```bash
docker build --build-arg BUILD_VERSION=1.3.45 -t firewall-collector:1.3.45 .
```

The repository's `.github/workflows/docker.yml` builds and pushes the image
on every push to the default branch. A fork that wants to publish its own
image sets two repository secrets: `DOCKERHUB_USERNAME` and
`DOCKERHUB_TOKEN` (a Docker Hub access token with read/write scope).
