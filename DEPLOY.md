## GitHub Actions Setup (Automatic Docker Builds)

### Step 1: Already Done
The code is already pushed to GitHub.

### Step 2: Add Docker Hub Secrets

1. Go to: https://github.com/xphox2/Firewall-Collector/settings/secrets/actions
2. Add these secrets:

| Secret Name | Value |
|-------------|-------|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Your Docker Hub access token |

**To get Docker Hub token:**
- Go to https://hub.docker.com/settings/security
- Click "New Access Token"
- Give it a name, set permissions to "Read, Write, Delete"
- Copy the token

### Step 3: Trigger Build

Push any commit to main branch:
```bash
git add .
git commit -m "Enable Docker auto-build"
git push origin master
```

### Step 4: Check Build Status

1. Go to **Actions** tab in your GitHub repo
2. You should see the build running
3. Once complete, image will be at: `docker.io/xphox/firewall-collector:latest`

---

**Now anyone can run:**
```bash
docker run -d \
  -e PROBE_REGISTRATION_KEY=your-key \
  xphox/firewall-collector:latest
```
