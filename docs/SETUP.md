# Setup & Deployment

## Prerequisites

- Python 3.10+
- (Optional, for PDF export) system libraries required by WeasyPrint:
  Pango, Cairo, GDK-Pixbuf, libffi. On Debian/Ubuntu:
  ```bash
  sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libcairo2 \
       libgdk-pixbuf2.0-0 libffi-dev
  ```

## Local installation

```bash
git clone <this-repo-url> security-header-analyzer
cd security-header-analyzer

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python app.py
```

Open `http://127.0.0.1:5000`.

Set `FLASK_DEBUG=1` to enable Flask's debug/reload mode during
development (do not use in any shared/production environment).

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `HEADER_ANALYZER_SECRET_KEY` | Flask session/flash signing key | random per-process |
| `FLASK_DEBUG` | `1` enables Flask debug mode | `0` |

For anything beyond local/single-user use, set `HEADER_ANALYZER_SECRET_KEY`
explicitly and run behind a production WSGI server.

## Deployment

### Option A — Docker Compose (recommended)

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_hex(32))"   # paste into .env

docker compose up -d --build
```

Open `http://<host>:5000`. Logs: `docker compose logs -f`. Stop:
`docker compose down`.

The image runs the app under **gunicorn** as a non-root user, with
WeasyPrint's system dependencies already installed so PDF export works
out of the box.

Put a reverse proxy (nginx, Caddy, Traefik) in front for TLS termination.

### Option B — Bare metal with gunicorn + systemd + nginx

1. Install as above (venv + `pip install -r requirements.txt`, which
   includes `gunicorn`).

2. Create `/etc/systemd/system/header-analyzer.service`:
   ```ini
   [Unit]
   Description=Security Header Analyzer
   After=network.target

   [Service]
   User=www-data
   WorkingDirectory=/opt/security-header-analyzer
   Environment="HEADER_ANALYZER_SECRET_KEY=<random-hex>"
   ExecStart=/opt/security-header-analyzer/.venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 2 --timeout 60 app:app
   Restart=on-failure

   [Install]
   WantedBy=multi-user.target
   ```

3. Enable and start:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now header-analyzer
   ```

4. Put nginx in front for TLS:
   ```nginx
   server {
       listen 443 ssl;
       server_name headers.internal.example.com;
       # ssl_certificate / ssl_certificate_key ...
       location / { proxy_pass http://127.0.0.1:5000; }
   }
   ```

### Production checklist

- [ ] Set a real, random `HEADER_ANALYZER_SECRET_KEY` — required for
      sessions/flash messages to work correctly across multiple gunicorn
      workers.
- [ ] `FLASK_DEBUG` unset or `0`.
- [ ] Run behind gunicorn, never Flask's built-in dev server.
- [ ] Put the tool behind authentication (nginx basic auth, VPN-only
      access, or an auth proxy) — as shipped, anyone who can reach the
      app can trigger a scan that originates from your server's IP.
- [ ] Terminate TLS at the reverse proxy; don't expose the raw gunicorn
      port directly.
- [ ] If internet-facing, rate-limit the `/` POST route to prevent the
      tool being used to scan arbitrary third parties from your
      infrastructure.

## Running the test suite

```bash
python -m unittest test_analyzer.py -v
```

The test suite mocks all network calls, so it runs offline and quickly.
