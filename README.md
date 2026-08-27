# Proxy IPQuality Checker v5

Cloud web UI for small personal batches of `host:port:username:password` proxies.

## Architecture
The web app runs the upstream IPQuality Bash script inside the same Docker container. It uses its documented `-x` proxy support and `-j` JSON mode rather than reimplementing the provider integrations. The web request starts a job and polls for partial results, so a slow IPQuality run does not block Gunicorn.

This personal UI intentionally does not run the media/AI, email, or 400+ DNSBL sections because the user does not need those checks. The upstream script itself supports these modules and JSON output. See https://github.com/xykt/IPQuality.

## Render
Use Docker runtime. Start command is already in Dockerfile. Set `APP_PASSWORD` and `FLASK_SECRET_KEY` as Render environment variables.

## Security
Proxy credentials are used only as the `-x` argument to the local IPQuality process and are not sent to separate enrichment APIs by the web app. Never commit credentials or secrets.

## Limits
This build caps a batch at 20 unique proxy lines. Full IPQuality runs can still take up to ~150 seconds per proxy. Render Free has its own CPU/memory/time limits. The IPQuality upstream services have their own availability/rate/access policies. The keepalive workflow is best-effort and depends on GitHub Actions and Render quotas.
