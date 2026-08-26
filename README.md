# Proxy IP & IP2Location Checker

Private web tool for checking authenticated proxies in `host:port:username:password` format.

## What this version adds

- Concurrent proxy checks (up to 20 at once).
- Concurrent IP2Location lookups for unique detected IPs.
- Reuses one IP2Location lookup when multiple proxies exit through the same IP.
- Click any proxy or detected IP to copy it to the clipboard.
- `/health` endpoint for uptime monitoring.
- GitHub Actions workflow that pings `/health` every 10 minutes to reduce Render free-tier cold starts.
- Shows the main data source: `ipify.org` for detected exit IP and `IP2Location.io` for geolocation/proxy intelligence.
- Displays ISP, ASN, AS name, usage type, proxy flag, fraud score and proxy-detection flags when returned by IP2Location.io.

## Important IP2Location note

The documented IP2Location.io bulk endpoint supports large batches but requires a paid plan. This project therefore keeps the normal free/keyed single-IP endpoint and performs unique IP lookups concurrently. `IP2LOCATION_BULK_ENABLED=true` is included only as an optional switch for users who have a plan that supports the bulk endpoint.

## Keep-alive

The GitHub Actions workflow is deliberately used instead of a Render Cron Job because Render Cron Jobs have a minimum monthly charge. The workflow calls `/health` every 10 minutes. Scheduled GitHub Actions can occasionally be delayed, so this reduces but cannot absolutely guarantee zero cold starts.

## Security

Proxy credentials are sent to this application because the application must connect through the proxy. Keep the repository free of credentials and do not paste real proxy lists into public GitHub issues, commits, logs, or screenshots.
