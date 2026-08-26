# Proxy IP Intelligence Checker v3

Personal/mobile-friendly Render web app for `host:port:username:password` proxy lists.

## Workflow

1. Parse each proxy line and connect through the proxy.
2. Ask an IP echo service for the detected public IP.
3. Deduplicate detected IPs.
4. Enrich unique IPs from multiple sources in parallel.
5. Show source attribution for major displayed values.
6. Show provider-level errors instead of silently treating missing data as a value.

## Enrichment sources

- **IP2Location.io** official API: basic geolocation/ASN/basic proxy data on the Free plan.
- **IPinfo** demo widget: geolocation/network/privacy fields when available.
- **ipapi.is**: ASN/company/usage and public risk indicators.
- **DB-IP Free API**: documented free location/ISP/ASN/connection/threat/proxy/VPN fields.
- **DB-IP public page**: IP-only compatibility fallback for threat/proxy values; HTML changes can break this parser.
- **IPQuality public data bridge**: the current IPQuality script calls `https://ipinfo.check.place/$IP?db=...` for Scamalytics, IP2Location, IPQS and AbuseIPDB; this app uses that same public endpoint pattern for additional risk fields.

IPQuality documents that it aggregates risk information from IPinfo, ipregistry, ipapi, AbuseIPDB, IP2Location, IPQS, DB-IP and Scamalytics and supports JSON output. This app uses that project as a reference and uses its public data bridge for extra source coverage rather than bundling/running the whole shell script. See https://github.com/xykt/IPQuality.

## Security

Proxy credentials are used only to establish the proxy connection. Only the detected IP is sent to enrichment providers. Raw proxy credentials are not stored. Errors are sanitized so request exceptions do not expose proxy URLs/credentials.

## Render environment variables

- `APP_PASSWORD`
- `FLASK_SECRET_KEY`
- Optional `IP2LOCATION_API_KEY`

## Keepalive

`.github/workflows/keepalive.yml` pings `/healthz` every 5 minutes. GitHub says scheduled workflows can run as often as every 5 minutes, but they may be delayed during busy periods. Public repositories also have scheduled workflows automatically disabled after 60 days without repository activity. Render Free services spin down after 15 minutes without inbound traffic, so keepalive reduces cold starts but is not a contractual guarantee.

## Known limits

- Render Free: 750 instance hours/workspace/month; if exhausted, Free web services are suspended. An always-awake service can consume almost the entire allowance by itself.
- Render Free services have limited CPU/RAM and can cold-start.
- IP2Location Free: 50,000 API queries/month; keyless use is 1,000/day. Advanced fields such as full ISP/usage/fraud/proxy-object coverage are not guaranteed on Free. Attribution is required.
- DB-IP Free API: 500 daily requests; batch queries have a 10% quota bonus. The public page parser is not a stable API.
- IPQuality/check.place is an external dependency. Its availability, rate limits and upstream provider behavior can change, and it is not an API under this project's control.
- A 20-proxy batch can result in several enrichment requests per unique IP. Deduplication prevents duplicate IPs from multiplying those requests.
- Some fields are not authoritative across providers. Conflicts are shown by source rather than silently presented as one “true” value.
- Scamalytics/IPQS/AbuseIPDB values are only available when the corresponding IPQuality bridge responds; this does not mean their underlying paid APIs are freely available to this application.
- No provider credentials are required except optional IP2Location API key. Do not put any provider or proxy secrets in GitHub.

## Deploy

Build: `pip install -r requirements.txt`
Start: `gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 180`
