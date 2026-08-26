PROXY IP INTELLIGENCE CHECKER — CLOUD

This version is designed for Render and mobile use. The Windows laptop can be off.

FEATURES
- Paste up to 50 proxy lines in host:port:username:password format.
- Checks proxies concurrently to discover the public IP seen through each proxy.
- Deduplicates repeated detected IPs before enrichment.
- DB-IP Free API is batch queried for a whole run (documented batch API).
- IP2Location.io uses its free single-IP endpoint in parallel; if you configure an IP2Location API key, the app will use the bulk endpoint when that plan supports it.
- Optional Scamalytics official API integration using credentials supplied through Render environment variables.
- Results show which provider supplied each field.
- Tapping/clicking a proxy or detected-IP cell copies the exact value to the clipboard.
- Health endpoint: /healthz.
- Optional GitHub Actions keepalive pings /healthz every 10 minutes.

KEEPALIVE / RENDER FREE
The included GitHub Actions workflow keeps the Render Free service receiving inbound requests so it normally stays awake. Render currently grants 750 free instance hours per workspace per calendar month; a continuously running single service is roughly 744 hours/month, so this leaves very little headroom for other free services. Render can still suspend services if the workspace exhausts its included free hours. A paid Render instance is the clean way to get an always-on service.

The workflow is not a background process on your phone or Windows laptop; GitHub runs it.
If you prefer to accept Render's normal cold start, simply delete .github/workflows/keepalive.yml.

ENVIRONMENT VARIABLES (RENDER)
- APP_PASSWORD: private app login password.
- FLASK_SECRET_KEY: long random secret for authentication tokens.
- IP2LOCATION_API_KEY: optional free-plan key. Without it the keyless endpoint is used.
- SCAMALYTICS_ENDPOINT: optional official API endpoint supplied by Scamalytics.
- SCAMALYTICS_API_TOKEN: optional Scamalytics API token.

SECURITY
- Raw proxy credentials are never sent to IP2Location.io, DB-IP, or Scamalytics. Only the detected IP is sent to enrichment providers.
- Do not log, screenshot, or commit real proxy credentials.
- Keep APP_PASSWORD, FLASK_SECRET_KEY and provider API tokens in Render environment variables only.

SCRAPING
This version intentionally does not scrape provider websites. Scamalytics' July 3, 2026 Terms expressly prohibit automated scraping/data extraction without prior written consent. Its official API and free bulk portal are the appropriate routes. DB-IP also provides an official batch API.

ATTRIBUTION
IP2Location.io's Free/keyless service requires visible attribution. DB-IP's free API/database also has attribution/licensing requirements. The UI includes links/attribution for both.

DEPLOY
Build: pip install -r requirements.txt
Start: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 120
