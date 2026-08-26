PROXY IP + IP2LOCATION CHECKER — CLOUD DEPLOYMENT

Recommended hosting: Render Free Web Service.
Your Windows laptop does NOT need to stay on. You use the app from Safari on iPhone or any browser.

DEPLOYMENT (Render)
1. Put this folder in a GitHub repository (private is recommended).
2. In Render, create New -> Web Service and connect the repository.
3. Runtime: Python 3.
4. Build command: pip install -r requirements.txt
5. Start command: gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --threads 8 --timeout 120
6. Plan: Free.
7. Add environment variables:
   APP_PASSWORD = a strong private password
   IP2LOCATION_API_KEY = optional; leave unset to use the keyless free endpoint.
   FLASK_SECRET_KEY = optional; if omitted, a random key is generated on each restart.

SECURITY
Set APP_PASSWORD. Otherwise anyone who discovers your URL could submit proxies through your server.
Do not put real proxy passwords into screenshots, GitHub, logs, or public posts.

USAGE
Open your Render URL in Safari. Paste one proxy per line, e.g.:
hostname:port:username:password
Then tap Check proxies.
The server connects through each proxy, discovers the public IP seen through it, and sends ONLY that IP to IP2Location.io.
Repeated detected IPs are looked up only once per batch to reduce API usage.

FREE HOSTING NOTE
Render's free web service can spin down after 15 minutes without inbound traffic and may take about a minute to wake. This is normal and means no always-on Windows machine is required.
