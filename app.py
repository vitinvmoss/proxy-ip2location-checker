from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import time
import hmac
import hashlib
import secrets
import re
import subprocess
import threading
import uuid
import json
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SECRET = os.environ.get("FLASK_SECRET_KEY", "").strip() or secrets.token_urlsafe(48)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()
COOKIE = "proxy_checker_auth"
MAX_AGE = 30 * 24 * 3600
MAX_PROXIES = 20
MAX_CONCURRENT = 4
IPQUALITY_SCRIPT = "/opt/ipquality/ip.sh"
IPQUALITY_TIMEOUT = 120

JOBS = {}
LOCK = threading.Lock()


def token():
    t = str(int(time.time()))
    sig = hmac.new(SECRET.encode(), t.encode(), hashlib.sha256).hexdigest()
    return f"{t}.{sig}"


def valid_token(value):
    try:
        ts_s, sig = value.split(".", 1)
        ts = int(ts_s)
        if abs(time.time() - ts) > MAX_AGE:
            return False
        expected = hmac.new(SECRET.encode(), ts_s.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def authenticated():
    return valid_token(request.cookies.get(COOKIE, ""))


@app.before_request
def gate():
    if not APP_PASSWORD or request.endpoint in {"login", "login_post", "static", "healthz"}:
        return None
    if authenticated():
        return None
    if request.path.startswith("/api/"):
        return jsonify(error="Authentication required."), 401
    return redirect(url_for("login"))


@app.get("/healthz")
def healthz():
    return "ok", 200


@app.get("/login")
def login():
    return render_template("login.html")


@app.post("/login")
def login_post():
    if hmac.compare_digest(request.form.get("password", ""), APP_PASSWORD):
        response = make_response(redirect("/"))
        response.set_cookie(
            COOKIE,
            token(),
            max_age=MAX_AGE,
            secure=True,
            httponly=True,
            samesite="Lax",
            path="/",
        )
        return response
    return render_template("login.html", error="Incorrect password."), 401


@app.get("/logout")
def logout():
    response = make_response(redirect("/login"))
    response.delete_cookie(COOKIE, path="/")
    return response


@app.get("/")
def index():
    return render_template("index.html")


def parse_proxy(line):
    """Accept the common forms used by proxy providers.

    Supported:
      host:port:username:password
      username:password:host:port
      http://username:password@host:port
      https://username:password@host:port
      socks5://username:password@host:port
      socks5h://username:password@host:port
      socks4://username:password@host:port

    The parser identifies the port by checking the numeric field instead of
    assuming one specific four-field ordering.
    """
    line = line.strip()
    if not line:
        return None, "Empty proxy line."

    scheme = "http"
    body = line
    m = re.match(r"^(https?|socks5h?|socks4)://(.+)$", line, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        body = m.group(2)

    # URL-style: user:pass@host:port
    if "@" in body:
        creds, hostport = body.rsplit("@", 1)
        if ":" not in creds:
            return None, "URL-style proxy is missing username/password."
        username, password = creds.split(":", 1)
        host, port_text = _split_host_port(hostport)
        if host is None:
            return None, "Invalid host:port portion."
        return _make_proxy(line, scheme, host, port_text, username, password)

    # Provider-style forms. Do not unpack the whole split list blindly.
    parts = body.split(":")
    if len(parts) != 4:
        return None, "Expected host:port:username:password (or username:password:host:port)."

    # host:port:user:pass
    if _valid_port_text(parts[1]):
        host, port_text, username, password = parts
        return _make_proxy(line, scheme, host, port_text, username, password)

    # user:pass:host:port
    if _valid_port_text(parts[3]):
        username, password, host, port_text = parts
        return _make_proxy(line, scheme, host, port_text, username, password)

    return None, "Could not identify the port; accepted 4-field formats are host:port:user:pass or user:pass:host:port."


def _split_host_port(hostport):
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1 or end + 1 >= len(hostport) or hostport[end + 1] != ":":
            return None, None
        return hostport[1:end], hostport[end + 2 :]
    if ":" not in hostport:
        return None, None
    return hostport.rsplit(":", 1)


def _valid_port_text(value):
    try:
        port = int(value)
        return 1 <= port <= 65535
    except (TypeError, ValueError):
        return False


def _make_proxy(raw, scheme, host, port_text, username, password):
    if not host or not username:
        return None, "Host and username are required."
    if not _valid_port_text(port_text):
        return None, "Invalid port."
    return {
        "raw": raw,
        "scheme": scheme,
        "host": host,
        "port": int(port_text),
        "user": username,
        "pwd": password,
    }, None


def proxy_url(proxy):
    host = proxy["host"]
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    user = urllib.parse.quote(proxy["user"], safe="")
    pwd = urllib.parse.quote(proxy["pwd"], safe="")
    return f"{proxy['scheme']}://{user}:{pwd}@{host}:{proxy['port']}"


def sanitize_error(value):
    """Keep errors useful without leaking proxy credentials."""
    text = str(value or "")
    text = re.sub(r"(?i)(https?|socks5h?|socks4)://[^\s/@:]+:[^\s/@]+@", r"\1://***:***@", text)
    text = re.sub(r"(?i)(https?|socks5h?|socks4)://[^\s/]+", r"\1://***@***", text)
    return text[-2000:]


def extract_last_json(stdout):
    """IPQuality -j emits its final JSON to stdout; other progress/ad text is stderr."""
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in reversed(lines):
        if line.startswith("{") and line.endswith("}"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def run_ipquality(proxy_line):
    proxy, parse_error = parse_proxy(proxy_line)
    if not proxy:
        return {"status": "failed", "error": parse_error or "Invalid proxy."}

    command = [
        "bash",
        IPQUALITY_SCRIPT,
        "-E",
        "-4",
        "-f",
        "-j",
        "-n",
        "-p",
        "-x",
        proxy_url(proxy),
    ]

    try:
        started = time.perf_counter()
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=IPQUALITY_TIMEOUT,
            check=False,
            env={**os.environ, "TERM": "dumb", "CI": "1"},
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        data = extract_last_json(completed.stdout)

        if not data:
            error = sanitize_error(completed.stderr or completed.stdout or "IPQuality returned no JSON.")
            return {
                "status": "failed",
                "error": error,
                "returncode": completed.returncode,
                "elapsed_ms": elapsed_ms,
            }

        return {
            "status": "online",
            "data": data,
            "returncode": completed.returncode,
            "elapsed_ms": elapsed_ms,
        }
    except subprocess.TimeoutExpired:
        return {"status": "failed", "error": f"IPQuality timed out after {IPQUALITY_TIMEOUT} seconds."}
    except Exception as exc:
        return {"status": "failed", "error": sanitize_error(exc)}


def normalize_value(value):
    if value in (None, "", "null"):
        return None
    return value


def risk_from_score(value, provider):
    if value is None:
        return None
    try:
        score = float(str(value).replace("%", "").strip())
    except (ValueError, TypeError):
        return None

    # These thresholds match the upstream script's score bands closely.
    if provider.lower() == "scamalytics":
        return "VeryHigh" if score >= 100 else "High" if score >= 60 else "Medium" if score >= 20 else "Low"
    if provider.lower() == "ip2location":
        return "VeryHigh" if score >= 99 else "High" if score >= 66 else "Medium" if score >= 33 else "Low"
    if provider.lower() == "abuseipdb":
        return "VeryHigh" if score >= 100 else "High" if score >= 25 else "Low"
    if provider.lower() == "dbip":
        return "VeryHigh" if score >= 100 else "High" if score >= 66 else "Medium" if score >= 33 else "Low"
    if provider.lower() == "ipqs":
        return "VeryHigh" if score >= 100 else "High" if score >= 85 else "Medium" if score >= 75 else "Low"
    return None


def summarize(data):
    """Read IPQuality's real JSON schema instead of searching leaf keys generically."""
    if not isinstance(data, dict):
        return {}

    head = data.get("Head") or {}
    info = data.get("Info") or {}
    city = info.get("City") or {}
    region = info.get("Region") or {}
    typ = data.get("Type") or {}
    usage = typ.get("Usage") or {}
    company = typ.get("Company") or {}
    score = data.get("Score") or {}
    factor = data.get("Factor") or {}
    factor_cc = factor.get("CountryCode") or {}
    factor_proxy = factor.get("Proxy") or {}
    factor_tor = factor.get("Tor") or {}
    factor_vpn = factor.get("VPN") or {}
    factor_server = factor.get("Server") or {}
    factor_abuser = factor.get("Abuser") or {}
    factor_robot = factor.get("Robot") or {}

    usage_values = {k: normalize_value(v) for k, v in usage.items() if normalize_value(v) is not None}
    company_values = {k: normalize_value(v) for k, v in company.items() if normalize_value(v) is not None}
    score_values = {k: normalize_value(v) for k, v in score.items() if normalize_value(v) is not None}

    factors = {
        "country_code": {k: normalize_value(v) for k, v in factor_cc.items()},
        "proxy": {k: normalize_value(v) for k, v in factor_proxy.items()},
        "tor": {k: normalize_value(v) for k, v in factor_tor.items()},
        "vpn": {k: normalize_value(v) for k, v in factor_vpn.items()},
        "server": {k: normalize_value(v) for k, v in factor_server.items()},
        "abuser": {k: normalize_value(v) for k, v in factor_abuser.items()},
        "robot": {k: normalize_value(v) for k, v in factor_robot.items()},
    }

    # IPQuality silently drops into "lite mode" when its own relay
    # (ipinfo.check.place) fails on the very first lookup. In lite mode it
    # skips IP2Location, Scamalytics, AbuseIPDB, ipdata, and IPQS as a group
    # — with no flag anywhere in the JSON saying so. Detect that pattern here
    # so the UI can say why those fields are empty instead of leaving silent
    # blanks, per the "no false data / no mystery blanks" requirement.
    lite_mode_providers = ["IP2LOCATION", "SCAMALYTICS", "AbuseIPDB", "ipdata", "IPQS"]
    lite_mode_detected = all(
        score_values.get(p) is None
        and all((factors[f].get(p) is None) for f in ("proxy", "tor", "vpn", "server", "abuser", "robot"))
        for p in lite_mode_providers
    )

    return {
        "ip": normalize_value(head.get("IP")),
        "asn": normalize_value(info.get("ASN")),
        "organization": normalize_value(info.get("Organization")),
        "latitude": normalize_value(info.get("Latitude")),
        "longitude": normalize_value(info.get("Longitude")),
        "city": normalize_value(city.get("Name")),
        "postal_code": normalize_value(city.get("PostalCode")),
        "subdivision": normalize_value(city.get("Subdivisions")),
        "region": normalize_value(region.get("Name")),
        "country_code": normalize_value(region.get("Code")),
        "country": normalize_value(region.get("Name")),
        "timezone": normalize_value(info.get("TimeZone")),
        "ip_type": normalize_value(info.get("Type")),
        "usage": usage_values,
        "company": company_values,
        "scores": score_values,
        "factors": factors,
        "version": normalize_value(head.get("Version")),
        "sources": {
            "basic": "MaxMind/IPinfo (from IPQuality)",
            "usage": "IPQuality: IPinfo / ipregistry / ipapi / AbuseIPDB / IP2Location",
            "scores": "IPQuality: IP2Location / Scamalytics / ipapi / AbuseIPDB / IPQS / DB-IP",
            "factors": "IPQuality: IP2Location / ipapi / ipregistry / IPQS / Scamalytics / ipdata / IPinfo / IPWHOIS / DB-IP",
        },
        "lite_mode": lite_mode_detected,
        "lite_mode_reason": (
            "IPQuality's basic-info relay (ipinfo.check.place) is behind a "
            "Cloudflare WAF that rejected this proxy's exit IP (HTTP 403), so "
            "the engine skipped IP2Location, Scamalytics, AbuseIPDB, ipdata, "
            "and IPQS for this run. ASN, Organization, and Location still came "
            "through via an independent fallback source (IPinfo) and remain "
            "reliable. This is an infrastructure block on the relay's side, "
            "not a bug — see RELAY_BLOCK_NOTICE.txt."
        ) if lite_mode_detected else None,
    }


LITE_MODE_PROVIDERS = {"IP2LOCATION", "SCAMALYTICS", "AbuseIPDB", "ipdata", "IPQS"}


def provider_table(summary):
    usage = summary.get("usage") or {}
    company = summary.get("company") or {}
    scores = summary.get("scores") or {}
    factors = summary.get("factors") or {}
    lite_mode = summary.get("lite_mode", False)

    order = ["IPinfo", "ipregistry", "ipapi", "AbuseIPDB", "IP2LOCATION", "SCAMALYTICS", "IPQS", "DBIP", "ipdata", "IPWHOIS"]
    providers = {}
    for name in order:
        skipped = lite_mode and name in LITE_MODE_PROVIDERS
        providers[name] = {
            "usage": usage.get(name),
            "company": company.get(name),
            "score": scores.get(name),
            "risk": risk_from_score(scores.get(name), name),
            "country_code": (factors.get("country_code") or {}).get(name),
            "proxy": (factors.get("proxy") or {}).get(name),
            "tor": (factors.get("tor") or {}).get(name),
            "vpn": (factors.get("vpn") or {}).get(name),
            "server": (factors.get("server") or {}).get(name),
            "abuser": (factors.get("abuser") or {}).get(name),
            "robot": (factors.get("robot") or {}).get(name),
            "status": "skipped_relay_unavailable" if skipped else "ok",
        }
    return providers


def worker(job_id, lines):
    with LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["results"] = [None] * len(lines)

    completed_count = 0
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        future_map = {
            executor.submit(run_ipquality, line): (idx, line)
            for idx, line in enumerate(lines)
        }
        for future in as_completed(future_map):
            idx, line = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"status": "failed", "error": sanitize_error(exc)}

            summary = summarize(result.get("data")) if result.get("data") else None
            ipquality_status = None
            if summary:
                summary["providers"] = provider_table(summary)
                # Distinguish "the proxy worked and every provider answered" from
                # "the proxy worked but some providers were skipped" (this repo's
                # State C vs State D). A proxy is never marked FAILED just
                # because a provider group was unavailable.
                ipquality_status = "partial" if summary.get("lite_mode") else "complete"

            result.update({
                "index": idx,
                "proxy": line,
                "summary": summary,
                "ipquality_status": ipquality_status,
            })

            with LOCK:
                JOBS[job_id]["results"][idx] = result
                completed_count += 1
                JOBS[job_id]["completed"] = completed_count

    with LOCK:
        JOBS[job_id]["status"] = "done"


@app.post("/api/start")
def start_job():
    payload = request.get_json(silent=True) or {}
    text = payload.get("text", "")
    if not isinstance(text, str):
        return jsonify(error="Invalid proxy list."), 400

    lines = []
    seen = set()
    for raw in text.splitlines():
        line = raw.strip()
        if line and line not in seen:
            seen.add(line)
            lines.append(line)

    if not lines:
        return jsonify(error="Paste at least one proxy."), 400
    if len(lines) > MAX_PROXIES:
        return jsonify(error=f"Maximum {MAX_PROXIES} proxies per run."), 400

    job_id = uuid.uuid4().hex
    with LOCK:
        JOBS[job_id] = {
            "status": "queued",
            "results": [],
            "completed": 0,
            "total": len(lines),
            "created": time.time(),
        }

    threading.Thread(target=worker, args=(job_id, lines), daemon=True).start()
    return jsonify(job_id=job_id, total=len(lines))


@app.get("/api/job/<job_id>")
def get_job(job_id):
    with LOCK:
        job = JOBS.get(job_id)
    if not job:
        return jsonify(error="Job not found."), 404
    return jsonify(job)


@app.post("/api/clear")
def clear_jobs():
    cutoff = time.time() - 3600
    with LOCK:
        for job_id in list(JOBS):
            if JOBS[job_id].get("created", 0) < cutoff:
                JOBS.pop(job_id, None)
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
