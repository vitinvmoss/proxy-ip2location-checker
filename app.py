from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import os
import time
import hmac
import hashlib
import secrets
import threading
import copy
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

from checker import check_proxy, detect_exit_ip, parse_proxy, proxy_url, sanitize_error

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SECRET = os.environ.get("FLASK_SECRET_KEY", "").strip() or secrets.token_urlsafe(48)
APP_PASSWORD = os.environ.get("APP_PASSWORD", "").strip()
COOKIE = "proxy_checker_auth"
MAX_AGE = 30 * 24 * 3600
MAX_PROXIES = 20
MAX_CONCURRENT = 4
DETECT_TIMEOUT = 12

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


def worker(job_id, lines):
    with LOCK:
        JOBS[job_id]["status"] = "running"
        JOBS[job_id]["results"] = [None] * len(lines)

    completed_count = 0

    def bump():
        nonlocal completed_count
        completed_count += 1
        JOBS[job_id]["completed"] = completed_count

    # Phase 1: fast exit-IP detection for every proxy (also acts as the
    # fail-fast pre-flight: dead proxies die here in ~DETECT_TIMEOUT seconds
    # instead of occupying a full check slot).
    exit_ips = [None] * len(lines)
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        future_map = {
            executor.submit(_detect_for_line, line): idx
            for idx, line in enumerate(lines)
        }
        for future in as_completed(future_map):
            idx = future_map[future]
            try:
                exit_ips[idx] = future.result()
            except Exception:
                exit_ips[idx] = None

    # Phase 2: group proxies sharing the same exit IP. The first member of
    # each group gets the full check; the rest get its result cloned, so
    # identical exit IPs are never checked twice in a job.
    primaries = {}   # exit_ip -> index of the proxy that will be fully checked
    clone_map = {}   # idx -> primary idx
    for idx, ip in enumerate(exit_ips):
        if ip is None:
            continue
        if ip in primaries:
            clone_map[idx] = primaries[ip]
        else:
            primaries[ip] = idx

    for idx, ip in enumerate(exit_ips):
        if ip is None:
            proxy, parse_error = parse_proxy(lines[idx])
            with LOCK:
                JOBS[job_id]["results"][idx] = {
                    "index": idx,
                    "proxy": lines[idx],
                    "status": "failed",
                    "error": parse_error
                    or f"Proxy unreachable or no exit IP within {DETECT_TIMEOUT}s (detection failed).",
                    "summary": None,
                    "ipquality_status": None,
                }
                bump()

    # Phase 3: full check for each unique exit IP.
    primary_results = {}
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        future_map = {
            executor.submit(check_proxy, lines[p_idx], exit_ip): (p_idx, exit_ip)
            for exit_ip, p_idx in primaries.items()
        }
        for future in as_completed(future_map):
            p_idx, exit_ip = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"status": "failed", "error": sanitize_error(exc)}
            result.update({
                "index": p_idx,
                "proxy": lines[p_idx],
                "summary": result.get("summary"),
                # The direct engine either answers or doesn't per provider;
                # there is no relay/lite-mode state anymore.
                "ipquality_status": "complete" if result.get("status") == "online" else None,
                "deduplicated": False,
            })
            primary_results[exit_ip] = result
            with LOCK:
                JOBS[job_id]["results"][p_idx] = result
                bump()

    # Phase 4: clone primary results onto proxies that share the same exit IP.
    for idx, p_idx in clone_map.items():
        source = primary_results.get(exit_ips[p_idx])
        if source is None:
            clone = {
                "index": idx,
                "proxy": lines[idx],
                "status": "failed",
                "error": "Primary check for this exit IP failed.",
                "summary": None,
                "ipquality_status": None,
            }
        else:
            clone = copy.deepcopy(source)
            clone["index"] = idx
            clone["proxy"] = lines[idx]
            clone["deduplicated"] = True
            clone["same_exit_ip_as"] = lines[p_idx]
            if clone.get("summary"):
                clone["summary"] = dict(clone["summary"])
                clone["summary"]["deduplicated_from"] = lines[p_idx]
        with LOCK:
            JOBS[job_id]["results"][idx] = clone
            bump()

    with LOCK:
        JOBS[job_id]["status"] = "done"


def _detect_for_line(line):
    proxy, parse_error = parse_proxy(line)
    if not proxy:
        return None
    return detect_exit_ip(proxy_url(proxy))


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
