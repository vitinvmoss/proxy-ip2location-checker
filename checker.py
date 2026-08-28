"""Direct provider checker: Scamalytics + IP2Location + IPinfo.

Flow per proxy:
  1. Detect the proxy's exit IP by curling through the proxy (curl supports
     http/socks4/socks5 uniformly, which urllib does not).
  2. Run three direct (non-proxied) HTTPS lookups against the exit IP in
     parallel: ipinfo.io JSON, scamalytics.com/ip/<ip>, and the IP2Location
     free demo page, whose HTML embeds a JSON blob with the PX12 proxy data
     (fraud_score, proxy_type, is_proxy, usage_type, asn, isp).

This bypasses ipinfo.check.place (the IPQuality relay whose Cloudflare WAF
caused lite-mode partial results) entirely, and cuts per-proxy wall-clock
time from ~55-120s to a few seconds.
"""

import json
import re
import subprocess
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DETECT_TIMEOUT = 12          # seconds, per curl through the proxy
LOOKUP_TIMEOUT = 15          # seconds, per direct provider lookup
DETECT_ENDPOINTS = ("https://ipinfo.io/ip", "https://icanhazip.com", "https://api.ipify.org")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+$")

_SCAM_SCORE_RE = re.compile(r"Fraud Score:\s*(\d+)")
_SCAM_RISK_RE = re.compile(r"(Very High|High|Medium|Low)\s+Risk")
_IP2_KV_PATTERNS = {
    "asn": re.compile(r'"asn"\s*:\s*"(\d+)"'),
    "as_name": re.compile(r'"as_name"\s*:\s*"([^"]*)"'),
    "isp": re.compile(r'"isp"\s*:\s*"([^"]*)"'),
    "domain": re.compile(r'"domain"\s*:\s*"([^"]*)"'),
    "usage_type": re.compile(r'"usage_type"\s*:\s*"([^"]*)"'),
    "is_proxy": re.compile(r'"is_proxy"\s*:\s*(true|false)'),
    "fraud_score": re.compile(r'"fraud_score"\s*:\s*(\d+)'),
    "proxy_type": re.compile(r'"proxy_type"\s*:\s*"([^"]*)"'),
    "threat": re.compile(r'"threat"\s*:\s*"([^"]*)"'),
}

_USAGE_TYPE_LABELS = {
    "DCH": "Data Center",
    "ISP": "Residential",
    "RES": "Residential",
    "MOB": "Mobile",
    "EDU": "Education",
    "GOV": "Government",
    "ORG": "Business",
    "LIB": "Library",
    "CDN": "CDN",
}


# --- proxy parsing (moved from app.py so both the Flask app and this engine share it) ---

def _split_hostport(hostport):
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1 or end + 1 >= len(hostport) or hostport[end + 1] != ":":
            return None, None
        return hostport[1:end], hostport[end + 2:]
    if ":" not in hostport:
        return None, None
    return hostport.rsplit(":", 1)


def _valid_port_text(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


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


def parse_proxy(line):
    """Accept host:port:user:pass, user:pass:host:port, and scheme://user:pass@host:port forms."""
    line = line.strip()
    if not line:
        return None, "Empty proxy line."

    scheme = "http"
    body = line
    m = re.match(r"^(https?|socks5h?|socks4)://(.+)$", line, re.IGNORECASE)
    if m:
        scheme = m.group(1).lower()
        body = m.group(2)

    m = re.match(r"^([^@/]+)@(.+)$", body)
    if m:
        creds, hostport = m.group(1), m.group(2)
        if ":" in creds:
            username, password = creds.split(":", 1)
        else:
            username, password = creds, ""
        host, port = _split_hostport(hostport)
        return _make_proxy(line, scheme, host, port, username, password)

    parts = body.split(":")
    if len(parts) == 4:
        # Disambiguate host:port:user:pass vs user:pass:host:port by locating
        # the numeric port field.
        if _valid_port_text(parts[1]) and not _valid_port_text(parts[3]):
            return _make_proxy(line, scheme, parts[0], parts[1], parts[2], parts[3])
        if _valid_port_text(parts[3]) and not _valid_port_text(parts[1]):
            return _make_proxy(line, scheme, parts[2], parts[3], parts[0], parts[1])
        if _valid_port_text(parts[1]) and _valid_port_text(parts[3]):
            return None, "Ambiguous proxy line: two numeric fields."
        return None, "Could not identify host, port, username, and password."

    if len(parts) == 3 and _valid_port_text(parts[1]):
        return _make_proxy(line, scheme, parts[0], parts[1], parts[2], "")

    return None, "Unsupported proxy format."


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


# --- lookups ---

def _curl_through_proxy(purl, url, timeout=DETECT_TIMEOUT):
    """Return (text, None) or (None, error). Uses curl so all proxy schemes work."""
    try:
        completed = subprocess.run(
            ["curl", "-s", "-x", purl, "--max-time", str(timeout), url],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
    except Exception as exc:
        return None, str(exc)
    text = (completed.stdout or "").strip()
    if completed.returncode != 0 or not text:
        return None, f"curl exit {completed.returncode}"
    return text, None


def detect_exit_ip(purl):
    for endpoint in DETECT_ENDPOINTS:
        text, _ = _curl_through_proxy(purl, endpoint)
        if text and (_IPV4_RE.match(text) or _IPV6_RE.match(text)):
            return text
    return None


def _fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=LOOKUP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _lookup_ipinfo(ip):
    raw = _fetch(f"https://ipinfo.io/{ip}/json")
    data = json.loads(raw)
    if "error" in data:
        raise ValueError(data["error"].get("title") or "ipinfo error")
    org = (data.get("org") or "").strip()
    asn = None
    organization = org
    m = re.match(r"^(AS\d+)\s+(.*)$", org)
    if m:
        asn, organization = m.group(1), m.group(2)
    return {
        "ip": data.get("ip"),
        "hostname": data.get("hostname"),
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "postal_code": data.get("postal"),
        "timezone": data.get("timezone"),
        "asn": asn,
        "organization": organization,
    }


def _lookup_scamalytics(ip):
    html = _fetch(f"https://scamalytics.com/ip/{ip}")
    m = _SCAM_SCORE_RE.search(html)
    score = int(m.group(1)) if m else None
    m = _SCAM_RISK_RE.search(html)
    risk = m.group(1) if m else None
    if score is None and risk is None:
        raise ValueError("no fraud score found on Scamalytics page")
    return {"score": score, "risk": risk}


def _lookup_ip2location(ip):
    html = _fetch(f"https://www.ip2location.com/demo/{ip}")
    fields = {}
    for key, pattern in _IP2_KV_PATTERNS.items():
        m = pattern.search(html)
        if not m:
            continue
        value = m.group(1)
        if key == "is_proxy":
            value = value == "true"
        elif key in ("asn", "fraud_score"):
            value = int(value)
        fields[key] = value
    if "fraud_score" not in fields:
        raise ValueError("no fraud score found on IP2Location demo page")
    return fields


def _safe(fn, arg):
    try:
        return fn(arg), None
    except Exception as exc:
        return None, sanitize_error(exc)


def _ip_type(ip2):
    if not ip2:
        return None
    if ip2.get("is_proxy") and ip2.get("proxy_type") not in (None, "-", ""):
        return f"Proxy ({ip2.get('proxy_type')})"
    label = _USAGE_TYPE_LABELS.get((ip2.get("usage_type") or "").upper())
    return label or ip2.get("usage_type") or None


def _provider_entry(status, **fields):
    entry = {"status": status}
    entry.update(fields)
    return entry


def check_proxy(proxy_line, exit_ip=None):
    """Full check of one proxy line. Returns the result dict used by app.py.

    If exit_ip is already known (pre-detection / dedup pass), pass it to skip
    the detection step.
    """
    started = time.perf_counter()
    proxy, parse_error = parse_proxy(proxy_line)
    if not proxy:
        return {"status": "failed", "error": parse_error or "Invalid proxy."}

    if not exit_ip:
        exit_ip = detect_exit_ip(proxy_url(proxy))
        if not exit_ip:
            return {
                "status": "failed",
                "error": f"Proxy unreachable or no exit IP within {DETECT_TIMEOUT}s (detection failed).",
            }

    with ThreadPoolExecutor(max_workers=3) as pool:
        f_ipinfo = pool.submit(_safe, _lookup_ipinfo, exit_ip)
        f_scam = pool.submit(_safe, _lookup_scamalytics, exit_ip)
        f_ip2 = pool.submit(_safe, _lookup_ip2location, exit_ip)
        ipinfo, ipinfo_err = f_ipinfo.result()
        scam, scam_err = f_scam.result()
        ip2, ip2_err = f_ip2.result()

    summary = {
        "ip": exit_ip,
        "asn": ipinfo.get("asn") if ipinfo else (f"AS{ip2['asn']}" if ip2.get("asn") else None),
        "organization": (ipinfo.get("organization") if ipinfo else None)
        or ip2.get("isp")
        or ip2.get("as_name"),
        "country": ipinfo.get("country") if ipinfo else None,
        "region": ipinfo.get("region") if ipinfo else None,
        "city": ipinfo.get("city") if ipinfo else None,
        "postal_code": ipinfo.get("postal_code") if ipinfo else None,
        "timezone": ipinfo.get("timezone") if ipinfo else None,
        "hostname": ipinfo.get("hostname") if ipinfo else None,
        "ip_type": _ip_type(ip2),
    }

    ip2_score = ip2.get("fraud_score")
    ip2_proxy = ip2.get("is_proxy")
    summary["scores"] = {
        "SCAMALYTICS": scam.get("score") if scam else None,
        "IP2LOCATION": ip2_score,
    }
    summary["factors"] = {
        "proxy": {
            "SCAMALYTICS": (scam or {}).get("risk"),
            "IP2LOCATION": ip2_proxy,
        },
    }
    summary["ip2location"] = {
        "proxy_type": ip2.get("proxy_type"),
        "usage_type": ip2.get("usage_type"),
        "threat": ip2.get("threat"),
        "domain": ip2.get("domain"),
    }
    # The UI's usage column reads summary["usage"][<provider>] by priority;
    # surface the IP type there (e.g. "Residential", "Data Center").
    summary["usage"] = {"IP2LOCATION": summary["ip_type"]} if summary["ip_type"] else {}
    summary["scamalytics_risk"] = (scam or {}).get("risk")
    summary["lite_mode"] = False
    summary["sources"] = "Scamalytics + IP2Location + IPinfo (direct lookups, no relay)"

    summary["providers"] = {
        "IPinfo": _provider_entry("ok" if ipinfo else "unavailable", error=ipinfo_err),
        "SCAMALYTICS": _provider_entry(
            "ok" if scam else "unavailable",
            score=(scam or {}).get("score"),
            risk=(scam or {}).get("risk"),
            error=scam_err,
        ),
        "IP2LOCATION": _provider_entry(
            "ok" if ip2 else "unavailable",
            score=ip2_score,
            proxy=ip2_proxy,
            proxy_type=ip2.get("proxy_type"),
            usage_type=ip2.get("usage_type"),
            error=ip2_err,
        ),
    }

    # All three providers down while the proxy itself works -> still online,
    # but flagged so the UI can explain the empty score columns.
    if not ipinfo and not scam and not ip2:
        summary["providers_error"] = "All provider lookups failed for this exit IP."

    return {
        "status": "online",
        "summary": summary,
        "elapsed_ms": round((time.perf_counter() - started) * 1000),
    }
