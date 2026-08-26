from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import hmac
import hashlib
import time
import secrets
import requests
import os
import socket
import re
import json
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SECRET = os.environ.get('FLASK_SECRET_KEY', '').strip()
if not SECRET:
    # Development fallback only. Render should always have FLASK_SECRET_KEY set.
    SECRET = secrets.token_urlsafe(48)
APP_PASSWORD = os.environ.get('APP_PASSWORD', '').strip()
AUTH_COOKIE = 'proxy_checker_auth'
AUTH_MAX_AGE = 60 * 60 * 24 * 30
MAX_PROXIES = 50
MAX_WORKERS = 10
IP_ECHO_URL = "https://api.ipify.org?format=json"
IP2LOCATION_URL = "https://api.ip2location.io/"
DBIP_FREE_URL = "http://api.db-ip.com/v2/free"
SCAMALYTICS_ENDPOINT = os.environ.get("SCAMALYTICS_ENDPOINT", "").strip().rstrip("/")
SCAMALYTICS_API_TOKEN = os.environ.get("SCAMALYTICS_API_TOKEN", "").strip()


def parse_proxy(line: str):
    """Parse host:port:user:pass, user:pass@host:port, or scheme://user:pass@host:port."""
    line = line.strip()
    if not line:
        return None

    # Normalize common forms.
    raw = line
    m = re.match(r'^(?:(https?|socks5h?|socks4)://)?(.+)$', line, re.I)
    if not m:
        return None
    scheme = (m.group(1) or '').lower()
    body = m.group(2)

    if '@' in body:
        creds, hostport = body.rsplit('@', 1)
        if ':' in creds:
            username, password = creds.split(':', 1)
        else:
            username, password = creds, ''
    else:
        parts = body.split(':')
        if len(parts) < 4:
            return None
        host = ':'.join(parts[:-3]) if len(parts) > 4 and parts[0].count('.') == 0 else parts[0]
        # For normal host:port:user:pass this is exact.
        if len(parts) == 4:
            host, port, username, password = parts
        else:
            # Best effort for an IPv6-ish unbracketed host.
            host = ':'.join(parts[:-3])
            port, username, password = parts[-3:]
        hostport = f"{host}:{port}"

    # hostport may include IPv6 in brackets.
    if hostport.startswith('['):
        end = hostport.find(']')
        if end == -1 or end + 1 >= len(hostport) or hostport[end+1] != ':':
            return None
        host = hostport[1:end]
        port_s = hostport[end+2:]
    else:
        if ':' not in hostport:
            return None
        host, port_s = hostport.rsplit(':', 1)

    try:
        port = int(port_s)
        if not 1 <= port <= 65535:
            return None
    except ValueError:
        return None

    return {
        'raw': raw,
        'scheme': scheme,
        'host': host,
        'port': port,
        'username': username,
        'password': password,
    }


def proxy_url(p, scheme):
    user = quote(p['username'], safe='')
    password = quote(p['password'], safe='')
    host = p['host']
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'
    return f"{scheme}://{user}:{password}@{host}:{p['port']}"


def detect_exit_ip(p):
    """Make a request through the supplied proxy and ask an external service which IP it sees."""
    declared = p['scheme']
    schemes = []
    if declared:
        if declared in ('socks5', 'socks5h'):
            schemes = ['socks5h']
        elif declared == 'socks4':
            schemes = ['socks4']
        else:
            schemes = ['http']
    else:
        # AUTO: try HTTP first, then SOCKS5.
        schemes = ['http', 'socks5h']

    last_error = None
    for sch in schemes:
        url = proxy_url(p, sch)
        proxies = {'http': url, 'https': url}
        try:
            r = requests.get(IP_ECHO_URL, proxies=proxies, timeout=15)
            r.raise_for_status()
            data = r.json()
            ip = data.get('ip')
            if not ip:
                raise RuntimeError('IP echo service returned no IP')
            return {'exit_ip': ip, 'proxy_type': sch, 'response_ms': r.elapsed.total_seconds() * 1000}
        except Exception as exc:
            last_error = str(exc)
    raise RuntimeError(last_error or 'Proxy connection failed')



def _first(data, *keys):
    for key in keys:
        if isinstance(data, dict) and key in data and data[key] not in (None, ''):
            return data[key]
    return None


def normalize_ip2location(data):
    proxy = data.get('proxy') if isinstance(data, dict) and isinstance(data.get('proxy'), dict) else {}
    return {
        'country': _first(data, 'country_name'), 'country_code': _first(data, 'country_code'),
        'region': _first(data, 'region_name'), 'city': _first(data, 'city_name'),
        'zip': _first(data, 'zip_code', 'zipcode'), 'latitude': _first(data, 'latitude'),
        'longitude': _first(data, 'longitude'), 'timezone': _first(data, 'time_zone', 'timezone'),
        'asn': _first(data, 'asn'), 'as': _first(data, 'as'), 'isp': _first(data, 'isp'),
        'organization': _first(data, 'organization', 'org'), 'usage_type': _first(data, 'usage_type'),
        'is_proxy': _first(data, 'is_proxy'), 'fraud_score': _first(data, 'fraud_score'),
        'proxy_type': _first(proxy, 'proxy_type'), 'proxy_threat': _first(proxy, 'threat'),
        'proxy_provider': _first(proxy, 'provider'), 'is_vpn': _first(proxy, 'is_vpn'),
        'is_tor': _first(proxy, 'is_tor'), 'is_data_center': _first(proxy, 'is_data_center'),
        'is_public_proxy': _first(proxy, 'is_public_proxy'), 'is_web_proxy': _first(proxy, 'is_web_proxy'),
        'is_residential_proxy': _first(proxy, 'is_residential_proxy'),
    }


def normalize_dbip(data):
    return {
        'country': _first(data, 'countryName'), 'country_code': _first(data, 'countryCode'),
        'region': _first(data, 'stateProv'), 'city': _first(data, 'city'), 'zip': _first(data, 'zipCode'),
        'latitude': _first(data, 'latitude'), 'longitude': _first(data, 'longitude'),
        'timezone': _first(data, 'timeZone'), 'asn': _first(data, 'asNumber'),
        'as': _first(data, 'asName'), 'isp': _first(data, 'isp'),
        'organization': _first(data, 'organization'), 'usage_type': _first(data, 'usageType'),
        'connection_type': _first(data, 'linkType'), 'is_proxy': _first(data, 'isProxy'),
        'proxy_type': _first(data, 'proxyType'), 'threat_level': _first(data, 'threatLevel'),
        'threat_details': _first(data, 'threatDetails'), 'is_crawler': _first(data, 'isCrawler'),
        'is_anycast': _first(data, 'isAnycast'),
    }


def normalize_scamalytics(data):
    s = data.get('scamalytics', data) if isinstance(data, dict) else {}
    return {
        'fraud_score': _first(s, 'score', 'fraud_score', 'scamalytics_score'),
        'risk': _first(s, 'risk', 'scamalytics_risk'),
        'isp': _first(s, 'isp', 'isp_name', 'scamalytics_isp'),
        'organization': _first(s, 'organization', 'organization_name'),
        'asn': _first(s, 'asn', 'scamalytics_asn'),
        'country': _first(s, 'country_name'), 'country_code': _first(s, 'country_code'),
        'region': _first(s, 'region_name', 'state_province'), 'city': _first(s, 'city_name'),
        'zip': _first(s, 'postal_code'), 'latitude': _first(s, 'latitude'), 'longitude': _first(s, 'longitude'),
        'is_proxy': _first(s, 'is_proxy', 'proxy'), 'is_vpn': _first(s, 'is_vpn'),
        'is_tor': _first(s, 'is_tor'), 'is_datacenter': _first(s, 'is_datacenter', 'datacenter'),
        'residential_proxy': _first(s, 'residential_proxy'),
        'isp_risk_score': _first(s, 'isp_risk_score'),
    }

def ip2location(ip):
    """IP2Location.io single-IP lookup. Free/keyless endpoint supports basic data."""
    params = {'ip': ip, 'format': 'json'}
    key = os.environ.get('IP2LOCATION_API_KEY', '').strip()
    if key:
        params['key'] = key
    r = requests.get(IP2LOCATION_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()


def ip2location_bulk(ips):
    """IP2Location bulk endpoint. This is only used when an API key is configured;
    IP2Location documents bulk as a paid-plan feature."""
    key = os.environ.get('IP2LOCATION_API_KEY', '').strip()
    if not key:
        return None
    payload = json.dumps(ips)
    r = requests.post(
        'https://bulk.ip2location.io/?key=' + quote(key, safe='') + '&format=json',
        data=payload,
        headers={'Content-Type': 'application/json', 'Accept': 'application/json'},
        timeout=20,
    )
    r.raise_for_status()
    return r.json()


def dbip_bulk(ips):
    """DB-IP documented Free API batch endpoint. Free API is HTTP-only."""
    if not ips:
        return {}
    url = f"{DBIP_FREE_URL}/{','.join(quote(ip, safe='') for ip in ips)}"
    r = requests.get(url, timeout=15)
    r.raise_for_status()
    return r.json()


def scamalytics_lookup(ip):
    """Optional official Scamalytics API integration.
    Configure SCAMALYTICS_ENDPOINT and SCAMALYTICS_API_TOKEN in Render.
    The endpoint format is supplied by Scamalytics when API access is provisioned.
    """
    if not (SCAMALYTICS_ENDPOINT and SCAMALYTICS_API_TOKEN):
        return None
    url = SCAMALYTICS_ENDPOINT
    separator = '&' if '?' in url else '?'
    r = requests.get(
        url + separator + 'ip=' + quote(ip, safe=''),
        headers={'Authorization': f'Bearer {SCAMALYTICS_API_TOKEN}', 'Accept': 'application/json'},
        timeout=10,
    )
    r.raise_for_status()
    return r.json()


def enrich_ips(ips):
    """Enrich a de-duplicated IP list using each provider independently.
    DB-IP is batched on its free API. IP2Location uses bulk only with a configured
    key (documented as paid); otherwise parallel single-IP calls are used.
    """
    out = {ip: {'sources': {}} for ip in ips}
    if not ips:
        return out

    # IP2Location
    try:
        bulk = ip2location_bulk(ips)
        if bulk is not None:
            for ip in ips:
                raw = bulk.get(ip) if isinstance(bulk, dict) else None
                if raw is not None:
                    out[ip]['sources']['IP2Location'] = normalize_ip2location(raw)
        else:
            with ThreadPoolExecutor(max_workers=min(8, len(ips))) as ex:
                fs = {ex.submit(ip2location, ip): ip for ip in ips}
                for f in as_completed(fs):
                    ip = fs[f]
                    try:
                        out[ip]['sources']['IP2Location'] = normalize_ip2location(f.result())
                    except Exception as exc:
                        out[ip].setdefault('errors', {})['IP2Location'] = str(exc)
    except Exception as exc:
        for ip in ips:
            out[ip].setdefault('errors', {})['IP2Location'] = str(exc)

    # DB-IP free batch endpoint
    try:
        raw_batch = dbip_bulk(ips)
        if isinstance(raw_batch, dict):
            for ip in ips:
                raw = raw_batch.get(ip)
                if raw and isinstance(raw, dict) and not raw.get('errorCode'):
                    out[ip]['sources']['DB-IP'] = normalize_dbip(raw)
                elif raw and raw.get('error'):
                    out[ip].setdefault('errors', {})['DB-IP'] = raw.get('error')
    except Exception as exc:
        for ip in ips:
            out[ip].setdefault('errors', {})['DB-IP'] = str(exc)

    # Scamalytics official API, one request per unique IP if configured.
    if SCAMALYTICS_ENDPOINT and SCAMALYTICS_API_TOKEN:
        with ThreadPoolExecutor(max_workers=min(8, len(ips))) as ex:
            fs = {ex.submit(scamalytics_lookup, ip): ip for ip in ips}
            for f in as_completed(fs):
                ip = fs[f]
                try:
                    raw = f.result()
                    if raw is not None:
                        out[ip]['sources']['Scamalytics'] = normalize_scamalytics(raw)
                except Exception as exc:
                    out[ip].setdefault('errors', {})['Scamalytics'] = str(exc)

    return out

def check_proxy(index, line):
    p = parse_proxy(line)
    base = {'index': index, 'proxy': line, 'status': 'failed'}
    if not p:
        base['error'] = 'Unsupported proxy format. Use host:port:user:pass.'
        return base
    try:
        detected = detect_exit_ip(p)
        base.update({
            'status': 'online',
            'exit_ip': detected['exit_ip'],
            'proxy_type': detected['proxy_type'],
            'response_ms': round(detected['response_ms']),
        })
        return base
    except Exception as exc:
        base['error'] = str(exc)
        return base


def apply_location(result, data):
    result.update({
        'country': data.get('country_name', ''),
        'country_code': data.get('country_code', ''),
        'region': data.get('region_name', ''),
        'city': data.get('city_name', ''),
        'isp': data.get('isp', ''),
        'asn': data.get('asn', ''),
        'usage_type': data.get('usage_type', ''),
        'is_proxy': data.get('is_proxy'),
        'fraud_score': data.get('fraud_score'),
    })


def make_auth_token():
    # Timestamped, HMAC-signed token; no password is stored in the browser.
    ts = str(int(time.time()))
    sig = hmac.new(SECRET.encode(), ts.encode(), hashlib.sha256).hexdigest()
    return f'{ts}.{sig}'


def valid_auth_token(token):
    try:
        ts_s, sig = token.split('.', 1)
        ts = int(ts_s)
        if time.time() - ts > AUTH_MAX_AGE or ts > time.time() + 60:
            return False
        expected = hmac.new(SECRET.encode(), ts_s.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except (ValueError, TypeError):
        return False


def is_authenticated():
    return valid_auth_token(request.cookies.get(AUTH_COOKIE, ''))


@app.before_request
def require_password():
    if not APP_PASSWORD:
        return None
    if request.endpoint in ('login', 'login_post', 'healthz', 'static'):
        return None
    if is_authenticated():
        return None
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required.'}), 401
    return redirect(url_for('login'))


@app.get('/login')
def login():
    return render_template('login.html')


@app.post('/login')
def login_post():
    password = request.form.get('password', '')
    if password and hmac.compare_digest(password, APP_PASSWORD):
        response = make_response(redirect(url_for('index')))
        response.set_cookie(
            AUTH_COOKIE,
            make_auth_token(),
            max_age=AUTH_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Lax',
            path='/',
        )
        return response
    return render_template('login.html', error='Incorrect password.'), 401


@app.get('/logout')
def logout():
    response = make_response(redirect(url_for('login')))
    response.delete_cookie(AUTH_COOKIE, path='/')
    return response


@app.get('/healthz')
def healthz():
    return jsonify({'status': 'ok'})


@app.get('/')
def index():
    return render_template('index.html')


@app.post('/api/check')
def api_check():
    payload = request.get_json(silent=True) or {}
    text = payload.get('text', '')
    if not isinstance(text, str):
        return jsonify({'error': 'Invalid proxy list.'}), 400

    lines = list(dict.fromkeys(x.strip() for x in text.splitlines() if x.strip()))
    if len(lines) > MAX_PROXIES:
        return jsonify({'error': f'Maximum {MAX_PROXIES} proxies per run.'}), 400

    results = [None] * len(lines)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(check_proxy, i, line): i for i, line in enumerate(lines)}
        for future in as_completed(futures):
            i = futures[future]
            try:
                results[i] = future.result()
            except Exception as exc:
                results[i] = {'index': i, 'proxy': lines[i], 'status': 'failed', 'error': str(exc)}

    # Enrich only unique detected IPs, once per provider. DB-IP is batched; IP2Location
    # uses bulk when a paid API key is present and otherwise parallel single lookups.
    unique_ips = list(dict.fromkeys(r.get('exit_ip') for r in results if r and r.get('status') == 'online' and r.get('exit_ip')))
    enrichment = enrich_ips(unique_ips)
    for result in results:
        if not result or result.get('status') != 'online':
            continue
        item = enrichment.get(result.get('exit_ip'), {})
        result['sources'] = item.get('sources', {})
        result['source_errors'] = item.get('errors', {})

    return jsonify({'results': results, 'unique_ips_looked_up': len(unique_ips)})


if __name__ == '__main__':
    # Accessible from other devices on the same Wi-Fi/LAN.
    app.run(host='0.0.0.0', port=5000, threaded=True)
