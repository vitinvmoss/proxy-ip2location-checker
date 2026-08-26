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


def ip2location(ip):
    """Use IP2Location.io. A registered key is optional; without one the keyless free endpoint is used."""
    params = {'ip': ip, 'format': 'json'}
    key = os.environ.get('IP2LOCATION_API_KEY', '').strip()
    if key:
        params['key'] = key
    r = requests.get(IP2LOCATION_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()


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
    if request.endpoint in ('login', 'login_post', 'static'):
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

    # Look up each unique detected IP only once, then reuse the result.
    unique_ips = list(dict.fromkeys(r.get('exit_ip') for r in results if r and r.get('status') == 'online' and r.get('exit_ip')))
    location_cache = {}
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(unique_ips)))) as executor:
        futures = {executor.submit(ip2location, ip): ip for ip in unique_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                location_cache[ip] = {'ok': True, 'data': future.result()}
            except Exception as exc:
                location_cache[ip] = {'ok': False, 'error': str(exc)}

    for result in results:
        if not result or result.get('status') != 'online':
            continue
        item = location_cache.get(result.get('exit_ip'))
        if item and item.get('ok'):
            apply_location(result, item['data'])
        elif item:
            result['location_error'] = item.get('error', 'IP2Location lookup failed')

    return jsonify({'results': results, 'unique_ips_looked_up': len(unique_ips)})


if __name__ == '__main__':
    # Accessible from other devices on the same Wi-Fi/LAN.
    app.run(host='0.0.0.0', port=5000, threaded=True)
