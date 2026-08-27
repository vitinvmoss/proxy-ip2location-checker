from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import hmac, hashlib, time, secrets, requests, os, re, json
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SECRET = os.environ.get('FLASK_SECRET_KEY', '').strip() or secrets.token_urlsafe(48)
APP_PASSWORD = os.environ.get('APP_PASSWORD', '').strip()
AUTH_COOKIE = 'proxy_checker_auth'
AUTH_MAX_AGE = 60 * 60 * 24 * 30
MAX_PROXIES = 50
MAX_WORKERS = 6
PROXY_TIMEOUT = 8
IP2LOCATION_URL = 'https://api.ip2location.io/'
IPINFO_WIDGET_URL = 'https://ipinfo.io/widget/demo/'
IPAPI_URL = 'https://api.ipapi.is/'
DBIP_API_URL = 'https://api.db-ip.com/v2/free/'
DBIP_PAGE_URL = 'https://db-ip.com/'
CHECK_PLACE_URL = 'https://ipinfo.check.place/'


def sanitize_error(exc):
    """Return a useful, credential-safe error message."""
    msg = str(exc or "Unknown error")
    # Never expose proxy usernames/passwords in the UI/log response.
    msg = re.sub(r'(?i)(https?|socks5h?|socks4)://[^@\s]+@', r'\1://***:***@', msg)
    msg = re.sub(r'(?i)(://)[^\s/@:]+:[^\s/@]+@', r'\1***:***@', msg)
    return msg[:500]


def parse_proxy(line):
    line = line.strip()
    if not line: return None
    m = re.match(r'^(?:(https?|socks5h?|socks4)://)?(.+)$', line, re.I)
    if not m: return None
    scheme = (m.group(1) or '').lower(); body = m.group(2)
    if '@' in body:
        creds, hostport = body.rsplit('@', 1)
        username, password = creds.split(':', 1) if ':' in creds else (creds, '')
    else:
        parts = body.split(':')
        if len(parts) != 4: return None
        host, port_s, username, password = parts
        hostport = f'{host}:{port_s}'
    if hostport.startswith('['):
        end = hostport.find(']')
        if end < 0 or end + 1 >= len(hostport) or hostport[end+1] != ':': return None
        host, port_s = hostport[1:end], hostport[end+2:]
    else:
        if ':' not in hostport: return None
        host, port_s = hostport.rsplit(':', 1)
    try:
        port = int(port_s)
        if not 1 <= port <= 65535: return None
    except ValueError: return None
    return {'raw': line, 'scheme': scheme, 'host': host, 'port': port, 'username': username, 'password': password}


def proxy_url(p, scheme):
    host = p['host']
    if ':' in host and not host.startswith('['): host = f'[{host}]'
    return f"{scheme}://{quote(p['username'], safe='')}:{quote(p['password'], safe='')}@{host}:{p['port']}"


def detect_exit_ip(p):
    """Find the proxy's public exit IP using several independent echo services.

    A single blocked echo endpoint must never make the whole batch fail.
    """
    schemes = [p['scheme']] if p['scheme'] else ['http', 'socks5h']
    echo_urls = [
        'https://api.ipify.org?format=json',
        'https://api64.ipify.org?format=json',
        'https://icanhazip.com/',
        'https://ifconfig.me/ip',
    ]
    errors = []
    for scheme in schemes:
        try:
            u = proxy_url(p, scheme)
            proxies = {'http': u, 'https': u}
            for echo_url in echo_urls:
                try:
                    started = time.perf_counter()
                    r = requests.get(
                        echo_url, proxies=proxies, timeout=PROXY_TIMEOUT,
                        headers={'User-Agent': 'proxy-ip-checker/4.0'},
                    )
                    r.raise_for_status()
                    if 'json' in r.headers.get('content-type','').lower() or echo_url.endswith('format=json'):
                        try: ip = r.json().get('ip')
                        except Exception: ip = None
                    else:
                        ip = r.text.strip().split()[0] if r.text.strip() else None
                    if ip and re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', ip):
                        return {'exit_ip': ip, 'proxy_type': scheme,
                                'response_ms': round((time.perf_counter()-started)*1000)}
                    errors.append(f'{scheme}/{echo_url}: no public IPv4 returned')
                except Exception as e:
                    errors.append(f'{scheme}/{echo_url}: {sanitize_error(e)}')
        except Exception as e:
            errors.append(f'{scheme}: {sanitize_error(e)}')
    raise RuntimeError('Proxy connection failed. ' + ' | '.join(errors[-4:]))


def safe_get_json(url, **kwargs):
    r = requests.get(url, timeout=kwargs.pop('timeout', 10), **kwargs)
    r.raise_for_status(); return r.json()


def ip2location(ip):
    params = {'ip': ip, 'format': 'json'}
    key = os.environ.get('IP2LOCATION_API_KEY','').strip()
    if key: params['key'] = key
    return safe_get_json(IP2LOCATION_URL, params=params, timeout=10)


def ipinfo_demo(ip):
    return safe_get_json(IPINFO_WIDGET_URL + quote(ip, safe=''), timeout=10)


def ipapi(ip):
    return safe_get_json(IPAPI_URL, params={'q': ip}, timeout=10)


def dbip_api(ip):
    return safe_get_json(DBIP_API_URL + quote(ip, safe=''), timeout=10)


def check_place(ip, db):
    return safe_get_json(f'{CHECK_PLACE_URL}{quote(ip, safe="")}?db={quote(db, safe="")}', timeout=12)


def dbip_page(ip):
    # Compatibility fallback modeled on the parsing IPQuality itself documents/uses.
    # No proxy credentials are sent to this website; only the detected IP is requested.
    r = requests.get(DBIP_PAGE_URL + quote(ip, safe=''), timeout=12, headers={'User-Agent':'Mozilla/5.0'})
    r.raise_for_status(); html = r.text
    def sr(label):
        m = re.search(rf'<th[^>]*>{re.escape(label)}</th>\s*<td[^>]*>(.*?)</td>', html, re.I|re.S)
        return re.sub('<[^>]+>', ' ', m.group(1)).strip() if m else None
    def yesno(label):
        m = re.search(rf'<th[^>]*>{re.escape(label)}</th>\s*<td[^>]*>.*?<(?:span|b)[^>]*class=[\'\"][^\'\"]*sr-only[^\'\"]*[\'\"][^>]*>(.*?)</(?:span|b)>', html, re.I|re.S)
        if not m: return None
        v = re.sub('<[^>]+>', ' ', m.group(1)).strip().lower()
        return True if v == 'yes' else False if v == 'no' else None
    return {
        'threat_level': sr('Estimated threat level'),
        'crawler': yesno('Crawler'),
        'proxy': yesno('Proxy'),
        'abuser': yesno('Abuser'),
        '_page_scrape': True,
    }


def first(d, *keys):
    if not isinstance(d, dict): return None
    for k in keys:
        v = d.get(k)
        if v not in (None, '', 'null'): return v
    return None


def norm_ip2(d):
    proxy = d.get('proxy') if isinstance(d,dict) and isinstance(d.get('proxy'),dict) else {}
    return {
        'country': first(d,'country_name'), 'country_code': first(d,'country_code'), 'region': first(d,'region_name'), 'city': first(d,'city_name'),
        'zip': first(d,'zip_code','zipcode'), 'latitude': first(d,'latitude'), 'longitude': first(d,'longitude'), 'timezone': first(d,'time_zone','timezone'),
        'asn': first(d,'asn'), 'organization': first(d,'as','organization','org'), 'isp': first(d,'isp'), 'usage_type': first(d,'usage_type'),
        'is_proxy': first(d,'is_proxy'), 'fraud_score': first(d,'fraud_score'), 'proxy_type': first(proxy,'proxy_type'), 'threat': first(proxy,'threat'),
        'provider': first(proxy,'provider'), 'is_vpn': first(proxy,'is_vpn'), 'is_tor': first(proxy,'is_tor'), 'is_data_center': first(proxy,'is_data_center'),
        'is_public_proxy': first(proxy,'is_public_proxy'), 'is_web_proxy': first(proxy,'is_web_proxy'), 'is_residential_proxy': first(proxy,'is_residential_proxy'),
    }


def norm_ipinfo(d):
    x = d.get('data',d) if isinstance(d,dict) else {}
    asn = x.get('asn') or {}; company = x.get('company') or {}; privacy = x.get('privacy') or {}
    return {'country_code':first(x,'country'), 'region':first(x,'region'), 'city':first(x,'city'), 'zip':first(x,'postal'), 'timezone':first(x,'timezone'),
            'latitude': (first(x,'loc') or ',').split(',')[0] if first(x,'loc') else None, 'longitude': (first(x,'loc') or ',').split(',')[1] if first(x,'loc') and ',' in x['loc'] else None,
            'asn':first(asn,'asn','id'), 'organization':first(asn,'name'), 'usage_type':first(asn,'type'), 'isp':first(company,'name'), 'is_proxy':first(privacy,'proxy'), 'is_vpn':first(privacy,'vpn'),'is_tor':first(privacy,'tor'),'is_hosting':first(privacy,'hosting')}


def norm_ipapi(d):
    asn=d.get('asn') or {}; company=d.get('company') or {}
    return {'country_code':first(d,'location_country_code','country_code'), 'region':first(d,'region','region_name'), 'city':first(d,'city','city_name'), 'asn':first(d,'asn'), 'organization':first(d,'org','organization','company_name'), 'isp':first(d,'isp','organization'), 'usage_type':first(asn,'type'), 'company_type':first(company,'type'), 'abuser_score':first(company,'abuser_score'), 'is_proxy':first(d,'is_proxy'),'is_tor':first(d,'is_tor'),'is_vpn':first(d,'is_vpn'),'is_datacenter':first(d,'is_datacenter'),'is_abuser':first(d,'is_abuser'),'is_crawler':first(d,'is_crawler')}


def norm_dbip(d):
    return {'country':first(d,'countryName'), 'country_code':first(d,'countryCode'), 'region':first(d,'stateProv'), 'city':first(d,'city'), 'zip':first(d,'zipCode'), 'latitude':first(d,'latitude'), 'longitude':first(d,'longitude'), 'timezone':first(d,'timeZone'), 'asn':first(d,'asNumber','asn'), 'organization':first(d,'asName','organization'), 'isp':first(d,'isp'), 'usage_type':first(d,'usageType'), 'connection_type':first(d,'linkType'), 'is_proxy':first(d,'isProxy'), 'proxy_type':first(d,'proxyType'), 'threat_level':first(d,'threatLevel'), 'threat_details':first(d,'threatDetails'), 'is_crawler':first(d,'isCrawler')}


def norm_risk_bridge(name,d):
    # IPQuality's backend responses use different shapes per upstream. Preserve a broad normalized view.
    if not isinstance(d,dict): return {}
    s=d.get('scamalytics') if isinstance(d.get('scamalytics'),dict) else d
    ip2=d if name=='IP2Location bridge' else {}
    return {
        'fraud_score':first(s,'scamalytics_score','score','fraud_score'),
        'risk':first(s,'risk','scamalytics_risk'),
        'isp':first(s,'isp','isp_name','organization'), 'organization':first(s,'organization','organization_name'),
        'asn':first(s,'asn','scamalytics_asn'), 'country_code':first(s,'country_code','countryCode'),
        'region':first(s,'region_name','region','state_province'), 'city':first(s,'city_name','city'), 'usage_type':first(s,'usage_type','usageType'),
        'is_proxy':first(s,'is_proxy','proxy'), 'is_vpn':first(s,'is_vpn','vpn'), 'is_tor':first(s,'is_tor','tor'),
        'is_datacenter':first(s,'is_datacenter','datacenter','is_data_center'), 'is_public_proxy':first(s,'is_public_proxy','public_proxy'),
        'is_residential_proxy':first(s,'is_residential_proxy','residential_proxy'), 'is_blacklisted':first(s,'is_blacklisted_external','is_blacklisted'),
        'recent_abuse':first(d,'recent_abuse'), 'bot_status':first(d,'bot_status'), 'provider':first(s,'provider')
    }


def score_risk(score):
    try:
        n=float(score)
    except: return None
    if n < 20: return 'Very Low'
    if n < 60: return 'Medium'
    if n < 90: return 'High'
    return 'Very High'


def enrich_ip(ip):
    out={'sources':{},'errors':{},'raw_present':{}}
    jobs={
        'IP2Location': lambda: ip2location(ip),
        'IPinfo': lambda: ipinfo_demo(ip),
        'ipapi.is': lambda: ipapi(ip),
        'DB-IP API': lambda: dbip_api(ip),
        'IPQuality/Scamalytics': lambda: check_place(ip,'scamalytics'),
        'IPQuality/IP2Location': lambda: check_place(ip,'ip2location'),
        'IPQuality/DB-IP': lambda: check_place(ip,'dbip'),
        'IPQuality/IPQS': lambda: check_place(ip,'ipqualityscore'),
        'IPQuality/AbuseIPDB': lambda: check_place(ip,'abuseipdb'),
        'DB-IP page': lambda: dbip_page(ip),
    }
    with ThreadPoolExecutor(max_workers=5) as ex:
        fs={ex.submit(fn):name for name,fn in jobs.items()}
        for f in as_completed(fs):
            name=fs[f]
            try:
                raw=f.result()
                if name=='IP2Location': out['sources'][name]=norm_ip2(raw)
                elif name=='IPinfo': out['sources'][name]=norm_ipinfo(raw)
                elif name=='ipapi.is': out['sources'][name]=norm_ipapi(raw)
                elif name=='DB-IP API': out['sources'][name]=norm_dbip(raw)
                elif name=='DB-IP page': out['sources'][name]=raw
                else:
                    out['sources'][name]=norm_risk_bridge(name,raw)
                out['raw_present'][name]=True
            except Exception as e:
                out['errors'][name]=sanitize_error(e)
    return out


def make_auth_token():
    ts=str(int(time.time())); sig=hmac.new(SECRET.encode(),ts.encode(),hashlib.sha256).hexdigest(); return f'{ts}.{sig}'

def valid_auth_token(token):
    try:
        ts_s,sig=token.split('.',1); ts=int(ts_s)
        if time.time()-ts>AUTH_MAX_AGE or ts>time.time()+60:return False
        return hmac.compare_digest(sig,hmac.new(SECRET.encode(),ts_s.encode(),hashlib.sha256).hexdigest())
    except: return False

def auth(): return valid_auth_token(request.cookies.get(AUTH_COOKIE,''))

@app.before_request
def guard():
    if not APP_PASSWORD:return
    if request.endpoint in ('login','login_post','healthz','static'):return
    if auth():return
    if request.path.startswith('/api/'):return jsonify({'error':'Authentication required.'}),401
    return redirect(url_for('login'))

@app.get('/login')
def login(): return render_template('login.html')
@app.post('/login')
def login_post():
    if request.form.get('password','') and hmac.compare_digest(request.form.get('password',''),APP_PASSWORD):
        r=make_response(redirect(url_for('index'))); r.set_cookie(AUTH_COOKIE,make_auth_token(),max_age=AUTH_MAX_AGE,secure=True,httponly=True,samesite='Lax',path='/'); return r
    return render_template('login.html',error='Incorrect password.'),401
@app.get('/logout')
def logout():
    r=make_response(redirect(url_for('login'))); r.delete_cookie(AUTH_COOKIE,path='/'); return r
@app.get('/healthz')
def healthz(): return jsonify({'status':'ok','version':'v4'})
@app.get('/')
def index(): return render_template('index.html')

@app.post('/api/check')
def check():
    payload=request.get_json(silent=True) or {}; text=payload.get('text','')
    if not isinstance(text,str): return jsonify({'error':'Invalid proxy list.'}),400
    lines=list(dict.fromkeys(x.strip() for x in text.splitlines() if x.strip()))
    if len(lines)>MAX_PROXIES:return jsonify({'error':f'Maximum {MAX_PROXIES} proxies per run.'}),400
    results=[None]*len(lines)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fs={ex.submit(_check_one,i,line):i for i,line in enumerate(lines)}
        for f in as_completed(fs):
            i=fs[f]
            try:results[i]=f.result()
            except Exception as e:results[i]={'index':i,'proxy':lines[i],'status':'failed','error':sanitize_error(e)}
    ips=list(dict.fromkeys(r.get('exit_ip') for r in results if r and r.get('status')=='online' and r.get('exit_ip')))
    cache={}
    # Risk enrichment is provider-heavy; cap concurrency to avoid stampeding free endpoints.
    with ThreadPoolExecutor(max_workers=min(4,len(ips) or 1)) as ex:
        fs={ex.submit(enrich_ip,ip):ip for ip in ips}
        for f in as_completed(fs):
            ip=fs[f]
            try:
                x=f.result(); x.setdefault('raw_present',{}); cache[ip]=x
            except Exception as e: cache[ip]={'sources':{},'errors':{'enrichment':sanitize_error(e)},'raw_present':{}}
    for r in results:
        if r and r.get('exit_ip') in cache:
            r['enrichment']=cache[r['exit_ip']]
    return jsonify({'results':results,'unique_ips_looked_up':len(ips),'version':'v4'})

def _check_one(index,line):
    p=parse_proxy(line); base={'index':index,'proxy':line,'status':'failed'}
    if not p:base['error']='Unsupported format. Use host:port:username:password.';return base
    try:base.update({'status':'online',**detect_exit_ip(p)});return base
    except Exception as e:base['error']=sanitize_error(e);return base

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT',5000)),threaded=True)
