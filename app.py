from flask import Flask, render_template, request, jsonify, redirect, url_for, make_response
from werkzeug.middleware.proxy_fix import ProxyFix
import os, time, hmac, hashlib, secrets, re, subprocess, tempfile, threading, uuid, json, urllib.parse

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
SECRET = os.environ.get('FLASK_SECRET_KEY','').strip() or secrets.token_urlsafe(48)
APP_PASSWORD = os.environ.get('APP_PASSWORD','').strip()
COOKIE='proxy_checker_auth'; MAX_AGE=30*24*3600
JOBS={}; LOCK=threading.Lock()
MAX_PROXIES=20
IPQUALITY_URL=os.environ.get('IPQUALITY_URL','https://IP.Check.Place').strip()


def token():
    t=str(int(time.time())); s=hmac.new(SECRET.encode(),t.encode(),hashlib.sha256).hexdigest(); return t+'.'+s

def valid_token(v):
    try:
        t,s=v.split('.',1); ts=int(t)
        if abs(time.time()-ts)>MAX_AGE:return False
        return hmac.compare_digest(s,hmac.new(SECRET.encode(),t.encode(),hashlib.sha256).hexdigest())
    except:return False

def auth(): return valid_token(request.cookies.get(COOKIE,''))
@app.before_request
def gate():
    if not APP_PASSWORD or request.endpoint in ('login','login_post','static','healthz'): return
    if auth(): return
    if request.path.startswith('/api/'): return jsonify(error='Authentication required.'),401
    return redirect(url_for('login'))
@app.get('/healthz')
def healthz(): return 'ok',200
@app.get('/login')
def login(): return render_template('login.html')
@app.post('/login')
def login_post():
    if hmac.compare_digest(request.form.get('password',''),APP_PASSWORD):
        r=make_response(redirect('/')); r.set_cookie(COOKIE,token(),max_age=MAX_AGE,secure=True,httponly=True,samesite='Lax',path='/'); return r
    return render_template('login.html',error='Incorrect password.'),401
@app.get('/logout')
def logout():
    r=make_response(redirect('/')); r.delete_cookie(COOKIE,path='/'); return r
@app.get('/')
def index(): return render_template('index.html')


def parse_proxy(line):
    line=line.strip();
    if not line:return None
    scheme='http'; body=line
    m=re.match(r'^(https?|socks5h?|socks4)://(.+)$',line,re.I)
    if m: scheme=m.group(1).lower(); body=m.group(2)
    if '@' not in body:
        p=body.split(':')
        if len(p)<4:return None
        host,port=user=None,None,None
        host=':'.join(p[:-3]); port=p[-3]; user=p[-2]; pwd=p[-1]
    else:
        cred,hp=body.rsplit('@',1); user,pwd=(cred.split(':',1)+[''])[:2] if ':' in cred else (cred,'')
        if hp.startswith('['):
            e=hp.find(']'); host=hp[1:e]; port=hp[e+2:]
        else: host,port=hp.rsplit(':',1)
    try: port=int(port); assert 1<=port<=65535
    except:return None
    return dict(raw=line,scheme=scheme,host=host,port=port,user=user,pwd=pwd)

def proxy_url(p):
    host=p['host'];
    if ':' in host and not host.startswith('['): host='['+host+']'
    return f"{p['scheme']}://{urllib.parse.quote(p['user'],safe='')}:{urllib.parse.quote(p['pwd'],safe='')}@{host}:{p['port']}"

def sanitize(s):
    s=str(s or '')
    s=re.sub(r'(?i)(https?|socks5h?|socks4)://[^\s/@:]+:[^\s/@]+@',r'\1://***:***@',s)
    s=re.sub(r'(?i)(proxy[^\s]*)',lambda m:m.group(0),s)
    return s[-1800:]

def run_ipquality(proxy):
    p=parse_proxy(proxy)
    if not p: return {'status':'failed','error':'Invalid format. Use host:port:username:password.'}
    url=proxy_url(p)
    with tempfile.NamedTemporaryFile(prefix='ipq_',suffix='.json',delete=False) as f: out=f.name
    try:
        # Exact upstream IPQuality script, with full IP, English, JSON and privacy mode.
        # Dependencies are preinstalled in the Docker image, so -n skips install prompts.
        cmd=['bash','/opt/ipquality/ip.sh','-E','-4','-f','-j','-n','-p','-x',url,'-o',out]
        cp=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=150,check=False,env={**os.environ,'TERM':'dumb'})
        raw=''
        try: raw=open(out,'r',encoding='utf-8',errors='replace').read().strip()
        except: pass
        data=None
        # JSON file is authoritative; fall back to the last valid JSON-looking stdout line.
        try:data=json.loads(raw)
        except:
            for line in reversed(cp.stdout.splitlines()):
                line=line.strip()
                if line.startswith('{') and line.endswith('}'):
                    try:data=json.loads(line);break
                    except:pass
        if not data:
            return {'status':'failed','error':sanitize(cp.stderr or cp.stdout or 'IPQuality returned no JSON.'),'returncode':cp.returncode}
        return {'status':'online','data':data,'returncode':cp.returncode}
    except subprocess.TimeoutExpired:
        return {'status':'failed','error':'IPQuality timed out after 150 seconds.'}
    except Exception as e:return {'status':'failed','error':sanitize(e)}
    finally:
        try: os.unlink(out)
        except: pass

def walk(obj,path=''):
    if isinstance(obj,dict):
        for k,v in obj.items(): yield from walk(v,(path+'.'+k).strip('.'))
    elif isinstance(obj,list):
        for i,v in enumerate(obj): yield from walk(v,f'{path}[{i}]')
    else: yield path,obj

def find_fields(data):
    flat=list(walk(data)); result={}
    keys=['ip','asn','organization','city','country','countrycode','timezone','proxy','tor','vpn','server','abuser','robot','score','risk','usage','usetype','comtype','company','isp','fraud','abuser_score']
    for k in keys:
        vals=[(p,v) for p,v in flat if p.lower().endswith('.'+k) or p.lower()==k]
        if vals: result[k]=vals
    return result

def summarize(data):
    f=find_fields(data)
    # Preserve exact upstream JSON and provide a useful normalized summary.
    def first(k):
        vals=f.get(k,[])
        return vals[0][1] if vals else None
    return {'ip':first('ip'),'asn':first('asn'),'organization':first('organization'),'city':first('city'),'country':first('country'),'countrycode':first('countrycode'),'timezone':first('timezone'),'proxy':first('proxy'),'tor':first('tor'),'vpn':first('vpn'),'server':first('server'),'abuser':first('abuser'),'robot':first('robot'),'score':first('score'),'risk':first('risk'),'usage':first('usage'),'raw_fields':f}

def worker(job_id,lines):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with LOCK:
        JOBS[job_id]['status']='running'
        JOBS[job_id]['results']=[None]*len(lines)
    completed=0
    # Keep concurrency deliberately low: IPQuality itself performs many outbound checks.
    # Two concurrent runs are faster for small batches without turning one Render Free
    # instance into a connection storm.
    with ThreadPoolExecutor(max_workers=2) as ex:
        futs={ex.submit(run_ipquality,line):(i,line) for i,line in enumerate(lines)}
        for f in as_completed(futs):
            i,line=futs[f]
            try:
                r=f.result()
            except Exception as e:
                r={'status':'failed','error':sanitize(e)}
            r['index']=i; r['proxy']=line; r['summary']=summarize(r['data']) if r.get('data') else None
            with LOCK:
                JOBS[job_id]['results'][i]=r
                completed += 1
                JOBS[job_id]['completed']=completed
    with LOCK: JOBS[job_id]['status']='done'

@app.post('/api/start')
def start():
    payload=request.get_json(silent=True) or {}; text=payload.get('text','')
    lines=[]; seen=set()
    for x in text.splitlines():
        x=x.strip()
        if x and x not in seen: seen.add(x); lines.append(x)
    if not lines:return jsonify(error='Paste at least one proxy.'),400
    if len(lines)>MAX_PROXIES:return jsonify(error=f'Maximum {MAX_PROXIES} proxies per run.'),400
    jid=uuid.uuid4().hex
    with LOCK: JOBS[jid]={'status':'queued','results':[],'completed':0,'total':len(lines),'created':time.time()}
    threading.Thread(target=worker,args=(jid,lines),daemon=True).start()
    return jsonify(job_id=jid,total=len(lines))
@app.get('/api/job/<jid>')
def job(jid):
    with LOCK: j=JOBS.get(jid)
    if not j:return jsonify(error='Job not found.'),404
    return jsonify(j)
@app.post('/api/clear')
def clear():
    now=time.time()
    with LOCK:
        for k in list(JOBS):
            if now-JOBS[k]['created']>3600: JOBS.pop(k,None)
    return jsonify(ok=True)

if __name__=='__main__': app.run(host='0.0.0.0',port=int(os.environ.get('PORT','5000')))
