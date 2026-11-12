# -*- coding: utf-8 -*-
# author: Tyraaah
"""
solver.py — Standalone MLBB Aliyun WAF Captcha Solver (multi-browser)

Session lifecycle: every browser is force-restarted after SESSION_MAX_AGE_S
seconds (default 120). Override via env WAF_SESSION_MAX_AGE or --session-ttl.

Drag profile: loaded from best_drag_params.json if present, else DEFAULT_PARAMS.
The tuned file (evo_best, rate 100.0) is load-bearing — do not tune by hand.
DEFAULT_PARAMS below is the fallback only; the file overrides it.

Trigger paths (in order):
  1. curl_cffi TLS-impersonation probe across _IMPERSONATE_TARGETS (fast).
  2. Browser fallback — primed mtacc origin does the POST itself with
     credentials:'include', exactly like kontolsolver.py. Used when every
     curl_cffi alias is served the 405 block page.

Latency wins shipped here (all non-behavioral — no drag timing touched):

  - _prime uses wait_until='commit' + 150ms settle (was domcontentloaded,
    which blocked ~1–3s per browser start on the mtacc page we never read).
  - Post-load settle after _load_challenge_page: 0–150ms (was 0–800ms).
    _wait_slider() is the real readiness gate; the long pre-sleep was waste.
  - _diag_challenge() gated behind DEBUG — was ~50–100ms per solve for a log.
  - TOKEN_WAIT_S 2.0 → 1.2 — happy path returns in 100–300ms.
  - SLIDER_WAIT_S 12 → 10 — failure-path only.

Drag params, cookiejar handling, session cap, trigger cache: unchanged.
"""

import atexit
import json
import math
import os
import platform
import random
import re
import socket
import subprocess
import sys
import threading
import time

try:
    import cloakbrowser
    CLOAK_OK = True
    CLOAK_ERR = None
except Exception as e:
    CLOAK_OK = False
    CLOAK_ERR = str(e)

try:
    from cloakbrowser import license as _fb_license
    SEAT_CHECK_OK = True
except Exception:
    _fb_license = None
    SEAT_CHECK_OK = False

try:
    from playwright.sync_api import sync_playwright
    PW_OK = True
    PW_ERR = None
except Exception as e:
    sync_playwright = None
    PW_OK = False
    PW_ERR = str(e)

try:
    from curl_cffi import requests as _cffi_requests
    CFFI_OK = True
except Exception:
    _cffi_requests = None
    CFFI_OK = False


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_FILE = os.path.join(BASE_DIR, "tokens.txt")
SERVER_URL = ""
LOGIN_URL = 'https://accountmtapi.mobilelegends.com'
MTACC_PAGE = 'https://mtacc.mobilelegends.com/v2.1/inapp/login-new'
WAF_HOST = 'accountmtapi.mobilelegends.com'

# Hard session cap: browser is torn down and re-opened after this many
# seconds regardless of state. 120s matches the checker's own solve window.
SESSION_MAX_AGE_S = int(os.environ.get('WAF_SESSION_MAX_AGE', '120'))

TRANSPORT = 'cloak'
DEBUG = ('--debug' in sys.argv or '-d' in sys.argv
         or os.environ.get('CLOAK_DEBUG', '').strip().lower()
         in ('1', 'true', 'yes', 'on'))

START_JITTER_S = 0.2
STAGGER_S = 1.5
FETCH_TIMEOUT = 20000
SLIDER_WAIT_S = 10                     # was 12 — failure path only
DRAG_RETRIES = 2
DRAG_REFRESH_LOOPS = 1
TOKEN_WAIT_S = 1.2                     # was 2.0 — happy path returns far faster
START_RETRIES = 3
CHALLENGE_SETTLE_S = 0.0
BLOCK_RETRIES = 12
BLOCK_BACKOFF_S = 2.0

UA = (
    "Mozilla/5.0 (Linux; Android 15; SM-A055F Build/AP3A.240905.015.A2; wv) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/151.0.7922.199 "
    "Mobile Safari/537.36;UniWebView;mtakit"
)

CHROMIUM_ARGS = [
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
    '--disable-software-rasterizer',
    '--disable-extensions',
    '--disable-background-networking',
    '--renderer-process-limit=1',
    '--disable-component-extensions-with-background-pages',
    '--disable-ipc-flooding-protection',
    '--js-flags=--max-old-space-size=256',
    '--disable-blink-features=AutomationControlled',
    '--disable-infobars',
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    '--disable-background-page-throttling',
    '--disable-features=CalculateNativeWinOcclusion',
]

CHROME_EXE_CANDIDATES = [
    r'C:\Program Files\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe',
    r'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
    r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
]

STEALTH_JS = """() => {
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  window.chrome = window.chrome || { runtime: {} };
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
  Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
}"""

FINGERPRINT_JS = """() => {
  try {
    Object.defineProperty(navigator, 'platform', { get: () => 'Linux armv8l' });
    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });
    Object.defineProperty(navigator, 'deviceMemory', { get: () => 4 });
    Object.defineProperty(navigator, 'maxTouchPoints', { get: () => 5 });
    Object.defineProperty(navigator, 'language', { get: () => 'en-US' });
    Object.defineProperty(window, 'devicePixelRatio', { get: () => 2.625 });
  } catch (e) {}
}"""

PREWARM_HOSTS = (
    'https://o.alicdn.com/captcha-frontend/aliyunCaptcha/AliyunCaptcha.js',
    'https://g.alicdn.com/',
    'https://cloudauth-device-dualstack.cn-shanghai.aliyuncs.com/',
    'https://cloudauth-device-dualstack.ap-southeast-1.aliyuncs.com/',
    'https://aliyun.captcha-open.aliyuncs.com/',
    'https://aliyun.captcha-open-b.aliyuncs.com/',
    'https://aliyun.captcha-open-southeast.aliyuncs.com/',
    'https://aliyun.captcha-open-southeast-b.aliyuncs.com/',
    'https://upload.captcha-open.aliyuncs.com/',
    'https://upload.captcha-open-b.aliyuncs.com/',
    'https://upload.captcha-open-southeast.aliyuncs.com/',
)

PREWARM_JS = """async (hosts) => {
  const out = [];
  await Promise.all(hosts.map(async (u) => {
    const t0 = performance.now();
    try {
      const ctl = new AbortController();
      const to = setTimeout(() => ctl.abort(), 4000);
      await fetch(u, {mode: 'no-cors', cache: 'no-store', signal: ctl.signal});
      clearTimeout(to);
      out.push([u, Math.round(performance.now() - t0)]);
    } catch (e) { out.push([u, -1]); }
  }));
  return out;
}"""

TRIGGER_PAYLOAD = {
    'op': 'new_login_pwd',
    'sign': '8b4887cb029a87d032ea8e932ec77f1e',
    'params': {'account': 'trigger_probe@mlbb.com', 'country': '',
               'md5pwd': 'e10adc3949ba59abbe56e057f20f883e'},
    'lang': 'en',
}

_CLOSED_MARKERS = (
    'has been closed', 'target closed', 'browser closed',
    'connection closed', 'browser has disconnected', 'context closed',
    'page closed', 'target page, context or browser',
)
_NET_MARKERS = ('ENOTFOUND', 'ECONNREFUSED', 'ECONNRESET', 'net::ERR_',
                'getaddrinfo', 'EAI_AGAIN')


class C:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GRN = '\033[32m'
    YEL = '\033[33m'
    BLU = '\033[34m'
    MAG = '\033[35m'
    CYN = '\033[36m'
    GRY = '\033[90m'

    @classmethod
    def disable(cls):
        for name in dir(cls):
            if name.isupper() and name != 'disable':
                setattr(cls, name, '')


if not sys.stdout.isatty() or os.environ.get('NO_COLOR'):
    C.disable()

_BROWSER_COLORS = (C.CYN, C.MAG, C.YEL, C.GRN, C.BLU)


PRINT_LOCK = threading.Lock()
TOKEN_LOCK = threading.Lock()
VPN_LOCK = threading.Lock()
STOP_EVENT = threading.Event()
_VPN_RECOVERED_AT = 0.0


def _thread_color():
    name = threading.current_thread().name
    if name.startswith('Browser-'):
        try:
            idx = int(name.split('-')[1]) - 1
            return _BROWSER_COLORS[idx % len(_BROWSER_COLORS)]
        except (ValueError, IndexError):
            pass
    return ''


def log(msg):
    name = threading.current_thread().name
    tagged = name.startswith('Browser-') or name.startswith('Thread-')
    col = _thread_color()
    prefix = f"{col}{C.BOLD}[{name}]{C.RESET} " if tagged else ''
    with PRINT_LOCK:
        print(f"{prefix}{msg}{C.RESET}", flush=True)


def dbg_log(tag, msg):
    if DEBUG:
        log(f"{C.GRY}[debug:{tag}] {msg}{C.RESET}")


def ok(msg):
    log(f"{C.GRN}{C.BOLD}[✓] {msg}{C.RESET}")


def warn(msg):
    log(f"{C.YEL}[!] {msg}{C.RESET}")


def err(msg):
    log(f"{C.RED}[x] {msg}{C.RESET}")


def info(msg):
    log(f"{C.BLU}[*] {msg}{C.RESET}")


def is_closed_error(e):
    s = str(e).lower()
    return any(m in s for m in _CLOSED_MARKERS)


def is_net_error(e):
    s = str(e)
    return any(m in s for m in _NET_MARKERS)


def looks_real_json(text):
    if not text:
        return False
    t = text.lstrip()
    return t.startswith('{') and '"code"' in t[:200]


def is_waf_challenge(text):
    if not text:
        return False
    if is_block_page(text):
        return False
    return ('<textarea id="renderData"' in text or 'aliyunCaptcha' in text
            or ('aliyun_waf' in text and '<script' in text.lower()))


def is_block_page(text):
    """Detect the nginx/WAF 405 block page (Chromium TLS/JA3 is rejected)."""
    if not text:
        return False
    t = text
    return ('<title>405</title>' in t
            or 'id="block_message"' in t
            or 'blocked as it may cause' in t)


# Widened probe list — 18 aliases spanning Chrome/Edge/Safari. curl_cffi's
# bare 'chrome' alias resolves to a single build; once the WAF rotates its
# accepted-fingerprint list, one alias 405s. Probing the full set finds a
# working one on the first pass in nearly all cases. 'chrome' kept as a last
# resort so old curl_cffi builds still function.
_IMPERSONATE_TARGETS = (
    'chrome136', 'chrome133a', 'chrome131', 'chrome130', 'chrome129',
    'chrome128', 'chrome124', 'chrome120', 'chrome116', 'chrome110',
    'chrome107', 'chrome101', 'chrome99',
    'edge101', 'edge99',
    'safari17_0', 'safari17_2_ios', 'safari15_5',
    'chrome',
)

_TRIGGER_HEADERS = {
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Content-Type': 'application/json',
    'Origin': 'https://mtacc.mobilelegends.com',
    'Referer': 'https://mtacc.mobilelegends.com/',
    'X-Requested-With': 'com.mobile.legends',
    'sec-ch-ua': '"Chromium";v="130", "Android WebView";v="130", "Not;A=Brand";v="8"',
    'sec-ch-ua-mobile': '?1',
    'sec-ch-ua-platform': '"Android"',
    'Sec-Fetch-Site': 'same-site',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Dest': 'empty',
}


# Trigger cache: (target, session) after first working probe. Safe speedup —
# skips the TLS handshake and probe loop on every subsequent solve. Only
# invalidated when the cached session itself gets a 405 block page.
_TRIGGER_CACHE = None
_TRIGGER_CACHE_LOCK = threading.Lock()


def http_trigger_challenge(payload=None, proxy=None, timeout=15):
    """Trigger the WAF challenge via curl_cffi (Chrome TLS impersonation).

    Returns (text, cookie_header). The browser's own fetch is served the 405
    block page; curl_cffi is served the real slider challenge HTML from the
    SAME exit IP. The caller route-fulfills this HTML so the browser renders
    and solves it — the browser never performs the trigger POST itself.
    """
    global _TRIGGER_CACHE
    if not CFFI_OK or _cffi_requests is None:
        raise RuntimeError('curl_cffi not importable — pip install curl_cffi')
    body = json.dumps(payload or TRIGGER_PAYLOAD)
    target = LOGIN_URL + '/'

    with _TRIGGER_CACHE_LOCK:
        cached = _TRIGGER_CACHE

    if cached:
        try:
            s = cached['session']
            r = s.post(target, data=body, headers=_TRIGGER_HEADERS,
                       timeout=timeout, verify=False)
            text = r.text
            if is_waf_challenge(text):
                dbg_log('TRIGGER', f'cached session hit — {cached["target"]}')
                return text, '; '.join(f'{k}={v}' for k, v in s.cookies.items())
            if not is_block_page(text):
                return text, ''
            dbg_log('TRIGGER', 'cached session got 405 — re-probing')
        except Exception as e:
            dbg_log('TRIGGER', f'cached session raised — re-probing: {str(e)[:60]}')

    last = None
    for tgt in _IMPERSONATE_TARGETS:
        try:
            s = _cffi_requests.Session(impersonate=tgt)
            if proxy:
                s.proxies = {'http': proxy, 'https': proxy}
            r = s.post(target, data=body, headers=_TRIGGER_HEADERS,
                       timeout=timeout, verify=False)
            text = r.text
            if is_block_page(text):
                last = text
                continue
            cookies = '; '.join(f'{k}={v}' for k, v in s.cookies.items())
            if is_waf_challenge(text):
                with _TRIGGER_CACHE_LOCK:
                    _TRIGGER_CACHE = {'target': tgt, 'session': s}
                dbg_log('TRIGGER', f'probe found working target: {tgt} (cached)')
                return text, cookies
            last = text
        except Exception:
            continue
    with _TRIGGER_CACHE_LOCK:
        _TRIGGER_CACHE = None
    return (last or ''), ''


DEFAULT_PARAMS = {
    't_lo': 0.95, 't_hi': 1.35, 'base_n': 9, 'density': 0.014,
    'accel_lo': 0.42, 'accel_hi': 0.56, 'peak_lo': 2.8, 'peak_hi': 3.3,
    'wobble': 4.0, 'rev_p': 0.0, 'micro_slow': 0.001,
    'hold_lo': 1, 'hold_hi': 2, 's_hold_lo': 0.003, 's_hold_hi': 0.010,
    'settle_lo': 0.001, 'settle_hi': 0.003,
    'pre_clicks': 0, 'mid_clicks': 0, 'pre_drag': 0.15,
    'pre_scroll': 0.0, 'post_sensor': 0, 'no_verify_delay': 0,
}


def load_best_drag_params(quiet=False):
    """Load tuned drag profile. best_drag_params.json wins over DEFAULT_PARAMS."""
    params = dict(DEFAULT_PARAMS)
    json_path = os.path.join(BASE_DIR, "best_drag_params.json")
    if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "params" in data:
                params.update(data["params"])
                if not quiet:
                    info(f"Loaded drag params from best_drag_params.json "
                         f"({data.get('variant', 'default')}, "
                         f"rate={data.get('rate', '?')})")
            elif "variants" in data:
                pri = data.get("primary_variant", "p_flash_turbo")
                if pri in data["variants"]:
                    params.update(data["variants"][pri].get("params", {}))
                    if not quiet:
                        info(f"Loaded drag profile from JSON: {pri}")
        except Exception as e:
            warn(f"Warning while loading best_drag_params.json: {e}")
    for lo, hi in (('t_lo', 't_hi'), ('accel_lo', 'accel_hi'),
                   ('peak_lo', 'peak_hi'), ('hold_lo', 'hold_hi'),
                   ('s_hold_lo', 's_hold_hi'), ('settle_lo', 'settle_hi')):
        if lo in params and hi in params and params[lo] > params[hi]:
            params[lo], params[hi] = params[hi], params[lo]
    return params


def rewrite_challenge(html, no_verify_delay=0):
    html = re.sub(r'<script src="(/[^"]+)"',
                  r'<script src="https://accountmtapi.mobilelegends.com\1"',
                  html)
    if no_verify_delay:
        html = html.replace(
            'initAliyunCaptcha(captchaOptions)',
            'initAliyunCaptcha(Object.assign({delayBeforeSuccess:false},'
            'captchaOptions))')
    base = '<base href="https://accountmtapi.mobilelegends.com/">'
    m = re.search(r'<head[^>]*>', html, flags=re.I)
    if m is not None:
        return html[:m.end()] + base + html[m.end():]
    m = re.search(r'<!doctype[^>]*>', html, flags=re.I)
    if m is not None:
        return html[:m.end()] + base + html[m.end():]
    return base + html


def check_host_connectivity(host=WAF_HOST):
    try:
        socket.gethostbyname(host)
        return True
    except (socket.gaierror, OSError):
        return False


def wait_for_vpn_change():
    global _VPN_RECOVERED_AT
    t_call = time.time()
    with VPN_LOCK:
        if _VPN_RECOVERED_AT > t_call and check_host_connectivity(WAF_HOST):
            info("Network was already restored by another browser. Continuing...")
            return
        if check_host_connectivity(WAF_HOST):
            _VPN_RECOVERED_AT = time.time()
            return
        with PRINT_LOCK:
            print(f"{C.YEL}{'!' * 60}{C.RESET}")
            print(f"{C.YEL}[!] NETWORK / IP BLOCK DETECTED!{C.RESET}")
            print(f"{C.YEL}[!] {WAF_HOST} cannot be resolved or is blocked{C.RESET}")
            print(f"{C.YEL}[!] Please CHANGE or RECONNECT your VPN now...{C.RESET}")
            print(f"{C.YEL}{'!' * 60}{C.RESET}")
        dots = 0
        while not STOP_EVENT.is_set():
            with PRINT_LOCK:
                sys.stdout.write(
                    f"\r{C.CYN}[*] Waiting for an active VPN / connection"
                    f"{'.' * (dots % 6)}      {C.RESET}")
                sys.stdout.flush()
            dots += 1
            time.sleep(2)
            if check_host_connectivity(WAF_HOST):
                with PRINT_LOCK:
                    sys.stdout.write("\n")
                ok("Network restored! Host is reachable again. Continuing...")
                time.sleep(2)
                _VPN_RECOVERED_AT = time.time()
                break


def seat_cap():
    if not SEAT_CHECK_OK or _fb_license is None:
        return None
    try:
        with open(os.path.join(os.path.expanduser('~'),
                               '.cloakbrowser', 'license.key')) as f:
            key = f.read().strip()
        return getattr(_fb_license.get_session_seats(key), 'limit', None)
    except Exception:
        return None


def seat_busy():
    if not SEAT_CHECK_OK or _fb_license is None:
        return False
    try:
        with open(os.path.join(os.path.expanduser('~'),
                               '.cloakbrowser', 'license.key')) as f:
            key = f.read().strip()
        s = _fb_license.get_session_seats(key)
        active = getattr(s, 'active', None)
        limit = getattr(s, 'limit', None)
        if limit is None or active is None:
            return False
        return bool(active >= limit)
    except Exception:
        return False


def wait_seat_free(timeout_s=600, poll_s=10):
    t0 = time.time()
    while time.time() - t0 < timeout_s and not STOP_EVENT.is_set():
        if not seat_busy():
            return True
        time.sleep(poll_s)
    return False


def _hard_kill_solver_browsers():
    if os.environ.get('CLOAK_SKIP_BROWSER_KILL', '').strip().lower() in (
            '1', 'true', 'yes'):
        return 0
    killed = 0
    try:
        import psutil
        markers = ('playwright_chromiumdev_profile', 'playwright_profile',
                   'playwright_crash_reporter')
        names = ('chrome.exe', 'chromium.exe', 'msedge.exe', 'chrome', 'chromium')
        for proc in psutil.process_iter(['name', 'cmdline']):
            try:
                name = (proc.info.get('name') or '').lower()
                cmd = ' '.join(proc.info.get('cmdline') or [])
                if name not in names or not any(m in cmd for m in markers):
                    continue
                proc.kill()
                killed += 1
            except Exception:
                continue
    except Exception:
        if platform.system() == 'Windows':
            try:
                subprocess.run(['taskkill', '/F', '/IM', 'chrome.exe', '/T'],
                               capture_output=True, timeout=8)
                killed = 1
            except Exception:
                pass
    if killed:
        print(f"{C.YEL}[!] Force-closed {killed} stuck browser process(es){C.RESET}")
    return killed


atexit.register(_hard_kill_solver_browsers)


BOOTSTRAP_HTML = '<!doctype html><html><head><meta charset="utf-8"></head><body></body></html>'


class _FetchBlockedError(ConnectionError):
    pass


class WAFSolver:
    def __init__(self, transport=TRANSPORT, headless=False, proxy=None,
                 browser_id=1):
        self.transport = transport
        self.headless = headless
        self.proxy = proxy
        self.browser_id = browser_id
        self.browser = None
        self.ctx = None
        self.page = None
        self._pw = None
        self._started = False
        self.restarts = 0
        self.cookies = {}
        self.certify_ids = []
        self.last_challenge = ''
        self.token = None
        self.asig = None
        self._submit_asig = None
        self._submit_token = None
        self._challenge_route_html = None
        # best_drag_params.json auto-loaded here; DEFAULT_PARAMS is fallback.
        self.params = load_best_drag_params(quiet=(browser_id != 1))
        self.solved_count = 0
        self.server_url = ""
        self._trigger_cookies = ""
        self._session_started_at = None
        # Track which trigger path won last time — informational only.
        self._last_trigger_source = None

    def start(self):
        if START_JITTER_S > 0:
            time.sleep(random.uniform(0.0, START_JITTER_S))
        info(f"Starting browser via {C.BOLD}{self.transport}{C.RESET}...")
        self._pw = None
        if self.transport == 'chromium':
            if not PW_OK:
                raise RuntimeError(
                    'playwright not importable: ' + str(PW_ERR)
                    + ' — pip install playwright && playwright install chromium')
            self._pw = sync_playwright().start()
            launch_kw = dict(headless=self.headless, args=list(CHROMIUM_ARGS))
            for cand in CHROME_EXE_CANDIDATES:
                if os.path.exists(cand):
                    launch_kw['executable_path'] = cand
                    break
            self.browser = self._pw.chromium.launch(**launch_kw)
        elif self.transport == 'cloak':
            if not CLOAK_OK:
                raise RuntimeError(
                    'cloakbrowser not importable: ' + str(CLOAK_ERR)
                    + ' — pip install cloakbrowser')
            self.browser = cloakbrowser.launch(headless=self.headless,
                                               humanize=True,
                                               args=['--disable-dev-shm-usage'])
        else:
            raise ValueError("transport must be 'cloak' or 'chromium'")

        ctx_kw = dict(
            user_agent=UA,
            locale='en-US',
            viewport={'width': 412, 'height': 915},
            is_mobile=True,
            has_touch=True,
            ignore_https_errors=True,
            color_scheme='light',
        )
        if self.proxy:
            ctx_kw['proxy'] = self.proxy
        self.ctx = self.browser.new_context(**ctx_kw)
        if self.transport == 'chromium':
            try:
                self.ctx.add_init_script(STEALTH_JS)
                self.ctx.add_init_script(FINGERPRINT_JS)
            except Exception as e:
                dbg_log('STEALTH', f'init script failed: {e}')
        self.page = self.ctx.new_page()
        self.certify_ids = []
        self._submit_asig = None
        self._submit_token = None
        self.last_challenge = ''
        self._challenge_route_html = None
        self.page.on('response', self._on_response)
        if not self._prime():
            dbg_log('START', 'prime failed — browser/page not usable')
            self.close()
            raise RuntimeError('prime failed: browser/page died at launch')
        self._started = True
        self._session_started_at = time.time()
        ok(f"Browser session ready (TTL {SESSION_MAX_AGE_S}s).")

    def _prime(self):
        # wait_until='commit' fires as soon as response headers arrive —
        # Set-Cookie is processed at commit. domcontentloaded blocked ~1–3s
        # per browser start on a page we never actually read.
        try:
            info("Priming mtacc page...")
            self.page.goto(MTACC_PAGE, wait_until='commit', timeout=30000)
            self.page.wait_for_timeout(150)
        except Exception as e:
            dbg_log('PRIME', f'goto failed: {e}')
            if is_net_error(e):
                wait_for_vpn_change()
            return False
        if not self._alive():
            dbg_log('PRIME', 'page not usable after goto')
            return False
        self._snap_cookies()
        dbg_log('PRIME', f'cookies={list(self.cookies)}')
        self._prewarm_captcha()
        return True

    def _prewarm_captcha(self):
        try:
            res = self.page.evaluate(PREWARM_JS, list(PREWARM_HOSTS))
        except Exception as e:
            dbg_log('PREWARM', f'skipped: {str(e)[:90]}')
            return
        warm = [u.split('/')[2] for u, ms in (res or [])
                if ms is not None and ms >= 0]
        dbg_log('PREWARM', f'warm {len(warm)}/{len(PREWARM_HOSTS)}')

    def _alive(self, fast=False):
        try:
            if fast:
                return not self.page.is_closed()
            self.page.wait_for_timeout(50)
            self.page.evaluate('1')
            return True
        except Exception:
            return False

    def close(self):
        if self.browser:
            try:
                self.browser.close()
            except Exception:
                pass
        self.browser = None
        self.ctx = None
        self.page = None
        self._started = False
        self._session_started_at = None
        if self._pw:
            try:
                self._pw.stop()
            except Exception:
                pass
            self._pw = None

    def _mark_dead(self, reason):
        warn(f"Browser session died ({reason}) — will restart...")
        self._started = False
        self.close()

    def _session_age(self):
        if self._session_started_at is None:
            return 0.0
        return time.time() - self._session_started_at

    def ensure_session(self):
        # 2-minute session cap. Every producer path calls this per iteration.
        if self._started and self._session_age() >= SESSION_MAX_AGE_S:
            info(f"⏱  {SESSION_MAX_AGE_S}s session cap reached — restarting browser")
            self.close()

        if self._started:
            if self.transport == 'chromium':
                try:
                    if not self._alive(fast=True):
                        dbg_log('FARM', 'session page dead — relaunching')
                        self._mark_dead('page closed')
                except Exception:
                    self._mark_dead('page closed')
            if self.transport == 'cloak' and self._started:
                try:
                    self.page.evaluate('1')
                except Exception:
                    dbg_log('FARM', 'cloak browser unresponsive — relaunching')
                    self._mark_dead('cloak browser unresponsive')
            if self._started:
                return True

        retry_count = 0
        while not self._started and not STOP_EVENT.is_set():
            if not check_host_connectivity():
                wait_for_vpn_change()
            if self.transport == 'cloak':
                if not wait_seat_free(60, 5):
                    warn(f"All cloak seats busy ({self.restarts} restarts) — waiting...")
                    wait_seat_free(120, 10)
            try:
                self.start()
                self.restarts += 1
                dbg_log('FARM', f'browser respawned (restart #{self.restarts})')
            except Exception as e:
                self.close()
                retry_count += 1
                msg = str(e)
                if 'not importable' in msg or 'No module named' in msg:
                    err(f"Fatal: {msg}")
                    STOP_EVENT.set()
                    return False
                if retry_count <= START_RETRIES:
                    delay = 2 if self.transport == 'chromium' else 10
                    err(f"Session start failed (try {retry_count}/{START_RETRIES}): {msg[:80]}")
                    time.sleep(delay)
                else:
                    err(f"Session start failed {START_RETRIES}x: {msg[:80]}")
                    return False
            if not self._started:
                time.sleep(3)
        return self._started

    def _clear_routes(self):
        for pattern in ('**/accountmtapi.mobilelegends.com/**',
                        '**/*u_asig=*', '**/*u_atoken=*'):
            try:
                self.page.unroute(pattern)
            except Exception:
                pass
        self._challenge_route_html = None

    def _install_challenge_router(self, rewritten_html):
        self._challenge_route_html = rewritten_html

        def handler(route):
            try:
                req = route.request
                is_nav = False
                try:
                    is_nav = req.is_navigation_request()
                except Exception:
                    is_nav = (req.resource_type == 'document')
                if is_nav and req.method == 'GET' and self._challenge_route_html:
                    route.fulfill(
                        status=200,
                        headers={
                            'Content-Type': 'text/html; charset=utf-8',
                            'Access-Control-Allow-Origin': '*',
                            'Cache-Control': 'no-store',
                        },
                        body=self._challenge_route_html,
                    )
                    return
            except Exception as e:
                dbg_log('ROUTE', f'handler err: {str(e)[:80]}')
            try:
                route.continue_()
            except Exception:
                pass

        try:
            self.page.unroute('**/accountmtapi.mobilelegends.com/**')
        except Exception:
            pass
        try:
            self.page.route('**/accountmtapi.mobilelegends.com/**', handler)
        except Exception as e:
            dbg_log('ROUTE', f'install failed: {str(e)[:90]}')

    def _install_bootstrap_router(self):
        self._install_challenge_router(BOOTSTRAP_HTML)

    def _install_submit_router(self):
        def handler(route):
            try:
                url = route.request.url
                if 'u_asig=' in url or 'u_atoken=' in url:
                    ma = re.search(r'[?&]u_asig=([a-zA-Z0-9]+)', url)
                    mt = re.search(r'[?&]u_atoken=([a-zA-Z0-9]+)', url)
                    if ma:
                        self._submit_asig = ma.group(1)
                    if mt:
                        self._submit_token = mt.group(1)
                    ok(f"Intercepted tokens: asig={self._submit_asig} | token={self._submit_token}")
                    route.fulfill(status=200, headers={'Content-Type': 'text/html'},
                                  body='<html></html>')
                    return
            except Exception as e:
                dbg_log('SUBMIT', f'route err: {e}')
            try:
                route.continue_()
            except Exception:
                pass

        try:
            self.page.unroute('**/*u_asig=*')
            self.page.unroute('**/*u_atoken=*')
        except Exception:
            pass
        try:
            self.page.route('**/*u_asig=*', handler)
            self.page.route('**/*u_atoken=*', handler)
        except Exception as e:
            dbg_log('SUBMIT', f'route install failed: {str(e)[:90]}')

    def _uninstall_submit_router(self):
        for pattern in ('**/*u_asig=*', '**/*u_atoken=*'):
            try:
                self.page.unroute(pattern)
            except Exception:
                pass

    def _on_response(self, resp):
        try:
            u = resp.url
            if resp.status == 405 and ('u_asig=' in u or 'u_atoken=' in u):
                ma = re.search(r'[?&]u_asig=([a-zA-Z0-9]+)', u)
                mt = re.search(r'[?&]u_atoken=([a-zA-Z0-9]+)', u)
                if ma:
                    self._submit_asig = ma.group(1)
                if mt:
                    self._submit_token = mt.group(1)
                dbg_log('SUBMIT', f'nginx 405; harvested u_asig={self._submit_asig}')
            if 'captcha-open' in u:
                body = resp.text()
                c = re.findall(r'"[Cc]ertifyId":"([a-zA-Z0-9]{8,})"', body)
                if c:
                    self.certify_ids.extend(c)
                    ok(f"Captured CertifyId: {c[-1]}")
        except Exception:
            pass

    def _snap_cookies(self):
        out = {}
        try:
            for c in self.ctx.cookies():
                out[c['name']] = c['value']
        except Exception:
            pass
        self.cookies = out

    def _sync_trigger_cookies(self):
        """Set the WAF cookies captured by the HTTP trigger into the browser
        context so the solved challenge binds to the same WAF session.

        Batched into one add_cookies() call — same cookies, fewer round-trips.
        """
        if not self._trigger_cookies or not self.ctx:
            return
        try:
            batch = []
            for pair in self._trigger_cookies.split(';'):
                pair = pair.strip()
                if '=' not in pair:
                    continue
                name, _, value = pair.partition('=')
                for domain in ('accountmtapi.mobilelegends.com',
                               '.mobilelegends.com'):
                    batch.append({
                        'name': name.strip(),
                        'value': value.strip(),
                        'domain': domain,
                        'path': '/',
                    })
            if batch:
                self.ctx.add_cookies(batch)
            self._snap_cookies()
            dbg_log('TRIGGER', f'synced {len(batch)} trigger cookies')
        except Exception as e:
            dbg_log('TRIGGER', f'cookie sync failed: {str(e)[:80]}')

    def _pw_proxy_to_cffi(self):
        """Convert Playwright proxy dict to curl_cffi proxies dict.
        Returns None when direct."""
        if not self.proxy:
            return None
        p = self.proxy
        if isinstance(p, str):
            return {'http': p, 'https': p}
        server = p.get('server', '')
        if not server:
            return None
        user = p.get('username')
        pw = p.get('password')
        if user and '://' in server:
            scheme, rest = server.split('://', 1)
            if '@' not in rest:
                server = f"{scheme}://{user}:{pw}@{rest}"
        return {'http': server, 'https': server}

    def _cookie_header(self):
        return '; '.join(f'{k}={v}' for k, v in self.cookies.items())

    def _waf_cookie_header(self):
        """Return every cookie the WAF set for *.mobilelegends.com.
        acw_tc is what the WAF bound the solved challenge to."""
        out = {}
        try:
            for c in self.ctx.cookies():
                domain = (c.get('domain') or '').lstrip('.').lower()
                if domain.endswith('mobilelegends.com'):
                    out[c['name']] = c['value']
        except Exception:
            pass
        return ';'.join(f'{k}={v}' for k, v in out.items())

    def _ensure_same_origin(self):
        try:
            origin = self.page.evaluate('location.origin')
        except Exception:
            origin = ''
        if origin == LOGIN_URL:
            return True
        self._install_bootstrap_router()
        try:
            self.page.goto(LOGIN_URL + '/', wait_until='domcontentloaded',
                           timeout=15000)
            return True
        except Exception as e:
            dbg_log('BOOTSTRAP', f'goto origin failed: {str(e)[:90]}')
            return False

    # ── trigger: curl_cffi first, browser fallback when 405-blocked ──
    def _browser_trigger(self):
        """Fallback: have the primed browser POST the trigger itself with
        credentials:'include' (kontolsolver model). Returns the challenge
        HTML served from the same origin, or '' on failure.

        The browser must already be on an mtacc / accountmtapi origin so
        same-site cookies attach. _prime() lands on MTACC_PAGE, and
        _ensure_same_origin() forces accountmtapi if needed.
        """
        if not self.page or not self.ctx:
            return ''
        try:
            if not self._ensure_same_origin():
                dbg_log('TRIGGER', 'browser fallback: cannot reach same origin')
                return ''
            body = json.dumps(TRIGGER_PAYLOAD)
            js = """async ([url, body, hdrs]) => {
              try {
                const r = await fetch(url, {method:'POST',
                  credentials:'include', headers: hdrs, body: body});
                return await r.text();
              } catch (e) { return '__ERR__' + (e && e.message || e); }
            }"""
            text = self.page.evaluate(js, [LOGIN_URL + '/', body,
                                           _TRIGGER_HEADERS])
            if not isinstance(text, str) or text.startswith('__ERR__'):
                dbg_log('TRIGGER', f'browser fallback err: {str(text)[:100]}')
                return ''
            self._snap_cookies()
            dbg_log('TRIGGER', f'browser fallback: {len(text)}b '
                               f'block={is_block_page(text)} '
                               f'slider={is_waf_challenge(text)}')
            if is_waf_challenge(text):
                # WAF cookies now live in ctx naturally — no _trigger_cookies
                # to sync, the browser already sent them with the POST.
                self._trigger_cookies = ''
                return text
            return text
        except Exception as e:
            dbg_log('TRIGGER', f'browser fallback raised: {str(e)[:100]}')
            return ''

    def _try_post(self, payload=None, url=None):
        """Trigger the WAF challenge.

        Order:
          1. curl_cffi across _IMPERSONATE_TARGETS (fast, cached after first hit).
          2. If every alias is 405-blocked, fall back to the browser doing the
             POST itself with credentials:'include'.
        Returns the response body (challenge HTML, JSON, or block page).
        """
        result, cookies = http_trigger_challenge(
            payload or TRIGGER_PAYLOAD,
            proxy=self._pw_proxy_to_cffi(),
        )
        if cookies:
            self._trigger_cookies = cookies
        dbg_log('TRIGGER', f'http trigger: {len(result or "")}b '
                           f'block={is_block_page(result)} '
                           f'slider={is_waf_challenge(result)}')
        self._last_trigger_source = 'curl_cffi'

        if is_block_page(result) and self.page:
            dbg_log('TRIGGER', 'all curl_cffi aliases 405 — trying browser fallback')
            br = self._browser_trigger()
            if br:
                result = br
                self._last_trigger_source = 'browser'
        elif not is_waf_challenge(result) and self.page and result:
            # Non-block, non-challenge body (JSON) — leave as-is. Caller
            # handles the re-POST loop. Don't waste a browser fallback here.
            pass
        return result

    def _reset_challenge(self):
        try:
            self.page.goto('about:blank', wait_until='commit')
        except Exception as e:
            if is_closed_error(e):
                raise
        try:
            self.page.wait_for_timeout(20)
        except Exception as e:
            if is_closed_error(e):
                raise

    def _reset_harvest(self):
        self.certify_ids = []
        self._submit_asig = None
        self._submit_token = None
        self.asig = None
        self.token = None

    def _load_challenge_page(self):
        """wait_until='commit' — the route handler fulfills the body
        immediately, so waiting for domcontentloaded adds only the SDK's
        inline-init latency. The subsequent _wait_slider() covers the
        actual readiness the drag needs."""
        try:
            self.page.goto(LOGIN_URL + '/', wait_until='commit', timeout=15000)
            return True
        except Exception as e:
            if is_closed_error(e):
                raise
            dbg_log('SOLVE', f'goto real origin failed: {str(e)[:90]}')
            return False

    def _diag_challenge(self):
        try:
            diag = self.page.evaluate("""() => ({
                title: document.title,
                url: location.href,
                origin: location.origin,
                hasSlider: !!document.querySelector('#aliyunCaptcha-sliding-slider'),
                sliderVisible: (() => {
                    const s = document.querySelector('#aliyunCaptcha-sliding-slider');
                    if (!s) return false;
                    const r = s.getBoundingClientRect();
                    return r.width > 0 && r.height > 0;
                })(),
                hasCheckbox: !!document.querySelector('#aliyunCaptcha-checkbox-icon'),
                hasRenderData: !!document.querySelector('#renderData'),
                bodyLen: document.body ? document.body.innerHTML.length : 0,
                scripts: Array.from(document.scripts)
                    .map(s => s.src).filter(Boolean).slice(0, 6)
            })""")
            dbg_log('DIAG', f"challenge page: {diag}")
            return diag
        except Exception as e:
            dbg_log('DIAG', f'eval failed: {str(e)[:90]}')
            return None

    def _wait_slider(self):
        try:
            self.page.wait_for_selector('#aliyunCaptcha-sliding-slider',
                                        timeout=SLIDER_WAIT_S * 1000,
                                        state='visible')
            return True
        except Exception as e:
            if is_closed_error(e):
                raise
            return False

    def _refresh_challenge(self):
        result = self._try_post()
        if not is_waf_challenge(result):
            dbg_log('DRAG', f'refresh: no challenge ({len(result or "")}b)')
            return False
        self._reset_harvest()
        self.last_challenge = result
        rewritten = rewrite_challenge(result, self.params.get('no_verify_delay', 0))
        self._install_challenge_router(rewritten)
        self._load_challenge_page()
        # Short settle — _wait_slider() below is the real readiness gate.
        time.sleep(random.uniform(0.0, 0.15))
        return True

    def _cdp(self):
        return self.ctx.new_cdp_session(self.page)

    def _ev_touch(self, cdp, t, x, y, keep=False):
        pts = [{'x': x, 'y': y, 'radiusX': 6, 'radiusY': 6, 'force': 1,
                'id': 1}] if not keep else []
        try:
            cdp.send('Input.dispatchTouchEvent', {'type': t, 'touchPoints': pts})
            return True
        except Exception as e:
            if is_closed_error(e):
                raise
            return False

    def _bezier_points(self, x1, y1, x2, y2, steps):
        cx1, cy1 = x1 + random.randint(-40, 40), y1 + random.randint(-30, 30)
        cx2, cy2 = x2 + random.randint(-40, 40), y2 + random.randint(-30, 30)
        pts = []
        for i in range(steps + 1):
            t = i / steps
            u = 1 - t
            px = int(u ** 3 * x1 + 3 * u ** 2 * t * cx1 + 3 * u * t ** 2 * cx2 + t ** 3 * x2)
            py = int(u ** 3 * y1 + 3 * u ** 2 * t * cy1 + 3 * u * t ** 2 * cy2 + t ** 3 * y2)
            pts.append((max(5, min(px, 407)), max(5, min(py, 910))))
        return pts

    def _human_click(self, cdp, x, y, prev=None):
        try:
            if prev is None:
                prev = (random.randint(24, 120), random.randint(80, 320))
            pts = self._bezier_points(prev[0], prev[1], x, y,
                                      steps=random.randint(14, 24))
            n = len(pts)
            for i, (px, py) in enumerate(pts):
                cdp.send('Input.dispatchMouseEvent',
                         {'type': 'mouseMoved', 'x': px, 'y': py})
                frac = i / max(n - 1, 1)
                time.sleep(random.uniform(0.004, 0.010) * (1.0 + (1.0 - frac) ** 2) * 1.8)
            time.sleep(random.uniform(0.035, 0.085))
            down_js = """([x, y]) => {
              const el = document.elementFromPoint(x, y) || document.body;
              el.dispatchEvent(new PointerEvent('pointerdown', {bubbles: true,
                cancelable: true, pointerType: 'mouse', isPrimary: true,
                clientX: x, clientY: y, button: 0, buttons: 1 }));
              el.dispatchEvent(new MouseEvent('mousedown', {bubbles: true,
                cancelable: true, clientX: x, clientY: y, button: 0, buttons: 1 }));
            }"""
            up_js = """([x, y]) => {
              const el = document.elementFromPoint(x, y) || document.body;
              el.dispatchEvent(new PointerEvent('pointerup', {bubbles: true,
                cancelable: true, pointerType: 'mouse', clientX: x, clientY: y,
                button: 0, buttons: 0 }));
              el.dispatchEvent(new MouseEvent('mouseup', {bubbles: true,
                cancelable: true, clientX: x, clientY: y, button: 0, buttons: 0 }));
            }"""
            cdp.send('Input.dispatchMouseEvent',
                     {'type': 'mousePressed', 'x': x, 'y': y,
                      'button': 'left', 'buttons': 1, 'clickCount': 1})
            self.page.evaluate(down_js, [x, y])
            time.sleep(random.uniform(0.06, 0.16))
            cdp.send('Input.dispatchMouseEvent',
                     {'type': 'mouseReleased', 'x': x, 'y': y,
                      'button': 'left', 'buttons': 0, 'clickCount': 1})
            self.page.evaluate(up_js, [x, y])
            return (x, y)
        except Exception as e:
            if is_closed_error(e):
                raise
            return prev

    def _click_around(self, n=3):
        if n < 1 or not (self.ctx and self.page):
            return
        try:
            cdp = self._cdp()
            vw, vh = 412, 915
            zones = [
                (random.randint(30, vw - 60), random.randint(42, 110)),
                (random.randint(30, vw - 60), random.randint(vh - 150, vh - 40)),
                ((random.randint(8, 44) if random.random() < 0.5
                  else random.randint(vw - 44, vw - 8)), random.randint(200, vh - 200)),
                (random.randint(60, vw - 120), random.randint(120, 260)),
                (random.randint(60, vw - 120), random.randint(600, vh - 220)),
            ]
            prev = None
            for (cx, cy) in random.sample(zones, min(n, len(zones))):
                prev = self._human_click(cdp, cx, cy, prev)
                time.sleep(random.uniform(0.005, 0.015))
        except Exception as e:
            if is_closed_error(e):
                raise

    def _pre_scroll(self):
        try:
            cdp = self._cdp()
            x, y = random.randint(170, 270), random.randint(160, 470)
            total = random.choice([-180, -140, -100, -70, 60, 90, 130, 170])
            steps = random.randint(4, 8)
            prev_f = 0.0
            for i in range(1, steps + 1):
                t = i / steps
                f = t * t * (3 - 2 * t)
                cdp.send('Input.dispatchMouseEvent', {
                    'type': 'mouseWheel', 'x': x + random.randint(-2, 2),
                    'y': y + random.randint(-2, 2), 'deltaX': 0,
                    'deltaY': round(total * (f - prev_f), 1)})
                prev_f = f
                time.sleep(random.uniform(0.04, 0.11))
        except Exception as e:
            if is_closed_error(e):
                raise

    def _bezier_drag(self, sx, sy, dist):
        """ML_CHECKER style bezier drag. Do not tune — profile is load-bearing."""
        cdp = self._cdp()
        end = sx + dist
        P = self.params

        pre_drag = P.get('pre_drag', 0.15)
        if random.random() < pre_drag:
            test_x = sx + random.uniform(5, 20)
            self._ev_touch(cdp, 'touchStart', test_x, sy)
            time.sleep(random.uniform(0.05, 0.12))
            self._ev_touch(cdp, 'touchEnd', test_x, sy)
            time.sleep(random.uniform(0.08, 0.18))

        pre_clicks = int(P.get('pre_clicks', 0))
        for _ in range(pre_clicks):
            click_x = sx + random.uniform(-10, 30)
            click_y = sy + random.uniform(-5, 5)
            self._ev_touch(cdp, 'touchStart', click_x, click_y)
            time.sleep(random.uniform(0.04, 0.08))
            self._ev_touch(cdp, 'touchEnd', click_x, click_y)
            time.sleep(random.uniform(0.06, 0.12))

        t_lo = P.get('t_lo', 0.95)
        t_hi = P.get('t_hi', 1.35)
        base_n = int(P.get('base_n', 9))
        density = P.get('density', 0.014)
        accel_lo = P.get('accel_lo', 0.42)
        accel_hi = P.get('accel_hi', 0.56)
        peak_lo = P.get('peak_lo', 2.8)
        peak_hi = P.get('peak_hi', 3.3)

        hover_x = sx + random.randint(-2, 2)
        hover_y = sy + random.randint(-1, 1)
        self._ev_touch(cdp, 'touchStart', hover_x, hover_y)
        time.sleep(random.uniform(0.06, 0.14))

        n_steps = max(base_n, int(abs(dist) * density) + random.randint(2, 6))
        accel_frac = random.uniform(accel_lo, accel_hi)
        accel_end = int(n_steps * accel_frac)

        for i in range(n_steps + 1):
            t = i / n_steps if n_steps > 0 else 0

            if i < accel_end:
                progress = (t / accel_frac) ** random.uniform(peak_lo, peak_hi)
            else:
                remaining_t = (t - accel_frac) / (1 - accel_frac)
                progress = accel_frac + remaining_t * (1 - accel_frac) * (1 - (1 - remaining_t) ** 1.5)

            progress = max(0.0, min(1.0, progress))
            target_x = sx + dist * progress

            wobble = P.get('wobble', 4.0)
            target_y = sy + math.sin(progress * math.pi) * wobble * random.uniform(0.3, 0.7)
            target_y += random.gauss(0, 0.5)

            vel_factor = 1.0 + (1.0 - progress) ** 1.2 if i >= accel_end else 0.5
            dt = random.uniform(t_lo, t_hi) * vel_factor
            dt = max(0.003, min(dt, 0.05))

            self._ev_touch(cdp, 'touchMove', target_x, target_y)
            time.sleep(dt)

        settle_lo = P.get('settle_lo', 0.001)
        settle_hi = P.get('settle_hi', 0.003)
        rev_p = P.get('rev_p', 0.0)

        for _ in range(random.randint(2, 4)):
            if random.random() < rev_p:
                reverse_x = end + random.uniform(-3, 2)
            else:
                reverse_x = end + random.uniform(-0.5, 0.5)
            self._ev_touch(cdp, 'touchMove', reverse_x, sy + random.gauss(0, 0.3))
            time.sleep(random.uniform(settle_lo, settle_hi))

        self._ev_touch(cdp, 'touchMove', end, sy)
        time.sleep(random.uniform(0.04, 0.12))
        for _ in range(random.randint(1, 2)):
            micro_x = end + random.uniform(-1, 1)
            self._ev_touch(cdp, 'touchMove', micro_x, sy + random.gauss(0, 0.2))
            time.sleep(random.uniform(0.01, 0.03))
        self._ev_touch(cdp, 'touchEnd', end, sy, keep=True)
        return True

    def _human_like_drag(self, sx, sy, dist):
        """Legacy drag (kept for compatibility)"""
        return self._bezier_drag(sx, sy, dist)

    def _harvested(self, pre_cert=0):
        return bool(self._submit_asig) or len(self.certify_ids) > pre_cert

    def drag_slider(self, retries=DRAG_RETRIES, refresh_loops=DRAG_REFRESH_LOOPS):
        refresh_left = refresh_loops
        P = self.params
        for attempt in range(retries):
            need_refresh = False
            slider = self.page.query_selector('#aliyunCaptcha-sliding-slider')
            if not slider:
                dbg_log('DRAG', 'slider gone (solved after drag)')
                return self._harvested()
            box = slider.bounding_box()
            if not box:
                err("Failed to get slider coordinates.")
                return False
            track = self.page.query_selector(
                '#aliyunCaptcha-sliding-body, #aliyunCaptcha-sliding-track')
            tbox = (track.bounding_box() if track else None) or box
            sx = box['x'] + box['width'] / 2
            sy = box['y'] + box['height'] / 2
            base_dist = (tbox['x'] + tbox['width'] - box['width'] / 2) - sx
            dist = base_dist + random.uniform(10, 15)
            info(f"Sliding Aliyun WAF Captcha "
                 f"(try {attempt + 1}/{retries}, dist: {C.BOLD}{dist:.1f}px{C.RESET} [+{dist-base_dist:.1f}px])...")
            pre_cert = len(self.certify_ids)
            if random.random() < P.get('pre_scroll', 0.0):
                self._pre_scroll()
            self._human_like_drag(sx, sy, dist)

            confirmed = False
            for i in range(10):
                if self._harvested(pre_cert):
                    confirmed = True
                    break
                if i % 2 == 0 or i == 9:
                    st = None
                    try:
                        st = self.page.evaluate(
                            """()=>{const e=document.getElementById('aliyunCaptcha-sliding-left');
                            const f=document.getElementById('aliyunCaptcha-sliding-failTip');
                            return {left:e?e.getBoundingClientRect().width:0,
                                    fail:(f&&f.textContent)||''};}""")
                    except Exception as e:
                        if is_closed_error(e):
                            raise
                    if st and st.get('left', 0) >= (tbox['width'] - 2):
                        dbg_log('DRAG', 'slider reached end of track')
                        confirmed = True
                        break
                    tip_l = ((st or {}).get('fail') or '').lower()
                    if 'fail' in tip_l or 'retry' in tip_l or 'refresh' in tip_l:
                        need_refresh = ('refresh' in tip_l
                                        or 'verification failed' in tip_l
                                        or 'try again' in tip_l)
                        warn(f"Fail tip: {tip_l[:44]!r}")
                        break
                self.page.wait_for_timeout(5)

            if not confirmed:
                try:
                    fail_txt = self.page.evaluate("""() => {
                        const f = document.getElementById('aliyunCaptcha-sliding-failTip');
                        const s = document.getElementById('aliyunCaptcha-sliding-slider');
                        return {
                            tip: (f && f.textContent) || '',
                            slider_left: s ? s.getBoundingClientRect().left : -1,
                            track_w: (document.getElementById('aliyunCaptcha-sliding-body')||{}).clientWidth
                        };
                    }""")
                    dbg_log('DRAG', f'after-drag state: {fail_txt}')
                except Exception as e:
                    dbg_log('DRAG', f'state eval failed: {str(e)[:90]}')

            if confirmed:
                return True
            if need_refresh and refresh_left > 0:
                refresh_left -= 1
                info(f"Verification failed — refreshing challenge ({refresh_left} left)...")
                if not self._refresh_challenge() or not self._wait_slider():
                    err("No slider after refresh.")
                    return False
                self._click_around(int(P.get('pre_clicks', 0)))
                continue
            self.page.wait_for_timeout(50)
        return self._harvested()

    def _wait_tokens(self, timeout_s=TOKEN_WAIT_S):
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if self._submit_asig and self._submit_token:
                break
            try:
                self.page.wait_for_timeout(100)
            except Exception as e:
                if is_closed_error(e):
                    raise
                time.sleep(0.1)
        self.asig = self._submit_asig or (self.certify_ids[-1] if self.certify_ids else None)
        self.token = self._submit_token
        if not self.token:
            m = re.search(r'["\']token["\']\s*[:=]\s*["\']([a-zA-Z0-9]+)["\']',
                          self.last_challenge or '')
            if m:
                self.token = m.group(1)
        return bool(self.asig and self.token)

    def _solve_once(self, refresh=False):
        self._clear_routes()
        self._reset_harvest()
        try:
            if self.page.url != 'about:blank':
                self.page.goto('about:blank', wait_until='commit', timeout=5000)
        except Exception:
            pass

        if refresh:
            info("Refreshing captcha page (same browser)...")
        else:
            info("Triggering WAF challenge...")

        try:
            result = self._try_post()
        except _FetchBlockedError as e:
            warn(f"fetch blocked ({str(e)[:60]}) — restarting browser context...")
            self._mark_dead('fetch blocked')
            return False

        block_tries = 0
        while is_block_page(result) and block_tries < BLOCK_RETRIES \
                and not STOP_EVENT.is_set():
            block_tries += 1
            backoff = min(BLOCK_BACKOFF_S * block_tries, 10.0) \
                + random.uniform(0.0, 1.5)
            err(f"405 block page — retrying trigger in {backoff:.1f}s "
                f"({block_tries}/{BLOCK_RETRIES})...")
            time.sleep(backoff)
            try:
                result = self._try_post()
            except _FetchBlockedError:
                continue
        if is_block_page(result):
            err(f"Still blocked after {block_tries} trigger retries "
                "(405 block page) — giving up this attempt.")
            return False

        # Only sync curl_cffi cookies. Browser fallback already set cookies
        # natively on .mobilelegends.com during its own POST.
        if self._last_trigger_source != 'browser':
            self._sync_trigger_cookies()

        for _ in range(3):
            if is_waf_challenge(result) or looks_real_json(result):
                break
            dbg_log('SOLVE', f'no-captcha body ({len(result or "")}b) — re-POST')
            time.sleep(0.1 + random.random() * 0.1)
            result = self._try_post()
        if not is_waf_challenge(result):
            err("Server did not serve a WAF challenge "
                f"({'JSON' if looks_real_json(result) else str(len(result or '')) + 'b'}).")
            return False

        self.last_challenge = result
        rewritten = rewrite_challenge(result, self.params.get('no_verify_delay', 0))

        self._install_challenge_router(rewritten)
        self._load_challenge_page()
        # Short settle — _wait_slider() below is the real readiness gate.
        time.sleep(random.uniform(0.0, 0.15))
        if DEBUG:
            self._diag_challenge()

        has_slider = self._wait_slider()
        if not has_slider:
            for rf in range(2):
                warn(f"No slider — refreshing challenge ({rf + 1}/2)...")
                if "blocked" in (self.page.url or "").lower():
                    raise ConnectionError("net::ERR_BLOCKED (about:blank#blocked)")
                if self._refresh_challenge() and self._wait_slider():
                    has_slider = True
                    break
        if not has_slider:
            if self._submit_asig:
                return self._wait_tokens(0.8)
            return False

        self._install_submit_router()
        try:
            self._click_around(int(self.params.get('pre_clicks', 0)))
            self.drag_slider()
            return self._wait_tokens()
        finally:
            self._uninstall_submit_router()

    def solve(self, max_retries=50, max_solves=0):
        fails = 0
        attempt = 0
        last_res = None
        refresh = False
        while not STOP_EVENT.is_set():
            if max_solves and self.solved_count >= max_solves:
                info(f"Reached max solves ({max_solves}). Stopping this browser.")
                break
            if fails >= max_retries:
                err(f"{max_retries} failed attempts in a row. Stopping this browser.")
                break
            attempt += 1
            info(f"Solve attempt {C.BOLD}#{attempt}{C.RESET} "
                 f"(solved: {C.GRN}{self.solved_count}{C.RESET}, "
                 f"fails in a row: {C.YEL}{fails}{C.RESET}/{max_retries})...")
            if not self.ensure_session():
                err("Could not start the browser session — retrying...")
                fails += 1
                refresh = False
                time.sleep(5)
                continue
            try:
                if self._solve_once(refresh=refresh):
                    ok("CAPTCHA SOLVED SUCCESSFULLY!")
                    last_res = self.save_token()
                    self.solved_count += 1
                    fails = 0
                    refresh = True
                    time.sleep(random.uniform(0.3, 0.8))
                    continue
                fails += 1
                refresh = False
                warn("No token received. Trying a fresh challenge...")
                try:
                    self._reset_challenge()
                except Exception as e:
                    if is_closed_error(e):
                        self._mark_dead(str(e)[:60])
            except KeyboardInterrupt:
                raise
            except _FetchBlockedError as e:
                warn(f"fetch blocked ({str(e)[:60]}) — restarting browser...")
                self._mark_dead('fetch blocked')
                fails += 1
                refresh = False
            except Exception as e:
                if is_closed_error(e):
                    self._mark_dead(str(e)[:80])
                elif is_net_error(e):
                    if not check_host_connectivity():
                        wait_for_vpn_change()
                    self._mark_dead('network error')
                elif isinstance(e, ConnectionError):
                    msg = str(e)
                    if 'net::ERR_BLOCKED' in msg or 'ERR_BLOCKED' in msg:
                        self._mark_dead('request blocked')
                    else:
                        warn(f"Transient connection error: {msg[:100]}")
                        self._mark_dead('connection error')
                else:
                    err(f"Solve error: {str(e)[:160]}")
                    if self._started and not self._alive():
                        self._mark_dead('page unresponsive')
                fails += 1
                refresh = False
            time.sleep(1)
        info(f"Browser finished. Total solved: {C.BOLD}{self.solved_count}{C.RESET}")
        return last_res

    def save_token(self):
        cookies = self._waf_cookie_header()
        token_entry = (f"TIMESTAMP={int(time.time())} | browser={self.browser_id} "
                       f"| u_atoken={self.token or 'N/A'} | u_asig={self.asig} "
                       f"| cookies={cookies}\n")
        with TOKEN_LOCK:
            try:
                with open(TOKEN_FILE, "a", encoding="utf-8") as f:
                    f.write(token_entry)
            except Exception:
                pass
        with PRINT_LOCK:
            print(f"{C.GRN}{C.BOLD}{'=' * 60}{C.RESET}")
            print(f"{C.GRN}{C.BOLD}[★] TOKEN SAVED TO: {TOKEN_FILE}{C.RESET}")
            print(f"{C.CYN}    DATA: {token_entry.strip()[:180]}{C.RESET}")
            print(f"{C.GRN}{C.BOLD}{'=' * 60}{C.RESET}")
        token_data = {'token': self.token, 'asig': self.asig, 'cookies': cookies}
        if self.server_url:
            _post_token_to_server(token_data, self.server_url, self.browser_id)
        return token_data


_WORKING_ENDPOINT = None
_ENDPOINT_LOCK = threading.Lock()
SUBMIT_CANDIDATE_PATHS = [
    "/api/submit-token", "/submit-token", "/submit/token",
    "/submit", "/api/token", "/tokens",
]


def _post_token_to_server(token_data, server_url, browser_id):
    global _WORKING_ENDPOINT
    if not server_url:
        return
    import urllib.request
    import urllib.error

    base = server_url.rstrip('/')
    payload = {
        "u_atoken": token_data.get("token") or "",
        "u_asig": token_data.get("asig") or "",
        "cookies": token_data.get("cookies") or "",
        "browser": browser_id,
        "timestamp": int(time.time()),
    }
    encoded = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json",
               "User-Agent": "MLBB-WAF-Solver/1.0"}
    for path in SUBMIT_CANDIDATE_PATHS:
        try:
            req = urllib.request.Request(f"{base}{path}", data=encoded,
                                         headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status in (200, 201, 204):
                    log(f"{C.GRN}[+] Token sent to {base}{path} [HTTP {resp.status}].{C.RESET}")
                    return
        except Exception:
            continue


def _parse_proxy(s):
    if not s:
        return None
    if '://' not in s:
        s = 'http://' + s
    m = re.match(r'^(\w+)://(?:([^:@]+):([^@]+)@)?([^:/]+):(\d+)', s)
    if not m:
        return {'server': s}
    proxy = {'server': f'{m.group(1)}://{m.group(4)}:{m.group(5)}'}
    if m.group(2):
        proxy['username'] = m.group(2)
        proxy['password'] = m.group(3)
    return proxy


def _dependency_preflight():
    problems = []
    if not PW_OK:
        problems.append(f"playwright not importable: {PW_ERR}")
    if not CLOAK_OK:
        problems.append(f"cloakbrowser not importable: {CLOAK_ERR}")
    try:
        from greenlet import _greenlet  # noqa: F401
    except Exception as e:
        problems.append(f"greenlet._greenlet broken: {e}")
    return problems


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--browsers", type=int, default=1)
    ap.add_argument("--transport", default=TRANSPORT, choices=["cloak", "chromium"])
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--server-url", default=SERVER_URL)
    ap.add_argument("--debug", "-d", action="store_true")
    ap.add_argument("--session-ttl", type=int, default=None,
                    help=f"Force browser restart after N seconds "
                         f"(default {SESSION_MAX_AGE_S}, env WAF_SESSION_MAX_AGE)")
    args = ap.parse_args()

    if args.debug:
        DEBUG = True
    if args.server_url:
        SERVER_URL = args.server_url
    if args.session_ttl is not None and args.session_ttl > 0:
        SESSION_MAX_AGE_S = args.session_ttl
    print(f"{C.CYN}[*] Session TTL: {SESSION_MAX_AGE_S}s "
          f"(browsers auto-restart at cap){C.RESET}")

    solvers = [WAFSolver(transport=args.transport, headless=args.headless,
                         browser_id=i + 1) for i in range(args.browsers)]
    for s in solvers:
        s.server_url = SERVER_URL
    threads = []
    for i, s in enumerate(solvers):
        t = threading.Thread(target=s.solve, name=f"Browser-{i + 1}", daemon=False)
        threads.append(t)
    try:
        for t in threads:
            t.start()
            time.sleep(0.2)
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        STOP_EVENT.set()
        for t in threads:
            t.join(timeout=30)