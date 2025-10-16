import asyncio
import re
import time
from typing import List, Set, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult, urljoin, quote

import aiohttp
from aiohttp import ClientTimeout
from bs4 import BeautifulSoup
import os
from tqdm.asyncio import tqdm
# --------------------- Configuration ---------------------
USER_AGENT = "EPScanner/1.0"
DEFAULT_WORDLIST = [
    "", "admin", "login", "dashboard", "api", "wp-login.php", "wp-admin/", "sitemap.xml",
    "robots.txt", ".env", "config.php", ".git", ".git/config", ".well-known/security.txt"
]

# simple module-level debug config (controlled by init_debug_prints)
VERBOSE_PRINTS = False
PRINT_PREFIX = "[xss]"

# regex helpers for JS/html/JSON scanning
_JS_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_JS_PATH_RE = re.compile(r"(/(?:[a-zA-Z0-9_@%\-./]{2,200}))")
_PARAM_NAME_RE = re.compile(r"[?&]([a-zA-Z0-9_%-]{1,40})=")   # finds ?id= or &q=
_SIMPLE_PARAM_WORD_RE = re.compile(
    r"\b(id|q|query|search|page|url|redirect|next|token|user|uid|cat|name)\b", re.I
)
_JSON_URL_KEY_RE = re.compile(r'["\']?(?:url|endpoint|uri|path)["\']?\s*:\s*["\']([^"\']+)["\']', re.I)
# add near other helpers
COMMON_PARAM_TEMPLATES = [
    ("id", "1"),
    ("q", "test"),
    ("search", "test"),
    ("page", "1"),
    ("cat", "1"),
    ("artist", "1"),
    ("name", "test"),
    ("url", "http://example.com/"),   # for open-redirect checks
    ("redirect", "http://example.com/")
]
WORDLIST_FILE = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
MAX_CONCURRENT = 30
TIMEOUT = ClientTimeout(total=8)
# Base path
BASE_DIR = os.path.dirname(__file__)
# --- Redirect test payloads ---
redirect_payload_path = os.path.join(BASE_DIR, "redirecttargetpayload.txt")
try:
    with open(redirect_payload_path, "r", encoding="utf-8") as f:
        REDIRECT_TEST_TARGETS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    REDIRECT_TEST_TARGETS = ["http://example.com/"]  # fallback safe test domain
# Configurable markers / payloads
xss_payload_path = os.path.join(BASE_DIR, "xsspayload.txt")
try:
    with open(xss_payload_path, "r", encoding="utf-8") as f:
        XSS_MARKERS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    XSS_MARKERS = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']  # fallback

# --- SQLi payloads ---
sqli_payload_path = os.path.join(BASE_DIR, "sqlipayload.txt")
try:
    with open(sqli_payload_path, "r", encoding="utf-8") as f:
        SQLI_PAYLOADS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    SQLI_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", " OR 1=1 -- "]  # fallback
SQL_ERROR_SIGS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark after the character string", "pg_query(", "sql syntax",
    "mysql_fetch", "oracle error"
]
CHECK_TIMEOUT = ClientTimeout(total=8)          # per-request timeout
def make_semaphore():
    return asyncio.Semaphore(MAX_CONCURRENT)


# --------------------- Helpers ---------------------
def norm_url(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme or "http"
    netloc = p.netloc or p.path
    path = p.path if p.netloc else ""
    rebuilt = urlunparse((scheme, netloc, path or "/", "", "", ""))
    return rebuilt.rstrip("/")


def discover_seed_urls(domain: str) -> List[str]:
    if not domain.startswith(("http://", "https://")):
        return [f"https://{domain}", f"http://{domain}"]
    return [domain]




def load_external_wordlist():
    try:
        if os.path.exists(WORDLIST_FILE):
            with open(WORDLIST_FILE, 'r', encoding='utf-8') as fh:
                return [ln.strip() for ln in fh if ln.strip()]
    except Exception:
        pass
    return DEFAULT_WORDLIST
# --------------------- Async fetchers ---------------------
async def fetch_text(session, url, verbose=False, sem=None):
    sem = sem or asyncio.Semaphore(MAX_CONCURRENT)
    async with sem:
        try:
            async with session.get(url, timeout=TIMEOUT) as r:
                if r.status < 400 and "html" in r.headers.get("Content-Type", ""):
                    if verbose:
                        print(f"[fetch] OK {url}")
                    return await r.text()
        except Exception:
            pass
    return None


async def fetch_status(session, url, verbose=False, sem=None):
    sem = sem or asyncio.Semaphore(MAX_CONCURRENT)
    async with sem:
        try:
            async with session.head(url, timeout=TIMEOUT, allow_redirects=True) as r:
                if r.status < 400:
                    if verbose:
                        print(f"[probe] Found {url} ({r.status})")
                    return url
        except Exception:
            try:
                async with session.get(url, timeout=TIMEOUT, allow_redirects=True) as r:
                    if r.status < 400:
                        if verbose:
                            print(f"[probe] Found {url} ({r.status})")
                        return url
            except Exception:
                pass
    return None


def generate_param_variants(url: str, templates: List[tuple]=None, max_per_path: int=3) -> List[str]:
    """Return a short list of param-bearing variants for `url` (if it has no query)."""
    templates = templates or COMMON_PARAM_TEMPLATES
    if '?' in url:
        return [url]  # already param-bearing
    variants = []
    count = 0
    for name, val in templates:
        if count >= max_per_path:
            break
        sep = '&' if '?' in url else '?'
        variants.append(f"{url}{sep}{name}={val}")
        count += 1
    return variants


# requires BeautifulSoup already imported
def extract_form_targets(html: str, base_url: str) -> List[str]:
    """Return candidate URLs built from forms found in the HTML (GET method or converted to GET)."""
    soup = BeautifulSoup(html, "html.parser")
    targets = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        method = (form.get("method") or "get").lower()
        action_url = urljoin(base_url, action)
        # collect input names (use first occurrence)
        names = []
        for inp in form.find_all(["input", "select", "textarea"]):
            nm = inp.get("name")
            if nm and nm not in names:
                names.append(nm)
        # build a simple querystring with simple values
        if names:
            q = "&".join(f"{n}=test" for n in names[:5])
            if '?' in action_url:
                full = f"{action_url}&{q}"
            else:
                full = f"{action_url}?{q}"
            targets.append(full)
        else:
            # no input names: just include action (maybe it's GET without params)
            targets.append(action_url)
    return targets


async def crawl_domain(session, base_url, crawl_pages=50, verbose=False):
    seen = set()
    to_visit = {base_url}
    found = set()

    while to_visit and len(seen) < crawl_pages:
        url = to_visit.pop()
        seen.add(url)

        html = await fetch_text(session, url, verbose)
        if not html:
            continue

        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(base_url, a["href"])
            if base_url in link and link not in seen:
                to_visit.add(link)
                found.add(link)

         # --- new: extract forms and add targets ---
        forms = extract_form_targets(html, url)
        for ftarget in forms:
            if base_url in ftarget and ftarget not in seen:
                to_visit.add(ftarget)
                found.add(ftarget) 

          # --- new: generate param variants for plain pages ---
        # if page path looks like a candidate (e.g., endswith .php), create variants
        if url.endswith(('.php', '/', 'index') ) or url.count('/')>2:
            for variant in generate_param_variants(url):
                if variant not in seen:
                    found.add(variant)       


    return found

async def async_gather_endpoints(domain, crawl_pages=50, verbose=False):
    """Scan a single domain asynchronously"""
    base_url = f"http://{domain}"
    async with aiohttp.ClientSession() as session:
        crawled = await crawl_domain(session, base_url, crawl_pages, verbose)
        found = await asyncio.gather(
            *(fetch_status(session, url, verbose) for url in crawled),
            return_exceptions=True
        )
    return {url for url in found if isinstance(url, str)}


async def async_gather_endpoints_for_domains(domains, crawl_pages=50, verbose=False):
    """Run endpoint discovery concurrently for multiple domains within one loop"""
    tasks = [
        asyncio.create_task(async_gather_endpoints(domain, crawl_pages, verbose))
        for domain in domains
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # pair each domain with its set of endpoints
    return dict(zip(domains, results))

# --------------------- Passive discovery ---------------------
async def passive_discovery(session, domain, verbose=False):
    found = set()
    for file in ["robots.txt", "sitemap.xml"]:
        url = urljoin(domain.rstrip("/") + "/", file)
        text = await fetch_text(session, url, verbose)
        if text:
            found.add(url)
            for m in re.findall(r"https?://[^\s\"'>]+", text):
                found.add(m.rstrip("/"))
            if verbose:
                print(f"[passive] {file} yielded {len(found)} URLs")
    return found


# --------------------- Probe common paths ---------------------
async def probe_common_paths(session, domain_root, wordlist=None, verbose=False, sem=None):
    sem = sem or asyncio.Semaphore(MAX_CONCURRENT)
    if wordlist is None:
       wordlist = load_external_wordlist()
    tasks = []
    for p in wordlist:
        candidate = urljoin(domain_root.rstrip("/") + "/", p)
        tasks.append(fetch_status(session, candidate, verbose, sem))

    results = []
    for fut in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc=f"Probing {domain_root}"):
        r = await fut
        if r:
            results.append(r)
    return {r.rstrip("/") for r in results if r}


# --------------------- Async crawl ---------------------
async def crawl(session, domain_root, max_pages=50, max_depth=2, verbose=False):
    parsed_root = urlparse(domain_root)
    base_netloc = parsed_root.netloc
    to_visit = [(domain_root, 0)]
    visited = set()
    discovered = set()

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        text = await fetch_text(session, url, verbose)
        if not text:
            continue
        discovered.add(url)
        soup = BeautifulSoup(text, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            joined = urljoin(url, href)
            parsed = urlparse(joined)
            if parsed.netloc == base_netloc:
                cleaned = urlunparse(
                    (parsed.scheme or parsed_root.scheme, parsed.netloc, parsed.path or "/", "", "", "")
                )
                if cleaned not in visited and len(visited) + len(to_visit) < max_pages:
                    to_visit.append((cleaned, depth + 1))
                    if verbose:
                        print(f"[crawl] Queued: {cleaned}")
    if verbose:
        print(f"[crawl] Done: {len(discovered)} URLs discovered")
    return discovered


# --------------------- Gather all endpoints ---------------------
async def async_gather_endpoints(domain, crawl_pages=50, verbose=False):
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}) as session:
        passive = await passive_discovery(session, domain, verbose)
        probe = await probe_common_paths(session, domain, verbose=verbose)  # <-- fixed here
        crawlset = await crawl(session, domain, max_pages=crawl_pages, verbose=verbose)
        return passive | probe | crawlset


def gather_endpoints(domain, crawl_pages=50, verbose=False):
    return asyncio.run(async_gather_endpoints(domain, crawl_pages, verbose))

async def async_gather_endpoints_single(session, domain, crawl_pages=50, verbose=False):
    """
    Reuse your existing async functions to scan a single domain using the provided session.
    Returns set of endpoints.
    """
    # passive discovery
    sem = asyncio.Semaphore(MAX_CONCURRENT)
    passive = await passive_discovery(session, domain, verbose)

    # probe common paths (concurrent via tasks)
    probe = await probe_common_paths(session, domain, verbose=verbose, sem=sem)

    # crawl
    crawlset = await crawl(session, domain, max_pages=crawl_pages, verbose=verbose)
       # NEW: discover JS-derived endpoints from a few seed pages:
    js_candidates = set()
    seeds = set()
    # include root and index and some pages from crawlset (small sample)
    parsed = urlparse(domain)
    base_origin = domain if domain.startswith('http') else f"http://{domain}"
    seeds.add(base_origin)
    seeds.add(urljoin(base_origin, '/index.php'))
    for u in list(crawlset)[:6]:
        seeds.add(u)

    for s in seeds:
        js_candidates |= await discover_from_js_on_page(session, s, sem, verbose=verbose)

    # Also try scanning a few passive URLs if they look like JSON endpoints
    json_candidates = set()
    for u in list(passive)[:6]:
        json_candidates |= await extract_urls_from_json_endpoint(session, u, sem, verbose=verbose)

    return passive | probe | crawlset


async def _async_gather_domains(domains, crawl_pages=50, verbose=False):
    """
    Internal concurrent runner for multiple domains within one event loop.
    Returns dict: domain -> set(endpoints) or exception.
    """
    results = {}
    # Use a single session reused across domains (better performance)
    async with aiohttp.ClientSession(headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT) as session:
        # create tasks for each domain
        tasks = {domain: asyncio.create_task(async_gather_endpoints_single(session, domain, crawl_pages, verbose))
                 for domain in domains}

        # await them and collect results
        for domain, task in tasks.items():
            try:
                res = await task
                results[domain] = res
            except Exception as e:
                # store exception to let caller handle it
                results[domain] = e
    return results


def gather_endpoints_for_domains(domains, crawl_pages=50, verbose=False):
    """
    Synchronous wrapper that runs the async scan for multiple domains in a single event loop.
    Returns dict: domain -> set(endpoints) or exception.
    """
    if isinstance(domains, str):
        domains = [domains]
    return asyncio.run(_async_gather_domains(domains, crawl_pages=crawl_pages, verbose=verbose))


# Backwards-compatible single-domain wrapper (optional)
def gather_endpoints(domain, crawl_pages=50, verbose=False):
    """
    Backwards compatible API: scan a single domain (runs its own loop).
    Prefer gather_endpoints_for_domains for multi-domain runs.
    """
    res = gather_endpoints_for_domains([domain], crawl_pages=crawl_pages, verbose=verbose)
    return res.get(domain, set())
# --------------------- HTML Report ---------------------
def render_html_report(data: Dict) -> str:
    title = "Endpoint Discovery Report"
    html_parts = [
        "<!doctype html>",
        "<html lang='en'><head><meta charset='utf-8'/><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>{title}</title>",
        "<style>body{font-family:Arial;padding:20px;background:#fafafa;} .card{background:#fff;padding:12px;margin:10px 0;border-radius:6px;box-shadow:0 1px 3px rgba(0,0,0,0.08);} pre{white-space:pre-wrap;}</style>",
        "</head><body>",
        f"<h1>{title}</h1>",
        f"<p>Generated: {time.ctime(data.get('generated_at', time.time()))}</p>",
    ]

    for target, info in data.get("targets", {}).items():
        html_parts.append(f"<div class='card'><h2>Target: {target}</h2>")
        eps = info.get("endpoints", [])
        html_parts.append(f"<p>Endpoints discovered: {len(eps)}</p>")
        for ep in eps:
            html_parts.append(f"<div style='margin-left:10px;'>{ep.get('url')}</div>")
        html_parts.append("</div>")

    html_parts.append("</body></html>")
    return "\n".join(html_parts)










# helper to test various transformed forms of the marker
def seen_in_response(marker: str, text: str) -> bool:
    if not text:
        return False
    # raw marker
    if marker in text:
        return True
    # HTML-escaped (e.g. &lt;script&gt;)
    try:
        if html.escape(marker) in text:
            return True
    except Exception:
        pass
    # unescape and check
    try:
        if marker in html.unescape(text):
            return True
    except Exception:
        pass
    # URL-encoded
    try:
        if quote(marker, safe='') in text:
            return True
    except Exception:
        pass
    # normalized whitespace check
    norm_resp = text.replace('\n', '').replace('\r', '')
    if marker.replace(' ', '') in norm_resp:
        return True
    return False



def init_debug_prints(verbose: bool = False, prefix: str = "[xss]") -> None:
    """
    Initialize simple print-based debugging.
    Call once at program start if you want global control over prints.
    Individual calls may still pass `verbose=True` to force printing.
    """
    global VERBOSE_PRINTS, PRINT_PREFIX
    VERBOSE_PRINTS = bool(verbose)
    PRINT_PREFIX = str(prefix)


async def check_reflected_xss(
    session,
    url: str,
    sem: asyncio.Semaphore,
    verbose: bool = False,
) -> Dict:
    """
    For a single `url` with query params, inject inert markers from XSS_MARKERS into each param
    (one marker at a time) and check whether the marker (or common transformed forms) appears
    in the response body.

    Returns: {"vulnerable": bool, "details": [ {param, tested_url, evidence}, ... ]}
    """
    # effective verbosity: call-time override > global init
    do_print = verbose or VERBOSE_PRINTS

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)  # values are lists
    print(qs)
    findings = []

    if do_print:
        print(f"{PRINT_PREFIX} start check_reflected_xss: url={url} params={list(qs.keys())} markers={len(XSS_MARKERS)}")

    if not qs:
        if do_print:
            print(f"{PRINT_PREFIX} no query params for url={url}; skipping")
        return {"vulnerable": False, "details": []}

    # iterate params and each marker
    for param in qs.keys():
        # original param values (take first element for non-list semantics)
        original_values = {k: (v[:] if isinstance(v, list) else [v]) for k, v in qs.items()}
        if do_print:
            sample_vals = {k: (v[0] if v else "") for k, v in original_values.items()}
            print(f"{PRINT_PREFIX} testing param='{param}' original_values={sample_vals}")

        for marker in XSS_MARKERS:
            # build query where only `param` is replaced with marker (single value)
            new_qs = {}
            for k, vals in original_values.items():
                if k == param:
                    # use single string for this param
                    new_qs[k] = marker
                else:
                    # keep first original value (common behaviour)
                    new_qs[k] = vals[0] if vals else ''

            # urlencode with doseq=False because values are strings
            new_query = urlencode(new_qs, doseq=False)
            test_parsed = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            test_url = urlunparse(test_parsed)

            if do_print:
                # print a truncated marker to avoid huge output
                truncated_marker = (marker[:60] + "...") if len(marker) > 60 else marker
                print(f"{PRINT_PREFIX} requesting test_url={test_url} (param={param} marker={truncated_marker})")

            try:
                start_ts = time.perf_counter()
                async with sem:
                    async with session.get(test_url, timeout=CHECK_TIMEOUT) as resp:
                        elapsed = time.perf_counter() - start_ts
                        status = getattr(resp, "status", None)
                        text = await resp.text(errors="ignore")
                        text_len = len(text) if text is not None else 0

                        if do_print:
                            print(f"{PRINT_PREFIX} response: url={test_url} status={status} time={elapsed:.3f}s len={text_len}")

                        if seen_in_response(marker, text):
                            findings.append({"param": param, "tested_url": test_url, "evidence": marker})
                            if do_print:
                                print(f"{PRINT_PREFIX} reflection FOUND for param='{param}' @ {test_url} (marker visible)")
                            # if you want only the first marker per param, uncomment the next line:
                            # break
                        else:
                            if do_print:
                                print(f"{PRINT_PREFIX} marker not seen in response for param='{param}'")

            except asyncio.TimeoutError:
                if do_print:
                    print(f"{PRINT_PREFIX} timeout while requesting {test_url}")
            except Exception:
                if do_print:
                    print(f"{PRINT_PREFIX} request failed for {test_url}; exception:")
                    traceback.print_exc()

    vulnerable = bool(findings)
    if do_print:
        print(f"{PRINT_PREFIX} finished check_reflected_xss: url={url} vulnerable={vulnerable} findings={len(findings)}")

    return {"vulnerable": vulnerable, "details": findings}
async def check_sqli_fingerprints(session, url: str, sem: asyncio.Semaphore, verbose: bool = False) -> Dict:
    """
    For a single `url` with query params, inject benign SQL-like payloads and
    look for DB error signatures or large response diffs vs baseline.
    Returns {"vulnerable": bool, "details": [ {param, payload, signature, tested_url}, ... ]}
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    findings = []

    if not qs:
        return {"vulnerable": False, "details": []}

    # baseline
    try:
        async with sem:
            async with session.get(url, timeout=CHECK_TIMEOUT) as base:
                base_text = await base.text(errors="ignore")
    except Exception:
        base_text = ""

    for param in qs.keys():
        for payload in SQLI_PAYLOADS:
            print(f"Testing param {param} with payload {payload}")
            new_qs = {k: (payload if k == param else (v[0] if isinstance(v, list) else str(v))) for k, v in qs.items()}
            new_query = urlencode(new_qs)
            test_parsed = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            test_url = urlunparse(test_parsed)

            try:
                async with sem:
                    async with session.get(test_url, timeout=CHECK_TIMEOUT) as resp:
                        body = await resp.text(errors="ignore")
                        low = body.lower()
                        matched_sig = None
                        for sig in SQL_ERROR_SIGS:
                            if sig in low:
                                matched_sig = sig
                                break
                        if matched_sig:
                            findings.append({"param": param, "payload": payload, "signature": matched_sig, "tested_url": test_url})
                            if verbose:
                                print(f"[sqli] signature {matched_sig} at {test_url}")
                            # stop testing additional payloads for this param if we found a signature
                            break
                        else:
                            # heuristic: big change in content length may indicate different behavior
                            if base_text and abs(len(body) - len(base_text)) > 2000:
                                findings.append({"param": param, "payload": payload, "signature": "content-length-diff", "tested_url": test_url})
                                if verbose:
                                    print(f"[sqli] large content diff for {test_url}")
                                break
            except Exception:
                if verbose:
                    print(f"[sqli] request failed for {test_url}")
                continue

    return {"vulnerable": bool(findings), "details": findings}



def extract_host_from_payload(payload: str) -> str:
    """Try to get a host from a payload; return empty string if none."""
    try:
        # make it absolute-ish so urlparse can parse netloc
        sample = payload
        if payload.startswith("//"):
            sample = "http:" + payload
        if not payload.startswith(("http://", "https://")) and "/" in payload:
            # try prefixing http:// to let urlparse find host
            sample = "http://" + payload.lstrip("/")
        p = urlparse(sample)
        host = p.netloc.split("@")[-1].split(":")[0].lower()
        return host
    except Exception:
        return ""

async def check_open_redirect(session, url: str, sem: asyncio.Semaphore, verbose: bool = False) -> Dict:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, ParseResult

    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    findings = []
    if not qs:
        return {"vulnerable": False, "details": []}

    common_redirect_names = {"next", "url", "redirect", "return", "target", "r", "dest", "goto"}
    for param in qs.keys():
        if param.lower() not in common_redirect_names:
            continue

        for redirect_payload in REDIRECT_TEST_TARGETS:  # must be a list
            new_qs = {k: (redirect_payload if k == param else v[0] if isinstance(v, list) else str(v)) for k, v in qs.items()}
            new_query = urlencode(new_qs)
            test_parsed = ParseResult(parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
            test_url = urlunparse(test_parsed)

            try:
                async with sem:
                    async with session.get(test_url, timeout=CHECK_TIMEOUT, allow_redirects=False) as r:
                        loc = r.headers.get("Location", "") or ""
                        if any(target in loc for target in ["example.com", "bing.com"]):
                            findings.append({"param": param, "payload": redirect_payload, "evidence": loc, "tested_url": test_url})
                            if verbose:
                                print(f"[redir] Location header points to external target for {test_url}: {loc}")
                            continue

                    async with session.get(test_url, timeout=CHECK_TIMEOUT, allow_redirects=True) as r2:
                        final = str(r2.url)
                        if any(target in final for target in ["example.com", "bing.com"]):
                            findings.append({"param": param, "payload": redirect_payload, "evidence": final, "tested_url": test_url})
                            if verbose:
                                print(f"[redir] final URL points to external target for {test_url}: {final}")
            except Exception:
                if verbose:
                    print(f"[redir] request failed for {test_url}")
                continue

    return {"vulnerable": bool(findings), "details": findings}



# --------------------- Common config ---------------------
async def fetch_text_safe(session, url: str, sem: asyncio.Semaphore, timeout=None, verbose=False) -> str:
    """Fetch text, return '' on any error. Use your TIMEOUT and sem."""
    t = timeout or TIMEOUT
    try:
        async with sem:
            async with session.get(url, timeout=t) as r:
                if r.status < 400:
                    try:
                        return await r.text()
                    except Exception:
                        return ""
    except Exception:
        if verbose:
            print(f"[js-fetch] failed {url}")
    return ""


async def extract_endpoints_from_js_url(session, js_url: str, sem: asyncio.Semaphore, base_origin: str = "", verbose=False) -> Dict:
    """
    Fetch a JS (or JSON) url and extract candidate endpoints/paths/param-names.
    Returns {"urls": set(), "paths": set(), "params": set()}.
    Conservative: will prefer same-origin or relative paths when base_origin is given.
    """
    text = await fetch_text_safe(session, js_url, sem, verbose=verbose)
    if not text:
        return {"urls": set(), "paths": set(), "params": set()}

    urls = set(m.group(0) for m in _JS_URL_RE.finditer(text))
    paths = set()
    for m in _JS_PATH_RE.finditer(text):
        p = m.group(1)
        # filter likely static files & obviously bad matches
        if len(p) > 2 and not p.lower().endswith(('.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.ico')):
            if " " not in p:
                paths.add(p)

    params = set(m.group(1) for m in _PARAM_NAME_RE.finditer(text))
    for m in _SIMPLE_PARAM_WORD_RE.finditer(text):
        params.add(m.group(1).lower())

    # also try to spot url fields inside JSON-like payloads
    for m in _JSON_URL_KEY_RE.finditer(text):
        u = m.group(1)
        if u:
            urls.add(u)

    # normalize paths into same-origin absolute URLs if possible
    absolutes = set()
    for p in paths:
        if p.startswith("http://") or p.startswith("https://"):
            absolutes.add(p)
        elif base_origin:
            try:
                absolutes.add(urljoin(base_origin.rstrip("/") + "/", p.lstrip("/")))
            except Exception:
                pass
        else:
            absolutes.add(p)

    # combine results (urls may include external CDNs; keep them but caller can filter)
    return {"urls": urls, "paths": absolutes, "params": params}


async def discover_from_js_on_page(session, page_url: str, sem: asyncio.Semaphore, verbose=False, max_scripts=12) -> Set[str]:
    """
    For a page (HTML), fetch script srcs and inline scripts. Return candidate endpoints (absolute URLs).
    - max_scripts: cap number of external scripts fetched to avoid grabbing huge CDNs by default.
    """
    discovered = set()
    html = await fetch_text_safe(session, page_url, sem, verbose=verbose)
    if not html:
        return discovered

    # find script srcs
    script_srcs = []
    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
        script_srcs.append(urljoin(page_url, m.group(1)))

    # inline script blobs
    inline_scripts = [m.group(1) for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)]

    # prefer same-origin scripts first
    same_origin = []
    other = []
    parsed_base = urlparse(page_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    for s in script_srcs:
        ps = urlparse(s)
        if ps.netloc == parsed_base.netloc or not ps.netloc:
            same_origin.append(s)
        else:
            other.append(s)

    fetch_list = same_origin[:max_scripts] + other[:max(0, max_scripts - len(same_origin))]

    # fetch and analyze script files (conservative)
    for s in fetch_list:
        info = await extract_endpoints_from_js_url(session, s, sem, base_origin if s.startswith(base_origin) or s.startswith('/') else "", verbose=verbose)
        discovered.update(info.get("paths", set()))
        discovered.update(info.get("urls", set()))

    # scan inline scripts for URLs and path tokens
    for blob in inline_scripts:
        for m in _JS_URL_RE.finditer(blob):
            discovered.add(m.group(0))
        for m in _JS_PATH_RE.finditer(blob):
            p = m.group(1)
            if len(p) > 2:
                discovered.add(urljoin(page_url, p))

    # also try to parse JSON blobs inside the page (very small extraction)
    for m in _JSON_URL_KEY_RE.finditer(html):
        discovered.add(urljoin(page_url, m.group(1)))

    return discovered


async def extract_urls_from_json_endpoint(session, json_url: str, sem: asyncio.Semaphore, verbose=False) -> Set[str]:
    found = set()
    try:
        async with sem:
            async with session.get(json_url, timeout=TIMEOUT) as r:
                if r.status < 400:
                    js = await r.json(content_type=None)
                    # walk simple dict/list and find url-like strings
                    def walk(obj):
                        if isinstance(obj, dict):
                            for k,v in obj.items():
                                if isinstance(v, str) and (v.startswith('/') or v.startswith('http')):
                                    found.add(urljoin(json_url, v))
                                else:
                                    walk(v)
                        elif isinstance(obj, list):
                            for it in obj:
                                walk(it)
                    walk(js)
    except Exception:
        if verbose:
            print(f"[json-fetch] failed {json_url}")
    return found
