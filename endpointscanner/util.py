import asyncio
import re
import time
from typing import List, Set, Dict
from urllib.parse import urljoin, urlparse, urlunparse

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
WORDLIST_FILE = os.path.join(os.path.dirname(__file__), 'wordlist.txt')
MAX_CONCURRENT = 30
TIMEOUT = ClientTimeout(total=8)
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
