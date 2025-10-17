import argparse
import sys
import json
import logging
import asyncio
import aiohttp
from aiohttp import ClientTimeout
import time
# debug: inspect how many URLs have query params
import pprint
from typing import List, Optional
from util import gather_endpoints_for_domains, render_html_report  # using the multi-domain runner
from util import (
        check_reflected_xss,
        check_sqli_fingerprints,
        check_open_redirect,
        CHECK_TIMEOUT,
        USER_AGENT,
    )


BANNER = r"""
=========================================
   Endpoint Scanner — Discovery (Step 1)
   Find endpoints for domains before running checks
=========================================
"""
_GLOBAL_SESSION: Optional[aiohttp.ClientSession] = None

async def get_global_session(timeout=None, headers=None) -> aiohttp.ClientSession:
    """
    Return a single shared ClientSession. Creates it if needed.
    Call await close_global_session() when your program finishes.
    """
    global _GLOBAL_SESSION
    if _GLOBAL_SESSION is None or _GLOBAL_SESSION.closed:
        kw = {}
        if timeout is not None:
            kw["timeout"] = timeout
        if headers is not None:
            kw["headers"] = headers
        _GLOBAL_SESSION = aiohttp.ClientSession(**kw)
    return _GLOBAL_SESSION


async def close_global_session():
    """Close and clear the global session (await when shutting down)."""
    print("Closing global session...")
    global _GLOBAL_SESSION
    if _GLOBAL_SESSION is not None and not _GLOBAL_SESSION.closed:
        await _GLOBAL_SESSION.close()
    _GLOBAL_SESSION = None

def prompt_domains() -> List[str]:
    try:
        inp = input('Enter domain(s) (comma-separated), e.g. example.com,api.example.org: ').strip()
    except (KeyboardInterrupt, EOFError):
        print('Aborted.')
        sys.exit(1)
    items = [d.strip() for d in inp.split(',') if d.strip()]
    return items


def _build_overall_structure(results: dict) -> dict:
    """
    Build the 'overall' structure expected by render_html_report and our JSON output.
    results: dict(domain -> list_of_urls)
    """
    overall = {'generated_at': time.time(), 'targets': {}}
    for domain, eps in results.items():
        # eps is expected to be a list of URL strings
        overall['targets'][domain] = {'endpoints': [{'url': u, 'status': 'discovered'} for u in eps]}
    return overall


def _write_json(path: str, results: dict) -> bool:
    """Write results dict to JSON file using the same overall structure."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [write_json] %(message)s',
        datefmt='%H:%M:%S'
    )

    try:
        logging.info(f"Building overall structure for {len(results)} domain(s)")
        overall = _build_overall_structure(results)

        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(overall, fh, indent=2)

        logging.info(f"Successfully wrote JSON report → {path}")
        print(f"[+] Wrote JSON to {path}")
        return True

    except Exception as e:
        logging.error(f"Failed to write JSON file at {path}: {e}", exc_info=True)
        print(f"[!] Could not write JSON to {path}: {e}")
        return False


def _write_html(path: str, results: dict) -> bool:
    """Render HTML using render_html_report and write to the specified path."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [write_html] %(message)s',
        datefmt='%H:%M:%S'
    )

    try:
        logging.info(f"Building overall structure for {len(results)} domain(s)")
        overall = _build_overall_structure(results)

        logging.info("Rendering HTML report...")
        html = render_html_report(overall)

        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(html)

        logging.info(f"Successfully wrote HTML report → {path}")
        print(f"[+] Wrote HTML to {path}")
        return True

    except Exception as e:
        logging.error(f"Failed to write HTML file at {path}: {e}", exc_info=True)
        print(f"[!] Could not write HTML to {path}: {e}")
        return False


def _interactive_save(results: dict):
    """Interactive flow to save discovered endpoints for later (JSON or HTML)."""
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [interactive_save] %(message)s',
        datefmt='%H:%M:%S'
    )

    while True:
        try:
            choice = input("Save format — (j)son, (h)tml, (b)oth, (c)ancel: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            logging.warning("User cancelled input (KeyboardInterrupt/EOF).")
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")

        if choice in ('j', 'json'):
            fname = input(f"JSON filename (default endpoints-{timestamp}.json): ").strip() or f"endpoints-{timestamp}.json"
            logging.info(f"Saving results to JSON file: {fname}")
            _write_json(fname, results)
            print(f"[+] Saved JSON → {fname}")
            return

        elif choice in ('h', 'html'):
            fname = input(f"HTML filename (default endpoints-{timestamp}.html): ").strip() or f"endpoints-{timestamp}.html"
            logging.info(f"Saving results to HTML file: {fname}")
            _write_html(fname, results)
            print(f"[+] Saved HTML → {fname}")
            return

        elif choice in ('b', 'both'):
            fnamej = input(f"JSON filename (default endpoints-{timestamp}.json): ").strip() or f"endpoints-{timestamp}.json"
            fnameh = input(f"HTML filename (default endpoints-{timestamp}.html): ").strip() or f"endpoints-{timestamp}.html"
            logging.info(f"Saving results to JSON and HTML files: {fnamej}, {fnameh}")
            _write_json(fnamej, results)
            _write_html(fnameh, results)
            print(f"[+] Saved JSON → {fnamej}")
            print(f"[+] Saved HTML → {fnameh}")
            return

        elif choice in ('c', 'cancel'):
            logging.info("User cancelled saving.")
            print("Save cancelled.")
            return

        else:
            logging.warning(f"Invalid choice entered: {choice}")
            print("Invalid choice. Pick j / h / b / c.")


async def _interactive_menu(results: dict):
    """
    Interactive menu that can run active safe checks (XSS/SQLi/Open Redirect)
    using run_checks(...) from util.py, or save outputs.
    Expects the helper functions _load_saved_json, _write_json, _write_html,
    _interactive_save, and the heuristic helpers to exist in this module (as you have).
    """
    import json
    import re
    import time
    # import run_checks from util (synchronous wrapper over async checks)
    try:
        from util import run_checks
    except Exception:
        run_checks = None

    # re-use your existing _load_saved_json, heuristics, _print_findings, etc.
    # I'll re-declare the heuristics minimally here to keep behavior consistent:
    def xss_check(input_results: dict):
        findings = {}
        for dom, urls in input_results.items():
            f = []
            for u in urls:
                if '?' in u and ('=' in u):
                    f.append(f"Potential injectable param URL: {u}")
                elif any(tok in u.lower() for tok in ['/search', '/query', '/q/']):
                    f.append(f"Search-like endpoint (inspect): {u}")
            if f:
                findings[dom] = f
        return findings

    def sqli_check(input_results: dict):
        findings = {}
        for dom, urls in input_results.items():
            f = []
            for u in urls:
                if re.search(r"(id=|item=|product=)\d+", u, re.I):
                    f.append(f"ID parameter found (inspect for SQLi): {u}")
                elif '?' in u and ('=' in u):
                    f.append(f"Param-bearing URL (inspect for SQLi): {u}")
            if f:
                findings[dom] = f
        return findings

    def open_redirect_check(input_results: dict):
        redirect_params = ('next=', 'url=', 'redirect=', 'return=')
        findings = {}
        for dom, urls in input_results.items():
            f = []
            for u in urls:
                if any(p in u.lower() for p in redirect_params):
                    f.append(f"Possible redirect parameter: {u}")
            if f:
                findings[dom] = f
        return findings

    def _print_findings(findings: dict, title: str):
        if not findings:
            print(f"[+] {title}: no findings.")
            return
        total = sum(len(v) for v in findings.values())
        print(f"[!] {title}: {total} potential items found across {len(findings)} domain(s). Showing up to 10 examples:")
        shown = 0
        for dom, items in findings.items():
            for it in items:
                print(f" - {dom}: {it}")
                shown += 1
                if shown >= 10:
                    return

    def _maybe_save_findings_raw(raw_data: dict, prefix="findings"):
        """Save the raw findings dict (already JSON-serializable) to timestamped JSON/HTML files."""
        try:
            save = input("Save detailed findings to disk? (y)es/(n)o: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled save.")
            return
        if save not in ('y', 'yes'):
            return
        ts = time.strftime("%Y%m%d-%H%M%S")
        jname = f"{prefix}-{ts}.json"
        hname = f"{prefix}-{ts}.html"
        try:
            with open(jname, 'w', encoding='utf-8') as fh:
                json.dump({'generated_at': time.time(), 'findings': raw_data}, fh, indent=2)
            print(f"[+] Detailed findings JSON written to {jname}")
        except Exception as e:
            print(f"[!] Failed to write findings JSON: {e}")

        # create a minimal HTML for quick viewing
        try:
            html_parts = [f"<h1>Findings - {time.ctime()}</h1>"]
            for dom, urls in raw_data.items():
                html_parts.append(f"<h2>{dom} ({len(urls)} endpoints)</h2>")
                for url, checks in urls.items():
                    html_parts.append(f"<h3>{url}</h3><ul>")
                    for cname, cres in checks.items():
                        vuln = cres.get("vulnerable", False)
                        html_parts.append(f"<li><strong>{cname}:</strong> {'VULNERABLE' if vuln else 'no findings'}</li>")
                        for d in cres.get("details", [])[:50]:
                            html_parts.append(f"<li>{json.dumps(d)}</li>")
                    html_parts.append("</ul>")
            with open(hname, 'w', encoding='utf-8') as fh:
                fh.write("\n".join(html_parts))
            print(f"[+] Detailed findings HTML written to {hname}")
        except Exception as e:
            print(f"[!] Failed to write findings HTML: {e}")

    async def run_async_checks(kind: str, results: dict, verbose=False):
        """Run async safe checks using aiohttp for given kind: xss/sqli/redirect/all."""
        sess = await get_global_session(timeout=CHECK_TIMEOUT, headers={"User-Agent": USER_AGENT})
        sem = asyncio.Semaphore(5)
        findings = {}

        
        tasks = []
        for dom, urls in results.items():
            domain_has_candidate = False
            if not isinstance(urls, (list, tuple)):
                # normalize: skip bad shapes
                if verbose:
                    print(f"[debug] skipping domain {dom} because urls is not a list")
                    findings.setdefault(dom, [])
                    continue

               
            for url in urls:
                    # only test URLs that contain params
                if '?' not in url:
                        continue

                domain_has_candidate = True

                if kind == "xss":
                    coro = check_reflected_xss(sess, url, sem, verbose)
                elif kind == "sqli":
                    coro = check_sqli_fingerprints(sess, url, sem, verbose)
                elif kind == "redirect":
                    coro = check_open_redirect(sess, url, sem, verbose)
                else:
                    continue

                tasks.append((dom, url, asyncio.create_task(coro)))

            # ensure the domain key exists even if there were no param URLs
            if not domain_has_candidate:
                if verbose:
                    print(f"[!] No param-bearing URLs for domain {dom} to test for {kind}")
                findings.setdefault(dom, [])

        if not tasks:
            if verbose:
                print(f"[!] No URLs with parameters found to test for {kind}.")
            return findings

        # run tasks in small batches to limit concurrency (we already use sem but this keeps memory lower)
        for dom, url, task in tasks:
            try:
                res = await task
            except Exception as e:
                if verbose:
                    print(f"[!] {kind} check failed on {url}: {e}")
                continue

            if res and res.get("vulnerable"):
                findings.setdefault(dom, []).append({"url": url, "details": res.get("details", [])})
        
        return findings
   
    

    
    def _load_saved_json(path: str) -> dict:
        """Load previously saved JSON file with discovered endpoints."""
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            targets = data.get('targets', {})
            loaded = {}
            for dom, info in targets.items():
                eps = info.get('endpoints', [])
                urls = [e.get('url') for e in eps if 'url' in e]
                loaded[dom] = urls
            return loaded
        except Exception as e:
            print(f"[!] Could not load JSON from {path}: {e}")
            return None
    
    # Top-level loop
    print('Discovery step complete. Next: run safe checks (XSS/SQLi/open-redirect).')
    while True:
        print('\nHere are three options to proceed:')
        print('1. Run the checks now')
        print('2. Save the discovered endpoints for later')
        print('3. All outputs JSON/HTML reports')
        print('4. Exit')

        try:
            choice = input('Choose [1/2/3/4]: ').strip()
        except (KeyboardInterrupt, EOFError):
            print('\nAborted.')
            return

        if choice == '1':
            # choose data source
            print("\nRun checks now — choose data source:")
            print("  a. Use the endpoints discovered in this run (in-memory)")
            print("  b. Load endpoints from a previously saved JSON file")
            try:
                src = input("Choose [a/b] (or ENTER to cancel): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled checks.")
                continue

            if not src:
                print("Cancelled checks.")
                continue

            if src == 'a':
                use_results = results
            elif src == 'b':
                path = input("Enter path to saved JSON file: ").strip()
                loaded = _load_saved_json(path)
                if loaded is None:
                    print("[!] Failed to load saved endpoints — aborting checks.")
                    continue
                use_results = loaded
                print(f"[+] Loaded {sum(len(v) for v in use_results.values())} endpoints from {path}")
            else:
                print("Invalid choice. Choose a or b.")
                continue

            # choose which check
            print("\nChoose which check to run:")
            print("  a. XSS")
            print("  b. SQLi")
            print("  c. Open Redirect")
            print("  d. All scans")
            try:
                sub = input("Choose [a/b/c/d] (or ENTER to cancel): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                print("\nCancelled checks.")
                continue

            if not sub:
                print("Cancelled checks.")
                continue

            # If run_checks wrapper is available, run active safe checks; otherwise fall back to active.
            if run_checks is None:
                print("[!] Running active only.")
                if sub == 'a':
                    findings = await run_async_checks("xss", use_results, verbose=True)
                    _print_findings(findings, "Reflected XSS (Active Check)")
                elif sub == 'b':
                    findings = await run_async_checks("sqli", use_results, verbose=True)
                    _print_findings(findings, "SQLi (Active Check)")
                elif sub == 'c':
                    findings = await run_async_checks("redirect", use_results, verbose=True)
                    _print_findings(findings, "Open Redirect (Active Check)")
                elif sub == 'd':
                    f1 = await run_async_checks("xss", use_results, verbose=True)
                    f2 = await run_async_checks("sqli", use_results, verbose=True)
                    f3 = await run_async_checks("redirect", use_results, verbose=True)
                    print("\n--- Combined scan results ---")
                    _print_findings(f1, "XSS (Active Check)")
                    _print_findings(f2, "SQLi (Active Check)")
                    _print_findings(f3, "Open Redirect (Active Check)")
                    # offer to save active combined findings in simple form
                    try:
                        saveh = input("Save active findings? (y/n): ").strip().lower()
                    except (KeyboardInterrupt, EOFError):
                        saveh = 'n'
                    if saveh in ('y','yes'):
                        combined = {"xss": f1, "sqli": f2, "redirect": f3}
                        _maybe_save_findings_raw(combined, prefix="active-findings")
                continue  # return to top menu

            # build selected check list
            if sub == 'a':
                selected = ["xss"]
            elif sub == 'b':
                selected = ["sqli"]
            elif sub == 'c':
                selected = ["redirect"]
            elif sub == 'd':
                selected = ["xss", "sqli", "redirect"]
            else:
                print("Invalid choice for checks. Choose a / b / c / d or press ENTER to cancel.")
                continue

            # Ask user to confirm running active checks (safety)
            print("\n*** Safety reminder: active checks will send harmless test payloads to endpoints.")
            print("Only run against targets you own or have permission to test.")
            try:
                ok = input("Proceed? (y/n): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                ok = 'n'
            if ok not in ('y', 'yes'):
                print("Cancelled active checks.")
                continue

            # run checks (synchronous wrapper)
            print("[*] Running active checks (this may take a while).")
            # default parameters; you can expose these through CLI flags if desired
            findings = n(use_results, checks=selected, max_concurrency=20, per_domain_limit=200, verbose=False)

            # summarize findings
            total_items = 0
            domains_with_issues = 0
            for dom, urlmap in findings.items():
                dom_count = 0
                for url, checksmap in urlmap.items():
                    for cname, cres in checksmap.items():
                        if cres.get("vulnerable"):
                            dom_count += len(cres.get("details", []))
                if dom_count:
                    domains_with_issues += 1
                    total_items += dom_count

            print(f"[+] Active checks complete. Total potential findings: {total_items} across {domains_with_issues} domain(s).")

            # offer to save full detailed findings (JSON + HTML)
            try:
                save_full = input("Save full detailed findings to disk? (y/n): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                save_full = 'n'
            if save_full in ('y', 'yes'):
                ts = time.strftime("%Y%m%d-%H%M%S")
                fname = f"findings-{ts}.json"
                try:
                    with open(fname, 'w', encoding='utf-8') as fh:
                        json.dump({'generated_at': time.time(), 'findings': findings}, fh, indent=2)
                    print(f"[+] Wrote findings JSON to {fname}")
                except Exception as e:
                    print(f"[!] Failed to write findings JSON: {e}")
                # also write a small HTML summary
                hname = f"findings-{ts}.html"
                try:
                    html_parts = [f"<h1>Findings - {time.ctime()}</h1>"]
                    for dom, urlmap in findings.items():
                        html_parts.append(f"<h2>{dom}</h2>")
                        for url, checksmap in urlmap.items():
                            html_parts.append(f"<h3>{url}</h3><ul>")
                            for cname, cres in checksmap.items():
                                html_parts.append(f"<li>{cname}: {'VULNERABLE' if cres.get('vulnerable') else 'no findings'}</li>")
                                for d in cres.get('details', [])[:50]:
                                    html_parts.append(f"<li><pre>{json.dumps(d)}</pre></li>")
                            html_parts.append("</ul>")
                    with open(hname, 'w', encoding='utf-8') as fh:
                        fh.write("\n".join(html_parts))
                    print(f"[+] Wrote findings HTML to {hname}")
                except Exception as e:
                    print(f"[!] Failed to write findings HTML: {e}")

            # done — return to main menu
            continue

        elif choice == '2':
            print("Save discovered endpoints for later.")
            _interactive_save(results)

        elif choice == '3':
            # write both JSON and HTML with timestamped filenames
            ts = time.strftime("%Y%m%d-%H%M%S")
            jname = f"endpoints-all-{ts}.json"
            hname = f"endpoints-all-{ts}.html"
            ok1 = _write_json(jname, results)
            ok2 = _write_html(hname, results)
            if ok1 and ok2:
                print("[+] All outputs written successfully.")
            else:
                print("[!] Some outputs failed to write.")

        elif choice == '4':
            print("Exiting.")
            return

        else:
            print("Invalid choice. Please select 1, 2, 3, or 4.")












async def cli_main(argv=None):
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='[%(asctime)s] [%(levelname)s] [cli_main] %(message)s',
        datefmt='%H:%M:%S'
    )
    sess = await get_global_session(timeout=CHECK_TIMEOUT, headers={"User-Agent": USER_AGENT})
    p = argparse.ArgumentParser(description='Discovery-first: discover endpoints for given domains (Step 1).')
    p.add_argument('domains', nargs='*', help='Domain(s) to discover, e.g. example.com or https://example.com')
    p.add_argument('-f', '--file', help='File with list of domains, one per line')
    p.add_argument('-o', '--json', dest='out_json', help='Write discovered endpoints to JSON (non-interactive)')
    p.add_argument('--html', dest='out_html', help='Write discovered endpoints to HTML (non-interactive)')
    p.add_argument('--max-pages', type=int, default=50, help='Maximum pages to crawl per seed')
    p.add_argument('--verbose', action='store_true', help='Show crawling progress')
    args = p.parse_args(argv)

    print(BANNER)
    logging.info("CLI started with arguments: %s", vars(args))

    domains = list(args.domains or [])
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        domains.append(line)
            logging.info(f"Loaded {len(domains)} domains from file: {args.file}")
        except Exception as e:
            logging.error(f"Could not read file '{args.file}': {e}")
            sys.exit(1)

    if not domains:
        logging.warning("No domains passed, prompting user for input...")
        domains = prompt_domains()

    if not domains:
        logging.error("No domains provided — exiting.")
        sys.exit(1)

    logging.info(f"Starting endpoint discovery for {len(domains)} domain(s)...")
    try:
        raw_results = await gather_endpoints_for_domains(sess, domains, crawl_pages=args.max_pages, verbose=args.verbose)
    except Exception as e:
        logging.exception(f"Discovery failed: {e}")
        sys.exit(1)

    results = {}
    for d in domains:
        value = raw_results.get(d)
        if isinstance(value, Exception):
            logging.warning(f"Error scanning {d}: {value}")
            results[d] = []
            continue

        endpoints_list = sorted(value or [])
        logging.info(f"{d}: Found {len(endpoints_list)} endpoints")
        for e in endpoints_list:
            logging.debug(f"  - {e}")
        results[d] = endpoints_list

    if args.out_json:
        try:
            _write_json(args.out_json, results)
            logging.info(f"Results saved to JSON: {args.out_json}")
        except Exception as e:
            logging.error(f"Failed to write JSON: {e}")

    if args.out_html:
        try:
            _write_html(args.out_html, results)
            logging.info(f"Results saved to HTML: {args.out_html}")
        except Exception as e:
            logging.error(f"Failed to write HTML: {e}")

    logging.info("Entering interactive menu...")
    try:
        await _interactive_menu(results)
    except Exception as e:
        logging.exception(f"Interactive menu failed: {e}")
