import argparse
import sys
import json
import time
from typing import List
from util import gather_endpoints_for_domains, render_html_report  # using the multi-domain runner

BANNER = r"""
=========================================
   Endpoint Scanner — Discovery (Step 1)
   Find endpoints for domains before running checks
=========================================
"""


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
    """Write results dict to JSON file in the same shape we used previously."""
    try:
        overall = _build_overall_structure(results)
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(overall, fh, indent=2)
        print(f"[+] Wrote JSON to {path}")
        return True
    except Exception as e:
        print(f"[!] Could not write JSON to {path}: {e}")
        return False


def _write_html(path: str, results: dict) -> bool:
    """Render HTML using render_html_report and write to path."""
    try:
        overall = _build_overall_structure(results)
        html = render_html_report(overall)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(html)
        print(f"[+] Wrote HTML to {path}")
        return True
    except Exception as e:
        print(f"[!] Could not write HTML to {path}: {e}")
        return False


def _interactive_save(results: dict):
    """Interactive flow to save discovered endpoints for later (JSON or HTML)."""
    while True:
        try:
            choice = input("Save format — (j)son, (h)tml, (b)oth, (c)ancel: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        if choice == 'j' or choice == 'json':
            fname = input(f"JSON filename (default endpoints-{timestamp}.json): ").strip() or f"endpoints-{timestamp}.json"
            _write_json(fname, results)
            return
        elif choice == 'h' or choice == 'html':
            fname = input(f"HTML filename (default endpoints-{timestamp}.html): ").strip() or f"endpoints-{timestamp}.html"
            _write_html(fname, results)
            return
        elif choice == 'b' or choice == 'both':
            fnamej = input(f"JSON filename (default endpoints-{timestamp}.json): ").strip() or f"endpoints-{timestamp}.json"
            fnameh = input(f"HTML filename (default endpoints-{timestamp}.html): ").strip() or f"endpoints-{timestamp}.html"
            _write_json(fnamej, results)
            _write_html(fnameh, results)
            return
        elif choice == 'c' or choice == 'cancel':
            print("Save cancelled.")
            return
        else:
            print("Invalid choice. Pick j / h / b / c.")


def _interactive_menu(results: dict):
    """
    Show the interactive menu until the user exits.
    results is a mapping domain -> list_of_urls.
    """
    import json

    def _load_saved_json(path: str):
        """Load saved JSON file and normalize to {domain: [url, ...]}."""
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception as e:
            print(f"[!] Could not open/read file: {e}")
            return None

        # Accept either the 'overall' structure or a simple mapping
        if isinstance(data, dict) and 'targets' in data:
            targets = data['targets']
            norm = {}
            for dom, info in targets.items():
                eps = info.get('endpoints', [])
                urls = []
                for ep in eps:
                    if isinstance(ep, dict) and 'url' in ep:
                        urls.append(ep['url'])
                    elif isinstance(ep, str):
                        urls.append(ep)
                norm[dom] = urls
            return norm
        # fallback: maybe user saved a simple dict domain->list
        if isinstance(data, dict):
            # ensure values are lists of strings
            ok = True
            for k, v in data.items():
                if not isinstance(v, list):
                    ok = False
                    break
            if ok:
                return data
        print("[!] Unrecognized JSON structure in file.")
        return None

    # --- lightweight placeholder checks ---
    def xss_check(input_results: dict):
        """Heuristic: flag URLs containing query params or obvious 'search' keys as XSS candidates."""
        findings = {}
        for dom, urls in input_results.items():
            f = []
            for u in urls:
                if '?' in u and ('=' in u):
                    # treat any URL with query params as a potential XSS surface (very coarse)
                    f.append(f"Potential injectable param URL: {u}")
                elif any(tok in u.lower() for tok in ['/search', '/query', '/q/']):
                    f.append(f"Search-like endpoint (inspect): {u}")
            if f:
                findings[dom] = f
        return findings

    def sqli_check(input_results: dict):
        """Heuristic: flag endpoints with numeric-looking IDs or query params as SQLi candidates."""
        findings = {}
        for dom, urls in input_results.items():
            f = []
            for u in urls:
                # basic heuristics
                if re.search(r"(id=|item=|product=)\d+", u, re.I):
                    f.append(f"ID parameter found (inspect for SQLi): {u}")
                elif '?' in u and ('=' in u):
                    f.append(f"Param-bearing URL (inspect for SQLi): {u}")
            if f:
                findings[dom] = f
        return findings

    def open_redirect_check(input_results: dict):
        """Heuristic: flag endpoints with common redirect param names (next, url, redirect)."""
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

    print('Discovery step complete. Next: run safe checks (XSS/SQLi/open-redirect) — to be implemented as Step 2.')
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
            # allow selecting current in-memory results or loading from file
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

            if sub == 'a':
                findings = xss_check(use_results)
                _print_findings(findings, "XSS heuristic")
            elif sub == 'b':
                findings = sqli_check(use_results)
                _print_findings(findings, "SQLi heuristic")
            elif sub == 'c':
                findings = open_redirect_check(use_results)
                _print_findings(findings, "Open Redirect heuristic")
            elif sub == 'd':
                f1 = xss_check(use_results)
                f2 = sqli_check(use_results)
                f3 = open_redirect_check(use_results)
                print("\n--- Combined scan results ---")
                _print_findings(f1, "XSS heuristic")
                _print_findings(f2, "SQLi heuristic")
                _print_findings(f3, "Open Redirect heuristic")
            else:
                print("Invalid choice for checks. Choose a / b / c / d or press ENTER to cancel.")

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

def cli_main(argv=None):
    p = argparse.ArgumentParser(description='Discovery-first: discover endpoints for given domains (Step 1).')
    p.add_argument('domains', nargs='*', help='Domain(s) to discover, e.g. example.com or https://example.com')
    p.add_argument('-f', '--file', help='File with list of domains, one per line')
    p.add_argument('-o', '--json', dest='out_json', help='Write discovered endpoints to JSON (non-interactive)')
    p.add_argument('--html', dest='out_html', help='Write discovered endpoints to HTML (non-interactive)')
    p.add_argument('--max-pages', type=int, default=50, help='Maximum pages to crawl per seed')
    p.add_argument('--verbose', action='store_true', help='Show crawling progress')
    args = p.parse_args(argv)

    print(BANNER)

    domains = list(args.domains or [])
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        domains.append(line)
        except Exception as e:
            print(f"[!] Could not read file: {e}")
            sys.exit(1)

    if not domains:
        domains = prompt_domains()

    if not domains:
        print('No domains provided — exiting.')
        sys.exit(1)

    # Use the single-run gatherer (scans all domains inside one event loop)
    print(f"[+] Discovering endpoints for {len(domains)} domain(s) in one run...")
    raw_results = gather_endpoints_for_domains(domains, crawl_pages=args.max_pages, verbose=args.verbose)

    # Normalize results (list of sorted endpoints per domain) and print
    results = {}
    for d in domains:
        value = raw_results.get(d)
        if isinstance(value, Exception):
            print(f"[!] Error scanning {d}: {value}")
            results[d] = []
            continue
        endpoints_list = sorted(value or [])
        print(f"[+] {d} -> Found {len(endpoints_list)} endpoints")
        for e in endpoints_list:
            print(f"   - {e}")
        results[d] = endpoints_list

    # Non-interactive outputs via CLI flags (--json / --html)
    if args.out_json:
        _write_json(args.out_json, results)
    if args.out_html:
        _write_html(args.out_html, results)

    # Interactive menu to allow saving or other actions
    _interactive_menu(results)
