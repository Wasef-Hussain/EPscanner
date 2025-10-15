import argparse
import sys
import json
from util import gather_endpoints_for_domains, render_html_report

BANNER = r"""
=========================================
   EPScanner — Discovery (Step 1)
   Find endpoints for domains before running checks
=========================================
"""


def prompt_domains() -> list:
    try:
        inp = input('Enter domain(s) (comma-separated), e.g. example.com,api.example.org: ').strip()
    except (KeyboardInterrupt, EOFError):
        print('Aborted.')
        sys.exit(1)
    items = [d.strip() for d in inp.split(',') if d.strip()]
    return items


def cli_main(argv=None):
    p = argparse.ArgumentParser(description='Discovery-first: discover endpoints for given domains (Step 1).')
    p.add_argument('domains', nargs='*', help='Domain(s) to discover, e.g. example.com or https://example.com')
    p.add_argument('-f', '--file', help='File with list of domains, one per line')
    p.add_argument('-o', '--json', dest='out_json', help='Write discovered endpoints to JSON')
    p.add_argument('--html', dest='out_html', help='Write discovered endpoints to HTML')
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

      # Run all domain scans inside one asyncio event loop (faster + no loop binding issues)
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

    if args.out_json:
        try:
            with open(args.out_json, 'w', encoding='utf-8') as fh:
                json.dump({'generated_at': __import__('time').time(), 'targets': results}, fh, indent=2)
            print(f"[+] Wrote JSON to {args.out_json}")
        except Exception as e:
            print(f"[!] Could not write JSON: {e}")

    if args.out_html:
        try:
            # Build a minimal HTML structure using util.render_html_report expecting the old overall shape
            overall = {'generated_at': __import__('time').time(), 'targets': {}}
            for t, eps in results.items():
                overall['targets'][t] = {'endpoints': [{'url': u, 'status': 'discovered'} for u in eps]}
            html = render_html_report(overall)
            with open(args.out_html, 'w', encoding='utf-8') as fh:
                fh.write(html)
            print(f"[+] Wrote HTML to {args.out_html}")
        except Exception as e:
            print(f"[!] Could not write HTML: {e}")

    print('Discovery step complete. Next: run safe checks (XSS/SQLi/open-redirect) — to be implemented as Step 2.')
    print('Here are three options to proceed:')
    print('1. Run the checks now')
    print('   a. XSS')
    print('   b. SQLi')
    print('   c. Open Redirect')
    print('2. Save the discovered endpoints for later')
    print('3. Exit')
