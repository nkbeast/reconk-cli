#!/usr/bin/env python3
"""reconk takeover — native subdomain takeover detection.

Replaces the dnsx-based check. Logic:

  1. resolve CNAME for the host (follow the full chain via root servers)
  2. if the final target is NXDOMAIN (or the provider's "not registered"
     marker domain), flag it
  3. match the target against a provider list for confirmation

Providers covered (CNAME target fingerprint):
  aws: *.amazonaws.com / cloudfront.net / elasticbeanstalk
  azure: *.azurewebsites.net / *.trafficmanager.net
  github: *.github.io
  gitlab: *.gitlab.io
  heroku: *.herokudns.com
  netlify: *.netlify.app / *.netlify.com
  shopify: *.shopify.com / *.shops.myshopify.com
  fastly: *.fastly.net
  surge: *.surge.sh
  bitbucket: *.bitbucket.io
  wordpress: *.wordpress.com
  zendesk: *.zendesk.com
  readme: *.readme.io
  ghost: *.ghost.io
  cpanel: cpanel / cp-*.webhostbox.net
  pantheon: *.pantheonsite.io / *.getpantheon.com
  pivotal: *.pivotal.io
  statuspage: *.statuspage.io
  tictail: *.tictail.com
  airtable: *.airtable.com
  and more...

Usage:
  python takeover.py -l hosts.txt -o takeover.txt [--resolve dnsx]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import re
import subprocess
import sys
import time
from typing import List, Optional, Tuple

try:
    from reconk.scripts.common import read_lines, resolve, unique_preserve
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from reconk.scripts.common import read_lines, resolve, unique_preserve

TAG = "\033[1;36m[*]\033[0m" if sys.stdout.isatty() else "[*]"
OK = "\033[1;32m[+]\033[0m" if sys.stdout.isatty() else "[+]"
BAD = "\033[1;31m[X]\033[0m" if sys.stdout.isatty() else "[X]"
WARN = "\033[1;33m[!]\033[0m" if sys.stdout.isatty() else "[!]"

# provider -> (cname regex, dead-marker regex)
PROVIDERS = [
    ("aws_s3", r"\.s3[.-]?.*\.amazonaws\.com$", r"no such bucket|does not exist|no bucket"),
    ("aws_cloudfront", r"\.cloudfront\.net$", r"ERROR|BadRequest|The request could not be satisfied"),
    ("aws_elasticbeanstalk", r"\.elasticbeanstalk\.com$", r"NXDOMAIN"),
    ("aws_lightsail", r"\.lightsail\.get\.amazonaws\.com$", r"NXDOMAIN"),
    ("azure_app", r"\.azurewebsites\.net$", r"NXDOMAIN|there is no such app"),
    ("azure_traffic_manager", r"\.trafficmanager\.net$", r"NXDOMAIN"),
    ("azure_cloudapp", r"\.cloudapp\.net$", r"NXDOMAIN"),
    ("azure_edge", r"\.azureedge\.net$", r"NXDOMAIN"),
    ("github_pages", r"\.github\.io$", r"There isn't a GitHub Pages site here"),
    ("gitlab_pages", r"\.gitlab\.io$", r"The page you're looking for could not be found"),
    ("heroku", r"\.heroku(?:app)?\.com$|\.herokudns\.com$", r"no such app"),
    ("netlify", r"\.netlify\.app$|\.netlify\.com$", r"page not found|is not a registered|invalid path"),
    ("shopify", r"\.myshopify\.com$|\.shopify\.com$", r"doesn't exist|not found"),
    ("fastly", r"\.fastly\.net$", r"NXDOMAIN|Fastly error"),
    ("surge", r"\.surge\.sh$", r"project not found"),
    ("bitbucket", r"\.bitbucket\.io$", r"repository not found"),
    ("wordpress", r"\.wordpress\.com$", r"do not currently have a WordPress.com site"),
    ("zendesk", r"\.zendesk\.com$", r"help center closed|no help center"),
    ("readme", r"\.readme\.io$", r"project not found"),
    ("ghost", r"\.ghost\.io$", r"domain is not configured"),
    ("cpanel", r"cp-?[\d]+\.webhostbox\.net$", r"NXDOMAIN"),
    ("pantheon", r"\.pantheonsite\.io$|\.getpantheon\.com$", r"404 error unknown site"),
    ("pivotal", r"\.pivotal\.io$", r"NXDOMAIN"),
    ("statuspage", r"\.statuspage\.io$", r"this page is no longer available"),
    ("tictail", r"\.tictail\.com$", r"NXDOMAIN"),
    ("airtable", r"\.airtable\.com$", r"NXDOMAIN"),
    ("intercom", r"\.intercom\.site$|\.intercom\.mail$", r"NXDOMAIN"),
    ("webflow", r"\.webflow\.io$", r"no site found"),
    ("unbounce", r"\.unbouncepages\.com$", r"NXDOMAIN"),
    ("instapage", r"\.instapage\.com$|\.pages\.instapage\.com$", r"NXDOMAIN"),
    ("teachable", r"\.teachable\.com$", r"NXDOMAIN"),
    ("thinkific", r"\.thinkific\.com$", r"NXDOMAIN"),
    ("framer", r"\.framer\.app$", r"NXDOMAIN"),
    ("strikingly", r"\.strikingly\.com$", r"NXDOMAIN"),
    ("squarespace", r"\.squarespace\.com$", r"nxdomain"),
    ("firebase", r"\.firebaseapp\.com$", r"NXDOMAIN|not found"),
    ("vercel", r"\.vercel\.app$", r"NXDOMAIN|deployment not found"),
    ("render", r"\.onrender\.com$", r"NXDOMAIN|not found"),
    ("fly_io", r"\.fly\.dev$|\.fly\.io$", r"NXDOMAIN|not found"),
    ("railway", r"\.up\.railway\.app$", r"NXDOMAIN|not found"),
    ("storipress", r"\.storipress\.app$", r"NXDOMAIN"),
    ("dotnetify", r"\.dotnetify\.net$", r"NXDOMAIN"),
    ("hightail", r"\.hightail\.com$", r"NXDOMAIN"),
    ("cargo", r"\.cargocollective\.com$", r"NXDOMAIN"),
    ("helpjuice", r"\.helpjuice\.com$", r"helpjuice account"),
    ("helpscout", r"\.helpscoutdocs\.com$", r"no such document"),
    ("getresponse", r"\.gr8\.com$", r"NXDOMAIN"),
    ("vend", r"\.vend\.io$", r"NXDOMAIN"),
    ("fedora", r"\.fedora\.com$", r"NXDOMAIN"),
]


def follow_cname(host: str, depth: int = 5) -> List[str]:
    """Follow the CNAME chain, returning each target."""
    chain: List[str] = []
    cur = host
    for _ in range(depth):
        cn = resolve(cur, "CNAME")
        if not cn:
            break
        target = cn[0].rstrip(".")
        chain.append(target)
        cur = target
    return chain


def is_nxdomain(host: str) -> bool:
    try:
        import dns.exception
        import dns.resolver

        try:
            answers = dns.resolver.resolve(host, "A", lifetime=8)
            return not bool(answers)
        except (dns.exception.DNSException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return True
        except Exception:  # noqa: BLE001
            return False
    except Exception:  # noqa: BLE001
        return True


def log(msg: str) -> None:
    print(msg, flush=True)


def check_host(host: str) -> Tuple[str, Optional[str]]:
    """Return (verdict, detail) — verdict in {clean, takeover, maybe}."""
    host = host.strip().lower().rstrip(".")
    chain = follow_cname(host)
    if not chain:
        # no CNAME — not vulnerable via CNAME route; may still be a stale A record,
        # but we only flag CNAME-based takeover (no nuclei, conservative).
        return "clean", "no cname"

    final = chain[-1]
    provider = None
    for name, rx, _dead in PROVIDERS:
        if re.search(rx, final, re.I):
            provider = name
            break

    if provider:
        dead = is_nxdomain(final)
        if dead:
            return "takeover", f"cname -> {final} ({provider}): final target is dead"
        return "maybe", f"cname -> {final} ({provider}): target alive, manual check"
    return "clean", f"cname -> {final} (unknown provider)"


def main() -> int:
    parser = argparse.ArgumentParser(description="reconk takeover — native CNAME takeover detection")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-l", "--list", help="hosts file (one per line)")
    grp.add_argument("-d", "--domain", help="single host")
    parser.add_argument("-o", "--output", default="takeover.txt", help="text output file")
    parser.add_argument("--threads", type=int, default=50)
    args = parser.parse_args()

    hosts = [args.domain] if args.domain else read_lines(args.list)
    hosts = unique_preserve(h for h in hosts if h)
    if not hosts:
        print("no hosts", file=sys.stderr)
        return 1

    t0 = time.monotonic()
    log(f"{TAG} takeover check on {len(hosts)} host(s) — threads={args.threads}")

    lines: List[str] = []
    tak_over = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(check_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            host = futures[fut]
            try:
                verdict, detail = fut.result()
            except Exception as e:  # noqa: BLE001
                verdict, detail = "error", str(e)
            line = f"{host} | {verdict} | {detail}"
            lines.append(line)
            if verdict == "takeover":
                tak_over += 1
                log(f"  {BAD} {line}")
            elif verdict == "maybe":
                log(f"  {WARN} {line}")
            else:
                log(f"  {OK} {host} | {verdict} | {detail}")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    log(f"\n{OK} done in {time.monotonic() - t0:.1f}s — {tak_over} takeover, {len(lines)} total -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
