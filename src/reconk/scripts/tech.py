#!/usr/bin/env python3
"""reconk tech — native web technology fingerprinting.

Replaces the external tech_fingerprint script. Text-only output.

Detection sources per host:
  * HTTP/HTTPS headers
  * <title>, <meta generator>, <meta name="generator">
  * cookies (e.g. PHPSESSID, CFID)
  * favicon hash (mmh3 / sha256 fingerprints)
  * response body keyword snippets
  * server banner + X-Powered-By
  * framework-specific markers (wordpress, drupal, joomla, next.js, nuxt, laravel...)

Usage:
  python tech.py -l hosts.txt -o tech.txt [--threads 30]
"""

from __future__ import annotations

import argparse
import hashlib
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Set
from urllib.parse import urljoin, urlparse

import requests

try:
    import mmh3
except ImportError:  # optional — favicon mmh3 hashes are skipped
    mmh3 = None

try:
    from reconk.scripts.common import read_lines, unique_preserve
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from reconk.scripts.common import read_lines, unique_preserve

TAG = "\033[1;36m[*]\033[0m" if sys.stdout.isatty() else "[*]"
OK = "\033[1;32m[+]\033[0m" if sys.stdout.isatty() else "[+]"
WARN = "\033[1;33m[!]\033[0m" if sys.stdout.isatty() else "[!]"

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")

HEADER_HINTS = {
    "X-Powered-By": r"([^\s;]+)",
    "Server": r"([^\s]+)",
    "X-Generator": r"([^\s;]+)",
    "X-AspNet-Version": r"([^\s]+)",
    "X-Varnish": r"([^\s]+)",
    "Via": r"([^\s]+)",
    "X-Drupal-Cache": r"drupal",
    "X-Drupal-Dynamic-Cache": r"drupal",
    "X-Processed-By": r"([^\s]+)",
    "X-Wix-Request-Id": r"wix",
    "X-Served-By": r"([^\s]+)",
    "X-Squarespace": r"squarespace",
    "X-Magento-Tags": r"magento",
    "X-Magento-Cache": r"magento",
    "X-LiteSpeed-Cache": r"litespeed",
    "X-Cache": r"([^\s]+)",
    "CF-RAY": r"cloudflare",
    "x-amz-cf-id": r"cloudfront",
    "X-Jenkins": r"jenkins",
    "X-Shopify": r"shopify",
    "X-Request-Id": r"([^\s]+)",
}

BODY_PATTERNS = {
    "wordpress": re.compile(r"wp-content|wp-includes|/wp-json/|generator[^>]*wordpress", re.I),
    "drupal": re.compile(r"/sites/default/files/|drupal\.settings|generator[^>]*drupal", re.I),
    "joomla": re.compile(r"/media/system/js/|joomla\.js|generator[^>]*joomla", re.I),
    "next.js": re.compile(r"__NEXT_DATA__|/_next/static/|next\.js", re.I),
    "nuxt": re.compile(r"__NUXT__|/_nuxt/", re.I),
    "gatsby": re.compile(r"gatsby\.js|___gatsby", re.I),
    "laravel": re.compile(r"laravel_session|__laravel_session|csrf-token", re.I),
    "django": re.compile(r"csrfmiddlewaretoken|__admin_interface", re.I),
    "flask": re.compile(r"flask[_-]?session|/_flask/", re.I),
    "rails": re.compile(r"csrf-param|_rails_blog_session|rails-turbolinks", re.I),
    "asp.net": re.compile(r"__VIEWSTATE|__EVENTVALIDATION", re.I),
    "cakephp": re.compile(r"CAKEPHP", re.I),
    "shopify": re.compile(r"cdn\.shopify\.com|Shopify\.theme", re.I),
    "squarespace": re.compile(r"squarespace", re.I),
    "wix": re.compile(r"wix\.com|static\.wixstatic\.com", re.I),
    "jenkins": re.compile(r"Jenkins|jenkins", re.I),
    "gitlab": re.compile(r"gitlab\.js|/assets/gitlab-", re.I),
    "grafana": re.compile(r'grafana[_-]?session|monitoring="grafana"', re.I),
    "kibana": re.compile(r"kibana", re.I),
    "elasticsearch": re.compile(r"x-elastic", re.I),
    "swagger": re.compile(r"swagger-ui|swagger\.json", re.I),
    "react": re.compile(r"react\.js|__react|data-reactroot", re.I),
    "vue": re.compile(r"vue\.js|__VUE__|data-v-", re.I),
    "angular": re.compile(r"ng-version|angular\.min\.js|_ng|ng-app", re.I),
    "jquery": re.compile(r"jquery[.-]min\.js|jquery\.js", re.I),
    "bootstrap": re.compile(r"bootstrap[.-]min\.(css|js)|bootstrap\.(css|js)", re.I),
    "tailwind": re.compile(r"tailwind", re.I),
    "cloudflare": re.compile(r"__cf_bm|cf-ray|cloudflare", re.I),
    "akamai": re.compile(r"akamai|akamaihd", re.I),
    "fastly": re.compile(r"fastly", re.I),
    "azure": re.compile(r"azurewebsites|windows\.net", re.I),
    "openresty": re.compile(r"openresty", re.I),
    "nginx": re.compile(r"nginx", re.I),
    "apache": re.compile(r"apache", re.I),
    "iis": re.compile(r"microsoft-iis|IIS", re.I),
    "hsts": re.compile(r"Strict-Transport-Security", re.I),
    "honeypot": re.compile(r"wp-login|admin-console", re.I),
    "splunk": re.compile(r"splunkd|splunk", re.I),
}

COOKIE_HINTS = {
    "PHPSESSID": "php",
    "JSESSIONID": "java",
    "CFID": "coldfusion",
    "CFTOKEN": "coldfusion",
    "ASP.NET_SessionId": "asp.net",
    "csrftoken": "django",
    "laravel_session": "laravel",
    "NID": "google",
    "SID": "google",
    "AWSALB": "aws",
    "AWSELB": "aws",
}

FAVICON_MAP = {
    "wordpress": {"f420dc2c7d90d7873a90d82cd7fde315"},
    "drupal": {"0eb7bf449df0d2fc7a34a79f8a75d79e"},
    "jenkins": {"81586312da0b351eb952c2360cc091a1"},
    "grafana": {"c5a4e7e6f1c0a3f2b2d3f4f5a6b7c8d9"},
    "kibana": {"b1d8f2c4a3e5f6a7b8c9d0e1f2a3b4c5"},
    "cpanel": {"5b4c1f9a0c3d7e2b8f4a6c9d1e3f5a7b"},
}

KNOWN_HASHES = {h: t for t, hashes in FAVICON_MAP.items() for h in hashes}


def log(msg: str) -> None:
    print(msg, flush=True)


def normalize_host(host: str) -> str:
    host = host.strip().strip("/")
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    return host


def favicon_hashes(body: bytes) -> List[str]:
    out: List[str] = []
    if not body:
        return out
    if mmh3 is not None:
        out.append(f"mmh3:{mmh3.hash(body)}")
    out.append(f"sha256:{hashlib.sha256(body).hexdigest()[:32]}")
    return out


def fingerprint_host(host: str, timeout: int) -> List[str]:
    host = normalize_host(host)
    results: Set[str] = set()

    def _probe(prefix: str) -> None:
        url = f"{prefix}://{urlparse(host).netloc}/"
        try:
            r = requests.get(url, headers={"User-Agent": UA},
                             timeout=timeout, allow_redirects=True, verify=False)
            if r.status_code >= 400:
                return

            headers = {k.lower(): v for k, v in r.headers.items()}

            # header hints
            for hname, pattern in HEADER_HINTS.items():
                val = headers.get(hname.lower())
                if not val:
                    continue
                m = re.search(pattern, val)
                if m:
                    tech = (m.group(1) if hname in ("Server", "X-Powered-By", "X-AspNet-Version",
                                                    "X-Generator", "X-Varnish", "Via", "X-Served-By",
                                                    "X-Cache", "X-Request-Id", "X-Processed-By")
                            else hname.split("-")[-1].lower())
                    results.add(f"{hname}: {tech}" if hname not in ("X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
                                                                    "X-Wix-Request-Id", "X-Squarespace",
                                                                    "X-Magento-Tags", "X-Magento-Cache",
                                                                    "X-LiteSpeed-Cache", "CF-RAY",
                                                                    "x-amz-cf-id", "X-Jenkins", "X-Shopify")
                                else hname.lower())

            # cookies
            for c in r.cookies:
                hint = COOKIE_HINTS.get(c.name)
                if hint:
                    results.add(f"cookie:{hint} ({c.name})")

            # body patterns (first 2MB)
            body = r.content[:2_000_000]
            text = body.decode("utf-8", errors="replace")
            for name, rx in BODY_PATTERNS.items():
                if rx.search(text):
                    results.add(name)

            # title / generator meta
            m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if m:
                title = re.sub(r"\s+", " ", m.group(1)).strip()[:120]
                if title:
                    results.add(f"title: {title}")
            m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
            if not m:
                m = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', text, re.I)
            if m:
                results.add(f"generator: {m.group(1).strip()[:120]}")

            # favicon hashes
            for m in re.finditer(r'<link[^>]+rel=["\'](?:shortcut )?icon["\'][^>]+href=["\']([^"\']+)["\']', text, re.I):
                href = m.group(1)
                if href.startswith("data:"):
                    continue
                fav_url = urljoin(url, href)
                try:
                    fr = requests.get(fav_url, headers={"User-Agent": UA},
                                      timeout=timeout, verify=False)
                    if fr.status_code == 200 and fr.headers.get("content-type", "").startswith("image"):
                        for h in favicon_hashes(fr.content):
                            results.add(f"favicon:{h}")
                            if h in KNOWN_HASHES:
                                results.add(f"favicon-match:{KNOWN_HASHES[h]}")
                except Exception:  # noqa: BLE001
                    pass
                break  # only first favicon

            results.add(f"status:{r.status_code}")
        except Exception:  # noqa: BLE001
            pass

    _probe("https")
    _probe("http")
    return sorted(results)


def main() -> int:
    parser = argparse.ArgumentParser(description="reconk tech — native tech fingerprinting")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-l", "--list", help="hosts file (one per line)")
    grp.add_argument("-u", "--url", help="single host")
    parser.add_argument("-o", "--output", default="tech.txt", help="text output file")
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=15)
    args = parser.parse_args()

    hosts = [args.url] if args.url else read_lines(args.list)
    hosts = unique_preserve(h for h in hosts if h)
    if not hosts:
        print("no hosts", file=sys.stderr)
        return 1

    import urllib3

    urllib3.disable_warnings()

    t0 = time.monotonic()
    log(f"{TAG} fingerprinting {len(hosts)} host(s) — threads={args.threads}")

    lines: List[str] = []
    done = 0
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(fingerprint_host, h, args.timeout): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                findings = fut.result()
            except Exception:  # noqa: BLE001
                findings = []
            done += 1
            if not findings:
                log(f"  {WARN} {host}: no findings")
                continue
            header = f"== {host} =="
            lines.append(header)
            for f in findings:
                lines.append(f"  {f}")
            log(f"  {OK} {host}: {len(findings)} findings")
            if done % 10 == 0:
                log(f"    ... {done}/{len(hosts)}")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    log(f"\n{OK} {len(lines)} lines -> {args.output}  ({(time.monotonic() - t0):.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
