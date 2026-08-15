#!/usr/bin/env python3
"""reconk harvester — async multi-source URL harvesting.

One script replaces spidercrawl + waybackurls + gau:

  * wayback machine CDX   (streamed, huge)
  * common crawl          (latest 3 indexes, parallel)
  * alienvault OTX        (paginated)
  * crt.sh                (hosts for the root domains)
  * rapiddns              (hosts)
  * hackertarget          (hosts)
  * urlscan.io            (paginated, optional key)
  * virustotal            (urls + subdomains, optional key)
  * github code dorking   (optional token)

Output: all URLs in one text file, per-source files, plus any
subdomains discovered along the way.

Usage:
  python harvester.py -d example.com -o urls.txt [--subs subs.txt] [--per-source dir]
  python harvester.py -dL domains.txt -o urls.txt
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import re
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse, quote

import aiohttp

try:
    from reconk.scripts.common import clean_host, is_hostname, read_lines, unique_preserve
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from reconk.scripts.common import clean_host, is_hostname, read_lines, unique_preserve

TAG = "\033[1;36m[*]\033[0m" if sys.stdout.isatty() else "[*]"
OK = "\033[1;32m[+]\033[0m" if sys.stdout.isatty() else "[+]"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]

SEM_LIMITS: Dict[str, int] = {
    "wayback": 4, "commoncrawl": 5, "alienvault": 5, "urlscan": 3,
    "virustotal": 2, "crtsh": 4, "rapiddns": 6, "hackertarget": 5, "github": 2,
}


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# fetch core
# --------------------------------------------------------------------------- #
async def _fetch_text(session, url: str, headers=None, timeout: int = 30,
                      allow_status=(200,), retries: int = 2, sem=None) -> Optional[str]:
    hdrs = {"User-Agent": random.choice(USER_AGENTS), "Accept-Encoding": "gzip, deflate"}
    if headers:
        hdrs.update(headers)
    for attempt in range(retries):
        try:
            if sem is None:
                resp = session.get(url, headers=hdrs,
                                   timeout=aiohttp.ClientTimeout(total=timeout), ssl=False)
                response = await resp
                try:
                    if response.status not in allow_status:
                        return None
                    return await response.text(errors="replace")
                finally:
                    response.close()
            else:
                async with sem:
                    async with session.get(url, headers=hdrs,
                                           timeout=aiohttp.ClientTimeout(total=timeout),
                                           ssl=False) as response:
                        if response.status not in allow_status:
                            return None
                        return await response.text(errors="replace")
        except (asyncio.TimeoutError, aiohttp.ClientError, aiohttp.ClientResponseError):
            if attempt < retries - 1:
                await asyncio.sleep(1.5 * (attempt + 1))
        except Exception:  # noqa: BLE001
            return None
    return None


# --------------------------------------------------------------------------- #
# sources
# --------------------------------------------------------------------------- #
async def fetch_wayback(domain: str, session, sem) -> List[str]:
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text"
           f"&collapse=urlkey&fl=original&filter=statuscode:200&limit=200000")
    async with sem:
        for _ in range(3):
            try:
                async with session.get(url, headers={"User-Agent": random.choice(USER_AGENTS)},
                                       timeout=aiohttp.ClientTimeout(total=60), ssl=False) as resp:
                    if resp.status == 200:
                        return [line.strip() for line in (await resp.text(errors="replace")).splitlines()
                                if line.strip().startswith("http")]
                    return []
            except Exception:  # noqa: BLE001
                await asyncio.sleep(2)
    return []


async def fetch_commoncrawl(domain: str, session, sem) -> List[str]:
    urls: Set[str] = set()
    coll = await _fetch_text(session, "https://index.commoncrawl.org/collinfo.json", sem=sem, timeout=20)
    if not coll:
        return []
    try:
        indexes = [item["cdx-api"] for item in json.loads(coll)[:3]]
    except Exception:  # noqa: BLE001
        return []

    async def _query(api: str):
        q = f"{api}?url=*.{domain}/*&output=json&limit=20000&filter=status:200"
        text = await _fetch_text(session, q, sem=sem, timeout=45)
        if not text:
            return
        for line in text.splitlines():
            try:
                u = json.loads(line).get("url", "")
                if u:
                    urls.add(u)
            except Exception:  # noqa: BLE001
                continue

    await asyncio.gather(*[_query(a) for a in indexes])
    return list(urls)


async def fetch_alienvault(domain: str, session, sem) -> List[str]:
    out: List[str] = []
    page = 1
    while True:
        data = await _fetch_text(session,
                                 f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500&page={page}",
                                 sem=sem, timeout=30)
        if not data:
            break
        try:
            obj = json.loads(data)
        except Exception:  # noqa: BLE001
            break
        items = obj.get("url_list", [])
        if not items:
            break
        out += [i.get("url", "") for i in items if i.get("url")]
        if not obj.get("has_next"):
            break
        page += 1
        await asyncio.sleep(0.3)
    return out


async def fetch_urlscan(domain: str, session, sem, key: str) -> List[str]:
    if not key:
        return []
    urls: Set[str] = set()
    headers = {"API-Key": key}
    cursor = None
    for _ in range(5):
        q = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
        if cursor:
            q += f"&search_after={cursor}"
        data = await _fetch_text(session, q, headers=headers, sem=sem, allow_status=(200, 429), timeout=40)
        if not data:
            break
        try:
            obj = json.loads(data)
        except Exception:  # noqa: BLE001
            break
        for r in obj.get("results", []) or []:
            for u in (r.get("page") or {}).get("url", ""), (r.get("task") or {}).get("url", ""):
                if isinstance(u, str) and u.startswith("http"):
                    urls.add(u)
            for lnk in r.get("links", []) or []:
                href = lnk.get("href", "")
                if isinstance(href, str) and href.startswith("http"):
                    urls.add(href)
        if obj.get("has_more") and obj.get("results"):
            sort = obj["results"][-1].get("sort", [])
            if not sort:
                break
            cursor = ",".join(str(s) for s in sort)
            await asyncio.sleep(0.5)
        else:
            break
    return list(urls)


async def fetch_virustotal(domain: str, session, sem, key: str) -> List[str]:
    if not key:
        return []
    urls: Set[str] = set()
    headers = {"x-apikey": key}
    cursor = None
    for _ in range(8):
        q = f"https://www.virustotal.com/api/v3/domains/{domain}/urls?limit=40"
        if cursor:
            q += f"&cursor={cursor}"
        data = await _fetch_text(session, q, headers=headers, sem=sem, allow_status=(200, 204), timeout=40)
        if not data:
            break
        try:
            obj = json.loads(data)
        except Exception:  # noqa: BLE001
            break
        for item in obj.get("data", []) or []:
            u = (item.get("attributes") or {}).get("url") or item.get("id", "")
            if u:
                urls.add(u)
        cursor = (obj.get("meta") or {}).get("cursor")
        if not cursor:
            break
        await asyncio.sleep(1.2)
    return list(urls)


async def fetch_crtsh_hosts(domain: str, session, sem) -> List[str]:
    data = await _fetch_text(session, f"https://crt.sh/?q=%25.{domain}&output=json", sem=sem, timeout=60)
    if not data:
        return []
    hosts: Set[str] = set()
    try:
        obj = json.loads(data)
        for entry in obj:
            for f in ("name_value", "common_name"):
                for name in str(entry.get(f, "")).splitlines():
                    name = clean_host(name)
                    if is_hostname(name) and name.endswith("." + domain):
                        hosts.add(name)
    except Exception:  # noqa: BLE001
        pass
    return list(hosts)


async def fetch_rapiddns(domain: str, session, sem) -> List[str]:
    text = await _fetch_text(session, f"https://rapiddns.io/subdomain/{domain}?full=1", sem=sem, timeout=30)
    if not text:
        return []
    found = re.findall(r"(?:^|[\s\"'>])([a-zA-Z0-9\-\.]+\.re\.escape(domain))", "")  # placeholder, replaced below
    found = re.findall(r"(?:^|[\s\"'>])([a-zA-Z0-9\-\.]+\.)" + re.escape(domain) + r"(?:[\s\"'<]|$)", text)
    return sorted({f"https://{f}.{domain}" for f in found if f and f != domain})


async def fetch_hackertarget(domain: str, session, sem) -> List[str]:
    text = await _fetch_text(session, f"https://api.hackertarget.com/hostsearch/?q={domain}", sem=sem, timeout=30)
    if not text or "error" in text[:100].lower() or "API count exceeded" in text:
        return []
    urls: Set[str] = set()
    for line in text.splitlines():
        parts = line.split(",")
        if parts and parts[0].strip():
            urls.add(f"https://{parts[0].strip()}")
    return list(urls)


async def fetch_github(domain: str, session, sem, token: str) -> List[str]:
    if not token:
        return []
    urls: Set[str] = set()
    headers = {"Accept": "application/vnd.github.v3+json", "Authorization": f"token {token}"}
    queries = [f'"{domain}" path:*.js', f'"{domain}" path:*.json', f'"{domain}" path:*.env']
    for q in queries:
        api = f"https://api.github.com/search/code?q={quote(q)}&per_page=20"
        data = await _fetch_text(session, api, headers=headers, sem=sem, allow_status=(200, 403, 422), timeout=30)
        if data:
            try:
                obj = json.loads(data)
                for item in obj.get("items", []) or []:
                    raw = (item.get("html_url", "")
                           .replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/"))
                    text = await _fetch_text(session, raw, sem=sem, timeout=15)
                    if text:
                        for m in re.finditer(r'https?://[^\s"\'<>]+', text):
                            u = m.group(0)
                            if domain in u and u.startswith("http"):
                                urls.add(u)
            except Exception:  # noqa: BLE001
                pass
        await asyncio.sleep(2)
    return list(urls)


# --------------------------------------------------------------------------- #
# orchestrator
# --------------------------------------------------------------------------- #
def normalize_url(url: str) -> str:
    try:
        url = url.strip()
        if not url:
            return ""
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        p = urlparse(url)
        scheme = p.scheme.lower()
        netloc = (p.hostname or "").lower()
        if p.port and not ((p.port == 80 and scheme == "http") or (p.port == 443 and scheme == "https")):
            netloc += f":{p.port}"
        path = p.path or "/"
        query = ""
        if p.query:
            params = sorted(parse_qs(p.query, keep_blank_values=True).items())
            query = urlencode(params, doseq=True)
        return urlunparse((scheme, netloc, path, p.params, query, ""))
    except Exception:  # noqa: BLE001
        return url.strip()


def urlunparse_(*parts):  # noqa: ANN001
    return urlunparse(*parts)


def in_domain(url: str, roots: List[str]) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
        return any(host == r or host.endswith("." + r) for r in roots)
    except Exception:  # noqa: BLE001
        return False


def extract_subdomains(urls: List[str], roots: List[str]) -> List[str]:
    subs: Set[str] = set()
    for u in urls:
        host = (urlparse(u).hostname or "").lower()
        if host:
            for r in roots:
                if host.endswith("." + r) and host != r:
                    subs.add(host)
    return sorted(subs)


async def harvest_domain(domain: str, args, session, keys) -> Dict[str, List[str]]:
    sems = {n: asyncio.Semaphore(v) for n, v in SEM_LIMITS.items()}
    tasks = {
        "wayback": fetch_wayback(domain, session, sems["wayback"]),
        "commoncrawl": fetch_commoncrawl(domain, session, sems["commoncrawl"]),
        "alienvault": fetch_alienvault(domain, session, sems["alienvault"]),
        "crtsh": fetch_crtsh_hosts(domain, session, sems["crtsh"]),
        "rapiddns": fetch_rapiddns(domain, session, sems["rapiddns"]),
        "hackertarget": fetch_hackertarget(domain, session, sems["hackertarget"]),
    }
    if keys.get("urlscan"):
        tasks["urlscan"] = fetch_urlscan(domain, session, sems["urlscan"], keys["urlscan"])
    if keys.get("virustotal"):
        tasks["virustotal"] = fetch_virustotal(domain, session, sems["virustotal"], keys["virustotal"])
    if keys.get("github"):
        tasks["github"] = fetch_github(domain, session, sems["github"], keys["github"])

    log(f"  {TAG} {domain}: {len(tasks)} sources in parallel")
    results = {}
    for name, coro in tasks.items():
        try:
            raw = await coro
            results[name] = [normalize_url(u) for u in raw or [] if u.startswith("http")]
            log(f"    {OK} {name:<12} -> {len(results[name]):,}")
        except Exception as e:  # noqa: BLE001
            log(f"    [WARN] {name}: {e}")
            results[name] = []
    return results


async def async_main(args) -> int:
    domains = [args.domain] if args.domain else read_lines(args.list)
    domains = unique_preserve(d for d in domains if d and "." in d)
    if not domains:
        print("no domains", file=sys.stderr)
        return 1

    keys = {
        "urlscan": args.urlscan_key,
        "virustotal": args.virustotal_key,
        "github": args.github_token,
    }

    connector = aiohttp.TCPConnector(ssl=False, limit=200, limit_per_host=15, ttl_dns_cache=300)
    timeout = aiohttp.ClientTimeout(total=300, connect=10)
    t0 = time.monotonic()
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        all_urls: Set[str] = set()
        per_source: Dict[str, List[str]] = defaultdict(list)
        for domain in domains:
            results = await harvest_domain(domain, args, session, keys)
            for name, urls in results.items():
                all_urls.update(urls)
                per_source[name].extend(urls)

    final_urls = [u for u in sorted(all_urls) if in_domain(u, domains)]
    log(f"\n{OK} total unique URLs: {len(final_urls):,}")

    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(final_urls) + "\n")
    log(f"{OK} urls -> {args.output}")

    if args.per_source:
        import os

        os.makedirs(args.per_source, exist_ok=True)
        for name, urls in per_source.items():
            keep = [u for u in sorted(set(urls)) if in_domain(u, domains)]
            with open(os.path.join(args.per_source, f"{name}.txt"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(keep) + "\n")
        log(f"{OK} per-source files -> {args.per_source}")

    if args.subs:
        subs = extract_subdomains(final_urls, domains)
        with open(args.subs, "w", encoding="utf-8") as fh:
            fh.write("\n".join(subs) + "\n")
        log(f"{OK} {len(subs)} subdomains from URLs -> {args.subs}")

    log(f"{OK} harvesting done in {time.monotonic() - t0:.1f}s")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="reconk harvester — async multi-source URL harvesting")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--domain", help="single domain")
    grp.add_argument("-dL", "--list", help="file with domains (one per line)")
    parser.add_argument("-o", "--output", default="urls.txt", help="all URLs text file")
    parser.add_argument("--per-source", help="dir for per-source txt files")
    parser.add_argument("--subs", help="output file for subdomains discovered in URLs")
    parser.add_argument("--urlscan-key", default="", help="urlscan.io API key")
    parser.add_argument("--virustotal-key", default="", help="virustotal API key")
    parser.add_argument("--github-token", default="", help="github PAT for code dorking")
    args = parser.parse_args()
    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
