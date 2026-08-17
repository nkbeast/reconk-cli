#!/usr/bin/env python3
"""
SpiderCrawl v4 — by nk
Async, multi-source URL harvester. Crawls everything.

This is the speed-optimized variant (wayback CDX + common crawl only),
ported into reconk as its URL harvesting engine.
"""

import argparse
import asyncio
import json
import random
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any
from urllib.parse import parse_qs, urlparse, urlunparse, urlencode

import aiohttp
from aiohttp import ClientSession, TCPConnector
from rich.console import Console
from rich.progress import (
    BarColumn, MofNCompleteColumn, Progress,
    SpinnerColumn, TextColumn, TimeElapsedColumn,
)
from rich.table import Table

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
console = Console()

#: set from --proxy; applied to every request (aiohttp has no session-level
#: proxy for plain TCPConnector, so it is passed per request)
PROXY: Optional[str] = None

BANNER = r"""
⠀⠀⢀⡟⢀⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣧⠈⣧⠀⠀
⠀⠀⣼⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⡆⢸⡆⠀
⠀⢰⣿⠀⠻⠧⣤⡴⣦⣤⣤⣤⣠⡶⣤⣤⠾⠗⠈⣿⠀
⠀⠺⣷⡶⠖⠛⣩⣭⣿⣿⣿⣿⣿⣯⣭⡙⠛⠶⣶⡿⠃
⠀⠀⠀⢀⣤⠾⢋⣴⠟⣿⣿⣿⡟⢷⣬⠙⢷⣄⠀⠀⠀
⢀⣠⡴⠟⠁⠀⣾⡇⠀⣿⣿⣿⡇⠀⣿⡇⠀⠙⠳⣦⣀
⢸⡏⠀⠀⠀⠀⢿⡇⠀⢸⣿⣿⠁⠀⣿⡇⠀⠀⠀⠈⣿
⠀⣷⠀⠀⠀⠀⢸⡇⠀⠀⢻⠇⠀⠀⣿⠇⠀⠀⠀⠀⣿
⠀⢿⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⢸⡏
⠀⠘⡇⠀⠀⠀⠈⣷⠀⠀⠀⠀⠀⢀⡟⠀⠀⠀⠀⡾⠀
⠀⠀⠹⠀⠀⠀⠀⢻⠀⠀⠀⠀⠀⢸⠇⠀⠀⠀⢰⠁⠀
⠀⠀⠀⠁⠀⠀⠀⠈⢇⠀⠀⠀⠀⡞⠀⠀⠀⠀⠁⠀⠀
"""

# ─────────────────────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.5735.131 Mobile Safari/537.36",
]

SENSITIVE_EXTS = frozenset((
    ".json", ".env", ".conf", ".config", ".db", ".log", ".cnf",
    ".yaml", ".yml", ".xml", ".ini", ".bak", ".backup", ".sql",
    ".pem", ".key", ".crt", ".p12", ".pfx", ".der",
    ".zip", ".tar", ".gz", ".tgz", ".rar",
    ".csv", ".xls", ".xlsx", ".doc", ".docx",
    ".php", ".asp", ".aspx", ".cgi", ".pl",
))
IMAGE_EXTS = frozenset((".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif", ".bmp", ".tiff"))
MEDIA_EXTS  = frozenset((".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm", ".mkv", ".ogg", ".wav"))


SOURCE_SEM_LIMITS: dict[str, int] = {
    "wayback": 2, "commoncrawl": 3,
}


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class CrawlResult:
    domain: str
    urls: set = field(default_factory=set)
    per_source: dict = field(default_factory=lambda: defaultdict(int))
    subdomains: set = field(default_factory=set)
    errors: list = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def add(self, source: str, new_urls: list[str]) -> int:
        before = len(self.urls)
        self.urls.update(u for u in new_urls if u)
        self.per_source[source] = len(new_urls)
        return len(self.urls) - before


# ─────────────────────────────────────────────────────────────────────────────
# URL Utilities
# ─────────────────────────────────────────────────────────────────────────────
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
            params = parse_qs(p.query, keep_blank_values=True)
            # repair HTML-entity debris: "?amp%3Bfilter=x" was "?&amp;filter=x"
            # in the source page — normalize it to the real "&filter=x" so the
            # same URL found in both forms collapses to one entry
            for k, v in list(params.items()):
                if k.startswith("amp;") and len(k) > 4:
                    params.setdefault(k[4:], []).extend(v)
                    del params[k]
            query = urlencode(sorted((k, sorted(v)) for k, v in params.items()), doseq=True)
        return urlunparse((scheme, netloc, path, p.params, query, ""))
    except Exception:
        return url.strip()

def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url.strip())
        # generous cap: URLs with many parameters must be saved in full, not
        # dropped (only pathological >16k lines are rejected)
        return p.scheme in ("http", "https") and bool(p.netloc) and len(url) < 16384
    except Exception:
        return False

def get_extension(url: str) -> str:
    try:
        path = urlparse(url).path.lower()
        if "." in path:
            ext = "." + path.rsplit(".", 1)[-1].split("?")[0]
            return ext if len(ext) <= 8 else ""
    except Exception:
        pass
    return ""

def extract_param_keys(url: str) -> list[str]:
    try:
        qs = urlparse(url).query
        if not qs:
            return []
        keys = list(parse_qs(qs, keep_blank_values=True).keys())
        # ';' is a path-param separator, never a valid query key — keys like
        # "amp;filter" are HTML-entity debris ("?&amp;filter=") captured raw
        # by wayback and must not pollute the parameter list
        return [k for k in keys if ";" not in k and "&" not in k]
    except Exception:
        return []

def extract_hostname(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "https://" + raw
    return urlparse(raw).hostname or raw


# ─────────────────────────────────────────────────────────────────────────────
# HTTP Core  ← THE FIX: read body inside context, return data not response obj
# ─────────────────────────────────────────────────────────────────────────────
async def _fetch_raw(
    session: ClientSession,
    url: str,
    headers: Optional[dict] = None,
    timeout: int = 30,
    as_json: bool = False,
    as_bytes: bool = False,
    allow_status: tuple = (200,),
) -> Optional[Any]:
    """
    Core fetch. Returns str (text), dict/list (json), or bytes.
    Reads the full body INSIDE the response context to avoid ClientResponseError.
    Returns None on any error / non-2xx status.
    """
    hdrs = {"User-Agent": random.choice(USER_AGENTS), "Accept-Encoding": "gzip, deflate"}
    if headers:
        hdrs.update(headers)
    try:
        async with session.get(
            url,
            headers=hdrs,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=True,
            ssl=False,
            proxy=PROXY,
        ) as resp:
            if resp.status not in allow_status:
                return None
            if as_json:
                try:
                    return await resp.json(content_type=None)
                except Exception:
                    raw = await resp.text(errors="replace")
                    try:
                        return json.loads(raw)
                    except Exception:
                        return None
            elif as_bytes:
                return await resp.read()
            else:
                return await resp.text(errors="replace")
    except asyncio.TimeoutError:
        return None
    except aiohttp.ClientResponseError:
        return None
    except aiohttp.ClientError:
        return None
    except Exception:
        return None


async def fetch_text(
    session: ClientSession, url: str,
    headers: Optional[dict] = None,
    sem: Optional[asyncio.Semaphore] = None,
    timeout: int = 30,
    allow_status: tuple = (200,),
    max_retries: int = 3,
) -> Optional[str]:
    sem_ctx = sem or asyncio.Semaphore(999)
    async with sem_ctx:
        for attempt in range(max_retries):
            result = await _fetch_raw(session, url, headers=headers, timeout=timeout,
                                       allow_status=allow_status)
            if result is not None:
                return result
            # Only retry on genuine transient failures (network), not 4xx
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        return None


async def fetch_json(
    session: ClientSession, url: str,
    headers: Optional[dict] = None,
    sem: Optional[asyncio.Semaphore] = None,
    timeout: int = 30,
    allow_status: tuple = (200,),
    max_retries: int = 3,
) -> Optional[Any]:
    sem_ctx = sem or asyncio.Semaphore(999)
    async with sem_ctx:
        for attempt in range(max_retries):
            result = await _fetch_raw(session, url, headers=headers, timeout=timeout,
                                       as_json=True, allow_status=allow_status)
            if result is not None:
                return result
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Source Fetchers
# ─────────────────────────────────────────────────────────────────────────────

async def fetch_wayback(domain: str, session: ClientSession, sem: asyncio.Semaphore,
                         max_retries: int = 2) -> list[str]:
    """Wayback Machine CDX API — optimized for speed with rate-limit resilience."""
    url = (
        f"https://web.archive.org/cdx/search/cdx"
        f"?url=*.{domain}/*&output=text&collapse=urlkey"
        f"&fl=original&filter=statuscode:200&limit=5000000"
    )
    async with sem:
        for attempt in range(max_retries):
            urls: list[str] = []
            ua = random.choice(USER_AGENTS)
            try:
                async with session.get(
                    url,
                    headers={
                        "User-Agent": ua,
                        "Accept-Encoding": "gzip, deflate",
                        "Accept": "text/plain",
                    },
                    # total=None: CDX streams can be huge — but a stalled
                    # connection must not hang the stage forever
                    timeout=aiohttp.ClientTimeout(total=None, connect=15, sock_read=60),
                    ssl=False,
                    proxy=PROXY,
                ) as resp:
                    if resp.status == 200:
                        async for raw_line in resp.content:
                            line = raw_line.decode("utf-8", errors="replace").strip()
                            if line and line.startswith("http"):
                                urls.append(line)
                        return urls
                    elif resp.status in (429, 503):
                        console.print(f"  [dim]⚠ Wayback: HTTP {resp.status} (rate limited)"
                                      f"{' retrying...' if attempt+1 < max_retries else ''}[/dim]")
                        if attempt < max_retries - 1:
                            await asyncio.sleep(5 + random.uniform(0, 3))
                        continue
                    elif resp.status in (403, 404):
                        console.print(f"  [dim]⚠ Wayback: HTTP {resp.status} — blocked or no data[/dim]")
                        return urls
                    else:
                        console.print(f"  [dim]⚠ Wayback: HTTP {resp.status}[/dim]")
                        return urls
            except asyncio.TimeoutError:
                console.print(f"  [dim]⚠ Wayback: timeout"
                              f"{' retrying...' if attempt+1 < max_retries else ''}[/dim]")
            except (aiohttp.ClientError, OSError) as e:
                console.print(f"  [dim]⚠ Wayback: {type(e).__name__}"
                              f"{' retrying...' if attempt+1 < max_retries else ''}[/dim]")
            except Exception as e:
                console.print(f"  [dim]⚠ Wayback: {type(e).__name__}[/dim]")
                return urls
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt + random.uniform(0, 1))
        return []


async def fetch_commoncrawl(domain: str, session: ClientSession, sem: asyncio.Semaphore) -> list[str]:
    """Common Crawl — 2 most recent indexes with fast fail."""
    urls: set[str] = set()
    index_data = await fetch_json(
        session, "https://index.commoncrawl.org/collinfo.json",
        sem=sem, timeout=15,
    )
    if not index_data:
        return []

    # Only use 2 most recent indexes — they overlap heavily
    indexes = [item["cdx-api"] for item in index_data[:2] if "cdx-api" in item]
    if not indexes:
        return []

    async def _query(api_url: str):
        ua = random.choice(USER_AGENTS)
        q = (
            f"{api_url}?url=*.{domain}/*&output=json"
            f"&filter=status:200&fl=url"
        )
        try:
            async with session.get(
                q,
                headers={"User-Agent": ua, "Accept-Encoding": "gzip"},
                timeout=aiohttp.ClientTimeout(total=None, connect=10, sock_read=60),
                ssl=False,
                proxy=PROXY,
            ) as resp:
                if resp.status != 200:
                    return
                raw = await resp.text(errors="replace")
                for line in raw.strip().splitlines():
                    try:
                        u = json.loads(line).get("url", "")
                        if u:
                            urls.add(u)
                    except (json.JSONDecodeError, KeyError):
                        continue
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
            pass  # fail silently — not critical

    await asyncio.gather(*[_query(api) for api in indexes])
    return list(urls)


# ─────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────────────
async def process_domain(domain: str, args: argparse.Namespace, session: ClientSession) -> CrawlResult:
    result = CrawlResult(domain=domain)
    sems = {name: asyncio.Semaphore(n) for name, n in SOURCE_SEM_LIMITS.items()}

    # Phase 1: all passive sources in parallel
    passive_tasks: dict[str, Any] = {
        "wayback":        fetch_wayback(domain, session, sems["wayback"]),
        "commoncrawl":    fetch_commoncrawl(domain, session, sems["commoncrawl"]),
    }

    source_names = list(passive_tasks.keys())
    coros = list(passive_tasks.values())

    console.print(f"\n[bold cyan]⚡ Phase 1 — {len(source_names)} sources in parallel for: [green]{domain}[/green][/bold cyan]")

    gathered: list[list[str]] = [[] for _ in coros]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        prog_task = progress.add_task("[cyan]Passive recon", total=len(source_names))

        async def _run(i: int, coro, name: str):
            try:
                r = await coro
                gathered[i] = r or []
            except Exception as e:
                result.errors.append(f"{name}: {type(e).__name__}: {e}")
                gathered[i] = []
            progress.advance(prog_task)
            cnt = len(gathered[i])
            color = "green" if cnt > 0 else "dim"
            progress.print(f"  [{color}]✓[/{color}] [bold]{name}[/bold] → [yellow]{cnt:,}[/yellow]")

        await asyncio.gather(*[_run(i, c, source_names[i]) for i, c in enumerate(coros)])

    # Aggregate Phase 1
    for name, raw in zip(source_names, gathered):
        clean = [normalize_url(u) for u in raw if is_valid_url(u)]
        result.add(name, clean)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────
def classify_urls(urls: set[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = defaultdict(list)
    for url in sorted(urls):
        ext = get_extension(url)
        buckets["all"].append(url)
        if "?" in url:
            buckets["params"].append(url)
        if ext == ".js":
            buckets["js"].append(url)
        elif ext == ".pdf":
            buckets["pdf"].append(url)
        elif ext in SENSITIVE_EXTS:
            buckets["sensitive"].append(url)
        elif ext in IMAGE_EXTS:
            buckets["images"].append(url)
        elif ext in MEDIA_EXTS:
            buckets["media"].append(url)
        else:
            buckets["other"].append(url)
    return dict(buckets)


def save_results(result: CrawlResult, args: argparse.Namespace):
    domain = result.domain
    base = Path(getattr(args, "output", None) or "results").expanduser()
    buckets = classify_urls(result.urls)

    param_keys: set[str] = set()
    for url in result.urls:
        param_keys.update(extract_param_keys(url))

    dirs = {
        "urls":       base / "urls",
        "params":     base / "parameters",
        "js":         base / "js",
        "sensitive":  base / "sensitive",
        "pdf":        base / "pdfs",
        "images":     base / "images",
        "media":      base / "media",
        "subdomains": base / "subdomains",
        "reports":    base / "reports",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)

    file_map = {
        "all":       dirs["urls"]      / f"{domain}.txt",
        "params":    dirs["params"]    / f"{domain}.txt",
        "js":        dirs["js"]        / f"{domain}.txt",
        "sensitive": dirs["sensitive"] / f"{domain}.txt",
        "pdf":       dirs["pdf"]       / f"{domain}.txt",
        "images":    dirs["images"]    / f"{domain}.txt",
        "media":     dirs["media"]     / f"{domain}.txt",
    }

    for bucket, path in file_map.items():
        items = buckets.get(bucket, [])
        if items:
            path.write_text("\n".join(items) + "\n", encoding="utf-8")

    # Param keys
    if param_keys:
        (dirs["params"] / f"{domain}_param_keys.txt").write_text(
            "\n".join(sorted(param_keys)) + "\n", encoding="utf-8"
        )

    # Subdomains (unique hosts found across all URLs)
    all_hosts: set[str] = set()
    for url in result.urls:
        h = urlparse(url).hostname
        if h and (h == domain or h.endswith("." + domain)):
            all_hosts.add(h)
    if all_hosts:
        (dirs["subdomains"] / f"{domain}.txt").write_text(
            "\n".join(sorted(all_hosts)) + "\n", encoding="utf-8"
        )

    # JSON report
    elapsed = time.time() - result.started_at
    report = {
        "domain": domain,
        "crawled_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(elapsed, 2),
        "total_unique_urls": len(result.urls),
        "unique_subdomains": len(all_hosts),
        "unique_param_keys": len(param_keys),
        "per_source": dict(sorted(result.per_source.items(), key=lambda x: -x[1])),
        "buckets": {k: len(v) for k, v in buckets.items()},
        "param_keys": sorted(param_keys),
        "errors": result.errors,
    }
    report_path = dirs["reports"] / f"{domain}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    # ── Terminal output ───────────────────────────────────────────────────────
    table = Table(title=f"[bold]Results — {domain}[/bold]", border_style="cyan", show_lines=True)
    table.add_column("Category", style="bold white")
    table.add_column("Count", justify="right", style="bright_green")
    table.add_column("Saved to", style="dim")

    rows = [
        ("🔗 All URLs",         "all",       file_map["all"]),
        ("📌 With parameters",  "params",    file_map["params"]),
        ("⚙️  JavaScript",      "js",        file_map["js"]),
        ("🔐 Sensitive files",  "sensitive", file_map["sensitive"]),
        ("📄 PDFs",             "pdf",       file_map["pdf"]),
        ("🖼  Images",          "images",    file_map["images"]),
        ("🎬 Media",            "media",     file_map["media"]),
    ]
    for label, bucket, fpath in rows:
        items = buckets.get(bucket, [])
        if items:
            table.add_row(label, f"{len(items):,}", str(fpath))

    if all_hosts:
        table.add_row("🌐 Subdomains", f"{len(all_hosts):,}",
                      str(dirs["subdomains"] / f"{domain}.txt"))

    console.print(table)

    src_table = Table(title="Per-Source Breakdown", border_style="magenta", show_lines=True)
    src_table.add_column("Source", style="bold")
    src_table.add_column("URLs", justify="right", style="yellow")
    for src, cnt in sorted(result.per_source.items(), key=lambda x: -x[1]):
        src_table.add_row(src, f"{cnt:,}")
    console.print(src_table)

    console.print(
        f"\n[bold yellow]📋 Report:[/bold yellow] {report_path}\n"
        f"[bold yellow]⏱  Time:[/bold yellow] {elapsed:.1f}s  "
        f"[bold yellow]|[/bold yellow]  "
        f"[bold green]🔗 Total unique URLs: {len(result.urls):,}[/bold green]  "
        f"[bold yellow]|[/bold yellow]  "
        f"[cyan]🌐 Subdomains: {len(all_hosts):,}[/cyan]\n"
    )

    if result.errors:
        console.print(f"[dim]⚠ {len(result.errors)} non-fatal errors logged in report.[/dim]")


# ─────────────────────────────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────────────────────────────
async def async_main(args: argparse.Namespace):
    connector = TCPConnector(
        ssl=False,
        limit=200,
        limit_per_host=15,
        ttl_dns_cache=300,
        enable_cleanup_closed=True,
    )
    timeout = aiohttp.ClientTimeout(total=300, connect=10)
    async with ClientSession(connector=connector, timeout=timeout) as session:
        if args.domain:
            domains = [extract_hostname(args.domain)]
        else:
            path = Path(args.list).expanduser()
            if not path.exists():
                console.print(f"[red][!] File not found: {args.list}[/red]")
                sys.exit(1)
            raw_lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            seen: dict[str, None] = {}
            for line in raw_lines:
                h = extract_hostname(line)
                if h:
                    seen[h] = None
            domains = list(seen.keys())

        for domain in domains:
            result = await process_domain(domain, args, session)
            save_results(result, args)


def main():
    console.print(f"[yellow]{BANNER}[/yellow]")
    console.print(f"[bold yellow]{'SpiderCrawl v4':^42}[/bold yellow]")
    console.print(f"[dim]{'by nk — async, multi-source, JS-aware URL harvester':^52}[/dim]\n")

    parser = argparse.ArgumentParser(
        description="SpiderCrawl v4 — Async URL harvester. Crawls everything.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-d", "--domain", metavar="DOMAIN",
                       help="Single domain to crawl (e.g. example.com)")
    group.add_argument("-l", "--list", metavar="FILE",
                       help="File with one domain per line")
    parser.add_argument("-o", "--output", metavar="DIR", default="results",
                       help="Output directory (default: ./results)")
    parser.add_argument("--proxy", metavar="URL",
                       help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")

    args = parser.parse_args()

    if not args.domain and not args.list:
        parser.error("provide -d/--domain or -l/--list")

    global PROXY
    PROXY = args.proxy

    try:
        asyncio.run(async_main(args))
    except KeyboardInterrupt:
        console.print("\n[bold red][!] Interrupted by user.[/bold red]")
        sys.exit(0)


if __name__ == "__main__":
    main()
