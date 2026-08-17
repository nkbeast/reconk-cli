"""JavaScript analysis.

Pipeline:
  1. katana (js-crawl) over the alive endpoints to discover JS files
  2. merge with all `.js` URLs harvested by the URL phase
  3. download every JS file (bounded concurrency, robust)
  4. extract endpoint candidates (relative + absolute URLs)
  5. scan for secrets (API keys, tokens, AWS/GCP/Azure creds, ...)

Outputs:
  07-js/js_files.txt           — all JS file URLs
  07-js/js_endpoints.txt       — endpoints extracted from JS bodies
  07-js/js_secrets.txt         — secret findings (url + line)
  07-js/fetched/               — downloaded JS bodies
"""

from __future__ import annotations

import re
import threading
import urllib3
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from hashlib import md5
from pathlib import Path
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import requests

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound

#: JS downloads intentionally skip TLS verification (self-signed/expired
#: certs are common on targets) — silence the urllib3 warning spam.
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --------------------------------------------------------------------------- #
# Endpoint / URL extraction regexes
# --------------------------------------------------------------------------- #
ENDPOINT_RE = re.compile(
    r"""(?ix)
    (?:
        ["'`]\s*(?P<url>https?://[^"'`\s}]+)["'`]
        |
        ["'`]\s*(?P<rel>/(?:api|v\d|rest|graphql|ws|s3|static|assets|download)
            [^"'`\s}]{2,})["'`]
        |
        (?P<dom>["'`]\s*(?://)?[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9\-]+)*
            \.[a-z]{2,}(?::\d+)?/(?:[a-zA-Z0-9_\-/.]{3,})["'`])
    )
    """
)

# --------------------------------------------------------------------------- #
# Secret patterns
# --------------------------------------------------------------------------- #
SECRET_PATTERNS: List[tuple] = [
    ("AWS Access Key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("AWS Secret Key", r"(?i)\baws[_-]?(?:secret|private)[_-]?(?:access[_-]?)?key\b.{0,20}[\"']?([A-Za-z0-9/+=]{40})"),
    ("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Google OAuth ID", r"\b\d{12}-[0-9a-z]{32}\.apps\.googleusercontent\.com\b"),
    ("Slack Token", r"\bxox[abpors]-[0-9A-Za-z\-]{10,}\b"),
    ("GitHub Token", r"\bghp_[0-9A-Za-z]{36}\b"),
    ("GitHub OAuth", r"\bgho_[0-9A-Za-z]{36}\b"),
    ("GitLab Token", r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    ("Stripe Secret", r"\bsk_live_[0-9A-Za-z]{24,}\b"),
    ("Stripe Publishable", r"\bpk_live_[0-9A-Za-z]{24,}\b"),
    ("Stripe Restricted", r"\brk_live_[0-9A-Za-z]{24,}\b"),
    ("Square Access", r"\bsq0atp-[0-9A-Za-z_\-]{22,}\b"),
    ("PayPal Braintree", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("Twilio API", r"\bSK[0-9a-fA-F]{32}\b"),
    ("SendGrid Key", r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    ("Mailgun Key", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("Heroku API", r"(?i)\bheroku[_-]?api[_-]?key\b.{0,40}[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"),
    ("Firebase URL", r"\b[a-z0-9\-]+\.firebaseio\.com\b"),
    ("Firebase API", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("JWT", r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
    ("Private Key Header", r"\b-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("Azure Storage", r"\bhttps://[a-z0-9]{3,24}\.blob\.core\.windows\.net\b"),
    ("S3 Bucket", r"\bhttps?://[a-z0-9\.\-]+\.s3[.-](?:[a-z0-9\-]+\.)?amazonaws\.com\b"),
    ("GCP Bucket", r"\bhttps?://[a-z0-9\.\-]+\.storage\.googleapis\.com\b"),
    ("Generic Bearer", r"""(?i)\b(?:bearer|token|apikey|api_key|secret)["']?\s*[:=]\s*["']([A-Za-z0-9_\-\.]{16,})["']"""),
    ("Generic Secret Assignment", r"""(?i)\b(?:secret|password|passwd|pwd|client[_-]?secret)["']?\s*[:=]\s*["'](?=[A-Za-z0-9!@#$%^&*_\-\.+/=]{8,}["'])(?=[^"']*[0-9!@#$%^&*_\-\.+/=])[A-Za-z0-9!@#$%^&*_\-\.+/=]+["']"""),
]

DEFAULT_JS_LIMIT = 1500


@register
class JsAnalysisModule(Module):
    name = "js"
    label = "JS Analysis"
    category = "js"

    def run(self) -> ModuleResult:
        res = ModuleResult(self.name)
        js_dir = self.ctx.out.cat(self.category)
        self.start("JS analysis — katana crawl + endpoint/secret extraction")

        # ---- 1. katana js-crawl -------------------------------------------
        # drop stale katana outputs so a failed/skipped crawl can never be
        # re-collected as fresh data
        for stale in ("katana_js.txt", "katana_js_raw.txt"):
            p = js_dir / stale
            if p.exists():
                p.unlink()
        katana_js: List[str] = self._katana_crawl()
        if katana_js:
            path = self.ctx.out.write(self.category, "katana_js.txt", katana_js, dedupe=True)
            res.files.append(str(path))

        # ---- 2. merge all js urls ------------------------------------------
        js_files = self._collect_js_urls()
        if not js_files:
            return ModuleResult(self.name, message="no JS files found")

        path = self.ctx.out.write(self.category, "js_files.txt", js_files, dedupe=True)
        res.files.append(str(path))
        self.console.print(f"  [cyan]· {len(js_files)} JS files to analyze[/cyan]")

        # ---- 3. download ----------------------------------------------------
        fetched = js_dir / "fetched"
        fetched.mkdir(parents=True, exist_ok=True)
        bodies: Dict[str, str] = self._download_js(js_files, fetched)

        # ---- 4. endpoints ---------------------------------------------------
        endpoints: Set[str] = set()
        for url, body in bodies.items():
            endpoints.update(self._extract_endpoints(body, url))
        if endpoints:
            ep = self.ctx.out.write(self.category, "js_endpoints.txt", sorted(endpoints), dedupe=True)
            res.files.append(str(ep))

        # ---- 5. secrets -----------------------------------------------------
        secrets: List[str] = []
        for url, body in bodies.items():
            secrets += self._scan_secrets(body, url)
        if secrets:
            sp = self.ctx.out.write(self.category, "js_secrets.txt", secrets, dedupe=True)
            res.files.append(str(sp))
            self.console.print(
                f"  [bold red]! {len(secrets)} potential secrets found — review 07-js/js_secrets.txt[/bold red]"
            )

        res.count = len(js_files)
        self.done(f"{len(bodies)} fetched, {len(endpoints)} endpoints, {len(secrets)} secrets")
        return res

    # ------------------------------------------------------------------ #
    # 1. katana
    # ------------------------------------------------------------------ #
    def _katana_crawl(self) -> List[str]:
        alive = self.ctx.out.read("live", "alive.txt")
        if not alive:
            return []
        try:
            self.runner.require("katana")
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")
            return []

        depth = self.ctx.cfg.get("scan.katana_depth", "3")
        hosts_file = self.ctx.out.root / "katana_input.txt"
        hosts_file.write_text("\n".join(sorted(alive)) + "\n", encoding="utf-8")
        out_file = self.ctx.out.cat(self.category) / "katana_js_raw.txt"

        # Explicit crawl scope so katana never wanders onto third-party hosts
        # (older katana builds had no default scope and followed every
        # outlink — socials, CDNs, corporate sites — into the raw file).
        args: List[str] = [
            "katana",
            "-list", str(hosts_file),
            "-jc",                     # javascript crawling
            "-d", str(depth),
            "-silent",
            "-timeout", "10",
            "-retry", "1",
            "-rate-limit", "100",
            "-o", str(out_file),
        ]
        scope_re = self._scope_regex()
        if scope_re:
            args += ["-cs", scope_re]

        try:
            self.runner.run(
                args,
                name="katana_js",
                timeout=3600,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ katana: {e}[/yellow]")
            return []

        if not out_file.exists():
            return []
        urls = []
        for line in out_file.read_text(errors="replace").splitlines():
            line = line.strip()
            if urlparse(line).path.lower().endswith(".js"):
                urls.append(line)
        return urls

    # ------------------------------------------------------------------ #
    # scope helpers
    # ------------------------------------------------------------------ #
    def _scope_regex(self) -> str:
        """Regex for katana -cs: match URLs inside the engagement scope.

        Covers every scope flavour:
          * exact domains  (``example.com``) + subdomains
          * wildcards      (``*.example.com``) — one entry per base domain,
            the optional subdomain prefix handles both
          * IPs            (``1.2.3.4``)
          * CIDRs          (``10.0.0.0/16``) — exact per-prefix ranges

        Returns ``""`` when the scope has no host entries (katana then uses
        its own default scope instead of an allow-list that matches nothing).
        """
        scope = self.ctx.scope
        entries = [re.escape(b) for b in sorted(set(scope.domains) | set(scope.wildcards))]
        entries.extend(re.escape(ip) for ip in sorted(scope.ips))
        entries.extend(self._cidr_regex(c) for c in sorted(scope.cidrs))
        if not entries:
            return ""
        pattern = r"https?://(?:[a-z0-9.-]+\.)?(?:"
        pattern += "|".join(entries)
        pattern += r")(?::\d+)?(?:/|$)"
        return pattern

    @staticmethod
    def _cidr_regex(cidr: str) -> str:
        """Exact-ish regex for a CIDR block's host addresses.

        Full octets are fixed; the octet containing the prefix boundary is
        enumerated to the exact allowed byte values (mask math, stride for
        the bit remainder); trailing octets take any valid byte.
        """
        host, prefix_s = cidr.split("/")
        prefix = int(prefix_s)
        octets = [int(o) for o in host.split(".")]
        fixed = prefix // 8
        rem = prefix % 8
        byte = r"(?:0|[1-9][0-9]?|1[0-9]{2}|2[0-4][0-9]|25[0-5])"
        parts = [str(o) for o in octets[:fixed]]
        if rem:
            stride = 1 << (8 - rem)
            lo = octets[fixed] & (0xFF << (8 - rem))
            parts.append("(?:%s)" % "|".join(
                str(v) for v in range(lo, lo + stride)))
            fixed += 1
        parts.extend(byte for _ in range(fixed, 4))
        return "\\.".join(parts)

    # ------------------------------------------------------------------ #
    # 2. collect js urls
    # ------------------------------------------------------------------ #
    def _collect_js_urls(self) -> List[str]:
        js: Set[str] = set()
        for fname in ("all_urls.txt",):
            for u in self.ctx.out.read("urls", fname):
                if urlparse(u).path.lower().endswith(".js"):
                    js.add(u)
        js.update(self.ctx.out.read(self.category, "katana_js.txt"))
        return sorted(js)[:DEFAULT_JS_LIMIT]

    # ------------------------------------------------------------------ #
    # 3. download
    # ------------------------------------------------------------------ #
    def _download_js(self, urls: List[str], fetched_dir: Path) -> Dict[str, str]:
        """Download JS files with a bounded thread pool. Returns url->body."""
        bodies: Dict[str, str] = {}
        lock = threading.Lock()
        session = requests.Session()
        session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                "Accept": "*/*",
            }
        )

        def fetch(url: str) -> Optional[str]:
            try:
                r = session.get(url, timeout=15, verify=False, allow_redirects=True)
                if r.status_code == 200 and r.text:
                    return r.text[:4_000_000]
            except Exception:  # noqa: BLE001
                pass
            return None

        with ThreadPoolExecutor(max_workers=30) as pool:
            futs = {pool.submit(fetch, u): u for u in urls}
            for fut in as_completed(futs):
                url = futs[fut]
                body = fut.result()
                if body is None:
                    continue
                with lock:
                    bodies[url] = body
                    name = self._filename_for(url)
                    (fetched_dir / name).write_text(body, encoding="utf-8", errors="replace")

        try:
            session.close()
        except Exception:  # noqa: BLE001
            pass
        return bodies

    def _filename_for(self, url: str) -> str:
        parsed = urlparse(url)
        name = Path(parsed.path).name or "index"
        if not name.endswith(".js"):
            name += ".js"
        # include a short URL hash so variants (?v=1 vs ?v=2) and long
        # truncated paths never clobber each other's downloaded body
        return f"{parsed.hostname or 'host'}__{name}__{md5(url.encode()).hexdigest()[:8]}.js"

    # ------------------------------------------------------------------ #
    # 4. endpoints
    # ------------------------------------------------------------------ #
    def _extract_endpoints(self, body: str, base_url: str) -> Set[str]:
        found: Set[str] = set()
        for m in ENDPOINT_RE.finditer(body):
            url = m.group("url") or m.group("dom") or m.group("rel")
            if not url:
                continue
            url = url.strip(" \t\n\"'`")
            if url.startswith("//"):
                url = "https:" + url
            if url.startswith("/"):
                try:
                    url = urljoin(base_url, url)
                except Exception:  # noqa: BLE001
                    continue
            # bare-host match (dom group), e.g. `"api.example.com/v1/users"`
            if "://" not in url:
                url = "https://" + url
            if url.lower().startswith("http") and len(url) < 2000 and "{" not in url:
                found.add(url)
        return found

    # ------------------------------------------------------------------ #
    # 5. secrets
    # ------------------------------------------------------------------ #
    def _scan_secrets(self, body: str, url: str) -> List[str]:
        hits: List[str] = []
        for label, pattern in SECRET_PATTERNS:
            for m in re.finditer(pattern, body):
                start = max(0, m.start() - 40)
                snippet = body[start : m.end() + 40].replace("\n", " ")
                hits.append(f"[{label}] {url} :: ...{snippet}...")
        return hits
