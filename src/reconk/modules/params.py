"""Parameter extraction.

From every harvested URL we extract:
  * URLs that carry query parameters          -> 06-parameters/param_urls.txt
  * the unique parameter names across the scope -> 06-parameters/param_keys.txt
  * per-keyendpoint counts for triage           -> 06-parameters/param_analysis.txt
  * gf pattern hits (xss, sqli, ssrf, ...)     -> 06-parameters/gf_<pattern>.txt
"""

from __future__ import annotations

import os
import re
import tempfile
from collections import Counter
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module

# gf patterns worth running, in preference order. Only patterns the
# installed gf actually has are used (stock gf ships a different set:
# aws-keys, debug-pages, s3-buckets, ...; the classic xss/sqli set comes
# from extra gf-templates). `gf <pattern>` errors with "no such pattern"
# (exit 0) when a pattern is missing — so never invoke one we didn't
# confirm via `gf -list`.
GF_PATTERNS = [
    "xss", "sqli", "ssrf", "idor", "rce", "lfi", "redirect",
    "debug-pages", "s3-buckets", "aws-keys", "firebase", "sec",
    "http-auth", "takeovers", "servers", "ip", "cors",
    "upload-fields", "php-errors", "php-sinks", "php-sources",
    "php-serialized", "json-sec",
]

# endpoints that are interesting but rarely carry params directly
STATIC_EXTS = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|pdf|zip|gz|tar|mp4|mp3|avi|mov|woff)(?:$|\?)",
    re.IGNORECASE,
)


@register
class ParamsModule(Module):
    name = "params"
    label = "Parameter Extraction"
    category = "params"

    def run(self) -> ModuleResult:
        urls = self.ctx.out.read("urls", "all_urls.txt")
        if not urls:
            return ModuleResult(self.name, message="no URLs harvested yet")

        self.start(f"Parameter extraction — {len(urls):,} URLs")
        res = ModuleResult(self.name)

        # ---- urls with params -------------------------------------------
        param_urls: List[str] = []
        key_counter: Counter = Counter()
        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            if STATIC_EXTS.search(url):
                continue
            param_urls.append(url)
            # keep_blank_values: valueless params (`?debug`) are real keys
            key_counter.update(parse_qs(parsed.query, keep_blank_values=True).keys())

        if param_urls:
            p1 = self.ctx.out.write(self.category, "param_urls.txt", param_urls, dedupe=True)
            res.files.append(str(p1))

        # ---- unique keys --------------------------------------------------
        if key_counter:
            keys = sorted(key_counter.keys())
            p2 = self.ctx.out.write(self.category, "param_keys.txt", keys, dedupe=True)
            res.files.append(str(p2))
            res.count = len(keys)

            # top parameters by occurrence
            top = [f"{k}\t{n}" for k, n in key_counter.most_common(200)]
            p3 = self.ctx.out.write(self.category, "top_parameters.txt", top, dedupe=False)
            res.files.append(str(p3))

        # ---- gf quick win -------------------------------------------------
        if param_urls and self.runner.which("gf"):
            self._run_gf(param_urls, res)

        self.done(f"{res.count} unique parameter names")
        return res

    # ------------------------------------------------------------------ #
    def _gf_patterns_available(self) -> List[str]:
        """Installed gf patterns (from `gf -list`), cached per run."""
        cached = getattr(self, "_gf_avail", None)
        if cached is not None:
            return cached
        try:
            proc = self.runner.run(
                ["gf", "-list"],
                name="gf_list", check=False, quiet=True,
            )
            avail = {ln.strip() for ln in (proc.stdout or "").splitlines() if ln.strip()}
        except Exception:  # noqa: BLE001
            avail = set()
        self._gf_avail = sorted(p for p in GF_PATTERNS if p in avail)
        return self._gf_avail

    # ------------------------------------------------------------------ #
    def _run_gf(self, param_urls: List[str], res: ModuleResult) -> None:
        patterns = self._gf_patterns_available()
        if not patterns:
            self.console.print(
                "  [dim]gf installed but none of the preferred patterns are "
                "present — skipping gf pass[/dim]"
            )
            return

        # gf does not read URLs from stdin — it greps the given FILE with
        # the pattern and prints `path:line:url` matches
        fd, tmp = tempfile.mkstemp(prefix="reconk_gf_", suffix=".txt")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write("\n".join(param_urls) + "\n")
            for pattern in patterns:
                try:
                    proc = self.runner.run(
                        ["gf", pattern, tmp],
                        name=f"gf_{pattern}",
                        check=False, quiet=True,
                    )
                    hits = []
                    for line in (proc.stdout or "").splitlines():
                        line = line.strip()
                        # drop gf diagnostics/errors, keep only match lines
                        if not line or line.startswith("no such pattern"):
                            continue
                        if ":" in line.split("\t", 1)[0]:
                            line = line.split(":", 2)[-1]
                        hits.append(line)
                    hits = list(dict.fromkeys(hits))
                    if hits:
                        path = self.ctx.out.write(
                            self.category, f"gf_{pattern}.txt", hits, dedupe=True)
                        res.files.append(str(path))
                        self.console.print(
                            f"  [green]✔ gf {pattern}: {len(hits)} hits[/green]")
                except Exception as e:  # noqa: BLE001
                    self.console.print(f"  [yellow]⚠ gf {pattern}: {e}[/yellow]")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
