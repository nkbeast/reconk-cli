"""Parameter extraction.

From every harvested URL we extract:
  * URLs that carry query parameters          -> 06-parameters/param_urls.txt
  * the unique parameter names across the scope -> 06-parameters/param_keys.txt
  * per-keyendpoint counts for triage           -> 06-parameters/param_analysis.txt
  * gf pattern hits (xss, sqli, ssrf, ...)     -> 06-parameters/gf_<pattern>.txt
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound

# gf patterns worth running when gf is installed
GF_PATTERNS = ["xss", "sqli", "ssrf", "idor", "rce", "lfi", "redirect", "debug_logic"]

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
    def _run_gf(self, param_urls: List[str], res: ModuleResult) -> None:
        try:
            for pattern in GF_PATTERNS:
                out = self.runner.run_pipe(
                    param_urls,
                    ["gf", pattern],
                    name=f"gf_{pattern}",
                    check=False,
                    timeout=600,
                    quiet=True,
                )
                hits = [h for h in out.splitlines() if h.strip()]
                if hits:
                    path = self.ctx.out.write(self.category, f"gf_{pattern}.txt", hits, dedupe=True)
                    res.files.append(str(path))
                    self.console.print(f"  [green]✔ gf {pattern}: {len(hits)} hits[/green]")
        except ToolNotFound:
            pass
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ gf: {e}[/yellow]")
