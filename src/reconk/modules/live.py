"""Live host filtering with httpx.

A host is considered LIVE when it answers the connection and any HTTP
response comes back from it — NOT only status 200. 3xx/4xx/5xx hosts
are alive too and stay in the pipeline (the status is kept per URL for
triage).

Takes the merged subdomain list (or the single-domain scope hosts) and
probes them with httpx in plain text mode (no JSON):

  * 03-live/alive.txt         — alive URLs (every responding host, any status)
  * 03-live/alive_details.txt — full httpx line (status, title, tech...)
  * 03-live/status_codes.txt  — raw status-code list for quick triage
"""

from __future__ import annotations

from collections import Counter
from typing import List

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound


@register
class LiveModule(Module):
    name = "live"
    label = "Live Filtering"
    category = "live"

    def run(self) -> ModuleResult:
        hosts = self._hosts_to_probe()
        if not hosts:
            return ModuleResult(self.name, message="nothing to probe")

        self.start(f"Live filtering — {len(hosts)} host(s)")
        res = ModuleResult(self.name)

        try:
            self.runner.require("httpx")
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")
            res.ok = False
            res.message = str(e)
            return res

        hosts_file = self.ctx.out.root / "probe_hosts.txt"
        hosts_file.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")

        threads = self.ctx.cfg.get("scan.httpx_threads", "100")

        detail_path = self.ctx.out.cat(self.category) / "httpx_probe.txt"
        try:
            self.runner.run(
                [
                    "httpx",
                    "-l", str(hosts_file),
                    "-silent",
                    "-threads", str(threads),
                    "-timeout", "8",
                    "-retries", "2",
                    "-random-agent",
                    "-follow-redirects",
                    "-status-code",
                    "-title",
                    "-tech-detect",
                    "-content-length",
                    "-location",
                    "-web-server",
                    "-ip",
                    "-cname",
                    "-o", str(detail_path),
                ],
                name="httpx_probe",
                timeout=3600,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ httpx probe: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        # ---- parse text output ------------------------------------------
        # format: url [status] [title] [length] [location] [ip:cname] [tech]...
        # EVERY host that answered the connection is alive — no 200-only
        # filtering. 3xx/4xx/5xx are kept and tagged with their status.
        details = self.ctx.out.read(self.category, "httpx_probe.txt")
        urls: List[str] = []
        status_counts: List[str] = []
        status_dist: Counter = Counter()
        for line in details:
            parts = line.strip().split()
            if not parts:
                continue
            url = parts[0]
            if not url.startswith("http"):
                continue
            status = ""
            for p in parts[1:]:
                if p.startswith("[") and p.endswith("]"):
                    try:
                        int(p[1:-1])
                        status = p[1:-1]
                    except ValueError:
                        pass
                    break
            urls.append(url)
            status_counts.append(f"{status} {url}" if status else url)
            if status:
                status_dist[status] += 1

        # always write the canonical files (possibly empty) so parallel
        # siblings (tech fingerprinting) can wait for their existence
        p1 = self.ctx.out.write(self.category, "alive.txt", urls, dedupe=True)
        res.files.append(str(p1))
        p2 = self.ctx.out.write(self.category, "alive_details.txt", details, dedupe=True)
        res.files.append(str(p2))
        p3 = self.ctx.out.write(self.category, "status_codes.txt", status_counts, dedupe=True)
        res.files.append(str(p3))
        # history per round (live runs twice on wildcard scopes)
        r = self.ctx.round_no
        if urls and (r > 1 or self.ctx.scope.is_wildcard):
            r1 = self.ctx.out.write(self.category, f"alive_round{r}.txt", urls, dedupe=True)
            res.files.append(str(r1))
            r2 = self.ctx.out.write(self.category, f"alive_details_round{r}.txt", details, dedupe=True)
            res.files.append(str(r2))
        res.count = len(urls)

        dist = ", ".join(f"{code}x:{n}" for code, n in sorted(status_dist.items()))
        self.done(f"{res.count} alive endpoints (any status) — {dist}")
        return res

    # ------------------------------------------------------------------ #
    def _hosts_to_probe(self) -> List[str]:
        """Wildcard mode: the merged unique in-scope subdomains
        (02-subdomains/all_subdomains.txt from the merge phase).
        Single mode: the scope hosts themselves."""
        if self.ctx.scope.is_single or self.ctx.scope.is_network_only:
            return self.ctx.scope.hosts_to_probe()
        hosts: List[str] = self.ctx.out.read("subdomains", "all_subdomains.txt")
        if not hosts:
            # fallback: merge on the fly (e.g. --only live after a partial run)
            for fname in ("passive.txt", "active.txt", "vertical.txt", "horizontal.txt"):
                hosts += self.ctx.out.read("subdomains", fname)
        return sorted(set(hosts))
