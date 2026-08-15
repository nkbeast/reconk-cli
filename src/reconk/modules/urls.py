"""URL harvesting via the bundled native async harvester.

``scripts/harvester.py`` replaces spidercrawl + waybackurls + gau with one
async multi-source harvester:

  * wayback CDX, commoncrawl, alienvault OTX, crtsh, rapiddns, hackertarget
  * optional: urlscan.io / virustotal (API keys from config)
  * GitHub code dorking (optional token)

Output: 05-urls/all_urls.txt (+ per-source files under 05-urls/sources/)
"""

from __future__ import annotations

from typing import List

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class UrlHarvestModule(Module):
    name = "urls"
    label = "URL Harvesting"
    category = "urls"

    def run(self) -> ModuleResult:
        domains = self._domains_to_harvest()
        if not domains:
            return ModuleResult(self.name, message="no domains in scope")

        self.start(f"URL harvesting — {len(domains)} domain(s)")
        res = ModuleResult(self.name)

        out_path = self.ctx.out.cat(self.category) / "all_urls.txt"
        sources_dir = self.ctx.out.cat(self.category) / "sources"
        subs_out = self.ctx.out.cat("subdomains") / "urls_harvested.txt"

        # harvest from EVERY unique in-scope subdomain, not just the roots
        input_path = self.ctx.out.cat(self.category) / "harvest_input.txt"
        input_path.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")

        args = [
            "-dL", str(input_path),
            "-o", str(out_path),
            "--per-source", str(sources_dir),
            "--subs", str(subs_out),
        ]
        keys = {
            "urlscan": self.ctx.cfg.get("api_keys.urlscan", ""),
            "virustotal": self.ctx.cfg.get("api_keys.virustotal", ""),
            "github": self.ctx.cfg.get("api_keys.github_token", ""),
        }
        if keys["urlscan"]:
            args += ["--urlscan-key", str(keys["urlscan"])]
        if keys["virustotal"]:
            args += ["--virustotal-key", str(keys["virustotal"])]
        if keys["github"]:
            args += ["--github-token", str(keys["github"])]

        try:
            self.runner.run_python(
                self.script("harvester.py"),
                args,
                name="harvester",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ harvester: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        merged = self.ctx.out.read(self.category, "all_urls.txt")
        path = self.ctx.out.write(self.category, "all_urls.txt", merged, dedupe=True)
        res.files.append(str(path))
        res.count = len(merged)

        # merge subdomains harvested from URLs into the canonical pool so
        # the later phases (js, tech, takeover) also see them
        url_subs = self.ctx.out.read("subdomains", "urls_harvested.txt")
        if url_subs:
            self.ctx.out.append("subdomains", "passive.txt", url_subs)
            current = set(self.ctx.out.read("subdomains", "all_subdomains.txt"))
            current.update(url_subs)
            self.ctx.out.write("subdomains", "all_subdomains.txt", sorted(current), dedupe=True)

        self.done(f"{res.count} unique URLs")
        return res

    # ------------------------------------------------------------------ #
    def _domains_to_harvest(self) -> List[str]:
        """Wildcard/mixed: root domains + every merged unique subdomain.
        Single: the exact scope hosts."""
        if self.ctx.scope.is_single:
            return self.ctx.scope.hosts_to_probe()
        domains = set(self.ctx.scope.all_domains())
        domains.update(self.ctx.out.read("subdomains", "all_subdomains.txt"))
        return sorted(domains)
