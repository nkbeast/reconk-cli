"""URL harvesting via the bundled SpiderCrawl v4 harvester.

``scripts/harvester.py`` is an exact port of the standalone SpiderCrawl
tool (async, speed-optimized URL harvester):

  * wayback machine CDX   (streamed, huge, rate-limit resilient)
  * common crawl          (2 most recent indexes, fast fail)

It runs against every unique in-scope host (roots + merged subdomains),
staging per-domain buckets, which this module assembles into the reconk
layout:

  * 05-urls/all_urls.txt            — every unique in-scope URL
  * 02-subdomains/urls_harvested.txt — hostnames observed in URLs
  * 02-subdomains/passive.txt       — in-scope URL hosts added to the pool
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

        # harvest from EVERY unique in-scope subdomain, not just the roots
        input_path = self.ctx.out.cat(self.category) / "harvest_input.txt"
        input_path.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")

        # SpiderCrawl stages per-domain buckets under its -o dir
        staging = self.ctx.out.cat(self.category) / "spidercrawl"
        args = [
            "-l", str(input_path),
            "-o", str(staging),
        ]

        try:
            self.runner.run_python(
                self.script("harvester.py"),
                args,
                name="spidercrawl",
                title="SpiderCrawl URL harvesting",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ harvester: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        # assemble the canonical outputs from the per-domain buckets
        merged = self._merge_bucket(staging / "urls")
        if merged:
            path = self.ctx.out.write(self.category, "all_urls.txt", merged, dedupe=True)
            res.files.append(str(path))
            res.count = len(merged)

        url_subs = self._merge_bucket(staging / "subdomains")
        # only hosts that are actually in scope (suffix match — the
        # harvester's own check is a substring match that admits
        # lookalikes like `notexample.com`)
        roots = self.ctx.scope.all_domains()
        url_subs = [h for h in url_subs if any(h == d or h.endswith("." + d) for d in roots)]
        if url_subs:
            subs_path = self.ctx.out.write("subdomains", "urls_harvested.txt", url_subs, dedupe=True)
            res.files.append(str(subs_path))

        # merge subdomains harvested from URLs into the canonical pool so
        # the later phases (js, tech, takeover) also see them. Single mode:
        # skip it — urls runs in the same parallel stage as ports (which
        # reads these files) and nothing downstream consumes them anyway.
        if url_subs and not self.ctx.scope.is_single:
            self.ctx.out.append("subdomains", "passive.txt", url_subs)
            current = set(self.ctx.out.read("subdomains", "all_subdomains.txt"))
            current.update(url_subs)
            self.ctx.out.write("subdomains", "all_subdomains.txt", sorted(current), dedupe=True)

        self.done(f"{res.count} unique URLs — {len(url_subs)} hosts from URLs")
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

    # ------------------------------------------------------------------ #
    def _merge_bucket(self, bucket_dir) -> List[str]:
        """Concatenate every per-domain file in a SpiderCrawl bucket dir."""
        from pathlib import Path

        bucket = Path(bucket_dir)
        if not bucket.is_dir():
            return []
        merged: List[str] = []
        for f in sorted(bucket.iterdir()):
            if f.is_file() and f.suffix == ".txt":
                merged += [
                    l.strip() for l in f.read_text(errors="replace").splitlines() if l.strip()
                ]
        return sorted(set(merged))
