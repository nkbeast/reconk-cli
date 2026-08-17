"""Subdomain merge — the single canonical unique subdomain list.

Consumes the subdomain sources produced so far:

  * passive.txt       (subfinder)
  * active.txt        (puredns bruteforce)
  * vertical.txt      (permutations + recursive)
  * urls_harvested.txt (hostnames observed in harvested URLs — merge #2
    only; merge #1 must never see them, and the URL harvest itself only
    runs on the merge #1 live result)

and writes:

  * 02-subdomains/all_subdomains.txt      — unique, in-scope, sorted
  * 02-subdomains/resolved_merge1.txt     — merge #1's resolved subset
  * 02-subdomains/resolved_subdomains.txt — merge #2's resolved subset

Everything downstream consumes these files (ports takes the merge #1
resolved list, takeover/live take all_subdomains + alive.txt).

In-scope filtering: only entries that belong to a scope root domain
(entry == root or entry.endswith("." + root)) survive. Wildcard patterns,
duplicates and out-of-scope third-party hosts are dropped.
"""

from __future__ import annotations

from typing import List, Set

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound

SOURCES = ("passive.txt", "active.txt", "vertical.txt")


@register
class MergeSubdomainsModule(Module):
    name = "merge"
    label = "Merge Subdomains"
    category = "subdomains"

    def run(self) -> ModuleResult:
        raw: Set[str] = set()
        for fname in SOURCES:
            raw.update(self.ctx.out.read(self.category, fname))
        if self.ctx.round_no > 1:
            # merge #2 folds the SpiderCrawl hostnames back into the pool
            raw.update(self.ctx.out.read(self.category, "urls_harvested.txt"))

        all_subs = self._filter_in_scope(raw)
        if not all_subs:
            return ModuleResult(self.name, message="no subdomains to merge")

        self.start(f"Merge — {len(raw):,} raw entries -> {len(all_subs):,} unique in-scope")
        res = ModuleResult(self.name)

        path = self.ctx.out.write(self.category, "all_subdomains.txt", all_subs, dedupe=True)
        res.files.append(str(path))
        res.count = len(all_subs)

        resolved = self._resolve(all_subs)
        # drop stale resolution files when nothing resolves now — the
        # ports phase would otherwise consume the previous run's hosts
        if resolved:
            rname = "resolved_merge1.txt" if self.ctx.round_no == 1 else "resolved_subdomains.txt"
            rpath = self.ctx.out.write(self.category, rname, resolved, dedupe=True)
            res.files.append(str(rpath))
        else:
            for stale in ("resolved_merge1.txt", "resolved_subdomains.txt"):
                p = self.ctx.out.cat(self.category) / stale
                if p.exists():
                    p.unlink()

        self.done(f"{res.count} unique subdomains (in scope) — {len(resolved)} resolve")
        return res

    # ------------------------------------------------------------------ #
    def _filter_in_scope(self, entries: Set[str]) -> List[str]:
        """Keep only hosts that belong to a scope root domain."""
        roots = self.ctx.scope.all_domains()
        kept: Set[str] = set()
        for entry in entries:
            e = entry.strip().lower().rstrip(".")
            if not e or "*" in e:
                continue
            if any(e == d or e.endswith("." + d) for d in roots):
                kept.add(e)
        return sorted(kept)

    # ------------------------------------------------------------------ #
    def _resolve(self, hosts: List[str]) -> List[str]:
        """Keep the HOSTNAMES that resolve (A/AAAA present) using dnsx.

        resolved_subdomains.txt carries hostnames (not IPs) so the ports
        phase can re-resolve them to IPs for scanning.
        """
        try:
            self.runner.require("dnsx")
        except ToolNotFound:
            return []
        hosts_file = self.ctx.out.root / "logs" / "merge_resolve_hosts.txt"
        hosts_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")
        try:
            out = self.runner.run(
                ["dnsx", "-l", str(hosts_file), "-silent"],
                name="dnsx_merge_resolve",
                quiet=True,
            )
            return sorted(l.strip() for l in out.stdout.splitlines() if l.strip())
        except Exception:  # noqa: BLE001
            return []
        finally:
            try:
                hosts_file.unlink(missing_ok=True)
            except OSError:
                pass
