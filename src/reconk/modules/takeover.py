"""Subdomain takeover detection via the bundled native ``scripts/takeover.py``.

For every host of the httpx live result (alive.txt) the script follows
the CNAME chain with dnspython and flags hosts whose CNAME target is a
known cloud provider AND does not resolve (classic dangling-DNS signal).

Output: 09-takeover/takeover.txt
"""

from __future__ import annotations

from typing import List, Set
from urllib.parse import urlparse

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class TakeoverModule(Module):
    name = "takeover"
    label = "Subdomain Takeover"
    category = "takeover"

    def run(self) -> ModuleResult:
        # takeover checks the live hosts only (merge #2 live result in
        # wildcard mode, the live result in single mode)
        hosts: Set[str] = set()
        for entry in self.ctx.out.read("live", "alive.txt"):
            e = entry.strip()
            if not e:
                continue
            if e.startswith("http"):
                host = urlparse(e).hostname
            else:
                host = e.split("/", 1)[0].split(":", 1)[0]
            if host:
                hosts.add(host.lower().rstrip("."))
        if not hosts:
            # fallback: the merged pool (e.g. --only takeover on a partial run)
            hosts.update(self.ctx.out.read("subdomains", "all_subdomains.txt"))
        subs = sorted(hosts)
        if not subs:
            return ModuleResult(self.name, message="no live hosts yet")

        self.start(f"Takeover check — {len(subs)} subdomains")
        res = ModuleResult(self.name)

        hosts_file = self.ctx.out.root / "takeover_hosts.txt"
        hosts_file.write_text("\n".join(subs) + "\n", encoding="utf-8")

        out_path = self.ctx.out.cat(self.category) / "takeover.txt"
        try:
            self.runner.run_python(
                self.script("takeover.py"),
                ["-l", str(hosts_file), "-o", str(out_path), "--threads", "50"],
                name="takeover_check",
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ takeover check: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        lines: List[str] = []
        tak_over: List[str] = []
        if res.ok:
            # only report data from a successful run — never stale leftovers
            lines = self.ctx.out.read(self.category, "takeover.txt")
            tak_over = [l for l in lines if "| takeover |" in l]
            path = self.ctx.out.write(self.category, "takeover.txt", lines, dedupe=True)
            res.files.append(str(path))
            res.count = len(tak_over)

        if tak_over:
            self.console.print(
                f"\n  [bold red]! {len(tak_over)} potential subdomain takeover(s) — "
                f"09-takeover/takeover.txt[/bold red]"
            )

        self.done(f"{res.count} potential takeover(s)")
        return res
