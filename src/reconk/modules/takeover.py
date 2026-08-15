"""Subdomain takeover detection via the bundled native ``scripts/takeover.py``.

For every discovered subdomain the script follows the CNAME chain with
dnspython and flags hosts whose CNAME target is a known cloud provider
AND does not resolve (classic dangling-DNS signal).

Output: 09-takeover/takeover.txt
"""

from __future__ import annotations

from typing import List

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class TakeoverModule(Module):
    name = "takeover"
    label = "Subdomain Takeover"
    category = "takeover"

    def run(self) -> ModuleResult:
        subs: List[str] = []
        for fname in ("passive.txt", "active.txt", "vertical.txt", "horizontal.txt"):
            subs += self.ctx.out.read("subdomains", fname)
        subs = sorted(set(subs))
        if not subs:
            return ModuleResult(self.name, message="no subdomains yet")

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
                timeout=3600,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ takeover check: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        lines = self.ctx.out.read(self.category, "takeover.txt")
        tak_over = [l for l in lines if "| takeover |" in l]
        if lines:
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
