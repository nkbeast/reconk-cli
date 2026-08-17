"""Passive subdomain enumeration — subfinder only.

Sources:
  * subfinder (all enabled sources via provider config)

Output: 02-subdomains/passive.txt
"""

from __future__ import annotations

from pathlib import Path

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound


@register
class PassiveEnumModule(Module):
    name = "passive"
    label = "Passive Subdomains"
    category = "subdomains"

    def run(self) -> ModuleResult:
        domains = self.ctx.scope.all_domains()
        if not domains:
            return ModuleResult(self.name, message="no domains in scope")

        self.start(f"Passive enumeration (subfinder) — {len(domains)} domain(s)")
        res = ModuleResult(self.name)
        scope_file = self.ctx.out.root / "scope.txt"
        subdir = self.ctx.out.cat(self.category) / "passive"
        subdir.mkdir(parents=True, exist_ok=True)

        try:
            self.runner.require("subfinder")
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")
            res.ok = False
            res.message = str(e)
            return res

        out_path = subdir / "subfinder.txt"
        cmd = [
            "subfinder",
            "-dL", str(self.scope_domains_file()),
            "-silent",
            "-o", str(out_path),
        ]
        # -all enables every source but is slow (rate-limited APIs).
        # Off by default for speed; enable via config/scan.subfinder_all.
        if self.ctx.cfg.get("scan.subfinder_all", "false") in ("true", "1", "yes"):
            cmd += ["-all"]
        sf_cfg = self.ctx.cfg.get("tools.subfinder_config")
        if sf_cfg:
            cfg_path = Path(sf_cfg).expanduser()
            if cfg_path.exists():
                cmd += ["-config", str(cfg_path)]

        try:
            self.runner.run(cmd, name="subfinder")
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ subfinder: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        found = []
        if out_path.exists():
            found = [l.strip() for l in out_path.read_text(errors="replace").splitlines() if l.strip()]
            res.files.append(str(out_path))

        # carry over what previous runs / the urls phase appended
        # (resume --only passive must not lose earlier results)
        dns_hosts = self.ctx.out.read(self.category, "passive.txt")
        found = list(dict.fromkeys(dns_hosts + found))

        path = self.ctx.out.write(self.category, "passive.txt", found, dedupe=True)
        res.files.append(str(path))
        res.count = len(found)

        self.done(f"{res.count} unique subdomains")
        return res
