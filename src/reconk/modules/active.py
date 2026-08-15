"""Active subdomain brute-force (puredns).

Bruteforces each root domain against a wordlist using the configured
resolver list. Wordlist size is configurable (small/medium/large).
"""

from __future__ import annotations

from pathlib import Path

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound


@register
class ActiveEnumModule(Module):
    name = "active"
    label = "Active Subdomains"
    category = "subdomains"

    # wordlist sizes: name -> seclists file
    WORDLISTS = {
        "small": "subdomains-top1million-5000.txt",
        "medium": "subdomains-top1million-20000.txt",
        "large": "subdomains-top1million.txt",
    }

    def run(self) -> ModuleResult:
        domains = self.ctx.scope.all_domains()
        if not domains:
            return ModuleResult(self.name, message="no domains in scope")

        self.start(f"DNS brute-force — {len(domains)} domain(s)")
        res = ModuleResult(self.name)

        try:
            self.runner.require("puredns")
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")
            res.ok = False
            res.message = str(e)
            return res

        scope_file = self.ctx.out.root / "scope.txt"
        subdir = self.ctx.out.cat(self.category) / "active"
        subdir.mkdir(parents=True, exist_ok=True)

        wordlist = self._wordlist()
        resolvers = self.ensure_resolvers()

        out_path = subdir / "bruteforce.txt"
        try:
            self.runner.run(
                [
                    "puredns", "bruteforce",
                    str(wordlist),
                    "-d", str(scope_file),
                    "-r", str(resolvers),
                    "-w", str(out_path),
                    "-q",
                ],
                name="puredns_bruteforce",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ puredns bruteforce: {e}[/yellow]")

        found = []
        if out_path.exists():
            found = [l.strip() for l in out_path.read_text(errors="replace").splitlines() if l.strip()]
            res.files.append(str(out_path))

        if found:
            self.ctx.out.append(self.category, "active.txt", found)
            merged_path = self.ctx.out.write(self.category, "active.txt", found, dedupe=True)
            res.files.append(str(merged_path))
            res.count = len(found)

        self.done(f"{res.count} resolved subdomains")
        return res

    # ------------------------------------------------------------------ #
    def _wordlist(self) -> Path:
        """Pick a brute-force wordlist: configured -> seclists -> bundled.

        The bundled package wordlist always exists, so this phase can never
        fail with a missing-file error.
        """
        size = self.ctx.cfg.get("scan.brute_size", "small")
        wl_name = self.WORDLISTS.get(size, self.WORDLISTS["small"])

        configured = self.ctx.cfg.tool_path("subdomain_wordlist")
        if configured.exists():
            self.console.print(f"  [dim]· wordlist: {configured}[/dim]")
            return configured

        seclists = Path("/usr/share/seclists/Discovery/DNS") / wl_name
        if seclists.exists():
            self.console.print(f"  [dim]· wordlist: {seclists}[/dim]")
            return seclists

        bundled = self.data_file("subdomains-small.txt")
        self.console.print(
            f"  [yellow]⚠ wordlist not found (configured/seclists) — using bundled {bundled.name}[/yellow]"
        )
        return bundled
