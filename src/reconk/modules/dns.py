"""DNS recon: full DNS record suite + zone transfer (AXFR) checks.

Runs the bundled native ``scripts/dnsrecon.py`` (one script, one text
output) against every domain in scope. Merges what used to be split
across dnsrecon_ultra (records suite) and zonesniper (AXFR).

Output: 01-dns/dns.txt
"""

from __future__ import annotations

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class DnsReconModule(Module):
    name = "dns"
    label = "DNS Recon"
    category = "dns"

    def run(self) -> ModuleResult:
        domains = self.ctx.scope.all_domains()
        if not domains:
            return ModuleResult(self.name, message="no domains in scope")

        self.start(f"DNS records + zone transfer — {len(domains)} domain(s)")
        res = ModuleResult(self.name)

        out_path = self.ctx.out.cat(self.category) / "dns.txt"
        try:
            self.runner.run_python(
                self.script("dnsrecon.py"),
                ["-l", str(self.scope_domains_file()), "-o", str(out_path)],
                name="dnsrecon",
                timeout=7200,
            )
            if out_path.exists():
                res.files.append(str(out_path))
                # count only actual record lines (TYPE|host|value), not the
                # "== domain ==" headers
                lines = self.ctx.out.read(self.category, "dns.txt")
                res.count = sum(1 for l in lines if "|" in l)
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ dnsrecon: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        self.done(f"{res.count} DNS records written")
        return res
