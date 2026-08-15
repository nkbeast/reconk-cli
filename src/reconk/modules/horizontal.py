"""Horizontal subdomain enumeration — ASN / org / CIDR expansion.

Runs the bundled native ``scripts/asn.py`` against the full scope
(domains, ASNs, CIDRs, IPs). The script:

  * resolves root domains -> ASNs via RDAP
  * expands ASNs into CIDR prefixes (whois.radb.net, bgpview fallback)
  * discovers alive hosts (fping / TCP-connect)
  * harvests hostnames from PTR + CT logs (crt.sh) + TLS cert SANs
  * writes the hosts back so the rest of the pipeline can use them

Output: 02-subdomains/horizontal.txt (hosts), 04-ports/prefixes.txt (CIDRs)
"""

from __future__ import annotations

from typing import List

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class HorizontalEnumModule(Module):
    name = "horizontal"
    label = "Horizontal Subdomains"
    category = "subdomains"

    def run(self) -> ModuleResult:
        res = ModuleResult(self.name)

        if not (self.ctx.scope.has_network_targets or self.ctx.scope.all_domains()):
            return ModuleResult(self.name, message="no network/domain targets")

        self.start("Horizontal (ASN / CIDR) enumeration")
        out_path = self.ctx.out.cat(self.category) / "asn.txt"
        hosts_path = self.ctx.out.cat(self.category) / "horizontal.txt"
        prefixes_path = self.ctx.out.cat("ports") / "prefixes.txt"

        try:
            self.runner.run_python(
                self.script("asn.py"),
                [
                    "--scope", str(self.ctx.out.root / "scope.txt"),
                    "-o", str(out_path),
                    "--hosts", str(hosts_path),
                    "--prefixes", str(prefixes_path),
                ],
                name="asn_recon",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ asn_recon: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        hosts: List[str] = self.ctx.out.read(self.category, "horizontal.txt")
        if hosts:
            path = self.ctx.out.write(self.category, "horizontal.txt", hosts, dedupe=True)
            res.files.append(str(path))
            res.count = len(hosts)

        prefixes = self.ctx.out.read("ports", "prefixes.txt")
        if prefixes:
            res.files.append(str(self.ctx.out.write("ports", "prefixes.txt", prefixes, dedupe=True)))

        self.done(f"{res.count} hosts from ASN/org expansion")
        return res
