"""Port scanning with naabu (fast).

Targets:
  * IPs resolved from the discovered subdomains (dnsx A/AAAA)
  * scope CIDRs / IPs (network-mode scopes)
  * asn_recon discovered hosts' IPs

Output: 04-ports/naabu_ports.txt (ip:port), plus a service mapping pass.
"""

from __future__ import annotations

import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Set

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound


@register
class PortScanModule(Module):
    name = "ports"
    label = "Port Scan"
    category = "ports"

    def run(self) -> ModuleResult:
        targets = self._collect_targets()
        if not targets:
            return ModuleResult(self.name, message="no IP targets")

        self.start(f"Port scan (naabu) — {len(targets)} IP(s)")
        res = ModuleResult(self.name)

        try:
            self.runner.require("naabu")
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")
            res.ok = False
            res.message = str(e)
            return res

        targets_file = self.ctx.out.cat(self.category) / "scan_targets.txt"
        targets_file.write_text("\n".join(sorted(targets)) + "\n", encoding="utf-8")

        top_ports = self.ctx.cfg.get("scan.naabu_top_ports", "1000")
        ports_flag = "-top-ports"
        ports_value = str(top_ports)

        out_path = self.ctx.out.cat(self.category) / "naabu_ports.txt"
        try:
            self.runner.run(
                [
                    "naabu",
                    "-list", str(targets_file),
                    ports_flag, ports_value,
                    "-silent",
                    "-rate", "1500",
                    "-o", str(out_path),
                ],
                name="naabu",
                timeout=7200,
                quiet=True,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ naabu: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        if out_path.exists():
            lines = [l.strip() for l in out_path.read_text(errors="replace").splitlines() if l.strip()]
            res.files.append(str(out_path))
            res.count = len(lines)
            # ip:port + optional service mapping
            self._service_map(lines)

        self.done(f"{res.count} open ports")
        return res

    # ------------------------------------------------------------------ #
    def _collect_targets(self) -> List[str]:
        """Gather IPs: subdomain A records + scope CIDRs/IPs."""
        targets: Set[str] = set()

        # network scopes: CIDRs / IPs come straight from the scope
        targets.update(self.ctx.scope.cidrs)
        targets.update(self.ctx.scope.ips)

        # scope_cidrs harvested by asn_recon (horizontal phase)
        targets.update(self.ctx.out.read(self.category, "scope_cidrs.txt"))

        # subdomain IPs: use the merge phase's canonical lists when present
        subdomain_hosts: Set[str] = set(self.ctx.out.read("subdomains", "resolved_subdomains.txt"))
        if not subdomain_hosts:
            for fname in ("passive.txt", "active.txt", "vertical.txt", "horizontal.txt"):
                subdomain_hosts.update(self.ctx.out.read("subdomains", fname))
        subdomain_hosts.update(self.ctx.scope.hosts_to_probe())

        if subdomain_hosts:
            ips = self._resolve_hosts(subdomain_hosts)
            targets.update(ips)
            if ips:
                ip_path = self.ctx.out.write(self.category, "resolved_ips.txt", sorted(ips), dedupe=True)

        return sorted(t for t in targets if t)

    # ------------------------------------------------------------------ #
    def _resolve_hosts(self, hosts: Set[str], limit: int = 5000) -> List[str]:
        """Resolve A records via a thread pool. Fallbacks to socket."""
        ips: Set[str] = set()
        try:
            self.runner.require("dnsx")
        except ToolNotFound:
            dnsx = None
        else:
            dnsx = True

        if dnsx:
            hosts_file = self.ctx.out.root / "resolve_hosts.txt"
            hosts_file.write_text("\n".join(sorted(hosts)) + "\n", encoding="utf-8")
            try:
                out = self.runner.run(
                    ["dnsx", "-l", str(hosts_file), "-a", "-resp-only", "-silent"],
                    name="dnsx_resolve",
                    timeout=900,
                    quiet=True,
                )
                for line in (out.stdout or "").splitlines():
                    ip = line.strip()
                    if self._valid_ip(ip):
                        ips.add(ip)
            except Exception:  # noqa: BLE001
                pass
        else:
            with ThreadPoolExecutor(max_workers=64) as pool:
                for host in list(hosts)[:limit]:
                    try:
                        for info in pool.submit(socket.getaddrinfo, host, None).result():
                            ip = str(info[4][0])
                            if self._valid_ip(ip):
                                ips.add(ip)
                    except Exception:  # noqa: BLE001
                        continue
        return sorted(ips)

    # ------------------------------------------------------------------ #
    def _service_map(self, lines: List[str]) -> None:
        """Build a host:ports summary from naabu output lines (ip:port)."""
        by_host: Dict[str, List[str]] = {}
        for line in lines:
            if ":" not in line:
                continue
            host, port = line.rsplit(":", 1)
            if not host or not port.isdigit():
                continue
            by_host.setdefault(host, []).append(port)
        summary = []
        for host in sorted(by_host):
            ports = sorted(set(by_host[host]), key=int)
            summary.append(f"{host}: {','.join(ports)}")
        if summary:
            self.ctx.out.write(self.category, "host_port_summary.txt", summary, dedupe=True)

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        try:
            import ipaddress

            return bool(ipaddress.ip_address(ip))
        except ValueError:
            return False
