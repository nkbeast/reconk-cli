"""Pipeline orchestration.

Plans and executes the recon phases in dependency order, honouring the
scope mode:

  wildcard : dns -> passive -> active -> vertical -> horizontal
             -> merge -> live -> ports -> urls -> params -> js
             -> tech -> takeover
  single   : dns -> live (root+www) -> ports -> urls -> params -> js
             -> tech        (no subdomain enum, no takeover)
  network  : horizontal -> ports -> live(ips)     (no DNS/subdomains)
  mixed    : union of the applicable phases
"""

from __future__ import annotations

import time
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconk.config import Config
from reconk.modules import ModuleResult, build_modules
from reconk.output import OutputTree
from reconk.runner import CommandRunner
from reconk.scope import Scope

#: full pipeline in dependency order
WILDCARD_PLAN = [
    "dns",
    "passive",
    "active",
    "vertical",
    "horizontal",
    "merge",
    "live",
    "ports",
    "urls",
    "params",
    "js",
    "tech",
    "takeover",
]

SINGLE_PLAN = [
    "dns",
    "live",
    "ports",
    "urls",
    "params",
    "js",
    "tech",
]

NETWORK_PLAN = [
    "horizontal",
    "ports",
    "live",
]

MODULE_LABELS = {
    "dns": "DNS recon + zone transfer",
    "passive": "Passive subdomain enumeration (subfinder)",
    "active": "Active DNS brute-force (puredns)",
    "vertical": "Vertical enumeration (permutations + recursive)",
    "horizontal": "Horizontal enumeration (ASN / org / CIDR)",
    "merge": "Merge subdomains (unique, in-scope, resolved)",
    "live": "Live filtering (httpx)",
    "ports": "Port scanning (naabu)",
    "urls": "URL harvesting (native multi-source)",
    "params": "Parameter extraction",
    "js": "JavaScript analysis (katana + endpoints + secrets)",
    "tech": "Technology fingerprinting",
    "takeover": "Subdomain takeover check (CNAME dangling)",
}


class Pipeline:
    """Executes a module plan against a run context."""

    def __init__(
        self,
        cfg: Config,
        scope: Scope,
        out: OutputTree,
        runner: CommandRunner,
        console: Console,
        skip: Optional[List[str]] = None,
        only: Optional[List[str]] = None,
    ):
        self.cfg = cfg
        self.scope = scope
        self.out = out
        self.runner = runner
        self.console = console
        self.skip = set(skip or [])
        self.only = set(only or [])
        self.results: List[ModuleResult] = []

    # ------------------------------------------------------------------ #
    def plan(self) -> List[str]:
        mode = self.scope.mode
        if mode == "single":
            plan = list(SINGLE_PLAN)
        elif mode == "network":
            plan = list(NETWORK_PLAN)
        else:  # wildcard / mixed
            plan = list(WILDCARD_PLAN)
            if self.scope.is_single or not self.scope.has_web_targets:
                # mixed scope with no web targets: drop the domain-only phases
                if not self.scope.has_web_targets:
                    plan = NETWORK_PLAN
        if self.only:
            plan = [p for p in plan if p in self.only]
        if self.skip:
            plan = [p for p in plan if p not in self.skip]
        return plan

    # ------------------------------------------------------------------ #
    def run_all(self) -> List[ModuleResult]:
        plan = self.plan()
        if not plan:
            self.console.print("[yellow]! nothing to do — all phases skipped[/yellow]")
            return []

        self.console.print(
            Panel.fit(
                f"[bold]Phase plan[/bold] — mode [cyan]{self.scope.mode}[/cyan]\n"
                + "\n".join(
                    f"  [cyan]{i + 1:>2}.[/cyan] {MODULE_LABELS.get(p, p)}"
                    for i, p in enumerate(plan)
                ),
                border_style="cyan",
            )
        )

        start = time.monotonic()
        modules = {m.name: m for m in build_modules(self.ctx())}
        for name in plan:
            mod = modules.get(name)
            if mod is None:
                continue
            t0 = time.monotonic()
            try:
                result = mod.run()
            except Exception as e:  # noqa: BLE001
                self.console.print(f"  [red]✗ {name} crashed: {e}[/red]")
                result = ModuleResult(name, ok=False, message=str(e))
            result.message += f" ({time.monotonic() - t0:.0f}s)"
            self.results.append(result)
        elapsed = time.monotonic() - start

        self._summary(plan, elapsed)
        return self.results

    # ------------------------------------------------------------------ #
    def ctx(self):
        from reconk.modules.base import RunContext

        return RunContext(
            cfg=self.cfg,
            scope=self.scope,
            out=self.out,
            runner=self.runner,
            console=self.console,
            skip=self.skip,
        )

    # ------------------------------------------------------------------ #
    def _summary(self, plan: List[str], elapsed: float) -> None:
        table = Table(title=f"Recon summary — {self.scope.name}", border_style="green")
        table.add_column("Phase", style="cyan")
        table.add_column("Result", style="bold")
        for result in self.results:
            status = "✔" if result.ok else "✗"
            color = "green" if result.ok else "red"
            files = result.files[:3]
            extra = f"  [dim]{', '.join(str(f).split('/')[-1] for f in files)}[/dim]" if files else ""
            table.add_row(f"[{color}]{status}[/{color}] {MODULE_LABELS.get(result.name, result.name)}",
                          result.message + extra)
        self.console.print(table)
        for result in self.results:
            if result.files:
                for f in result.files[:3]:
                    self.console.print(f"  [dim]· saved: {f}[/dim]")
                if len(result.files) > 3:
                    self.console.print(f"  [dim]· … +{len(result.files) - 3} more files[/dim]")
        self.console.print(
            f"[bold green]✔ Pipeline finished in {elapsed:.0f}s — "
            f"output at {self.out.root}[/bold green]"
        )
