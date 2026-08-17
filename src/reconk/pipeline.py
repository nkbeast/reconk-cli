"""Pipeline orchestration.

Executes the recon phases in dependency order as *stages*. A stage is a
group of phases: a single-phase stage runs alone, a multi-phase stage
runs all its phases in parallel threads.

  single   : [dns + live + ports + tech + urls] -> [params + js]
             (no subdomain enum, no takeover)
  wildcard : [dns + passive + horizontal] -> [active]
             -> [vertical] -> [merge #1] -> [live #1]
             -> [urls] -> [merge #2] -> [live #2]
             -> [js + tech + params] -> [ports + takeover]
             (merge #2 folds the URL-harvested subdomains back into the
             pool so the second live pass + all scans see the new hosts)
  network  : horizontal -> ports -> live
  mixed    : the single workflow runs first, then the wildcard workflow,
             into <target>/single and <target>/wildcard (collapsed tree)
"""

from __future__ import annotations

import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconk.config import Config
from reconk.modules import ModuleResult, REGISTRY
from reconk.output import OutputTree
from reconk.runner import CommandRunner
from reconk.scope import Scope

#: full pipeline as ordered stages (parallel groups)
SINGLE_STAGES = [
    ["dns", "live", "ports", "tech", "urls"],
    ["params", "js"],
]

WILDCARD_STAGES = [
    ["dns", "passive", "horizontal"],
    ["active"],
    ["vertical"],
    ["merge"],
    ["live"],
    ["urls"],
    ["merge"],
    ["live"],
    ["js", "tech", "params"],
    ["ports", "takeover"],
]

NETWORK_STAGES = [
    ["horizontal"],
    ["ports"],
    ["live"],
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
    "urls": "URL harvesting (SpiderCrawl)",
    "params": "Parameter extraction",
    "js": "JavaScript analysis (katana + endpoints + secrets)",
    "tech": "Technology fingerprinting",
    "takeover": "Subdomain takeover check (CNAME dangling)",
}


class Pipeline:
    """Executes a module plan against a run context, stage by stage."""

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
    def _raw_stages(self) -> List[List[str]]:
        """Stages for this scope mode, before skip/only filtering."""
        mode = self.scope.mode
        if mode == "single":
            return SINGLE_STAGES
        if mode == "network":
            return NETWORK_STAGES
        raw = WILDCARD_STAGES
        if not self.scope.has_web_targets:
            raw = NETWORK_STAGES
        return raw

    def stages(self) -> List[List[str]]:
        """Ordered stages after skip/only filtering (empty stages dropped)."""
        raw = self._raw_stages()
        applicable = {p for group in raw for p in group}
        known = {cls.name for cls in REGISTRY}
        for flag, phases in (("skip", self.skip), ("only", self.only)):
            if not phases:
                continue
            unknown = sorted(phases - known)
            if unknown:
                self.console.print(
                    f"  [yellow]⚠ {flag}: unknown phase(s) {', '.join(unknown)} — ignored[/yellow]"
                )
            irrelevant = sorted((phases & known) - applicable)
            if irrelevant:
                verb = "does not run" if len(irrelevant) == 1 else "do not run"
                self.console.print(
                    f"  [yellow]⚠ {flag}: {', '.join(irrelevant)} {verb} in the "
                    f"{self.scope.mode} workflow — ignored[/yellow]"
                )
        stages: List[List[str]] = []
        for group in raw:
            kept = [p for p in group if p not in self.skip]
            if self.only:
                kept = [p for p in kept if p in self.only]
            if kept:
                stages.append(kept)
        return stages

    def plan(self) -> List[str]:
        """Flat phase list (order of first appearance per stage)."""
        flat: List[str] = []
        for group in self.stages():
            for p in group:
                if p not in flat:
                    flat.append(p)
        return flat

    # ------------------------------------------------------------------ #
    def run_all(self) -> List[ModuleResult]:
        stages = self.stages()
        if not stages:
            self.console.print("[yellow]! nothing to do — all phases skipped[/yellow]")
            return []

        self._show_plan(stages)

        start = time.monotonic()
        counts = Counter()  # phase name -> times run (for round labels)
        try:
            for group in stages:
                parallel = len(group) > 1
                self.runner.parallel_mode = parallel
                if parallel:
                    with ThreadPoolExecutor(max_workers=len(group), thread_name_prefix="reconk") as pool:
                        futs = {pool.submit(self._run_phase, name, counts[name] + 1, group): name for name in group}
                        for fut in futs:
                            result = fut.result()
                            counts[result.name] += 1
                            self.results.append(result)
                else:
                    name = group[0]
                    result = self._run_phase(name, counts[name] + 1, group)
                    counts[result.name] += 1
                    self.results.append(result)
        finally:
            # always tear the parallel view down — a quit/interrupt must not
            # leave the terminal in raw mode or an orphaned Live
            self.runner.parallel_mode = False
        elapsed = time.monotonic() - start

        self._summary(elapsed)
        return self.results

    # ------------------------------------------------------------------ #
    def _run_phase(self, name: str, round_no: int, stage_group: List[str]) -> ModuleResult:
        ctx = self.ctx()
        ctx.round_no = round_no
        ctx.stage_modules = set(stage_group)
        mod = None
        for cls in REGISTRY:
            if cls.name == name:
                mod = cls(ctx)
                break
        if mod is None:
            return ModuleResult(name, ok=False, message="unknown phase")
        t0 = time.monotonic()
        try:
            result = mod.run()
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [red]✗ {name} crashed: {e}[/red]")
            result = ModuleResult(name, ok=False, message=str(e))
        result.message += f" ({time.monotonic() - t0:.0f}s)"
        return result

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
    def _show_plan(self, stages: List[List[str]]) -> None:
        lines = [f"[bold]Phase plan[/bold] — mode [cyan]{self.scope.mode}[/cyan]"]
        n = 0
        for group in stages:
            if len(group) > 1:
                names = ", ".join(f"[cyan]{MODULE_LABELS.get(p, p)}[/cyan]" for p in group)
                n += 1
                lines.append(f"  [magenta]▶ {n}.[/magenta] [parallel] {names}")
            else:
                n += 1
                lines.append(f"  [cyan]▶ {n}.[/cyan] {MODULE_LABELS.get(group[0], group[0])}")
        self.console.print(Panel.fit("\n".join(lines), border_style="cyan"))

    # ------------------------------------------------------------------ #
    def _summary(self, elapsed: float) -> None:
        table = Table(title=f"Recon summary — {self.scope.name}", border_style="green")
        table.add_column("Phase", style="cyan")
        table.add_column("Result", style="bold")
        counts: Counter = Counter()
        for result in self.results:
            counts[result.name] += 1
            round_no = counts[result.name]
            label = MODULE_LABELS.get(result.name, result.name)
            if round_no > 1:
                label += f" (round {round_no})"
            status = "✔" if result.ok else "✗"
            color = "green" if result.ok else "red"
            files = result.files[:3]
            extra = f"  [dim]{', '.join(str(f).split('/')[-1] for f in files)}[/dim]" if files else ""
            table.add_row(f"[{color}]{status}[/{color}] {label}", result.message + extra)
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