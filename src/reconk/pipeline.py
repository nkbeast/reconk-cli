"""Pipeline orchestration.

Executes the recon phases in dependency order as *stages*. A stage is a
group of phases: a single-phase stage runs alone, a multi-phase stage
runs all its phases in parallel threads.

  single   : [dns + live + ports] -> [tech + urls] -> [params + js]
             (no subdomain enum, no takeover; tech and SpiderCrawl both
             take the httpx live result, params takes the harvested URLs)
  wildcard : [dns + passive] -> [active] -> [vertical]
             -> [merge #1] -> [live #1] -> [urls] (SpiderCrawl on the
             live #1 result) -> [merge #2] (merge #1 + URL-harvested
             hosts) -> [live #2] -> [js + tech + params]
             -> [ports + takeover] (ports on the merge #1 pool, takeover
             on the live #2 result)
  network  : ports -> live
  mixed    : the single workflow runs first, then the wildcard workflow,
             into <target>/single and <target>/wildcard (collapsed tree)

Interactive behaviour:
  * before every stage the user can run it, skip it, or quit the scan
    ([Enter] run / [s] skip / [q] quit)
  * progress is tracked in <target>/reconk.progress.json; starting a run
    on a target that already has one offers to resume: completed and
    user-skipped phases are skipped, failed/cancelled ones re-run
"""

from __future__ import annotations

import json
import os
import select
import sys
import termios
import time
import tty
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconk.config import Config
from reconk.modules import ModuleResult, REGISTRY
from reconk.output import OutputTree
from reconk.runner import CommandError, CommandRunner
from reconk.scope import Scope

#: full pipeline as ordered stages (parallel groups)
SINGLE_STAGES = [
    ["dns", "live", "ports"],
    ["tech", "urls"],
    ["params", "js"],
]

WILDCARD_STAGES = [
    ["dns", "passive"],
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
    ["ports"],
    ["live"],
]

MODULE_LABELS = {
    "dns": "DNS recon + zone transfer",
    "passive": "Passive subdomain enumeration (subfinder)",
    "active": "Active DNS brute-force (puredns)",
    "vertical": "Vertical enumeration (permutations + recursive)",
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
        interactive: bool = False,
        resume: Optional[bool] = None,
    ):
        self.cfg = cfg
        self.scope = scope
        self.out = out
        self.runner = runner
        self.console = console
        self.skip = set(skip or [])
        self.only = set(only or [])
        self.interactive = interactive
        self.resume = resume  # None = ask, True = always, False = never
        self.results: List[ModuleResult] = []
        self._resume_done: Dict[str, Set[int]] = {}
        self._resume_skipped: Dict[str, Set[int]] = {}

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
    # progress file (resume support)
    # ------------------------------------------------------------------ #
    def _progress_path(self) -> Path:
        return self.out.root / "reconk.progress.json"

    def _load_progress(self) -> dict:
        p = self._progress_path()
        if not p.exists():
            return {}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def _mark_progress(self, name: str, round_no: int, status: str) -> None:
        data = self._load_progress()
        data.setdefault("phases", {})[f"{name}#{round_no}"] = status
        data["mode"] = self.scope.mode
        data["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            self._progress_path().write_text(
                json.dumps(data, indent=2), encoding="utf-8"
            )
        except Exception:  # noqa: BLE001
            pass

    def _expected_phase_keys(self) -> List[str]:
        """Every (name, round) the current plan will touch, in order."""
        keys: List[str] = []
        counts: Counter = Counter()
        for group in self.stages():
            for name in group:
                counts[name] += 1
                keys.append(f"{name}#{counts[name]}")
        return keys

    def _maybe_resume(self) -> None:
        """Offer to skip phases completed in a previous run of this target."""
        data = self._load_progress()
        phases: Dict[str, str] = data.get("phases", {})
        if not phases:
            return
        expected = set(self._expected_phase_keys())
        known = {k: v for k, v in phases.items() if k in expected}
        if not known:
            return
        done = {k for k, v in known.items() if v in ("done", "skipped")}
        if not done:
            return
        if self.resume is False:
            return
        if self.resume is None and not self.interactive:
            return
        resume_phases = sorted(done)
        self.console.print(
            Panel.fit(
                "\n".join(
                    [f"[bold cyan]Resume[/bold cyan] — {self.out.target}",
                     f"  [dim]previous run: {len(resume_phases)} phase(s) "
                     f"completed or skipped[/dim]"]
                    + [f"    · {k}" for k in resume_phases[:8]]
                    + (["    · …"] if len(resume_phases) > 8 else [])
                ),
                border_style="cyan",
            )
        )
        if self.resume is True:
            choice = "y"
        else:
            choice = self._prompt_key(
                "Skip these and continue?",
                "  [dim][Enter] resume   [n] start fresh[/dim]",
            )
        if choice != "y":
            self.console.print("  [dim]starting fresh — previous progress ignored[/dim]")
            return
        for key in done:
            name, _, r = key.rpartition("#")
            bucket = self._resume_skipped if phases[key] == "skipped" else self._resume_done
            bucket.setdefault(name, set()).add(int(r))

    def _prompt_key(self, question: str, hint: str) -> str:
        """Read a single terminal key (cbreak). y/n/s/enter/q/ctrl-c."""
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            # cbreak BEFORE printing: a key typed while the prompt renders
            # must land in the non-canonical input queue — bytes buffered
            # in canonical mode are never delivered after the mode switch
            tty.setcbreak(fd)
            self.console.print(f"\n[bold cyan]{question}[/bold cyan]")
            self.console.print(hint)
            while True:
                r, _, _ = select.select([fd], [], [], 120)
                if not r:
                    continue
                try:
                    ch = os.read(fd, 1)
                except OSError:
                    continue
                if not ch:
                    # EOF (terminal closed) — treat as quit
                    return "q"
                c = ch.decode(errors="replace").lower()
                if c in ("y",):
                    return "y"
                if c in ("n",):
                    return "n"
                if c in ("\r", "\n"):
                    return "enter"
                if c in ("s",):
                    return "s"
                if c in ("q", "\x03"):
                    return "q"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)

    # ------------------------------------------------------------------ #
    def run_all(self) -> List[ModuleResult]:
        stages = self.stages()
        if not stages:
            self.console.print("[yellow]! nothing to do — all phases skipped[/yellow]")
            return []

        self._maybe_resume()
        self._show_plan(stages)

        start = time.monotonic()
        counts = Counter()  # phase name -> times run (for round labels)
        try:
            for group in stages:
                if self.runner.cancel_event.is_set():
                    self.console.print(
                        "  [yellow]! cancelled — skipping remaining stages[/yellow]"
                    )
                    break
                # ---- resume: skip phases finished in a previous run ----
                pending: List[tuple] = []
                already: List[tuple] = []
                for name in group:
                    r = counts[name] + 1
                    done_rounds = self._resume_done.get(name, set())
                    if r in done_rounds:
                        already.append((name, r))
                        counts[name] += 1
                        self.results.append(
                            ModuleResult(name, ok=True, message="already completed — resumed")
                        )
                    else:
                        pending.append((name, r))
                for name, r in already:
                    self.console.print(
                        f"  [dim]· {name} (round {r}) already completed — skipping[/dim]"
                    )
                if not pending:
                    continue
                # ---- interactive: run / skip / quit for this stage ----
                if self.interactive and not self.runner.cancel_event.is_set():
                    labels = ", ".join(
                        MODULE_LABELS.get(n) or n for n, _ in pending
                    )
                    choice = self._prompt_key(
                        f"Stage — {labels}",
                        "  [dim][Enter] run   [s] skip   [q] quit scan[/dim]",
                    )
                    if choice == "q":
                        self.runner.cancel()
                        self.console.print(
                            "  [yellow]! quitting — running tools will be killed[/yellow]"
                        )
                        break
                    if choice == "s":
                        for name, r in pending:
                            self._mark_progress(name, r, "skipped")
                            self.console.print(
                                f"  [yellow]· {name} (round {r}) skipped[/yellow]"
                            )
                        continue
                parallel = len(pending) > 1
                self.runner.parallel_mode = parallel
                if parallel:
                    pool = ThreadPoolExecutor(
                        max_workers=len(pending), thread_name_prefix="reconk"
                    )
                    futs = {
                        pool.submit(self._run_phase, name, round_no, group): name
                        for name, round_no in pending
                    }
                    try:
                        for fut in futs:
                            result = fut.result()
                            counts[result.name] += 1
                            self.results.append(result)
                    finally:
                        # cancel_futures: on Ctrl-C we kill every tool (the
                        # runner's cancel()) so the still-queued phases never
                        # start; wait=True lets the in-flight ones finish
                        # fast (their processes are already dead)
                        pool.shutdown(wait=True, cancel_futures=True)
                else:
                    name, round_no = pending[0]
                    result = self._run_phase(name, round_no, group)
                    counts[result.name] += 1
                    self.results.append(result)
        except KeyboardInterrupt:
            # kill every running tool (process groups) before propagating,
            # so the ThreadPoolExecutor's wait below returns immediately
            # instead of blocking on live background processes
            self.runner.cancel()
            raise
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
        except CommandError as e:
            if self.runner.cancel_event.is_set():
                self.console.print(f"  [yellow]! {name} cancelled[/yellow]")
            else:
                self.console.print(f"  [red]✗ {name} failed: {e}[/red]")
            result = ModuleResult(name, ok=False, message=str(e))
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [red]✗ {name} crashed: {e}[/red]")
            result = ModuleResult(name, ok=False, message=str(e))
        result.message += f" ({time.monotonic() - t0:.0f}s)"
        # record for resume: done / skipped / cancelled / failed
        if result.ok:
            self._mark_progress(name, round_no, "done")
        elif self.runner.cancel_event.is_set():
            self._mark_progress(name, round_no, "cancelled")
        else:
            self._mark_progress(name, round_no, "failed")
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