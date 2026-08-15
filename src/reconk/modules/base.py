"""Module base class and the run context shared by every phase."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Optional

from rich.console import Console

from reconk.config import Config
from reconk.output import OutputTree
from reconk.runner import CommandRunner
from reconk.scope import Scope

if TYPE_CHECKING:
    from reconk.modules.registry import ModuleResult


@dataclass
class RunContext:
    """Everything a module needs to do its job."""

    cfg: Config
    scope: Scope
    out: OutputTree
    runner: CommandRunner
    console: Console
    #: which modules to skip (names)
    skip: set = field(default_factory=set)
    #: module kwargs overrides (e.g. extra httpx flags)
    extra: dict = field(default_factory=dict)

    def module_file(self, module: str, category: str, filename: str) -> Path:
        return self.out.cat(category) / filename

    def is_skipped(self, module: str) -> bool:
        return module in self.skip


class Module:
    """Base class for all recon phases."""

    #: short identifier used on the CLI (e.g. `dns`, `subdomains`)
    name: str = "module"
    #: pretty display name
    label: str = "Module"
    #: output category dir key
    category: str = "subdomains"

    def __init__(self, ctx: RunContext):
        self.ctx = ctx

    # ------------------------------------------------------------------ #
    def run(self) -> "ModuleResult":
        raise NotImplementedError

    # ------------------------------------------------------------------ #
    # convenience helpers
    # ------------------------------------------------------------------ #
    @property
    def console(self) -> Console:
        return self.ctx.console

    @property
    def out(self) -> OutputTree:
        return self.ctx.out

    @property
    def runner(self) -> CommandRunner:
        return self.ctx.runner

    def script(self, name: str) -> Path:
        """Absolute path of one of the bundled native scripts."""
        return Path(__file__).resolve().parent.parent / "scripts" / name

    def start(self, msg: str) -> None:
        self.console.print(f"\n[bold yellow]▶ {msg}[/bold yellow]")

    def done(self, msg: str = "") -> None:
        self.console.print(f"  [green]✔ {self.label} complete[/green]{(' — ' + msg) if msg else ''}")
