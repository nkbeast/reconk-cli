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

#: fallback public resolvers used when the configured resolver file is missing
BUILTIN_RESOLVERS = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]


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
    #: occurrence counter of this phase in the plan (1 = first run)
    round_no: int = 1
    #: names of the modules running in the current parallel stage
    stage_modules: set = field(default_factory=set)

    def module_file(self, module: str, category: str, filename: str) -> Path:
        return self.out.cat(category) / filename

    def is_skipped(self, module: str) -> bool:
        return module in self.skip

    def stage_has(self, module: str) -> bool:
        """True when `module` runs in the same stage as this one."""
        return module in self.stage_modules


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

    def data_file(self, name: str) -> Path:
        """Absolute path of a bundled data file (always exists in the package)."""
        return Path(__file__).resolve().parent.parent / "data" / name

    def ensure_resolvers(self) -> Path:
        """Return a usable resolver list, healing a missing configured file.

        When ``tools.resolvers`` does not exist, a small builtin list is
        written there once so every later run reuses it.
        """
        target = self.ctx.cfg.tool_path("resolvers")
        if target.exists():
            return target
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("\n".join(BUILTIN_RESOLVERS) + "\n", encoding="utf-8")
            self.console.print(
                f"  [yellow]⚠ resolvers not found — wrote builtin list to {target}[/yellow]"
            )
            return target
        except OSError:
            pass
        fallback = self.ctx.out.root / "logs" / "resolvers.txt"
        fallback.parent.mkdir(parents=True, exist_ok=True)
        fallback.write_text("\n".join(BUILTIN_RESOLVERS) + "\n", encoding="utf-8")
        return fallback

    def scope_domains_file(self) -> Path:
        """A list file containing ONLY the root domains in scope.

        The raw ``scope.txt`` may also carry CIDRs / ASNs / IPs / orgs
        (mixed + network scopes) which would break domain-only tools like
        subfinder (-dL) or puredns bruteforce (-d).
        """
        domains = sorted(set(self.ctx.scope.all_domains()))
        path = self.ctx.out.root / "scope_domains.txt"
        path.write_text("\n".join(domains) + ("\n" if domains else ""), encoding="utf-8")
        return path

    def start(self, msg: str) -> None:
        self.console.print(f"\n[bold yellow]▶ {msg}[/bold yellow]")

    def done(self, msg: str = "") -> None:
        self.console.print(f"  [green]✔ {self.label} complete[/green]{(' — ' + msg) if msg else ''}")

    def wait_for_file(self, path: Path, timeout: int = 600) -> bool:
        """Block until `path` exists (a parallel sibling phase writes it).

        Used when a phase runs in the same parallel stage as a producer
        (e.g. tech fingerprinting waits for the live filter's alive.txt).
        Returns True when the file appeared, False on timeout.
        """
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return True
            time.sleep(2)
        return False
