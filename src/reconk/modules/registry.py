"""Module registry — keeps `register` and `ModuleResult` import-safe."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Type

from reconk.modules.base import Module, RunContext

REGISTRY: List[Type[Module]] = []


@dataclass
class ModuleResult:
    """Outcome of a single module run."""

    name: str
    ok: bool = True
    files: List[str] = field(default_factory=list)
    count: int = 0
    message: str = ""

    @property
    def display(self) -> str:
        if self.ok:
            return f"[green]✔[/green] {self.name}: {self.message}"
        return f"[red]✗[/red] {self.name}: {self.message}"


def register(cls: Type[Module]) -> Type[Module]:
    REGISTRY.append(cls)
    return cls


def build_modules(ctx: RunContext) -> List[Module]:
    return [cls(ctx) for cls in REGISTRY]


def module_names() -> List[str]:
    return [cls.name for cls in REGISTRY]


def available_modules() -> str:
    return ", ".join(module_names())
