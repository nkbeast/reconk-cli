"""Recon modules package.

Importing this package registers every phase in the registry.
"""

from __future__ import annotations

from reconk.modules import (  # noqa: F401
    active,
    dns,
    horizontal,
    js,
    live,
    merge,
    params,
    passive,
    ports,
    takeover,
    tech,
    urls,
    vertical,
)
from reconk.modules.registry import (  # noqa: F401
    REGISTRY,
    ModuleResult,
    available_modules,
    build_modules,
    module_names,
    register,
)
