"""Vertical subdomain enumeration — deeper levels.

Two techniques feed this phase:

1. **Permutation**: mutate every discovered subdomain's prefix (dev →
   stg-dev, api → api-dev, ...) using a prefix wordlist, then resolve
   candidates with puredns.
2. **Recursive**: run passive enumeration (subfinder) *against the
   discovered subdomains* themselves (e.g. a 3rd-level `foo.example.com`
   can hide `bar.foo.example.com`).

Output: 02-subdomains/vertical.txt
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import List, Set

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module
from reconk.runner import ToolNotFound


@register
class VerticalEnumModule(Module):
    name = "vertical"
    label = "Vertical Subdomains"
    category = "subdomains"

    # A few standard mutation patterns applied on top of the wordlist
    MUTATIONS = [
        "{prefix}-{label}", "{label}-{prefix}",
        "{prefix}.{label}", "{label}.{prefix}",
        "{prefix}01", "{prefix}1", "{prefix}2",
        "{prefix}-prod", "prod-{prefix}", "{prefix}-stg", "stg-{prefix}",
        "{prefix}-dev", "dev-{prefix}", "{prefix}-test", "test-{prefix}",
        "{prefix}-new", "new-{prefix}", "{prefix}-old", "old-{prefix}",
    ]

    def run(self) -> ModuleResult:
        base_subs = self._all_known_subdomains()
        if not base_subs:
            return ModuleResult(self.name, message="no subdomains to permute on")

        self.start(f"Vertical enumeration — {len(base_subs)} base subdomains")
        res = ModuleResult(self.name)
        subdir = self.ctx.out.cat(self.category) / "vertical"
        subdir.mkdir(parents=True, exist_ok=True)
        resolvers = self._resolvers(subdir)

        # ---- 1. permutations ----------------------------------------------
        candidates = self._generate_permutations(base_subs)
        self.console.print(f"  [dim]· generated {len(candidates):,} permutation candidates[/dim]")
        cand_file = subdir / "candidates.txt"
        cand_file.write_text("\n".join(sorted(candidates)) + "\n", encoding="utf-8")

        resolved: List[str] = []
        try:
            self.runner.require("puredns")
            out_file = subdir / "permutations_resolved.txt"
            self.runner.run(
                ["puredns", "resolve", str(cand_file), "-r", str(resolvers), "-w", str(out_file), "-q"],
                name="puredns_resolve_permutations",
                timeout=3600,
            )
            if out_file.exists():
                resolved = [l.strip() for l in out_file.read_text(errors="replace").splitlines() if l.strip()]
                res.files.append(str(out_file))
        except ToolNotFound as e:
            self.console.print(f"  [yellow]⚠ {e}[/yellow]")

        # ---- 2. recursive passive -----------------------------------------
        recursive: List[str] = []
        if self.ctx.cfg.get("tools.subfinder_config"):
            try:
                self.runner.require("subfinder")
                sub_file = subdir / "recursive_input.txt"
                sub_file.write_text("\n".join(sorted(base_subs)) + "\n", encoding="utf-8")
                out_file = subdir / "recursive_subfinder.txt"
                self.runner.run(
                    [
                        "subfinder",
                        "-dL", str(sub_file),
                        "-all", "-silent",
                        "-config", str(Path(self.ctx.cfg.get("tools.subfinder_config")).expanduser()),
                        "-o", str(out_file),
                    ],
                    name="subfinder_recursive",
                    timeout=3600,
                )
                if out_file.exists():
                    recursive = [l.strip() for l in out_file.read_text(errors="replace").splitlines() if l.strip()]
                    res.files.append(str(out_file))
            except Exception as e:  # noqa: BLE001
                self.console.print(f"  [yellow]⚠ recursive subfinder: {e}[/yellow]")

        # ---- 3. merge -------------------------------------------------------
        merged = resolved + recursive
        merged = [m for m in merged if any(f".{d}" in m for d in self.ctx.scope.all_domains())]
        path = self.ctx.out.write(self.category, "vertical.txt", merged, dedupe=True)
        res.files.append(str(path))
        res.count = len(merged)

        self.done(f"{res.count} deeper subdomains")
        return res

    # ------------------------------------------------------------------ #
    def _all_known_subdomains(self) -> List[str]:
        known: Set[str] = set()
        for fname in ("passive.txt", "active.txt", "horizontal.txt"):
            known.update(self.ctx.out.read(self.category, fname))
        return sorted(known)

    def _resolvers(self, subdir: Path) -> Path:
        resolvers = self.ctx.cfg.tool_path("resolvers")
        if resolvers.exists():
            return resolvers
        rl = subdir / "resolvers.txt"
        rl.write_text("8.8.8.8\n1.1.1.1\n8.8.4.4\n1.0.0.1\n")
        return rl

    # ------------------------------------------------------------------ #
    def _generate_permutations(self, subs: List[str]) -> Set[str]:
        """Generate candidate hostnames from known subdomains.

        For each subdomain we take the left-most label(s) as the prefix
        and combine them with every word from the permutation wordlist.
        A cap keeps the candidate set bounded.
        """
        roots = self.ctx.scope.all_domains()
        wordlist = self.ctx.cfg.tool_path("permutation_wordlist")
        words = []
        if wordlist.exists():
            words = [w.strip() for w in wordlist.read_text(errors="replace").splitlines() if w.strip()[:1].isalnum()][:400]
        if not words:
            words = ["api", "app", "dev", "stg", "test", "stage", "prod", "www", "mail", "vpn",
                     "portal", "admin", "auth", "beta", "demo", "git", "gitlab", "jenkins",
                     "k8s", "kubernetes", "internal", "lab", "login", "new", "old", "ops",
                     "pay", "private", "public", "qa", "s3", "sandbox", "secure", "shop",
                     "static", "status", "support", "uat", "web", "ws", "www2", "jenkins"]

        candidates: Set[str] = set()
        prefixes: Set[str] = set()

        for sub in subs:
            if not any(sub.endswith("." + d) for d in roots):
                continue
            for w in words:
                for pat in self.MUTATIONS:
                    candidates.add(pat.format(prefix=sub, label=w))
                # extract word-ish prefix from the subdomain itself
                first = sub.split(".")[0]
                if first and first not in ("www",):
                    prefixes.add(first)

        # label<->label combinations (dev-api, api-dev, ...)
        labels = [w for w in words if len(w) <= 10][:60]
        for a in labels:
            for b in labels:
                if a != b:
                    candidates.add(f"{a}-{b}.{next(iter(roots), '')}") if False else None

        # cap for safety
        MAX = 200_000
        if len(candidates) > MAX:
            import random

            candidates = set(random.sample(sorted(candidates), MAX))

        # fix candidates to be full hostnames (prefix.label pattern already includes root)
        full: Set[str] = set()
        for c in candidates:
            if "." in c and c not in roots:
                full.add(c)
        return full
