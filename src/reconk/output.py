"""Output tree management.

Creates a per-target directory layout:

<base_dir>/<target>/
├── scope.txt
├── summary.txt
├── logs/                     # per-phase command logs
├── 01-dns/                   # DNS records + zone transfer
├── 02-subdomains/            # passive / active / vertical / horizontal
│                             # + all_subdomains / resolved_subdomains (merge)
├── 03-live/                  # alive.txt + alive_round<N>.txt (round history)
├── 04-ports/                 # naabu port scans
├── 05-urls/                  # spidercrawl (wayback + common crawl)
├── 06-parameters/            # param urls + keys + gf
├── 07-js/                    # katana js + endpoints + secrets
├── 08-tech/                  # technology fingerprint
├── 09-takeover/              # subdomain takeover findings (CNAME dangling)
└── 10-reports/               # generated reports
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import yaml

CATEGORY_DIRS = {
    "dns": "01-dns",
    "subdomains": "02-subdomains",
    "live": "03-live",
    "ports": "04-ports",
    "urls": "05-urls",
    "params": "06-parameters",
    "js": "07-js",
    "tech": "08-tech",
    "takeover": "09-takeover",
    "reports": "10-reports",
}


class OutputTree:
    """Owns the per-target directory structure and the run manifest."""

    def __init__(self, base_dir: Path, target_name: str):
        self.base_dir = base_dir.expanduser()
        self.target = target_name
        self.root = self.base_dir / target_name
        self.files: Dict[str, List[str]] = {}  # category -> list of files
        self.stats: Dict[str, int] = {}
        self._create()

    # ------------------------------------------------------------------ #
    def _create(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "logs").mkdir(exist_ok=True)
        for cat, sub in CATEGORY_DIRS.items():
            (self.root / sub).mkdir(exist_ok=True)

    def cat(self, category: str) -> Path:
        """Absolute path of a category directory."""
        return self.root / CATEGORY_DIRS[category]

    def log_file(self, name: str) -> Path:
        return self.root / "logs" / f"{name}.log"

    # ------------------------------------------------------------------ #
    def write(self, category: str, filename: str, lines, dedupe: bool = True) -> Path:
        """Write `lines` (iterable of str) into a category as txt.

        Returns the path written. Lines are deduplicated while preserving
        order and blank lines are dropped unless explicitly passed.
        """
        path = self.cat(category) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        items = [str(l).rstrip() for l in lines if str(l).strip()]
        if dedupe:
            seen: Dict[str, None] = {}
            items = [x for x in items if not (x in seen or seen.__setitem__(x, None))]
        path.write_text("\n".join(items) + ("\n" if items else ""), encoding="utf-8")
        self.files.setdefault(category, [])
        if str(path) not in self.files[category]:
            self.files[category].append(str(path))
        self.stats[category] = self.stats.get(category, 0) + len(items)
        return path

    def append(self, category: str, filename: str, lines) -> Path:
        path = self.cat(category) / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = set()
        if path.exists():
            existing = {x.strip() for x in path.read_text(errors="replace").splitlines() if x.strip()}
        with path.open("a", encoding="utf-8") as fh:
            for line in lines:
                line = str(line).rstrip()
                if line and line not in existing:
                    fh.write(line + "\n")
                    existing.add(line)
        return path

    def read(self, category: str, filename: str) -> List[str]:
        path = self.cat(category) / filename
        if not path.exists():
            return []
        return [l.strip() for l in path.read_text(errors="replace").splitlines() if l.strip()]

    def merge_into(self, category: str, filename: str, sources) -> Path:
        """Merge content of several files (paths) into one deduped file."""
        merged: List[str] = []
        for src in sources:
            p = Path(src)
            if p.exists():
                merged += [l.strip() for l in p.read_text(errors="replace").splitlines() if l.strip()]
        return self.write(category, filename, merged, dedupe=True)

    # ------------------------------------------------------------------ #
    def manifest(self) -> Dict:
        """Serialisable run manifest (categories -> files + stats)."""
        return {
            "target": self.target,
            "root": str(self.root),
            "stats": dict(sorted(self.stats.items())),
            "files": {k: sorted(v) for k, v in sorted(self.files.items())},
        }

    def save_manifest(self) -> Path:
        path = self.root / "logs" / "manifest.yaml"
        path.write_text(yaml.safe_dump(self.manifest(), sort_keys=False), encoding="utf-8")
        return path
