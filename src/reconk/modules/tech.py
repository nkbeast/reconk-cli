"""Technology fingerprinting via the bundled native ``scripts/tech.py``.

Runs the full TechFingerprint v2 engine (Wappalyzer-style signature DB,
confidence scoring, version extraction, implied technologies, TLS + security
grade, favicon hashes, source-map detection). Text-only output.

Output:
  08-tech/techfingerprint_<stamp>.txt  — engine report
  08-tech/tech.txt                     — canonical copy for reconk reports
"""

from __future__ import annotations

import glob
import os
from pathlib import Path
from typing import Optional

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class TechFingerprintModule(Module):
    name = "tech"
    label = "Tech Fingerprint"
    category = "tech"

    def run(self) -> ModuleResult:
        alive = self.ctx.out.read("live", "alive.txt")
        if not alive and self.ctx.round_no == 1 and self.ctx.stage_has("live"):
            # single scope: live filtering runs in the SAME parallel stage —
            # wait for it to write alive.txt before fingerprinting
            self.console.print("  [dim]· waiting for live filter output…[/dim]")
            self.wait_for_file(self.ctx.out.cat("live") / "alive.txt", timeout=900)
            alive = self.ctx.out.read("live", "alive.txt")
        if not alive:
            return ModuleResult(self.name, message="no alive endpoints yet")

        self.start(f"Technology fingerprinting — {len(alive)} endpoint(s)")
        res = ModuleResult(self.name)

        hosts_file = self.ctx.out.root / "tech_input.txt"
        hosts_file.write_text("\n".join(sorted(alive)) + "\n", encoding="utf-8")

        cat_dir = self.ctx.out.cat(self.category)
        # drop stale engine reports so a failed run can never present old data
        for old in glob.glob(str(cat_dir / "techfingerprint_*.txt")):
            try:
                os.remove(old)
            except OSError:
                pass
        try:
            self.runner.run_python(
                self.script("tech.py"),
                ["-l", str(hosts_file), "-o", str(cat_dir), "--txt", "-c", "30"],
                name="tech_fingerprint",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ tech_fingerprint: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        report = self._latest_report(cat_dir) if res.ok else None
        if report:
            lines = report.read_text(errors="replace").splitlines()
            lines = [l for l in lines if l.strip()]
            path = self.ctx.out.write(self.category, "tech.txt", lines, dedupe=False)
            res.files.append(str(path))
            res.files.append(str(report))
            res.count = len(lines)

        self.done(f"{res.count} fingerprint lines")
        return res

    @staticmethod
    def _latest_report(cat_dir: Path) -> Optional[Path]:
        """Newest techfingerprint_*.txt written by the engine, if any."""
        matches = glob.glob(str(cat_dir / "techfingerprint_*.txt"))
        if not matches:
            return None
        return Path(max(matches, key=os.path.getmtime))
