"""Technology fingerprinting via the bundled native ``scripts/tech.py``.

Fingerprints every alive endpoint: headers, cookies, title/generator
meta, body markers, favicon hashes. Text-only output.

Output: 08-tech/tech.txt
"""

from __future__ import annotations

from reconk.modules.registry import ModuleResult, register
from reconk.modules.base import Module


@register
class TechFingerprintModule(Module):
    name = "tech"
    label = "Tech Fingerprint"
    category = "tech"

    def run(self) -> ModuleResult:
        alive = self.ctx.out.read("live", "alive.txt")
        if not alive:
            return ModuleResult(self.name, message="no alive endpoints yet")

        self.start(f"Technology fingerprinting — {len(alive)} endpoint(s)")
        res = ModuleResult(self.name)

        hosts_file = self.ctx.out.root / "tech_input.txt"
        hosts_file.write_text("\n".join(sorted(alive)) + "\n", encoding="utf-8")

        out_path = self.ctx.out.cat(self.category) / "tech.txt"
        try:
            self.runner.run_python(
                self.script("tech.py"),
                ["-l", str(hosts_file), "-o", str(out_path), "--threads", "30"],
                name="tech_fingerprint",
                timeout=7200,
            )
        except Exception as e:  # noqa: BLE001
            self.console.print(f"  [yellow]⚠ tech_fingerprint: {e}[/yellow]")
            res.ok = False
            res.message = str(e)

        lines = self.ctx.out.read(self.category, "tech.txt")
        if lines:
            path = self.ctx.out.write(self.category, "tech.txt", lines, dedupe=True)
            res.files.append(str(path))
            res.count = len(lines)

        self.done(f"{res.count} fingerprint lines")
        return res
