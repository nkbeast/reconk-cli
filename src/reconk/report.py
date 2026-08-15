"""Summary report generation (txt only)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reconk.output import OutputTree
from reconk.scope import Scope


def _load(path: Path) -> list:
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="replace").splitlines() if l.strip()]


def _count(path: Path) -> int:
    return len(_load(path))


def build_report(out: OutputTree, scope: Scope, elapsed: float) -> dict:
    """Gather stats from every category into a report dict."""
    report = {
        "target": out.target,
        "scope_mode": scope.mode,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "elapsed_seconds": round(elapsed, 1),
        "output_root": str(out.root),
        "categories": {},
    }

    counts = {}
    # subdomains
    sub_total = 0
    for fname in ("passive.txt", "active.txt", "vertical.txt", "horizontal.txt"):
        n = _count(out.cat("subdomains") / fname)
        counts[f"subdomains_{fname.replace('.txt', '')}"] = n
        sub_total += n
    counts["subdomains_total_unique"] = _count(out.cat("subdomains") / "all_subdomains.txt") or sub_total

    for cat, files in (
        ("live", ["alive.txt", "alive_details.txt"]),
        ("ports", ["naabu_ports.txt", "host_port_summary.txt"]),
        ("urls", ["all_urls.txt"]),
        ("params", ["param_urls.txt", "param_keys.txt"]),
        ("js", ["js_files.txt", "js_endpoints.txt", "js_secrets.txt"]),
        ("tech", ["tech.txt"]),
        ("takeover", ["takeover.txt"]),
    ):
        for fname in files:
            counts[f"{cat}_{fname.replace('.txt', '')}"] = _count(out.cat(cat) / fname)

    report["counts"] = counts
    return report


def write_txt_report(report: dict, path: Path) -> Path:
    lines = [
        "=" * 64,
        f"  RECONK RECON REPORT — {report['target']}",
        f"  mode: {report['scope_mode']}   generated: {report['generated_at']}",
        "=" * 64,
        "",
        "  FINDINGS",
        "  " + "-" * 58,
    ]
    labels = {
        "subdomains_passive": "Passive subdomains",
        "subdomains_active": "Active (bruteforce) subdomains",
        "subdomains_vertical": "Vertical (permutation) subdomains",
        "subdomains_horizontal": "Horizontal (ASN) subdomains",
        "subdomains_total_unique": "Total unique subdomains",
        "live_alive": "Alive endpoints",
        "ports_naabu_ports": "Open ports",
        "urls_all_urls": "Total unique URLs",
        "params_param_urls": "URLs with parameters",
        "params_param_keys": "Unique parameter names",
        "js_js_files": "JS files",
        "js_js_endpoints": "Endpoints from JS",
        "js_js_secrets": "Potential secrets in JS",
        "tech_tech": "Tech fingerprint lines",
        "takeover_takeover": "Takeover check lines",
    }
    for key, label in labels.items():
        if key in report["counts"]:
            lines.append(f"    {label:<38} {report['counts'][key]:>8}")

    if report["counts"].get("js_js_secrets"):
        lines += ["", "  !! Review 07-js/js_secrets.txt — potential secrets found !!"]
    if any(v and "takeover" in k for k, v in report["counts"].items()):
        lines += ["", "  !! Review 09-takeover/takeover.txt — takeover candidates !!"]

    lines += [
        "",
        "=" * 64,
        "  CATEGORY LAYOUT",
        "=" * 64,
        f"  {report['output_root']}",
    ]
    for cat, sub in sorted(
        {
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
        }.items()
    ):
        lines.append(f"    {sub}/   {cat}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
