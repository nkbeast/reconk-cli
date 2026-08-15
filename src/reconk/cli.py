"""Reconk CLI — command line entry point with an interactive TUI.

Running ``./reconk`` with no arguments opens the interactive menu
(questionary). All the classic subcommands still work for scripting.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
import time
from pathlib import Path
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconk import __version__
from reconk.banner import TAGLINE, get_banner
from reconk.config import Config
from reconk.output import OutputTree
from reconk.pipeline import Pipeline, MODULE_LABELS
from reconk.report import build_report, write_txt_report
from reconk.runner import CommandRunner, ToolNotFound
from reconk.scope import Scope

console = Console()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _run_pipeline(
    cfg: Config,
    scope: Scope,
    skip: Optional[List[str]] = None,
    only: Optional[List[str]] = None,
    base_dir: Optional[str] = None,
    verbose: bool = False,
    target_name: Optional[str] = None,
) -> int:
    base = Path(base_dir) if base_dir else Path(cfg.output_base_dir()).expanduser()
    out = OutputTree(base, target_name or scope.name)
    out.root.mkdir(parents=True, exist_ok=True)

    # persist scope
    scope.to_file(out.root / "scope.txt")

    console.print(Panel.fit(f"[bold]Target[/bold] [green]{out.target}[/green]", border_style="green"))
    console.print(scope.summary())

    runner = CommandRunner(console, log_dir=out.root / "logs")
    pipeline = Pipeline(cfg, scope, out, runner, console, skip=skip, only=only)

    t0 = time.monotonic()
    results = pipeline.run_all()
    elapsed = time.monotonic() - t0

    # report
    report = build_report(out, scope, elapsed)
    txt = write_txt_report(report, out.cat("reports") / "summary.txt")
    out.save_manifest()
    console.print(f"  [green]Reports: {txt}[/green]")

    return 0 if all(r.ok for r in results) else 1


# --------------------------------------------------------------------------- #
# subcommand handlers
# --------------------------------------------------------------------------- #
def _cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    scope = Scope.from_input(
        args.target,
        args.scope,
        args.file,
        force_wildcard=args.wildcard,
    )
    if scope.is_empty:
        console.print("[red]! Empty scope. Pass --scope or --file.[/red]")
        return 2

    # default skip set — nothing for now
    skip = list(args.skip or [])
    if getattr(args, "no_takeover", False):
        skip.append("takeover")
    if getattr(args, "subfinder_all", False):
        cfg._data.setdefault("scan", {})["subfinder_all"] = "true"
    return _run_pipeline(
        cfg, scope, skip=skip, base_dir=args.out, verbose=args.verbose
    )


def _cmd_resume(args: argparse.Namespace, cfg: Config) -> int:
    """Re-run specific phases against an existing target directory."""
    base = Path(args.out or cfg.output_base_dir()).expanduser()
    root = base / args.target
    if not root.exists():
        console.print(f"[red]! No output directory for '{args.target}' at {root}[/red]")
        return 2
    scope_file = root / "scope.txt"
    if not scope_file.exists():
        console.print("[red]! scope.txt missing — cannot rebuild scope[/red]")
        return 2
    scope = Scope.from_input(args.target, "", str(scope_file), force_wildcard=args.wildcard)
    return _run_pipeline(cfg, scope, skip=args.skip, only=args.only, base_dir=str(base))


def _cmd_doctor(args: argparse.Namespace, cfg: Config) -> int:
    """Check tool availability."""
    console.print(Panel.fit("[bold]Tool doctor[/bold]", border_style="cyan"))

    binaries = [
        "subfinder", "puredns", "dnsx", "httpx", "naabu",
        "katana", "waybackurls", "gau", "anew", "gf",
    ]
    table = Table(title="Binaries")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="bold")
    for b in binaries:
        found = shutil.which(b)
        table.add_row(b, f"[green]✔ {found}[/green]" if found else "[red]✗ missing[/red]")
    console.print(table)

    table2 = Table(title="Bundled native scripts")
    table2.add_column("Script", style="cyan")
    table2.add_column("Status", style="bold")
    from pathlib import Path as _Path

    scripts_dir = _Path(__file__).resolve().parent / "scripts"
    for name in ("dnsrecon.py", "asn.py", "harvester.py", "tech.py", "takeover.py"):
        path = scripts_dir / name
        ok = path.exists()
        table2.add_row(name, f"[green]✔ {path}[/green]" if ok else f"[red]✗ missing[/red]")
    console.print(table2)

    # wordlists + resolvers
    table3 = Table(title="Data files")
    table3.add_column("Item", style="cyan")
    table3.add_column("Status", style="bold")
    for key in ("resolvers", "subdomain_wordlist", "permutation_wordlist", "subfinder_config"):
        path = Path(str(cfg.get(f"tools.{key}", ""))).expanduser()
        ok = path.exists()
        table3.add_row(key, f"[green]✔ {path}[/green]" if ok else f"[red]✗ {path}[/red]")
    console.print(table3)
    return 0


def _cmd_report(args: argparse.Namespace, cfg: Config) -> int:
    base = Path(args.out or cfg.output_base_dir()).expanduser()
    root = base / args.target
    summary = root / "10-reports" / "summary.txt"
    if not summary.exists():
        console.print(f"[red]! No report for '{args.target}' at {root}[/red]")
        return 1
    console.print(summary.read_text())
    return 0


def _cmd_config(args: argparse.Namespace, cfg: Config) -> int:
    import yaml

    if args.show:
        console.print(Panel.fit("[bold]Active configuration[/bold]", border_style="cyan"))
        console.print(yaml.safe_dump(cfg.data, sort_keys=False))
    else:
        dest = cfg.save()
        console.print(f"[green]Config written to {dest}[/green]")
    return 0


def _cmd_list(args: argparse.Namespace, cfg: Config) -> int:
    base = Path(args.out or cfg.output_base_dir()).expanduser()
    if not base.exists():
        console.print(f"[yellow]No targets yet at {base}[/yellow]")
        return 0
    table = Table(title=f"Targets — {base}")
    table.add_column("Target", style="cyan")
    table.add_column("Root", style="dim")
    for d in sorted(base.iterdir()):
        if d.is_dir() and (d / "scope.txt").exists():
            table.add_row(d.name, str(d))
    console.print(table)
    return 0


# --------------------------------------------------------------------------- #
# TUI (interactive mode)
# --------------------------------------------------------------------------- #
def _tui_collect_entries(questionary, label: str) -> List[str]:
    """Collect entries from the user, as many as they want to give."""
    entries: List[str] = []
    while True:
        more = (
            questionary.text(
                label,
                default="",
                instruction="comma separated — leave empty and press enter when done",
            ).ask()
            or ""
        )
        if more.strip():
            entries += [e.strip() for e in re.split(r"[\s,]+", more) if e.strip()]
        if not more.strip():
            break
        if not questionary.confirm("Add more?", default=False).ask():
            break
    return entries


def _tui_permutation(questionary) -> bool:
    return questionary.confirm(
        "Run a permutation scan for the wildcard scope? (vertical subdomain discovery)",
        default=False,
    ).ask() or False


def _ask_skip(questionary) -> List[str]:
    chosen = questionary.checkbox(
        "Phases to SKIP (space to toggle, enter to continue)",
        choices=[questionary.Choice(label, value=name) for name, label in MODULE_LABELS.items()],
        instruction="leave empty to run everything",
    ).ask()
    return list(chosen or [])


def _tui_new_recon(cfg: Config) -> int:
    """Guided new-recon setup: target -> scope type -> inputs -> run."""
    import questionary

    name = questionary.text("Target / company name", default="").ask()
    if not name or not name.strip():
        console.print("[red]! No target name given.[/red]")
        return 2
    name = name.strip()

    scope_type = questionary.select(
        "Scope type",
        choices=[
            "Single domains — no subdomain enumeration",
            "Wildcard domains — full subdomain enumeration",
            "Both single + wildcard domains",
        ],
    ).ask()
    if not scope_type:
        return 2

    # --------------------------------------------------------------- #
    # single mode
    # --------------------------------------------------------------- #
    if "Single domains" in scope_type and "Both" not in scope_type:
        entries = _tui_collect_entries(
            questionary, "Single domain(s) in scope (e.g. example.com)"
        )
        if not entries:
            console.print("[red]! No domains given.[/red]")
            return 2
        scope = Scope.from_input(name, ",".join(entries))
        return _run_pipeline(cfg, scope, base_dir=str(cfg.output_base_dir()))

    # --------------------------------------------------------------- #
    # wildcard mode
    # --------------------------------------------------------------- #
    if "Wildcard domains" in scope_type and "Both" not in scope_type:
        entries = _tui_collect_entries(
            questionary, "Wildcard scope(s) (e.g. *.example.com or example.com)"
        )
        if not entries:
            console.print("[red]! No wildcards given.[/red]")
            return 2
        skip = []
        if not _tui_permutation(questionary):
            skip.append("vertical")
        scope = Scope.from_input(name, ",".join(entries), force_wildcard=True)
        return _run_pipeline(cfg, scope, skip=skip, base_dir=str(cfg.output_base_dir()))

    # --------------------------------------------------------------- #
    # both single + wildcard: collect singles, then wildcards, run
    # the single engagement first, then the wildcard one.
    # --------------------------------------------------------------- #
    single_entries = _tui_collect_entries(
        questionary, "Single domain(s) in scope (comma separated)"
    )
    wild_entries = _tui_collect_entries(
        questionary, "Wildcard scope(s) (e.g. *.example.com or example.com)"
    )
    if not single_entries and not wild_entries:
        console.print("[red]! No scope given at all.[/red]")
        return 2

    skip = []
    if not (wild_entries and _tui_permutation(questionary)):
        skip.append("vertical")

    rc = 0
    if single_entries:
        scope = Scope.from_input(name, ",".join(single_entries))
        rc |= _run_pipeline(cfg, scope, base_dir=str(cfg.output_base_dir()),
                            target_name=f"{name}/single")
    if wild_entries:
        scope = Scope.from_input(name, ",".join(wild_entries), force_wildcard=True)
        rc |= _run_pipeline(cfg, scope, skip=skip, base_dir=str(cfg.output_base_dir()),
                            target_name=f"{name}/wildcard")

    # combined scope.txt + pointer report at the target root
    base = Path(cfg.output_base_dir()).expanduser()
    root = base / name
    root.mkdir(parents=True, exist_ok=True)
    (root / "scope.txt").write_text(
        "\n".join(sorted(set(single_entries + wild_entries))) + "\n", encoding="utf-8"
    )
    (root / "summary.txt").write_text(
        f"Reconk run — {name}\n"
        f"  single:   {base / name / 'single'}   (ran first)\n"
        f"  wildcard: {base / name / 'wildcard'}\n",
        encoding="utf-8",
    )
    return rc


def _tui_scan(cfg: Config) -> int:
    return _tui_new_recon(cfg)


def _tui_resume(cfg: Config) -> int:
    import questionary

    base = Path(cfg.output_base_dir()).expanduser()
    existing = sorted(
        d.name for d in base.iterdir() if d.is_dir() and (d / "scope.txt").exists()
    ) if base.exists() else []
    if not existing:
        console.print("[yellow]No existing targets yet.[/yellow]")
        return 2
    target = questionary.select("Existing target:", choices=existing).ask()
    if not target:
        return 2

    skip = _ask_skip(questionary)
    return _cmd_resume(
        argparse.Namespace(target=target, skip=skip, only=None, wildcard=False, out=None),
        cfg,
    )


def _tui_report(cfg: Config) -> int:
    import questionary

    base = Path(cfg.output_base_dir()).expanduser()
    existing = sorted(
        d.name for d in base.iterdir()
        if d.is_dir() and (d / "10-reports" / "summary.txt").exists()
    ) if base.exists() else []
    if not existing:
        console.print("[yellow]No reports yet.[/yellow]")
        return 2
    target = questionary.select("Target report:", choices=existing).ask()
    if not target:
        return 2
    return _cmd_report(argparse.Namespace(target=target, out=None), cfg)


def _tui_menu(cfg: Config) -> int:
    import questionary

    while True:
        action = questionary.select(
            "Reconk — main menu",
            choices=[
                "Start new recon (guided setup)",
                "Resume / partial run on existing target",
                "Show target report",
                "List targets",
                "Tool doctor",
                "Show / init config",
                "Exit",
            ],
        ).ask()
        if not action or action == "Exit":
            console.print("[dim]bye[/dim]")
            return 0
        if action == "Start new recon (guided setup)":
            _tui_scan(cfg)
        elif action == "Resume / partial run on existing target":
            _tui_resume(cfg)
        elif action == "Show target report":
            _tui_report(cfg)
        elif action == "List targets":
            _cmd_list(argparse.Namespace(out=None), cfg)
        elif action == "Tool doctor":
            _cmd_doctor(argparse.Namespace(), cfg)
        elif action == "Show / init config":
            _cmd_config(argparse.Namespace(show=True), cfg)


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconk",
        description=f"{TAGLINE}  (v{__version__})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  reconk scan uber --scope *.uber.com\n"
               "  reconk scan uber --scope example.com --file extra.txt\n"
               "  reconk scan acme --scope 1.2.3.0/24,AS15169 --skip passive,active\n"
               "  reconk scan shop --scope shop.com --wildcard --out ~/recon-out\n"
               "  reconk doctor\n",
    )
    p.add_argument("-v", "--version", action="version", version=f"reconk {__version__}")
    sub = p.add_subparsers(dest="command")

    # ---- scan --------------------------------------------------------------
    ps = sub.add_parser("scan", help="full end-to-end recon against a target")
    ps.add_argument("target", help="target/company name (output directory name)")
    ps.add_argument("--scope", default="", help="in-scope items: domains, *.wildcards, CIDRs, ASNs, IPs (comma/space separated)")
    ps.add_argument("-f", "--file", default=None, help="file with in-scope items (one per line)")
    ps.add_argument("-w", "--wildcard", action="store_true", help="treat all listed domains as wildcard scope (subdomain enum IN scope)")
    ps.add_argument("-o", "--out", default=None, help=f"output base directory (default: {Config.defaults().output_base_dir()})")
    ps.add_argument("--skip", default=None, help="comma-separated phases to skip: " + ", ".join(MODULE_LABELS))
    ps.add_argument("--no-takeover", action="store_true", help="skip the takeover phase")
    ps.add_argument("--subfinder-all", action="store_true", help="query ALL subfinder sources (slow, rate-limited)")
    ps.add_argument("--verbose", action="store_true", help="verbose output")
    ps.set_defaults(handler=_cmd_scan)

    # ---- resume --------------------------------------------------------------
    pr = sub.add_parser("resume", help="re-run specific phases on an existing target dir")
    pr.add_argument("target", help="target/company name")
    pr.add_argument("--skip", default=None, help="comma-separated phases to skip")
    pr.add_argument("--only", default=None, help="comma-separated phases to run (whitelist)")
    pr.add_argument("-w", "--wildcard", action="store_true", help="treat scope as wildcard")
    pr.add_argument("-o", "--out", default=None, help="output base directory")
    pr.set_defaults(handler=_cmd_resume)

    # ---- doctor ---------------------------------------------------------------
    sub.add_parser("doctor", help="verify all tools are installed and configured").set_defaults(handler=_cmd_doctor)

    # ---- report ----------------------------------------------------------------
    prt = sub.add_parser("report", help="print the summary report of a target")
    prt.add_argument("target", help="target/company name")
    prt.add_argument("-o", "--out", default=None, help="output base directory")
    prt.set_defaults(handler=_cmd_report)

    # ---- list -------------------------------------------------------------------
    pl = sub.add_parser("list", help="list all scanned targets")
    pl.add_argument("-o", "--out", default=None, help="output base directory")
    pl.set_defaults(handler=_cmd_list)

    # ---- config -----------------------------------------------------------------
    pc = sub.add_parser("config", help="show or initialise configuration")
    pc.add_argument("--show", action="store_true", help="print the active configuration")
    pc.add_argument("--init", action="store_true", help="write ~/.config/reconk/config.yaml")
    pc.set_defaults(handler=_cmd_config)

    return p


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    console.print(get_banner(__version__), style="bold blue", highlight=False)
    console.print(f"[dim]{TAGLINE}[/dim]\n")

    try:
        cfg = Config.load()
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        return 2

    # ---- no command -> interactive TUI -------------------------------------
    if not getattr(args, "command", None):
        try:
            return _tui_menu(cfg)
        except KeyboardInterrupt:
            console.print("\n[bold yellow]Interrupted by user.[/bold yellow]")
            return 130

    # ---- config command needs the raw config --------------------------------
    if args.command == "config":
        return args.handler(args, cfg)

    try:
        if hasattr(args, "skip") and args.skip:
            args.skip = [s.strip() for s in args.skip.split(",") if s.strip()]
        if hasattr(args, "only") and args.only:
            args.only = [s.strip() for s in args.only.split(",") if s.strip()]
        return args.handler(args, cfg)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted by user.[/bold yellow]")
        return 130
    except ToolNotFound as e:
        console.print(f"[red]{e}[/red]")
        console.print("[dim]Run `reconk doctor` to see what is missing.[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
