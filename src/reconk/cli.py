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
    # mixed scope: run the single workflow first, then the wildcard
    # workflow, into <target>/single and <target>/wildcard (collapsed tree)
    if scope.mode == "mixed":
        singles = [d for d in scope.domains if d not in scope.wildcards]
        wilds = scope.wildcards + scope.network_targets() + scope.orgs
        rc = 0
        if singles:
            s_scope = Scope.from_input(scope.name, ",".join(singles))
            rc |= _run_pipeline(cfg, s_scope, skip=skip, only=only, base_dir=base_dir,
                                verbose=verbose, target_name=f"{scope.name}/single")
        if wilds:
            w_scope = Scope.from_input(scope.name, ",".join(wilds), force_wildcard=True)
            rc |= _run_pipeline(cfg, w_scope, skip=skip, only=only, base_dir=base_dir,
                                verbose=verbose, target_name=f"{scope.name}/wildcard")
        return rc

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
    # wildcard runs persist a marker file; without it the scope would be
    # reclassified as `single` and the wrong pipeline would run
    force_wildcard = bool(args.wildcard)
    wild_marker = root / "scope_wildcards.txt"
    if wild_marker.exists() and wild_marker.read_text().strip():
        force_wildcard = True
    scope = Scope.from_input(args.target, "", str(scope_file), force_wildcard=force_wildcard)
    return _run_pipeline(cfg, scope, skip=args.skip, only=args.only, base_dir=str(base))


def _cmd_doctor(args: argparse.Namespace, cfg: Config) -> int:
    """Check tool availability."""
    console.print(Panel.fit("[bold]Tool doctor[/bold]", border_style="cyan"))

    binaries = [
        "subfinder", "puredns", "dnsx", "httpx", "naabu",
        "katana", "anew", "gf",
    ]
    table = Table(title="Binaries")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="bold")
    for b in binaries:
        found = shutil.which(b)
        table.add_row(b, f"[green]✔ {found}[/green]" if found else "[red]✗ missing[/red]")
    console.print(table)

    # puredns depends on massdns — check it explicitly
    table_md = Table(title="Tool dependencies")
    table_md.add_column("Dependency", style="cyan")
    table_md.add_column("Used by", style="dim")
    table_md.add_column("Status", style="bold")
    for b, by in (
        ("massdns", "puredns bruteforce/resolve (hard)"),
        ("dig", "dns phase zone transfer (soft)"),
        ("whois", "horizontal ASN prefixes (soft, bgpview fallback)"),
        ("fping", "horizontal host discovery (soft, tcp fallback)"),
    ):
        found = shutil.which(b)
        table_md.add_row(b, by, f"[green]✔ {found}[/green]" if found else "[yellow]⚠ missing[/yellow]")
    console.print(table_md)

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

    table_py = Table(title="Python dependencies")
    table_py.add_column("Module", style="cyan")
    table_py.add_column("Status", style="bold")
    for mod in ("rich", "yaml", "requests", "aiohttp", "dns", "mmh3", "questionary"):
        try:
            __import__(mod)
            table_py.add_row(mod, "[green]✔ present[/green]")
        except ImportError:
            table_py.add_row(mod, "[red]✗ missing[/red]")
    console.print(table_py)

    # wordlists + resolvers
    table3 = Table(title="Data files")
    table3.add_column("Item", style="cyan")
    table3.add_column("Status", style="bold")
    for key in ("resolvers", "subdomain_wordlist", "permutation_wordlist", "subfinder_config"):
        path = Path(str(cfg.get(f"tools.{key}", ""))).expanduser()
        ok = path.exists()
        table3.add_row(key, f"[green]✔ {path}[/green]" if ok else f"[yellow]⚠ {path}[/yellow]")
    bundled = _Path(__file__).resolve().parent / "data" / "subdomains-small.txt"
    table3.add_row(
        "bundled wordlist",
        f"[green]✔ {bundled}[/green]" if bundled.exists() else "[red]✗ missing[/red]",
    )
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


def _save_inputs(cfg: Config, name: str, scope_type: str, single_entries: List[str],
                 wild_entries: List[str], permutation: bool, skip: List[str],
                 nested: bool = False) -> Path:
    """Save every input the user gave BEFORE any recon starts.

    Writes into the output directory:
      <base>/<target>/scope.txt      — every in-scope entry
      <base>/<target>/inputs.txt     — full run spec (choices, files used)
      <base>/<target>/config.txt     — active config snapshot
    """
    from datetime import datetime

    base = Path(cfg.output_base_dir()).expanduser()
    root = base / name
    root.mkdir(parents=True, exist_ok=True)

    all_entries = sorted(set(single_entries + wild_entries))
    (root / "scope.txt").write_text("\n".join(all_entries) + "\n", encoding="utf-8")

    plan_files = (
        "  WORKFLOW (stages — phases in [] run in parallel):\n"
        "  single   : [dns + live + ports + tech + urls] -> [params + js]\n"
        "  wildcard : [dns + passive + horizontal] -> [active] -> [vertical]\n"
        "             -> [merge #1] -> [live #1] -> [urls]\n"
        "             -> [merge #2] -> [live #2]\n"
        "             -> [js + tech + params] -> [ports + takeover]\n"
        "  network  : horizontal -> ports -> live\n"
        "  mixed    : single workflow first (-> <target>/single), then\n"
        "             wildcard workflow (-> <target>/wildcard)\n"
        "\n"
        f"  dns        <- {root}/scope.txt            (scripts/dnsrecon.py -l)\n"
        f"  passive    <- {root}/scope.txt            (subfinder -dL)\n"
        f"  active     <- {root}/scope.txt            (puredns bruteforce -d)\n"
        f"  vertical   <- {root}/scope.txt            (puredns + permutations)\n"
        f"  horizontal <- {root}/scope.txt            (scripts/asn.py --scope)\n"
        f"  merge      <- passive+active+vertical+horizontal.txt\n"
        f"                -> all_subdomains.txt + resolved_subdomains.txt\n"
        f"  live       <- {root}/probe_hosts.txt      (httpx -l, all_subdomains)\n"
        f"  ports      <- {root}/04-ports/scan_targets.txt  (naabu -list, resolved IPs)\n"
        f"  urls       <- {root}/harvest_input.txt    (scripts/harvester.py -l, roots+subs)\n"
        f"  js         <- {root}/katana_input.txt     (katana -list, alive)\n"
        f"  tech       <- {root}/tech_input.txt       (scripts/tech.py -l, alive)\n"
        f"  takeover   <- {root}/takeover_hosts.txt   (scripts/takeover.py -l, all_subdomains)\n"
    )

    lines = [
        "=" * 62,
        "  RECONK RUN SPEC",
        "=" * 62,
        f"  target      : {name}",
        f"  created     : {datetime.now().isoformat(timespec='seconds')}",
        f"  scope type  : {scope_type}",
        f"  base dir    : {base}",
        "",
        "  SINGLE DOMAINS (no subdomain enumeration):",
    ]
    lines += [f"    - {e}" for e in sorted(single_entries)] or ["    (none)"]
    lines += ["", "  WILDCARD SCOPES (full subdomain pipeline):"]
    lines += [f"    - {e}" for e in sorted(wild_entries)] or ["    (none)"]
    lines += [
        "",
        f"  permutation scan : {'yes' if permutation else 'no'}",
        f"  skipped phases   : {', '.join(sorted(skip)) or 'none'}",
        "",
        "  PHASE INPUT FILES (every tool is driven via -l / file args):",
        plan_files,
        "  OUTPUT:",
    ]
    if nested:
        if single_entries:
            lines.append(f"    single   -> {base / name / 'single'}")
        else:
            lines.append("    single   -> (not in this run)")
        if wild_entries:
            lines.append(f"    wildcard -> {base / name / 'wildcard'}")
        else:
            lines.append("    wildcard -> (not in this run)")
    else:
        lines.append(f"    run      -> {root}")
    lines.append("")
    (root / "inputs.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    import yaml

    (root / "config.txt").write_text(yaml.safe_dump(cfg.data, sort_keys=False), encoding="utf-8")
    return root / "inputs.txt"


def _tui_new_recon(cfg: Config) -> int:
    """Guided new-recon setup: collect ALL inputs first, save them into the
    output directory, then run every phase from the saved files."""
    import questionary

    # ---- 1. collect everything --------------------------------------- #
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

    single_entries: List[str] = []
    wild_entries: List[str] = []
    if scope_type.startswith("Single"):
        single_entries = _tui_collect_entries(
            questionary, "Single domain(s) in scope (e.g. example.com)"
        )
    elif scope_type.startswith("Wildcard"):
        wild_entries = _tui_collect_entries(
            questionary, "Wildcard scope(s) (e.g. *.example.com or example.com)"
        )
    else:  # both
        single_entries = _tui_collect_entries(
            questionary, "Single domain(s) in scope — all of them, then wildcards"
        )
        wild_entries = _tui_collect_entries(
            questionary, "Wildcard scope(s) (e.g. *.example.com or example.com)"
        )

    if not single_entries and not wild_entries:
        console.print("[red]! No scope given at all.[/red]")
        return 2

    permutation = True
    if wild_entries:
        permutation = _tui_permutation(questionary)

    skip = _ask_skip(questionary)
    if wild_entries and not permutation:
        skip = [s for s in skip if s != "vertical"] + ["vertical"]

    # ---- 2. save inputs into the output dir, THEN start recon -------- #
    nested = scope_type.startswith("Both")
    inputs_path = _save_inputs(
        cfg, name, scope_type, single_entries, wild_entries, permutation, skip,
        nested=nested,
    )
    console.print(f"  [green]✔ inputs saved: {inputs_path}[/green]")

    # ---- 3. run the engagements from the saved files ----------------- #
    rc = 0
    if single_entries:
        scope = Scope.from_input(name, ",".join(single_entries))
        rc |= _run_pipeline(cfg, scope, skip=skip, base_dir=str(cfg.output_base_dir()),
                            target_name=f"{name}/single" if nested else name)
    if wild_entries:
        scope = Scope.from_input(name, ",".join(wild_entries), force_wildcard=True)
        rc |= _run_pipeline(cfg, scope, skip=skip, base_dir=str(cfg.output_base_dir()),
                            target_name=f"{name}/wildcard" if nested else name)
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
