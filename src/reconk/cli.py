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
from reconk.output import OutputTree, validate_target_name
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
        base = Path(base_dir) if base_dir else Path(cfg.output_base_dir()).expanduser()
        top = base / scope.name
        top.mkdir(parents=True, exist_ok=True)
        # persist the combined scope at the top level so list/resume/report
        # work for this target (each sub-run writes its own scope too)
        scope.to_file(top / "scope.txt")
        singles = [d for d in scope.domains if d not in scope.wildcards]
        wilds = scope.wildcards + scope.network_targets() + scope.orgs
        t0 = time.monotonic()
        rc = 0
        if singles:
            s_scope = Scope.from_input(scope.name, ",".join(singles))
            rc |= _run_pipeline(cfg, s_scope, skip=_filter_phases_for_mode(skip, "single"),
                                only=_filter_phases_for_mode(only, "single"),
                                base_dir=base_dir, verbose=verbose,
                                target_name=f"{scope.name}/single")
        if wilds:
            w_scope = Scope.from_input(scope.name, ",".join(wilds), force_wildcard=True)
            rc |= _run_pipeline(cfg, w_scope, skip=skip, only=only, base_dir=base_dir,
                                verbose=verbose, target_name=f"{scope.name}/wildcard")
        elapsed = time.monotonic() - t0
        # combined report + manifest at the top level
        top_out = OutputTree(base, scope.name)
        merged = {}
        for part in ("single", "wildcard"):
            part_report = build_report(OutputTree(base, f"{scope.name}/{part}"), scope, 0.0)
            for key, value in part_report["counts"].items():
                merged[key] = merged.get(key, 0) + value
        report = build_report(top_out, scope, elapsed)
        report["counts"] = merged
        txt = write_txt_report(report, top_out.cat("reports") / "summary.txt")
        top_out.save_manifest()
        console.print(f"  [green]Reports: {txt}[/green]")
        return rc

    base = Path(base_dir) if base_dir else Path(cfg.output_base_dir()).expanduser()
    out = OutputTree(base, target_name or scope.name)
    out.root.mkdir(parents=True, exist_ok=True)

    # persist scope
    scope.to_file(out.root / "scope.txt")

    console.print(Panel.fit(f"[bold]Target[/bold] [green]{out.target}[/green]", border_style="green"))
    console.print(scope.summary())

    log_dir = out.root / "logs" if str(cfg.get("output.save_tool_logs", "false")).lower() == "true" else None
    runner = CommandRunner(console, log_dir=log_dir, verbose=verbose)
    pipeline = Pipeline(cfg, scope, out, runner, console, skip=skip, only=only)

    t0 = time.monotonic()
    results = pipeline.run_all()
    elapsed = time.monotonic() - t0

    # report
    report = build_report(out, scope, elapsed)
    txt = write_txt_report(report, out.cat("reports") / "summary.txt")
    out.save_manifest()
    console.print(f"  [green]Reports: {txt}[/green]")

    return 2 if not results else (0 if all(r.ok for r in results) else 1)


# --------------------------------------------------------------------------- #
# subcommand handlers
# --------------------------------------------------------------------------- #
def _cmd_scan(args: argparse.Namespace, cfg: Config) -> int:
    try:
        scope = Scope.from_input(
            args.target,
            args.scope,
            args.file,
            force_wildcard=args.wildcard,
        )
    except FileNotFoundError as e:
        console.print(f"[red]! {e}[/red]")
        return 2
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
    if scope.is_empty:
        console.print(f"[red]! scope.txt for '{args.target}' is empty — nothing to resume[/red]")
        return 2
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
        return 0
    if args.init:
        dest = cfg.save()
        console.print(f"[green]Config written to {dest}[/green]")
        return 0
    console.print("[yellow]Pass --show to print the active config or --init to write it.[/yellow]")
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
#: phases that actually run per scope mode (subdomain enumeration and
#: takeover only exist in the wildcard workflow, etc.)
PHASES_SINGLE = ["dns", "live", "ports", "urls", "params", "js", "tech"]
PHASES_NETWORK = ["horizontal", "ports", "live"]


def _phases_for_mode(mode: str) -> List[str]:
    if mode == "single":
        return PHASES_SINGLE
    if mode == "network":
        return PHASES_NETWORK
    return list(MODULE_LABELS)  # wildcard / mixed


def _filter_phases_for_mode(phases: Optional[List[str]], mode: str) -> Optional[List[str]]:
    """Keep only the phases from `phases` that actually run in `mode`."""
    if not phases:
        return phases
    relevant = set(_phases_for_mode(mode))
    return [p for p in phases if p in relevant]


def _tui_collect_entries(questionary, label: str) -> List[str]:
    """Collect entries from the user, as many as they want to give."""
    entries: List[str] = []
    while True:
        more = (
            questionary.text(
                label,
                default="",
                instruction="comma/space separated — leave empty and press enter when done",
            ).ask()
            or ""
        )
        if more.strip():
            entries += [e.strip() for e in re.split(r"[\s,;]+", more) if e.strip()]
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


def _ask_skip(questionary, mode: str = "wildcard") -> List[str]:
    """Ask which phases to skip — only the phases relevant to `mode`."""
    relevant = _phases_for_mode(mode)
    chosen = questionary.checkbox(
        "Phases to SKIP (space to toggle, enter to continue)",
        choices=[questionary.Choice(MODULE_LABELS[p], value=p) for p in relevant],
        instruction="leave empty to run everything",
    ).ask()
    return list(chosen or [])


def _save_inputs(cfg: Config, name: str, scope_type: str, single_entries: List[str],
                 wild_entries: List[str], network_entries: List[str],
                 permutation: bool, skip: List[str], nested: bool = False) -> Path:
    """Save every input the user gave BEFORE any recon starts.

    Writes into the output directory:
      <base>/<target>/scope.txt      — every in-scope entry
      <base>/<target>/inputs.txt     — full run spec (choices, files used)
      <base>/<target>/config.txt     — active config snapshot
    """
    from datetime import datetime

    base = Path(cfg.output_base_dir()).expanduser()
    validate_target_name(name)
    root = base / name
    root.mkdir(parents=True, exist_ok=True)

    all_entries = sorted(set(single_entries + wild_entries + network_entries))
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
    lines += ["", "  NETWORK SCOPES (CIDRs / ASNs / IPs / orgs):"]
    lines += [f"    - {e}" for e in sorted(network_entries)] or ["    (none)"]
    lines += [
        "",
        (f"  permutation scan : {'yes' if permutation else 'no'}" if wild_entries
         else "  permutation scan : n/a (no wildcard scope)"),
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
    output directory, then run every phase from the saved files.

    The scan mode is detected from the input itself — no scope-type question:
      * example.com                -> single workflow
      * *.example.com              -> wildcard workflow (full subdomain pipeline)
      * example.com,*.foo.com      -> both, split and run one after the other
      * 1.2.3.0/24,AS12345         -> network workflow
    """
    import questionary

    # ---- 1. collect everything --------------------------------------- #
    name = questionary.text("Target / company name", default="").ask()
    if not name or not name.strip():
        console.print("[red]! No target name given.[/red]")
        return 2
    name = name.strip()

    entries = _tui_collect_entries(
        questionary, "Scope — domains, wildcards (*.example.com), CIDRs, ASNs"
    )
    if not entries:
        console.print("[red]! No scope given at all.[/red]")
        return 2

    # ---- 2. classify the input -> scan mode -------------------------- #
    scope = Scope.from_input(name, ",".join(entries))
    if scope.is_empty:
        console.print("[red]! Nothing recognisable in that scope.[/red]")
        return 2

    single_entries = [d for d in scope.domains if d not in scope.wildcards]
    wild_entries = [f"*.{w}" for w in scope.wildcards]
    network_entries = scope.network_targets() + scope.orgs

    if single_entries and (wild_entries or network_entries):
        mode, scope_type, nested = "mixed", "Both single + wildcard domains", True
    elif wild_entries:
        mode, scope_type, nested = "wildcard", "Wildcard domains — full subdomain enumeration", False
    elif network_entries:
        mode, scope_type, nested = "network", "Network scope — CIDRs / ASNs / IPs", False
    else:
        mode, scope_type, nested = "single", "Single domains — no subdomain enumeration", False

    permutation = True
    if wild_entries:
        permutation = _tui_permutation(questionary)

    skip = _ask_skip(questionary, mode)
    if wild_entries and not permutation:
        skip = [s for s in skip if s != "vertical"] + ["vertical"]

    # ---- 3. save inputs into the output dir, THEN start recon -------- #
    inputs_path = _save_inputs(
        cfg, name, scope_type, single_entries, wild_entries, network_entries,
        permutation, skip, nested=nested,
    )
    console.print(f"  [green]✔ inputs saved: {inputs_path}[/green]")

    # ---- 4. run the engagement from the saved files ------------------ #
    # mixed scope is split inside _run_pipeline: single workflow first,
    # then wildcard workflow -> <target>/single and <target>/wildcard
    return _run_pipeline(cfg, scope, skip=skip, base_dir=str(cfg.output_base_dir()),
                         target_name=name)


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

    # ask only about the phases that apply to this target's scope mode
    root = base / target
    force_wildcard = False
    wild_marker = root / "scope_wildcards.txt"
    if wild_marker.exists() and wild_marker.read_text().strip():
        force_wildcard = True
    scope_file = root / "scope.txt"
    try:
        scope = Scope.from_input(target, "", str(scope_file), force_wildcard=force_wildcard)
        mode = scope.mode
    except Exception:  # noqa: BLE001
        mode = "wildcard"
    skip = _ask_skip(questionary, mode)
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

    rc = 0
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
            return rc
        if action == "Start new recon (guided setup)":
            rc = _tui_scan(cfg)
        elif action == "Resume / partial run on existing target":
            rc = _tui_resume(cfg)
        elif action == "Show target report":
            rc = _tui_report(cfg)
        elif action == "List targets":
            rc = _cmd_list(argparse.Namespace(out=None), cfg)
        elif action == "Tool doctor":
            rc = _cmd_doctor(argparse.Namespace(), cfg)
        elif action == "Show / init config":
            rc = _cmd_config(argparse.Namespace(show=True), cfg)


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
        except ValueError as e:
            console.print(f"[red]! {e}[/red]")
            return 2

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
    except ValueError as e:
        console.print(f"[red]! {e}[/red]")
        return 2


if __name__ == "__main__":
    sys.exit(main())
