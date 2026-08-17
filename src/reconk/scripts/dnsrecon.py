#!/usr/bin/env python3
"""reconk dns — full DNS recon suite + zone transfer (AXFR) check.

One script, one text output. Merges what used to be split across
'dnsrecon_ultra' (records suite) and 'zonesniper' (AXFR):

  * A / AAAA / CNAME / NS / MX / TXT / SOA / CAA records
  * SPF + DMARC + DKIM (common selector probes)
  * DNSSEC presence (DS + DNSKEY)
  * wildcard detection (random label probe)
  * zone transfer attempts against every nameserver
  * PTR for the root/NS IPs

Usage:
  python dns.py -l domains.txt -o output.txt
  python dns.py -d example.com -o output.txt
  python dns.py -d example.com --axfr-only -o output.txt
"""

from __future__ import annotations

import argparse
import random
import shutil
import string
import subprocess
import sys
import time
from typing import List

try:
    from reconk.scripts.common import (
        append_line,
        clean_host,
        get_nameservers,
        read_lines,
        resolve,
        unique_preserve,
    )
except ImportError:
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from reconk.scripts.common import (
        append_line,
        clean_host,
        get_nameservers,
        read_lines,
        resolve,
        unique_preserve,
    )

DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "s1", "s2", "k1", "mail", "dkim", "em", "mandrill", "zoho"]

TAG = "\033[1;36m[*]\033[0m" if sys.stdout.isatty() else "[*]"
OK = "\033[1;32m[+]\033[0m" if sys.stdout.isatty() else "[+]"
WARN = "\033[1;33m[!]\033[0m" if sys.stdout.isatty() else "[!]"
BAD = "\033[1;31m[X]\033[0m" if sys.stdout.isatty() else "[X]"


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
def zone_transfer(domain: str, nameservers: List[str], out_path: str) -> List[str]:
    """Try AXFR against every NS via dig. Returns zone record lines."""
    if not shutil.which("dig"):
        log(f"  {WARN} dig not found in PATH — skipping zone transfer checks")
        append_line(out_path, f"ZONETRANSFER|{domain}|SKIPPED|dig missing")
        return []
    log(f"  {TAG} zone transfer check on {domain} — {len(nameservers)} NS")
    zone_lines: List[str] = []
    vulnerable = False
    for ns in nameservers:
        try:
            proc = subprocess.run(
                ["dig", f"@{ns}", domain, "AXFR", "+time=4", "+tries=1"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = proc.stdout.strip()
            if any(err in output.lower() for err in ("transfer failed", "communications error",
                                                     "connection timed out", "no servers could be reached",
                                                     "query refused")):
                log(f"    {WARN} {ns}: AXFR refused")
                continue
            lines = [l for l in output.splitlines() if l.strip() and not l.startswith(";")]
            if len(lines) > 3:
                log(f"    {BAD} {ns}: AXFR ALLOWED — zone transfer vulnerable!!")
                vulnerable = True
                for line in lines:
                    zone_lines.append(f"{domain} | AXFR {ns} | {line}")
                    append_line(out_path, f"ZONETRANSFER|{domain}|{ns}|{line}")
            else:
                log(f"    {OK} {ns}: AXFR denied")
        except subprocess.TimeoutExpired:
            log(f"    {WARN} {ns}: timed out")
        except Exception as e:  # noqa: BLE001
            log(f"    {WARN} {ns}: {e}")
    if not vulnerable:
        append_line(out_path, f"ZONETRANSFER|{domain}|CLEAN|all nameservers refuse AXFR")
    return zone_lines


def scan_domain(domain: str, out_path: str, do_axfr: bool, do_records: bool) -> None:
    domain = clean_host(domain)
    log(f"\n{TAG} === {domain} ===")
    append_line(out_path, "")
    append_line(out_path, f"== {domain} ==")

    nameservers = get_nameservers(domain)

    if do_records:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _resolve_parallel(tasks):
            """tasks: list of (label, host, rtype). Returns list of (label, records)."""
            with ThreadPoolExecutor(max_workers=16) as pool:
                futs = {pool.submit(resolve, host, rtype): (label,) for label, host, rtype in tasks}
                out = []
                for fut in as_completed(futs):
                    label = futs[fut][0]
                    try:
                        out.append((label, fut.result()))
                    except Exception:  # noqa: BLE001
                        out.append((label, []))
                return out

        # SOA + NS first (quick)
        soa = resolve(domain, "SOA")
        for r in soa:
            log(f"  SOA: {r}")
            append_line(out_path, f"SOA|{domain}|{r}")

        for ns in nameservers:
            log(f"  NS: {ns}")
            append_line(out_path, f"NS|{domain}|{ns}")

        # everything else in parallel
        tasks = []
        for host in (domain, f"www.{domain}"):
            for rtype in ("A", "AAAA", "CNAME"):
                tasks.append((f"{rtype}|{host}", host, rtype))
        for rtype in ("MX", "TXT", "CAA", "DS", "DNSKEY"):
            tasks.append((f"{rtype}|{domain}", domain, rtype))
        tasks.append(("DMARC|_dmarc", f"_dmarc.{domain}", "TXT"))
        tasks.append(("WILDCARD|*", "".join(random.choices(string.ascii_lowercase, k=12)) + "." + domain, "A"))

        for label, records in _resolve_parallel(tasks):
            if not records:
                continue
            kind, host = label.split("|", 1)
            if kind == "TXT":
                for r in records:
                    if "v=spf1" in r.lower():
                        log(f"  SPF: {r}")
                        append_line(out_path, f"SPF|{domain}|{r}")
                    else:
                        log(f"  TXT: {r}")
                        append_line(out_path, f"TXT|{domain}|{r}")
            elif kind == "WILDCARD":
                log(f"  {WARN} WILDCARD: *.{domain} resolves to {', '.join(records)} — beware of false positives")
                append_line(out_path, f"WILDCARD|{domain}|{' '.join(records)}")
            elif kind == "DMARC":
                for r in records:
                    log(f"  DMARC: {r}")
                    append_line(out_path, f"DMARC|{domain}|{r}")
            elif kind in ("DS", "DNSKEY"):
                log(f"  {kind}: {', '.join(records[:4])}")
                append_line(out_path, f"DNSSEC|{domain}|{kind} {' '.join(records)}")
            else:
                for r in records:
                    log(f"  {kind} {host}: {r}")
                    append_line(out_path, f"{kind}|{host}|{r}")

        # DMARC missing note
        dmarc = resolve(f"_dmarc.{domain}", "TXT")
        if not dmarc:
            log(f"  {WARN} DMARC: missing — mail spoofing possible")
            append_line(out_path, f"DMARC|{domain}|MISSING")

        # DNSSEC missing note
        if not resolve(domain, "DS") and not resolve(domain, "DNSKEY"):
            log("  DNSSEC: not signed (no DS/DNSKEY)")
            append_line(out_path, f"DNSSEC|{domain}|NOT SIGNED")

        # DKIM (parallel selector probes)
        def _dkim(sel):
            return sel, resolve(f"{sel}._domainkey.{domain}", "TXT")

        with ThreadPoolExecutor(max_workers=8) as pool:
            futs = {pool.submit(_dkim, sel): sel for sel in DKIM_SELECTORS}
            for fut in as_completed(futs):
                sel, recs = fut.result()
                if recs:
                    log(f"  DKIM {sel}._domainkey: present")
                    append_line(out_path, f"DKIM|{domain}|{sel}._domainkey present")

    if do_axfr:
        zone_transfer(domain, nameservers, out_path)


def main() -> int:
    parser = argparse.ArgumentParser(description="reconk dns — DNS records + zone transfer suite")
    grp = parser.add_mutually_exclusive_group(required=True)
    grp.add_argument("-d", "--domain", help="single domain")
    grp.add_argument("-l", "--list", help="file with domains (one per line)")
    parser.add_argument("-o", "--output", default="dns.txt", help="text output file")
    parser.add_argument("--no-records", action="store_true", help="skip the records suite")
    parser.add_argument("--axfr-only", action="store_true", help="only zone transfer checks")
    args = parser.parse_args()

    domains = [args.domain] if args.domain else read_lines(args.list)
    domains = unique_preserve(d for d in domains if d)
    if not domains:
        print("no domains given", file=sys.stderr)
        return 1

    do_records = not args.axfr_only and not args.no_records
    do_axfr = True

    # truncate the output file — this suite only ever appends, so a
    # resume/re-run would otherwise double every record
    try:
        with open(args.output, "w", encoding="utf-8"):
            pass
    except OSError as e:
        print(f"cannot write output {args.output}: {e}", file=sys.stderr)
        return 1

    t0 = time.monotonic()
    log(f"[*] DNS recon on {len(domains)} domain(s) — records={do_records} axfr={do_axfr}")
    for d in domains:
        scan_domain(d, args.output, do_axfr, do_records)
    log(f"\n{OK} DNS recon done in {time.monotonic() - t0:.1f}s — output: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
