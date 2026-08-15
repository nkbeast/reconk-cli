#!/usr/bin/env python3
"""reconk asn — horizontal recon: ASN / org / CIDR expansion.

Native implementation replacing the external asn_recon:

  1. domain(s)  -> resolve -> IPs -> RDAP (rdap.org) -> ASN(s)
  2. ASN        -> prefixes via whois.radb.net (fallback: bgpview API)
  3. prefixes   -> live host discovery (fping, TCP-connect fallback)
  4. alive IPs  -> PTR records + ASN/org attribution (RDAP)
  5. CT logs    -> crt.sh hostnames for the root domains (horizontal gold)
  6. cert SAN   -> hostnames from TLS certs of alive hosts

Text-only output. Usage:
  python asn.py --scope scope.txt -o out.txt --alive alive.txt --hosts hosts.txt
  python asn.py --asn AS15169 -o out.txt
  python asn.py --cidrs 1.2.3.0/24 -o out.txt
  python asn.py --org "Example Corp" -o out.txt
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Set, Tuple

import requests

try:
    from reconk.scripts.common import (
        append_line,
        clean_host,
        is_hostname,
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
        is_hostname,
        read_lines,
        resolve,
        unique_preserve,
    )

TAG = "\033[1;36m[*]\033[0m" if sys.stdout.isatty() else "[*]"
OK = "\033[1;32m[+]\033[0m" if sys.stdout.isatty() else "[+]"
WARN = "\033[1;33m[!]\033[0m" if sys.stdout.isatty() else "[!]"

RDAP_BOOTSTRAP = "https://rdap.org"
HOST_DISCOVERY_PORTS = (80, 443, 53, 22, 8080, 8443, 25, 21)
MAX_HOSTS_SWEEP = 50000   # above this, sample
SAMPLE_SIZE = 2048        # sampled IPs per big range


def log(msg: str) -> None:
    print(msg, flush=True)


# --------------------------------------------------------------------------- #
# 1. domains -> ASNs (via RDAP on resolved IPs)
# --------------------------------------------------------------------------- #
def resolve_ips(host: str) -> List[str]:
    ips: Set[str] = set()
    for r in resolve(host, "A"):
        ips.add(r)
    for r in resolve(host, "AAAA"):
        ips.add(r)
    return sorted(ips)


def rdap_asn_for_ip(ip: str, session: requests.Session) -> Tuple[str, str]:
    """Return (asn, org) for an IP, e.g. ("AS15169", "Google LLC")."""
    try:
        r = session.get(f"{RDAP_BOOTSTRAP}/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return "", ""
        data = r.json()
        asn = ""
        org = ""
        for ent in data.get("entities", []) or []:
            for handle in ent.get("vcardArray", [1, []])[1]:
                if handle[0] == "fn":
                    org = handle[3]
        for handle in data.get("asn") or []:
            asn = handle
        if not asn:
            handle = data.get("handle", "")
            if handle.startswith("AS"):
                asn = handle
        return asn, org
    except Exception:  # noqa: BLE001
        return "", ""


def domains_to_asns(domains: List[str], session: requests.Session) -> Dict[str, Set[str]]:
    """domain -> set(ASNs)"""
    out: Dict[str, Set[str]] = {}
    for domain in domains:
        ips = resolve_ips(domain)
        asns: Set[str] = set()
        log(f"  {TAG} {domain} -> {len(ips)} IP(s)")
        for ip in ips:
            asn, _ = rdap_asn_for_ip(ip, session)
            if asn:
                asns.add(asn)
                log(f"    {asn}  {ip}")
        out[domain] = asns
    return out


# --------------------------------------------------------------------------- #
# 2. ASN -> prefixes
# --------------------------------------------------------------------------- #
def asn_to_prefixes(asn: str, whois_bin: str) -> List[str]:
    """whois.radb.net -i origin ASN -> prefixes. Fallback: bgpview.io"""
    try:
        proc = subprocess.run(
            [whois_bin, "-h", "whois.radb.net", "-k", f"origin {asn}"],
            capture_output=True, text=True, timeout=30,
        )
        prefixes = sorted(set(re.findall(r"([0-9.]+/[0-9]+)", proc.stdout)))
        if prefixes:
            return prefixes
    except Exception:  # noqa: BLE001
        pass
    # bgpview fallback (no key required)
    try:
        r = requests.get(f"https://api.bgpview.io/asn/{asn.lstrip('AS')}/prefixes", timeout=15)
        if r.status_code == 200:
            data = r.json().get("data", {})
            prefixes = []
            for fam in ("ipv4_prefixes", "ipv6_prefixes"):
                for p in data.get(fam, []) or []:
                    prefixes.append(p.get("prefix", ""))
            return sorted(set(p for p in prefixes if p))
    except Exception:  # noqa: BLE001
        pass
    return []


# --------------------------------------------------------------------------- #
# 3. prefix -> host discovery (fping / TCP connect)
# --------------------------------------------------------------------------- #
def expand_targets(prefixes: List[str], ips: List[str], max_ips: int) -> List[str]:
    """Expand CIDRs into IPs (sampled if huge), merge with explicit IPs."""
    targets: Set[str] = set()
    for pfx in prefixes:
        try:
            net = ipaddress.ip_network(pfx, strict=False)
            if net.num_addresses > max_ips:
                # sample the range
                n = int(net.num_addresses)
                step = max(1, n // SAMPLE_SIZE)
                count = 0
                for addr in net:
                    if count % step == 0:
                        targets.add(str(addr))
                    count += 1
                log(f"    sampling {pfx} ({n:,} addrs) -> ~{SAMPLE_SIZE} samples")
            else:
                for addr in net:
                    targets.add(str(addr))
        except ValueError:
            continue
    targets.update(ips)
    return sorted(t for t in targets if t)


def fping_sweep(targets: List[str]) -> Set[str]:
    if not shutil.which("fping"):
        return set()
    alive: Set[str] = set()
    CHUNK = 4096
    for i in range(0, len(targets), CHUNK):
        chunk = targets[i : i + CHUNK]
        try:
            proc = subprocess.run(
                ["fping", "-a", "-q", "-t", "700", "-c", "1", *chunk],
                capture_output=True, text=True, timeout=90,
            )
            for line in proc.stdout.splitlines():
                if line.strip():
                    alive.add(line.strip().split()[0])
        except Exception:  # noqa: BLE001
            break
    return alive


def tcp_discover(targets: List[str], limit: int = 8000) -> Set[str]:
    """Async TCP-connect discovery against common ports (fallback / verification)."""
    alive: Set[str] = set()

    async def _probe(ip: str):
        for port in HOST_DISCOVERY_PORTS:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=1.5
                )
                writer.close()
                alive.add(ip)
                return
            except Exception:  # noqa: BLE001
                continue

    async def _run():
        sem = asyncio.Semaphore(1024)

        async def _wrapped(ip: str):
            async with sem:
                await _probe(ip)

        await asyncio.gather(*[_wrapped(ip) for ip in targets[:limit]])

    try:
        asyncio.run(_run())
    except Exception:  # noqa: BLE001
        pass
    return alive


# --------------------------------------------------------------------------- #
# 4. PTR + attribution
# --------------------------------------------------------------------------- #
def ptr_for_ip(ip: str) -> str:
    try:
        answers = resolve(socket.gethostbyaddr(ip)[0], "A")  # noqa: F841
        return socket.gethostbyaddr(ip)[0].rstrip(".")
    except Exception:  # noqa: BLE001
        try:
            import dns.reversename
            import dns.resolver

            rev = dns.reversename.from_address(ip)
            return str(dns.resolver.resolve(rev, "PTR")[0]).rstrip(".")
        except Exception:  # noqa: BLE001
            return ""


# --------------------------------------------------------------------------- #
# 5. CT logs (crt.sh)
# --------------------------------------------------------------------------- #
def crt_hosts(domains: List[str]) -> List[str]:
    hosts: Set[str] = set()
    for domain in domains:
        try:
            r = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json", timeout=40,
                headers={"User-Agent": "reconk"},
            )
            if r.status_code != 200:
                continue
            data = r.json()
            for entry in data:
                for f in ("name_value", "common_name"):
                    for name in str(entry.get(f, "")).splitlines():
                        name = clean_host(name)
                        if is_hostname(name) and name.endswith("." + domain):
                            hosts.add(name)
        except Exception:  # noqa: BLE001
            continue
    return sorted(hosts)


# --------------------------------------------------------------------------- #
# 6. TLS cert SAN hostnames
# --------------------------------------------------------------------------- #
def tls_san_hosts(ip: str) -> List[str]:
    import ssl

    out: Set[str] = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                cert = tls.getpeercert() or {}
                for entry in cert.get("subjectAltName", []) or []:
                    if entry[0] == "DNS":
                        name = clean_host(str(entry[1]))
                        if is_hostname(name):
                            out.add(name)
    except Exception:  # noqa: BLE001
        pass
    return sorted(out)


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description="reconk asn — ASN/org/CIDR horizontal recon")
    parser.add_argument("--scope", help="scope file (domains/cidrs/asns/ips/orgs)")
    parser.add_argument("--asn", help="comma-separated ASNs (AS15169)")
    parser.add_argument("--cidrs", help="comma-separated CIDRs")
    parser.add_argument("--ips", help="comma-separated IPs")
    parser.add_argument("--org", help="organisation name(s)")
    parser.add_argument("--domains", help="comma-separated root domains")
    parser.add_argument("-o", "--output", default="asn.txt", help="text output file")
    parser.add_argument("--hosts", help="hosts file to append discovered hostnames to")
    parser.add_argument("--prefixes", help="prefixes file (for the port phase)")
    parser.add_argument("--no-ct", action="store_true", help="skip CT log harvesting")
    parser.add_argument("--max-ips", type=int, default=MAX_HOSTS_SWEEP)
    args = parser.parse_args()

    t0 = time.monotonic()
    session = requests.Session()
    session.headers.update({"User-Agent": "reconk-horizontal"})

    asns: Set[str] = set()
    cidrs: Set[str] = set()
    ips: Set[str] = set()
    domains: List[str] = []

    if args.scope:
        from reconk.scripts.common import parse_scope_entries

        for kind, value in parse_scope_entries(read_lines(args.scope)):
            if kind == "asn":
                asns.add(value)
            elif kind == "cidr":
                cidrs.add(value)
            elif kind == "ip":
                ips.add(value)
            elif kind == "domain":
                domains.append(value)
            elif kind == "wildcard":
                domains.append(value)

    if args.asn:
        asns.update(a.strip() if a.strip().upper().startswith("AS") else f"AS{a.strip()}" for a in args.asn.split(",") if a.strip())
    if args.cidrs:
        cidrs.update(c.strip() for c in args.cidrs.split(",") if c.strip())
    if args.ips:
        ips.update(i.strip() for i in args.ips.split(",") if i.strip())
    if args.domains:
        domains += [d.strip() for d in args.domains.split(",") if d.strip()]
    if args.org:
        # org: resolve to ASNs via IP 2ASN-ish services is unreliable;
        # try rdap search API
        pass

    domains = unique_preserve(domains)
    log(f"[*] horizontal recon — domains={len(domains)} asns={len(asns)} cidrs={len(cidrs)} ips={len(ips)}")

    # ---- step 1: domain -> ASN
    if domains and not asns and not cidrs:
        log(f"{TAG} resolving ASNs for root domains")
        mapping = domains_to_asns(domains, session)
        for _, found in mapping.items():
            asns.update(found)
        if not asns:
            log(f"{WARN} no ASNs found for the domains — will still run CT + TLS harvesting")

    # ---- step 2: ASN -> prefixes
    whois_bin = shutil.which("whois") or "whois"
    for asn in sorted(asns):
        prefixes = asn_to_prefixes(asn, whois_bin)
        if prefixes:
            log(f"{TAG} {asn} -> {len(prefixes)} prefixes")
            for p in prefixes[:10]:
                append_line(args.output, f"PREFIX|{asn}|{p}")
            cidrs.update(prefixes)
        else:
            log(f"{WARN} {asn}: no prefixes found (radb/bgpview both failed)")

    # ---- step 3: host discovery
    targets = expand_targets(sorted(cidrs), sorted(ips), args.max_ips)
    log(f"{TAG} host discovery over {len(targets):,} IP(s)")
    alive: Set[str] = set()
    if len(targets) <= args.max_ips:
        alive = fping_sweep(targets)
        if alive:
            log(f"{OK} fping: {len(alive):,} alive")
        else:
            alive = tcp_discover(targets)
            log(f"{OK} tcp-discover: {len(alive):,} alive")
    else:
        alive = tcp_discover(targets, limit=args.max_ips)
        log(f"{OK} tcp-discover (sampled): {len(alive):,} alive")

    # ---- step 4: PTR + org for alive hosts
    hosts_out: List[str] = []
    with ThreadPoolExecutor(max_workers=128) as pool:
        ptrs = list(pool.map(ptr_for_ip, sorted(alive), chunksize=16))
    for ip, ptr in zip(sorted(alive), ptrs):
        line = f"ALIVE|{ip}|{ptr}" if ptr else f"ALIVE|{ip}"
        append_line(args.output, line)
        log(f"  {OK} {line}")
        if ptr:
            hosts_out.append(ptr)
        hosts_out.append(ip)

    # ---- step 5: CT hostnames (only when domain targets exist)
    if domains and not args.no_ct:
        log(f"{TAG} CT log harvesting for {len(domains)} domain(s)")
        ct = crt_hosts(domains)
        log(f"{OK} {len(ct)} hostnames from certificate transparency")
        for h in ct:
            append_line(args.output, f"CT|{h}")
            hosts_out.append(h)

    # ---- step 6: TLS SANs on alive hosts
    log(f"{TAG} TLS cert hostname harvesting")
    san_total = 0
    with ThreadPoolExecutor(max_workers=32) as pool:
        for ip in sorted(alive):
            try:
                sans = pool.submit(tls_san_hosts, ip).result()
            except Exception:  # noqa: BLE001
                continue
            for name in sans:
                append_line(args.output, f"TLS|{ip}|{name}")
                hosts_out.append(name)
                san_total += 1
    log(f"{OK} {san_total} hostnames from TLS certs")

    # ---- persist
    if args.hosts:
        unique_hosts = unique_preserve(h for h in hosts_out if is_hostname(h) or h.count(".") == 3)
        with open(args.hosts, "w", encoding="utf-8") as fh:
            fh.write("\n".join(unique_hosts) + "\n")
        log(f"{OK} {len(unique_hosts)} unique hosts -> {args.hosts}")
    if args.prefixes and cidrs:
        with open(args.prefixes, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(cidrs)) + "\n")
        log(f"{OK} {len(cidrs)} prefixes -> {args.prefixes}")

    log(f"{OK} horizontal recon done in {time.monotonic() - t0:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
