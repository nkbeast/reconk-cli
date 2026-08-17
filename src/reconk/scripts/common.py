#!/usr/bin/env python3
"""Shared helpers for the reconk native scripts.

Everything here is plain stdlib + dnspython; no secrets, no JSON output.
"""

from __future__ import annotations

import re
import socket
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set

import dns.exception
import dns.resolver

HOSTNAME_RE = re.compile(r"^([a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,}$")


# --------------------------------------------------------------------------- #
# text io
# --------------------------------------------------------------------------- #
def read_lines(path: str) -> List[str]:
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    out.append(line)
    except FileNotFoundError:
        pass
    return out


def append_line(path: str, line: str) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8", errors="replace") as fh:
        fh.write(line.rstrip() + "\n")


def is_hostname(value: str) -> bool:
    v = value.strip().rstrip(".").lstrip("*.")
    return bool(HOSTNAME_RE.match(v))


def clean_host(value: str) -> str:
    return value.strip().rstrip(".").lstrip("*.").lower()


# --------------------------------------------------------------------------- #
# DNS helpers (dnspython with socket fallbacks)
# --------------------------------------------------------------------------- #
def resolve(hostname: str, rtype: str = "A", timeout: float = 5.0) -> List[str]:
    """Resolve a record type; returns a list of string answers."""
    hostname = clean_host(hostname)
    if not hostname:
        return []
    try:
        answers = dns.resolver.resolve(hostname, rtype, lifetime=timeout)
        out = []
        for r in answers:
            out.append(str(r))
        return out
    except (dns.exception.DNSException, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except Exception:  # noqa: BLE001
        pass
    # fallback: A record via socket
    if rtype == "A":
        try:
            return [socket.gethostbyname(hostname)]
        except Exception:  # noqa: BLE001
            return []
    return []


def resolve_a(hostname: str) -> List[str]:
    ips: List[str] = []
    for r in resolve(hostname, "A"):
        if ":" not in r and r.count(".") == 3:
            ips.append(r)
    for r in resolve(hostname, "AAAA"):
        ips.append(r)
    return ips


def is_nxdomain(hostname: str) -> bool:
    """True when the hostname definitively does not resolve."""
    hostname = clean_host(hostname)
    if not hostname:
        return False
    try:
        dns.resolver.resolve(hostname, "A", lifetime=3.0)
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:  # noqa: BLE001
        # transient DNS failure — fail closed, do not call it dead
        return False


def cname_chain(hostname: str, limit: int = 6) -> List[str]:
    """Follow the CNAME chain; returns target hostnames."""
    chain: List[str] = []
    current = clean_host(hostname)
    for _ in range(limit):
        cnames = resolve(current, "CNAME")
        if not cnames:
            break
        target = clean_host(cnames[0])
        chain.append(target)
        current = target
    return chain


def get_nameservers(domain: str) -> List[str]:
    ns = resolve(domain, "NS")
    return [clean_host(x) for x in ns if is_hostname(x)]


# --------------------------------------------------------------------------- #
# misc
# --------------------------------------------------------------------------- #
def domain_roots() -> List[str]:
    """Load root domains from a scope file (first column)."""
    return []


def parse_scope_entries(lines: Iterable[str]) -> Iterator[tuple]:
    """Yield (kind, value) for scope lines: domain/wildcard/cidr/asn/ip/org."""
    import ipaddress
    import re as _re

    # ASNs must carry the AS prefix — a bare number is far more likely an
    # org name than a typo'd ASN
    asn_re = _re.compile(r"^AS(\d{1,10})$", _re.IGNORECASE)
    for raw in lines:
        raw = raw.strip()
        if not raw or raw.startswith("#"):
            continue
        line = raw.lower()
        if line.startswith("*."):
            yield ("wildcard", line[2:])
        elif "/" in line:
            try:
                ipaddress.ip_network(line, strict=False)
                yield ("cidr", line)
            except ValueError:
                yield ("domain", line)
        elif _re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", line):
            try:
                ipaddress.ip_address(line)
                yield ("ip", line)
            except ValueError:
                yield ("org", raw)
        elif asn_re.match(line):
            m = asn_re.fullmatch(line)
            if m and 1 <= int(m.group(1)) <= 4294967295:
                yield ("asn", f"AS{m.group(1)}")
        elif "." in line:
            yield ("domain", line.rstrip("."))
        else:
            # org names keep their original case for the bgpview search
            yield ("org", raw)


def unique_preserve(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        item = item.strip()
        if item and item not in seen:
            seen.add(item)
            out.append(item)
    return out


def in_domain(hostname: str, roots: List[str]) -> bool:
    h = clean_host(hostname)
    return any(h == r or h.endswith("." + r) for r in roots)
