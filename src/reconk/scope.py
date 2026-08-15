"""Scope parsing and classification.

A scope can contain any mix of:
  * root domains            -> example.com
  * wildcards               -> *.example.com
  * CIDR blocks             -> 1.2.3.0/24
  * ASNs                    -> AS12345 (or 12345)
  * organisation names      -> "Example Corp" (for ASN-based horizontal recon)
  * plain IPs               -> 8.8.8.8

Everything is normalised and deduplicated, then classified so each
pipeline phase knows exactly which targets apply to it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

_WILDCARD_RE = re.compile(r"^\*\.(.+)$")
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ASN_RE = re.compile(r"^(?:AS)?(\d{1,10})$", re.IGNORECASE)
_TLD_BLOCK = (
    "com", "net", "org", "io", "co", "ai", "dev", "app", "xyz", "info",
    "biz", "me", "tv", "cc", "in", "tech", "online", "site", "store",
    "cloud", "uk", "us", "ca", "au", "de", "fr", "nl", "ru", "jp", "cn",
    "br", "mx", "in", "za", "se", "no", "fi", "dk", "pl", "it", "es",
    "ch", "at", "be", "ie", "pt", "gr", "tr", "il", "ae", "sg", "hk",
    "kr", "tw", "th", "vn", "ph", "id", "my", "nz", "ar", "cl", "pe",
    "co.uk", "co.in", "com.au", "co.jp", "com.br", "co.nz", "gov.in",
    "org.uk", "ac.uk", "gov.uk", "com.sg", "com.hk", "com.my", "com.pk",
)


@dataclass
class Scope:
    """Normalised scope for a single target engagement.

    The scope *mode* determines which pipeline phases are in scope:

    * ``wildcard``  — ``*.example.com`` or user-declared wildcard.
      Subdomain enumeration (passive/active/vertical/horizontal),
      takeover and ASN expansion are all IN scope.
    * ``single``    — exact domains only (``example.com``).
      Subdomain enumeration / takeover / ASN expansion are OUT of scope.
      Only the root domain (+www, +explicitly listed hosts) is attacked.
    * ``network``   — CIDRs / ASNs / IPs only. Pure network phase.
    * ``mixed``     — combination; each part follows its own rules.
    """

    name: str
    domains: List[str] = field(default_factory=list)
    wildcards: List[str] = field(default_factory=list)
    cidrs: List[str] = field(default_factory=list)
    asns: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    orgs: List[str] = field(default_factory=list)
    raw_entries: List[str] = field(default_factory=list)
    #: forces wildcard interpretation even without a `*.` prefix
    force_wildcard: bool = False

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_input(
        cls,
        name: str,
        target: str,
        file: Optional[str] = None,
        force_wildcard: bool = False,
    ) -> "Scope":
        """Build a scope from a comma/space separated target string and/or file."""
        scope = cls(name=name, force_wildcard=force_wildcard)
        entries: List[str] = []
        if target:
            entries += [e.strip().lower() for e in re.split(r"[\s,]+", target) if e.strip()]
        if file:
            fpath = Path(file).expanduser()
            if not fpath.exists():
                raise FileNotFoundError(f"Scope file not found: {fpath}")
            for raw in fpath.read_text(errors="replace").splitlines():
                line = raw.strip()
                if line and not line.startswith("#"):
                    entries += [e.strip().lower() for e in re.split(r"[\s,]+", line) if e.strip()]

        scope.raw_entries = entries
        for entry in entries:
            scope._classify(entry)

        # When only wildcards are given, their base domains are also in scope.
        for wc in scope.wildcards:
            if wc not in scope.domains:
                scope.domains.append(wc)

        scope.domains = sorted(set(scope.domains))
        scope.wildcards = sorted(set(scope.wildcards))
        scope.cidrs = sorted(set(scope.cidrs))
        scope.asns = sorted(set(scope.asns))
        scope.ips = sorted(set(scope.ips))
        scope.orgs = sorted(set(scope.orgs))
        return scope

    # ------------------------------------------------------------------ #
    # Classification
    # ------------------------------------------------------------------ #
    def _classify(self, entry: str) -> None:
        # Wildcard
        m = _WILDCARD_RE.match(entry)
        if m:
            self.wildcards.append(m.group(1))
            return

        # CIDR / IP
        if "/" in entry or _IP_RE.match(entry):
            try:
                if "/" in entry:
                    net = ipaddress.ip_network(entry, strict=False)
                    self.cidrs.append(str(net))
                else:
                    self.ips.append(entry)
                return
            except ValueError:
                pass  # fall through, maybe an org/domain

        # ASN
        m = _ASN_RE.match(entry)
        if m and 1 <= int(m.group(1)) <= 4294967295:
            self.asns.append(f"AS{m.group(1)}")
            return

        # Domain-ish? has a dot and TLD block
        if "." in entry:
            domain = entry.rstrip(".")
            if self._looks_like_domain(domain):
                self.domains.append(domain)
                return

        # Everything else is treated as an organisation name
        self.orgs.append(entry)

    @staticmethod
    def _looks_like_domain(value: str) -> bool:
        if not re.match(r"^[a-z0-9][a-z0-9\-.]*$", value):
            return False
        parts = value.split(".")
        if len(parts) < 2:
            return False
        return parts[-1] in _TLD_BLOCK or parts[-2] in _TLD_BLOCK

    # ------------------------------------------------------------------ #
    # Query helpers
    # ------------------------------------------------------------------ #
    @property
    def is_empty(self) -> bool:
        return not (self.domains or self.cidrs or self.asns or self.ips or self.orgs)

    @property
    def has_web_targets(self) -> bool:
        return bool(self.domains or self.wildcards)

    @property
    def has_network_targets(self) -> bool:
        return bool(self.cidrs or self.asns or self.ips or self.orgs)

    # ------------------------------------------------------------------ #
    # Scope mode
    # ------------------------------------------------------------------ #
    @property
    def is_wildcard(self) -> bool:
        """True when subdomain enumeration is in scope."""
        if self.force_wildcard:
            return bool(self.domains)
        return bool(self.wildcards) and not self.domains

    @property
    def is_single(self) -> bool:
        """True when only exact domains are in scope (no subdomains)."""
        if self.force_wildcard or self.wildcards:
            return False
        return bool(self.domains) and not self.has_network_targets

    @property
    def is_network_only(self) -> bool:
        return not self.has_web_targets and self.has_network_targets

    @property
    def mode(self) -> str:
        if self.is_wildcard:
            return "wildcard"
        if self.is_single:
            return "single"
        if self.is_network_only:
            return "network"
        return "mixed"

    def hosts_to_probe(self) -> List[str]:
        """Hosts that are directly in scope for probing.

        * wildcard mode: nothing here — the subdomain phases feed this later
        * single mode: root domains + ``www`` + any hosts explicitly listed
        * network mode: empty (ports/httpx operate on IPs)
        """
        hosts: List[str] = []
        if self.is_single:
            for domain in self.domains:
                hosts.append(domain)
                if domain not in ("www." + domain,):
                    hosts.append(f"www.{domain}")
            # Hosts that are themselves subdomains were listed explicitly
            # (e.g. www.example.com) — they are in scope by definition.
            for domain in self.domains:
                if domain.startswith("www."):
                    hosts.append(domain)
        return sorted(set(hosts))

    def all_domains(self) -> List[str]:
        """Root domains used for subdomain enumeration / URL harvesting."""
        return self.domains

    def network_targets(self) -> List[str]:
        """CIDRs + ASNs + IPs + orgs, in the form asn_recon understands."""
        out: List[str] = []
        out += self.asns
        out += self.cidrs
        out += self.ips
        return out

    def summary(self) -> str:
        lines = [
            f"  Mode      : {self.mode.upper()}" + ("  (subdomain enumeration IN scope)" if self.is_wildcard else "  (subdomain enumeration OUT of scope)" if self.is_single else ""),
            f"  Domains   : {len(self.domains)}  ({', '.join(self.domains[:8])}{'...' if len(self.domains) > 8 else ''})",
            f"  Wildcards : {len(self.wildcards)}  ({', '.join(self.wildcards[:4])}{'...' if len(self.wildcards) > 4 else ''})",
            f"  CIDRs     : {len(self.cidrs)}  ({', '.join(self.cidrs[:4])}{'...' if len(self.cidrs) > 4 else ''})",
            f"  ASNs      : {len(self.asns)}  ({', '.join(self.asns[:4])}{'...' if len(self.asns) > 4 else ''})",
            f"  IPs       : {len(self.ips)}  ({', '.join(self.ips[:4])}{'...' if len(self.ips) > 4 else ''})",
            f"  Orgs      : {len(self.orgs)}  ({', '.join(self.orgs[:4])}{'...' if len(self.orgs) > 4 else ''})",
        ]
        return "\n".join(lines)

    def to_file(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = list(self.domains) + list(self.wildcards) + list(self.cidrs) + list(self.asns) + list(self.ips) + list(self.orgs)
        path.write_text("\n".join(sorted(set(lines))) + "\n")
        return path
