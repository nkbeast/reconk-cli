# Reconk CLI

**Recon isn't a phase. It's an obsession.**

Reconk is an end-to-end bug bounty reconnaissance orchestrator with an
interactive TUI. It drives battle-tested external binaries (subfinder,
puredns, httpx, naabu, katana) plus its own fast native Python scripts for
everything else — DNS, ASN expansion, URL harvesting, tech fingerprinting
and takeover checks. Every phase streams live into your terminal and saves
its own text file the moment it finishes.

- 🎛️ **Guided interactive setup** — target name → scope type (single /
  wildcard / both) → inputs → permutation scan? → run. Single domains run
  first, wildcard scope runs second.
- ⚡ **Live streaming** — every tool runs in an animated panel; you see
  subfinder, puredns, httpx and the native scripts working in real time.
- 📁 **Separate outputs, saved one by one** — each script writes its own
  `txt` output into a numbered category directory as soon as it completes.
  No JSON anywhere.
- 🧠 **Scope-aware workflow** — single-domain scope skips subdomain
  enumeration entirely; wildcard scope runs the full pipeline; network
  scope (CIDR/ASN/IP) runs the horizontal + ports phases.
- 🏃 **Fast by default** — subfinder uses its fast source set (optional
  `-all`), the native scripts are async / threaded, and heavy work is
  parallelised.

## Install

```bash
./install.sh                 # python deps + ~/bin/reconk
# or
./install.sh --dev           # + editable install into .venv
```

External tools (must be in `PATH`):

| Tool       | Used for                          |
|------------|-----------------------------------|
| subfinder  | passive subdomain enumeration     |
| puredns    | active brute-force + resolution   |
| httpx      | live host filtering               |
| naabu      | port scanning                     |
| katana     | JS crawling                       |
| waybackurls, gau | extra URL sources           |
| anew, gf   | dedupe + param triage             |

## Quick start

```bash
./reconk                     # interactive TUI menu
./reconk scan shop --scope shop.com --wildcard --skip ports,urls
./reconk resume shop --only live,tech
./reconk doctor
```

## Guided TUI flow

1. **Target name** — output directory name.
2. **Scope type**
   - *Single domains* — ask for the domains, skip subdomain enumeration.
   - *Wildcard domains* — ask for the wildcard scopes, then ask whether to
     run the **permutation scan** (vertical). Full pipeline.
   - *Both* — collect all single domains first, then all wildcard scopes,
     then the permutation question. **Single engagement runs first**, then
     the wildcard engagement.
3. **Phases to skip** — multi-select of any phase (dns, passive, merge,
   live, ports, ...). Leave empty to run everything.
4. Everything you answered is saved to the target directory **before any
   recon starts**: `scope.txt`, `inputs.txt` (full run spec) and
   `config.txt` (active config snapshot). Then phases stream live and save
   their outputs as they complete.

## Native scripts

`src/reconk/scripts/` — self-contained, text-only, usable standalone:

| Script            | Replaces                       | What it does |
|-------------------|--------------------------------|--------------|
| `dnsrecon.py`     | dnsrecon_ultra + zonesniper    | full DNS record suite (A/AAAA/CNAME/NS/MX/TXT/SPF/DMARC/DKIM/CAA/DNSSEC), wildcard detection, **zone transfer (AXFR)** check against every NS |
| `asn.py`          | asn_recon                      | domain→ASN (RDAP), ASN→prefixes (radb/bgpview), host discovery (fping/TCP), PTR + CT logs + TLS SAN hostname harvesting |
| `harvester.py`    | spidercrawl + waybackurls + gau | async multi-source URL harvest: wayback CDX, commoncrawl, OTX, crtsh, rapiddns, hackertarget, optional urlscan/virustotal/github |
| `tech.py`         | tech_fingerprint               | header / cookie / title / generator / body / favicon-hash fingerprinting |
| `takeover.py`     | dnsx CNAME check               | CNAME chain + dead-target detection across 45+ cloud providers |

## Output layout

```
~/Documents/bugbounty/reconk/<target>/
├── scope.txt                # every in-scope entry
├── inputs.txt               # full run spec (choices, files used)
├── config.txt               # active config snapshot
├── logs/                    # per-phase command logs
├── 01-dns/                  # dns.txt — records + zone transfer
├── 02-subdomains/           # passive.txt / active.txt / vertical.txt / horizontal.txt
│                            # + all_subdomains.txt (merged, in-scope, unique)
│                            # + resolved_subdomains.txt (subset that resolves)
├── 03-live/                 # alive.txt, alive_details.txt, status_codes.txt
├── 04-ports/                # naabu_ports.txt, host_port_summary.txt, prefixes.txt
├── 05-urls/                 # all_urls.txt + sources/<source>.txt + harvest_input.txt
├── 06-parameters/           # param_urls.txt, param_keys.txt, gf_*.txt
├── 07-js/                   # js_files.txt, js_endpoints.txt, js_secrets.txt
├── 08-tech/                 # tech.txt
├── 09-takeover/             # takeover.txt
└── 10-reports/              # summary.txt
```

The **merge phase** (wildcard runs only, right after horizontal) collapses
every subdomain source — passive, active, vertical, horizontal and
URL-harvested hosts — into one canonical `all_subdomains.txt`, drops
out-of-scope and wildcard entries, and writes the resolvable subset to
`resolved_subdomains.txt` (via dnsx). Everything downstream (live, ports,
urls, js, tech, takeover) reads those two files instead of re-merging
sources itself.

For "both" scopes the runs are separated:

```
<target>/single/     (runs first — no subdomain enumeration)
<target>/wildcard/   (full subdomain pipeline)
```

## Configuration

`config/config.yaml` (overridable in `~/.config/reconk/config.yaml`):

```yaml
output:
  base_dir: "~/Documents/bugbounty/reconk"
tools:
  resolvers: ".../resolvers.txt"
  subdomain_wordlist: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  permutation_wordlist: ".../deepmagic.com-prefixes-top500.txt"
  subfinder_config: "~/.config/subfinder/provider-config.yaml"
api_keys:
  urlscan: ""
  virustotal: ""
  github_token: ""
scan:
  naabu_top_ports: "1000"
  httpx_threads: "100"
  katana_depth: "3"
  brute_size: "small"        # small | medium | large
  subfinder_all: "false"     # true = query ALL sources (slow)
```

## License

MIT
