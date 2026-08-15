#!/usr/bin/env bash
# Reconk CLI — installer (v1.0)
#
#   ./install.sh                # check OS + python, install deps + recon tools,
#                               #   link ~/bin/reconk, then grant recon access
#   ./install.sh --dev          # also pip install -e . into a venv
#
# Everything is verified BEFORE recon access is granted:
#   1. OS prerequisites (python3 >= 3.9, git, curl, go)
#   2. python dependencies (pip)
#   3. external recon tools — missing ones are auto-installed
#      (apt first, then `go install`). If a tool cannot be installed,
#      the exact command is printed and the installer exits — install
#      it manually, then re-run this script.
#   4. ~/bin/reconk launcher + PATH, then the recon access summary.

set -euo pipefail

VERSION="1.0"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/bin"
GO_BIN="$(go env GOPATH 2>/dev/null || echo "${HOME}/go")/bin"

# recon tools reconk drives, with their `go install` package paths
GO_INSTALL=(
    "subfinder|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "httpx|github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "naabu|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "katana|github.com/projectdiscovery/katana/cmd/katana@latest"
    "dnsx|github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "puredns|github.com/d3mondev/puredns/v2@latest"
    "anew|github.com/tomnomnom/anew@latest"
    "gf|github.com/tomnomnom/gf@latest"
)

# tools available in distro repos (kali / apt)
APT_TOOLS="subfinder dnsx httpx naabu katana puredns anew gf"

say()  { printf "\033[1;36m==> %s\033[0m\n" "$*"; }
ok()   { printf "\033[1;32m    %-16s ✔ %s\033[0m\n" "$1" "$2"; }
fail() { printf "\033[1;31m    %-16s ✗ %s\033[0m\n" "$1" "$2"; }

die() {
    echo
    printf "\033[1;31m[!] %s\033[0m\n" "$1"
    echo "    install it manually, then re-run:  $0"
    exit 1
}

echo
say "Reconk CLI installer v${VERSION}"
say "Checking OS prerequisites before granting recon access..."
echo

# ---------------------------------------------------------------------------
# 0. root/sudo handling for apt
# ---------------------------------------------------------------------------
SUDO=""
if [[ "$(id -u)" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    fi
fi

# ---------------------------------------------------------------------------
# 1. OS prerequisites
# ---------------------------------------------------------------------------
if command -v python3 >/dev/null 2>&1; then
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        ok "python3" "v$(python3 --version 2>&1 | awk '{print $2}')"
    else
        fail "python3" "too old — reconk needs >= 3.9"
        die "upgrade python3 to >= 3.9 (apt install python3)"
    fi
else
    fail "python3" "not found"
    die "missing python3 — run: ${SUDO} apt-get install -y python3 python3-pip"
fi

for tool in git curl go; do
    if command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool}" "found ($(command -v "${tool}"))"
        continue
    fi
    fail "${tool}" "not found"
    echo "    trying: ${SUDO} apt-get install -y ${tool} ..."
    if [[ -n "${SUDO}" || "$(id -u)" -eq 0 ]] \
        && "${SUDO}" apt-get install -y -q "${tool}" >/dev/null 2>&1 \
        && command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool}" "installed via apt"
    else
        die "missing OS tool: ${tool} — run: ${SUDO} apt-get install -y ${tool}"
    fi
done

# ---------------------------------------------------------------------------
# 2. python dependencies
# ---------------------------------------------------------------------------
echo
say "Python dependencies..."
if python3 -c "import rich, yaml, requests, aiohttp, dns, mmh3, questionary" 2>/dev/null; then
    ok "python deps" "already present"
else
    echo "    installing rich PyYAML requests aiohttp dnspython mmh3 questionary ..."
    if python3 -m pip install --user -q rich PyYAML requests aiohttp dnspython mmh3 questionary; then
        ok "python deps" "installed via pip --user"
    elif python3 -m pip install -q --break-system-packages rich PyYAML requests aiohttp dnspython mmh3 questionary; then
        ok "python deps" "installed via pip --break-system-packages"
    else
        die "python deps failed — run: python3 -m pip install rich PyYAML requests aiohttp dnspython mmh3 questionary"
    fi
fi

# ---------------------------------------------------------------------------
# 3. external recon tools — install what is missing
# ---------------------------------------------------------------------------
echo
say "External recon tools (installing missing ones)..."

install_tool() {
    local tool="$1" pkg="$2"
    echo "    → ${tool} missing, installing..."
    # 1) distro repo (kali/apt)
    if [[ "${APT_TOOLS}" == *" ${tool} "* || "${APT_TOOLS}" == "${tool}"* ]] \
        && { [[ -n "${SUDO}" || "$(id -u)" -eq 0 ]]; } \
        && "${SUDO}" apt-get install -y -q "${tool}" >/dev/null 2>&1 \
        && command -v "${tool}" >/dev/null 2>&1; then
        return 0
    fi
    # 2) go install
    if command -v go >/dev/null 2>&1 && go install "${pkg}" 2>/dev/null; then
        if command -v "${tool}" >/dev/null 2>&1; then
            return 0
        fi
        if [[ -x "${GO_BIN}/${tool}" ]]; then
            mkdir -p "${BIN_DIR}"
            ln -sfn "${GO_BIN}/${tool}" "${BIN_DIR}/${tool}"
            return 0
        fi
    fi
    return 1
}

for entry in "${GO_INSTALL[@]}"; do
    tool="${entry%%|*}"
    pkg="${entry##*|}"
    if command -v "${tool}" >/dev/null 2>&1; then
        ok "${tool}" "$(command -v "${tool}")"
        continue
    fi
    if install_tool "${tool}" "${pkg}"; then
        ok "${tool}" "installed"
    else
        fail "${tool}" "could not be installed"
        die "missing tool: ${tool}
    go install ${pkg}   (or: ${SUDO} apt-get install -y ${tool})"
    fi
done

# gf needs its pattern files under ~/.gf (best effort)
if command -v gf >/dev/null 2>&1 && [[ ! -d "${HOME}/.gf" ]]; then
    echo "    setting up gf patterns in ~/.gf ..."
    TMP_GF="$(mktemp -d)"
    git clone -q --depth 1 https://github.com/tomnomnom/gf "${TMP_GF}/gf" 2>/dev/null \
        && mkdir -p "${HOME}/.gf" \
        && cp "${TMP_GF}"/gf/examples/*.json "${HOME}/.gf/" 2>/dev/null || true
    rm -rf "${TMP_GF}"
fi

# ---------------------------------------------------------------------------
# 4. launcher symlink
# ---------------------------------------------------------------------------
echo
say "Launcher..."
mkdir -p "${BIN_DIR}"
if [[ -e "${BIN_DIR}/reconk" && ! -L "${BIN_DIR}/reconk" ]]; then
    echo "    !! ${BIN_DIR}/reconk exists and is not a symlink — leaving it alone"
else
    ln -sfn "${ROOT}/reconk" "${BIN_DIR}/reconk"
    ok "reconk" "linked → ${BIN_DIR}/reconk"
fi
if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    echo "    !! Add ${BIN_DIR} to your PATH:"
    echo "       echo 'export PATH=\"\$HOME/bin:\$PATH\"' >> ~/.bashrc"
fi

# ---------------------------------------------------------------------------
# 5. dev venv (optional)
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--dev" ]]; then
    echo
    say "Dev venv..."
    python3 -m venv "${ROOT}/.venv"
    "${ROOT}/.venv/bin/pip" install -q -e "${ROOT}"
    ok "dev venv" "activate with: source ${ROOT}/.venv/bin/activate"
fi

# ---------------------------------------------------------------------------
# 6. recon access granted
# ---------------------------------------------------------------------------
echo
echo "================================================================"
echo "  ✅ RECON ACCESS GRANTED — reconk v${VERSION}"
echo "================================================================"
for entry in "${GO_INSTALL[@]}"; do
    tool="${entry%%|*}"
    if command -v "${tool}" >/dev/null 2>&1; then
        printf "    %-14s ✔ %s\n" "${tool}" "$(command -v "${tool}")"
    else
        printf "    %-14s ✔ %s\n" "${tool}" "${BIN_DIR}/${tool}"
    fi
done
echo
echo "  Run:  reconk"
echo "  Verify:  reconk doctor"
echo "================================================================"