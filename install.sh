#!/usr/bin/env bash
# Reconk CLI — installer
#
#   ./install.sh                # install dependencies + create ~/bin/reconk symlink
#   ./install.sh --dev          # also pip install -e . into a venv

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/bin"

echo "==> Reconk CLI installer (v1.0)"

# ---------------------------------------------------------------------------
# 1. python deps
# ---------------------------------------------------------------------------
if ! python3 -c "import rich, yaml, requests, aiohttp, dns, mmh3, questionary" 2>/dev/null; then
    echo "==> Installing python dependencies..."
    python3 -m pip install --user -q \
        rich PyYAML requests aiohttp dnspython mmh3 questionary
fi

# ---------------------------------------------------------------------------
# 2. dev venv (optional)
# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--dev" ]]; then
    echo "==> Creating dev venv..."
    python3 -m venv "${ROOT}/.venv"
    "${ROOT}/.venv/bin/pip" install -q -e "${ROOT}"
    echo "==> Dev install done. Activate with: source ${ROOT}/.venv/bin/activate"
fi

# ---------------------------------------------------------------------------
# 3. launcher symlink
# ---------------------------------------------------------------------------
mkdir -p "${BIN_DIR}"
if [[ -e "${BIN_DIR}/reconk" && ! -L "${BIN_DIR}/reconk" ]]; then
    echo "!! ${BIN_DIR}/reconk exists and is not a symlink — leaving it alone"
else
    ln -sfn "${ROOT}/reconk" "${BIN_DIR}/reconk"
    echo "==> Linked ${BIN_DIR}/reconk -> ${ROOT}/reconk"
fi

if [[ ":${PATH}:" != *":${BIN_DIR}:"* ]]; then
    echo "!! Add ${BIN_DIR} to your PATH:"
    echo '   echo '"'"'export PATH="$HOME/bin:$PATH"'"'"' >> ~/.bashrc'
fi

# ---------------------------------------------------------------------------
# 4. external binaries check
# ---------------------------------------------------------------------------
echo
echo "==> External tools:"
for tool in subfinder puredns dnsx httpx naabu katana anew gf; do
    if command -v "${tool}" >/dev/null 2>&1; then
        printf "    %-14s ✔\n" "${tool}"
    else
        printf "    %-14s ✗ missing\n" "${tool}"
    fi
done

echo
echo "==> Done. Run:  reconk"
