#!/usr/bin/env bash
set -euo pipefail

# Ephemeral SBOM generator (Python) using mise + cdxgen.
# Environment overrides:
# MISE_PYTHON_VERSION Python version (default 3.10)
# MISE_NODE_VERSION Node version (default latest)
# SBOM_OUT Output filename (default sbom.json)
# Usage: bash .evergreen/generate-sbom.sh
PYTHON_VERSION="${MISE_PYTHON_VERSION:-3.10}"
NODE_VERSION="${MISE_NODE_VERSION:-latest}"
JQ_VERSION="${JQ_VERSION:-latest}"
OUT_JSON="${SBOM_OUT:-sbom.json}"

# Acquire version from pymongo/_version.py
if [[ ! -f pymongo/_version.py ]]; then
  log "Cannot find pymongo/_version.py"; exit 1;
fi
PROJECT_VERSION=$(grep -E '^__version__' pymongo/_version.py | head -1 | sed -E 's/__version__\s*=\s*"([^"]+)"/\1/')
if [[ -z "${PROJECT_VERSION}" ]]; then
  log "Failed to parse version from pymongo/_version.py"; exit 1;
fi
OUT_JSON="sbom.json"

log() { printf '\n[sbom] %s\n' "$*"; }

cleanup() {
  if [[ -d sbom-venv ]]; then
    deactivate 2>/dev/null || true
    rm -rf sbom-venv
  fi
}
trap cleanup EXIT

# Ensure mise is available (installed locally in $HOME) and PATH includes shims.
ensure_mise() {
  # Installer places binary in ~/.local/bin/mise by default.
  if ! command -v mise >/dev/null 2>&1; then
    log "Installing mise"
    curl -fsSL https://mise.run | bash >/dev/null 2>&1 || { log "mise install script failed"; exit 1; }
  fi

  # Ensure ~/.local/bin precedes so 'mise' is found even if shims absent.
  export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$HOME/.local/share/mise/bin:$PATH"
  if ! command -v mise >/dev/null 2>&1; then
    log "mise not found on PATH after install"; ls -al "$HOME/.local/bin" || true; exit 1
  fi
}

# Returns space-separated tool@version specs required for SBOM generation.
resolve_toolchain_flags() {
  printf 'python@%s node@%s jq@%s' "$PYTHON_VERSION" "$NODE_VERSION" "$JQ_VERSION"
}

# Builds the mise exec prefix for ephemeral command runs.
prepare_exec_prefix() {
  local tools
  tools="$(resolve_toolchain_flags)"
  echo "mise exec $tools --"
}

# Installs cdxgen if not available.
ensure_cdxgen() {
  if ! mise exec node@"$NODE_VERSION" -- cdxgen --version >/dev/null 2>&1; then
    log "Installing @cyclonedx/cdxgen"
    mise exec node@"$NODE_VERSION" -- npm install -g @cyclonedx/cdxgen || { log "Failed to install cdxgen"; exit 1; }
  fi
}

# Downloads CycloneDX CLI binary if not available.
ensure_cyclonedx_cli() {
  if [ ! -f /tmp/cyclonedx ]; then
    log "Downloading CycloneDX CLI"
    local arch
    arch="$(uname -m)"
    case "$arch" in
      x86_64) arch="x64" ;;
      aarch64) arch="arm64" ;;
      *) log "Unsupported architecture for CycloneDX CLI: $arch"; exit 1 ;;
    esac
    local url="https://github.com/CycloneDX/cyclonedx-cli/releases/latest/download/cyclonedx-linux-${arch}"
    curl -L -s -o /tmp/cyclonedx "$url" || { log "Failed to download CycloneDX CLI"; exit 1; }
    chmod +x /tmp/cyclonedx || { log "Failed to make CycloneDX CLI executable"; exit 1; }
  fi
}

# Executes cdxgen to generate SBOM.
generate_sbom() {
  log "Generating SBOM using cdxgen"
  local exec_prefix
  exec_prefix="$(prepare_exec_prefix)"

  log "Creating virtual environment"
  $exec_prefix python -m venv sbom-venv
  # shellcheck disable=SC1091
  source sbom-venv/bin/activate

  log "Installing dependencies"
  pip install -e .

  log "Generating SBOM"
  $exec_prefix cdxgen -t python --python-path sbom-venv/bin/python -o "$OUT_JSON" --spec-version 1.5 --json-pretty --json >/dev/null

  if ! grep -q 'CycloneDX' "$OUT_JSON"; then
    log "CycloneDX marker missing in SBOM"; exit 1
  fi

  log "SBOM generated"
}

# Installs required runtime versions into the local mise cache unconditionally.
# (mise skips download if already present.)
install_toolchains() {
  local tools
  tools="$(resolve_toolchain_flags)"
  log "Installing toolchains: $tools"
  mise install $tools >/dev/null
}

# Formats the SBOM JSON with jq (required). Exits non-zero if formatting fails.
format_sbom() {
  log "Formatting SBOM via jq@$JQ_VERSION"
  if ! mise exec jq@"$JQ_VERSION" -- jq . "$OUT_JSON" > "$OUT_JSON.tmp" 2>/dev/null; then
    log "jq formatting failed"; return 1
  fi
  mv "$OUT_JSON.tmp" "$OUT_JSON"
}

# Verifies the SBOM is valid CycloneDX format using CycloneDX CLI.
verify_sbom() {
  log "Verifying SBOM validity with CycloneDX CLI"
  local size
  size=$(stat -c%s "$OUT_JSON" 2>/dev/null || echo 0)
  if [ "$size" -lt 1000 ]; then
    log "SBOM file too small (<1000 bytes)"; exit 1
  fi
  if ! /tmp/cyclonedx validate --input-file "$OUT_JSON" --fail-on-errors >/dev/null 2>&1; then
    log "SBOM validation failed"; exit 1
  fi
  log "SBOM verified successfully"
}

main() {
  ensure_mise
  install_toolchains
  ensure_cdxgen
  ensure_cyclonedx_cli
  generate_sbom
  format_sbom
  verify_sbom
}

main "$@"
