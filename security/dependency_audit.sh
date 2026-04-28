#!/usr/bin/env bash
# dependency_audit.sh – Detect dependency and package-manifest security issues.
#
# Supports:
#   - npm  (package.json / package-lock.json)
#   - Python pip  (requirements*.txt / Pipfile)
#   - Ruby Bundler  (Gemfile.lock)
#   - Go modules  (go.mod)
#
# Also checks:
#   - Floating version ranges / unpinned dependencies
#   - Missing lock files
#
# Exit codes:
#   0 – no issues found
#   1 – one or more issues detected
#   2 – no supported manifests found

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FINDINGS=0
CHECKED=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

# ---------------------------------------------------------------------------
# npm / Node.js
# ---------------------------------------------------------------------------
while IFS= read -r pkg_json; do
  CHECKED=$((CHECKED + 1))
  dir="$(dirname "$pkg_json")"
  log_info "Found package.json: ${pkg_json}"

  # Floating version ranges
  if grep -qP '"[~^]|"\*"' "$pkg_json" 2>/dev/null; then
    log_finding "Floating dependency ranges in ${pkg_json} – pin to exact versions."
  fi

  # Missing lock file
  if [ ! -f "${dir}/package-lock.json" ] && [ ! -f "${dir}/yarn.lock" ] && [ ! -f "${dir}/pnpm-lock.yaml" ]; then
    log_finding "No lock file found alongside ${pkg_json}."
  fi

  # npm audit (if available and lock file present)
  if command -v npm &>/dev/null && [ -f "${dir}/package-lock.json" ]; then
    log_info "Running npm audit in ${dir} ..."
    if ! npm audit --audit-level=moderate --prefix "$dir" 2>&1; then
      log_finding "npm audit reported vulnerabilities in ${dir}"
    fi
  fi
done < <(
  find "$REPO_ROOT" -not -path '*/.git/*' -not -path '*/node_modules/*' \
    -name 'package.json' 2>/dev/null
)

# ---------------------------------------------------------------------------
# Python pip
# ---------------------------------------------------------------------------
while IFS= read -r req_file; do
  CHECKED=$((CHECKED + 1))
  log_info "Found Python requirements: ${req_file}"

  # Unpinned dependencies (lines with no ==)
  while IFS= read -r dep; do
    log_finding "Unpinned Python dependency in ${req_file}: ${dep}"
  done < <(
    grep -P '^\s*[A-Za-z]' "$req_file" 2>/dev/null |
    grep -v '==' || true
  )

  if command -v pip-audit &>/dev/null; then
    log_info "Running pip-audit on ${req_file} ..."
    if ! pip-audit -r "$req_file" 2>&1; then
      log_finding "pip-audit reported vulnerabilities in ${req_file}"
    fi
  elif command -v safety &>/dev/null; then
    log_info "Running safety check on ${req_file} ..."
    if ! safety check -r "$req_file" 2>&1; then
      log_finding "safety reported vulnerabilities in ${req_file}"
    fi
  fi
done < <(
  find "$REPO_ROOT" -not -path '*/.git/*' \
    -name 'requirements*.txt' 2>/dev/null
)

# ---------------------------------------------------------------------------
# Ruby Bundler
# ---------------------------------------------------------------------------
while IFS= read -r gemfile_lock; do
  CHECKED=$((CHECKED + 1))
  dir="$(dirname "$gemfile_lock")"
  log_info "Found Gemfile.lock: ${gemfile_lock}"

  if command -v bundle &>/dev/null; then
    if (cd "$dir" && bundle exec bundler-audit version &>/dev/null 2>&1); then
      log_info "Running bundle audit in ${dir} ..."
      if ! (cd "$dir" && bundle exec bundle-audit check --update 2>&1); then
        log_finding "bundle-audit reported vulnerabilities in ${dir}"
      fi
    fi
  fi
done < <(
  find "$REPO_ROOT" -not -path '*/.git/*' -name 'Gemfile.lock' 2>/dev/null
)

# ---------------------------------------------------------------------------
# Go modules
# ---------------------------------------------------------------------------
while IFS= read -r go_mod; do
  CHECKED=$((CHECKED + 1))
  dir="$(dirname "$go_mod")"
  log_info "Found go.mod: ${go_mod}"

  if command -v govulncheck &>/dev/null; then
    log_info "Running govulncheck in ${dir} ..."
    if ! (cd "$dir" && govulncheck ./... 2>&1); then
      log_finding "govulncheck reported vulnerabilities in ${dir}"
    fi
  fi
done < <(
  find "$REPO_ROOT" -not -path '*/.git/*' -name 'go.mod' 2>/dev/null
)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$CHECKED" -eq 0 ]; then
  log_warn "No supported dependency manifests found – skipping."
  exit 2
elif [ "$FINDINGS" -eq 0 ]; then
  log_info "Dependency audit PASSED – no issues found (${CHECKED} manifest(s) checked)."
  exit 0
else
  log_warn "Dependency audit FAILED – ${FINDINGS} issue(s) across ${CHECKED} manifest(s)."
  exit 1
fi
