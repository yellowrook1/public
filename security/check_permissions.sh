#!/usr/bin/env bash
# check_permissions.sh – Audit file and directory permission hygiene.
#
# Checks for:
#   - World-writable files
#   - World-writable directories
#   - SUID / SGID bits on regular files
#   - Unexpected executable bits on data/config file types
#   - Overly-permissive shell scripts (group- or world-writable)
#   - Sensitive files (private keys, certs) with loose permissions
#
# Exit codes:
#   0 – no issues found
#   1 – one or more permission issues detected

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FINDINGS=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

# Portable stat (Linux vs macOS)
stat_perm() {
  stat -c '%a %n' "$1" 2>/dev/null || stat -f '%p %N' "$1" 2>/dev/null || echo "unknown $1"
}

GIT_EXCLUDE=(-not -path '*/.git/*')

# ---------------------------------------------------------------------------
# World-writable files
# ---------------------------------------------------------------------------
log_info "Checking for world-writable files ..."
while IFS= read -r f; do
  log_finding "World-writable file: $(stat_perm "$f")"
done < <(find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type f -perm -o+w 2>/dev/null)

# ---------------------------------------------------------------------------
# World-writable directories
# ---------------------------------------------------------------------------
log_info "Checking for world-writable directories ..."
while IFS= read -r d; do
  log_finding "World-writable directory: $(stat_perm "$d")"
done < <(find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type d -perm -o+w 2>/dev/null)

# ---------------------------------------------------------------------------
# SUID / SGID bits on regular files
# ---------------------------------------------------------------------------
log_info "Checking for SUID/SGID bits ..."
while IFS= read -r f; do
  log_finding "SUID/SGID bit set: $(stat_perm "$f")"
done < <(find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)

# ---------------------------------------------------------------------------
# Unexpected executable bits on data / config file types
# ---------------------------------------------------------------------------
NON_EXEC_EXTS=(txt md json yaml yml xml csv html htm css ini cfg conf toml
               png jpg jpeg gif svg ico bmp pdf zip tar gz log)
log_info "Checking for unexpected executable bits on data/config files ..."
for ext in "${NON_EXEC_EXTS[@]}"; do
  while IFS= read -r f; do
    log_finding "Unexpected +x bit on *.${ext}: $(stat_perm "$f")"
  done < <(find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type f -name "*.${ext}" -perm -u+x 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Shell scripts that are group- or world-writable
# ---------------------------------------------------------------------------
log_info "Checking for overly-permissive shell scripts ..."
while IFS= read -r f; do
  log_finding "Overly-permissive shell script: $(stat_perm "$f")"
done < <(
  find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type f \
    \( -name '*.sh' -o -name '*.bash' -o -name '*.zsh' \) \
    -perm /022 2>/dev/null
)

# ---------------------------------------------------------------------------
# Sensitive files with loose permissions (private keys, certificates)
# ---------------------------------------------------------------------------
log_info "Checking permissions on sensitive file types ..."
SENSITIVE_PATTERNS=(*.pem *.key *.p12 *.pfx *.cer *.crt id_rsa id_dsa id_ecdsa id_ed25519)
for pattern in "${SENSITIVE_PATTERNS[@]}"; do
  while IFS= read -r f; do
    perms=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%p' "$f" 2>/dev/null || echo "unknown")
    # Warn if readable by group (middle digit >= 4) or by others (last digit >= 4)
    if echo "$perms" | grep -qP '^[0-7]?[0-7]([4-7])[0-7]$|^[0-7]?[0-7][0-7]([4-7])$'; then
      log_finding "Sensitive file is group/world-readable: $(stat_perm "$f")"
    fi
  done < <(find "$REPO_ROOT" "${GIT_EXCLUDE[@]}" -type f -name "$pattern" 2>/dev/null)
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$FINDINGS" -eq 0 ]; then
  log_info "Permission audit PASSED – no issues found."
  exit 0
else
  log_warn "Permission audit FAILED – ${FINDINGS} issue(s) detected."
  exit 1
fi
