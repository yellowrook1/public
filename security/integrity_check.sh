#!/usr/bin/env bash
# integrity_check.sh – Generate and/or verify SHA-256 checksums for repository files.
#
# Usage:
#   ./integrity_check.sh generate   – create security/.checksums (baseline)
#   ./integrity_check.sh verify     – verify files against the stored baseline
#   ./integrity_check.sh            – auto: verify if baseline exists, else generate
#
# Exit codes:
#   0 – all files match (verify) or baseline written (generate)
#   1 – one or more files differ / are missing / are unexpected
#   2 – bad arguments or missing tools

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SECURITY_DIR="${REPO_ROOT}/security"
CHECKSUM_FILE="${SECURITY_DIR}/.checksums"
FINDINGS=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

# ---------------------------------------------------------------------------
# Require sha256sum or shasum
# ---------------------------------------------------------------------------
if command -v sha256sum &>/dev/null; then
  SHA_CMD=(sha256sum)
elif command -v shasum &>/dev/null; then
  SHA_CMD=(shasum -a 256)
else
  echo "[ERROR] Neither sha256sum nor shasum found." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Collect files to checksum (exclude .git and the checksum file itself)
# ---------------------------------------------------------------------------
collect_files() {
  find "$REPO_ROOT" \
    -not -path '*/.git/*' \
    -not -path "${CHECKSUM_FILE}" \
    -type f | sort
}

hash_file() {
  "${SHA_CMD[@]}" "$1" | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# Generate baseline
# ---------------------------------------------------------------------------
cmd_generate() {
  log_info "Generating SHA-256 checksums -> ${CHECKSUM_FILE}"
  : > "$CHECKSUM_FILE"
  local count=0
  while IFS= read -r f; do
    rel="${f#"${REPO_ROOT}/"}"
    printf '%s  %s\n' "$(hash_file "$f")" "$rel" >> "$CHECKSUM_FILE"
    count=$((count + 1))
  done < <(collect_files)
  log_info "Baseline written: ${count} file(s)."
}

# ---------------------------------------------------------------------------
# Verify against baseline
# ---------------------------------------------------------------------------
cmd_verify() {
  if [ ! -f "$CHECKSUM_FILE" ]; then
    log_warn "No baseline found at ${CHECKSUM_FILE}. Run: $0 generate"
    exit 1
  fi

  log_info "Verifying checksums against baseline ..."

  declare -A EXPECTED
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    h="${line%% *}"
    rel="${line#*  }"
    EXPECTED["$rel"]="$h"
  done < "$CHECKSUM_FILE"

  while IFS= read -r f; do
    rel="${f#"${REPO_ROOT}/"}"
    actual="$(hash_file "$f")"
    if [ -z "${EXPECTED[$rel]+_}" ]; then
      log_finding "NEW (untracked) file: ${rel}"
    elif [ "${EXPECTED[$rel]}" != "$actual" ]; then
      log_finding "MODIFIED: ${rel}  (expected ${EXPECTED[$rel]}, got ${actual})"
    fi
  done < <(collect_files)

  for rel in "${!EXPECTED[@]}"; do
    [ ! -f "${REPO_ROOT}/${rel}" ] && log_finding "DELETED: ${rel}"
  done

  echo ""
  if [ "$FINDINGS" -eq 0 ]; then
    log_info "Integrity check PASSED – all files match the baseline."
    exit 0
  else
    log_warn "Integrity check FAILED – ${FINDINGS} discrepancy(-ies) detected."
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
MODE="${1:-auto}"
case "$MODE" in
  generate) cmd_generate ;;
  verify)   cmd_verify   ;;
  auto)
    if [ -f "$CHECKSUM_FILE" ]; then cmd_verify; else cmd_generate; fi
    ;;
  *)
    echo "Usage: $0 [generate|verify]" >&2
    exit 2
    ;;
esac
