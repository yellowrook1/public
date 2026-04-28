#!/usr/bin/env bash
# scan_secrets.sh – Scan repository files for hardcoded secrets and credentials.
#
# Checks for:
#   - Passwords / passphrases in plain text
#   - API keys, tokens, and bearer credentials
#   - AWS / GCP / Azure credential patterns
#   - Private-key PEM headers
#   - Base64-encoded payloads that look like secrets
#   - .env files committed to the repository
#   - Well-known service tokens (GitHub, Slack, Stripe, Twilio, etc.)
#
# Exit codes:
#   0 – no issues found
#   1 – one or more potential secrets detected

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FINDINGS=0
REPORT_FILE="${TMPDIR:-/tmp}/secret_scan_report_$$.txt"

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); printf '%s\n' "$*" >> "$REPORT_FILE"; }

# ---------------------------------------------------------------------------
# Pattern definitions: label -> PCRE regex
# ---------------------------------------------------------------------------
declare -A PATTERNS=(
  [password_assignment]='(?i)(password|passwd|pwd)\s*[=:]\s*["\x27]?[^\s"]{8,}'
  [api_key]='(?i)(api[_-]?key|apikey)\s*[=:]\s*["\x27]?[A-Za-z0-9/_\-]{16,}'
  [access_token]='(?i)(access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*["\x27]?[A-Za-z0-9._\-]{16,}'
  [secret_key]='(?i)(secret[_-]?key|client[_-]?secret)\s*[=:]\s*["\x27]?[A-Za-z0-9/_\-]{16,}'
  [aws_access_key_id]='AKIA[0-9A-Z]{16}'
  [aws_secret_access_key]='(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\x27]?[A-Za-z0-9+/]{40}'
  [gcp_service_account]='"type"\s*:\s*"service_account"'
  [private_key_pem]='-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
  [generic_base64_secret]='(?i)(secret|token|key)\s*[=:]\s*["\x27]?[A-Za-z0-9+/]{40,}={0,2}'
  [github_pat]='ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}'
  [slack_token]='xox[baprs]-[A-Za-z0-9\-]{10,}'
  [stripe_key]='sk_(live|test)_[A-Za-z0-9]{24,}'
  [sendgrid_key]='SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'
  [twilio_sid]='AC[a-f0-9]{32}'
  [heroku_api_key]='(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'
  [npm_token]='//registry\.npmjs\.org/:_authToken\s*='
  [connection_string]='(?i)(jdbc|mongodb|postgresql|mysql|redis)://[^:\s]+:[^@\s]+@'
  [mailchimp_key]='[0-9a-f]{32}-us[0-9]{1,2}'
  [azure_storage_key]='(?i)DefaultEndpointsProtocol=https;AccountName='
)

# ---------------------------------------------------------------------------
# Directories to skip
# ---------------------------------------------------------------------------
SKIP_DIRS=(.git node_modules vendor .venv __pycache__ dist build .cache)

build_prune_args() {
  local args=()
  for d in "${SKIP_DIRS[@]}"; do
    args+=(-o -name "$d" -prune)
  done
  echo "${args[@]}"
}

# ---------------------------------------------------------------------------
# Collect non-binary text files
# ---------------------------------------------------------------------------
mapfile -t FILES < <(
  eval "find '$REPO_ROOT' \\( -false $(build_prune_args) \\) -o -type f -print 2>/dev/null" |
  while IFS= read -r f; do
    if ! file --mime "$f" 2>/dev/null | grep -q 'charset=binary'; then
      echo "$f"
    fi
  done
)

: > "$REPORT_FILE"
log_info "Scanning ${#FILES[@]} file(s) under ${REPO_ROOT} ..."
echo ""

# ---------------------------------------------------------------------------
# Run each pattern over all collected files
# ---------------------------------------------------------------------------
for label in "${!PATTERNS[@]}"; do
  pattern="${PATTERNS[$label]}"
  while IFS= read -r match; do
    log_finding "[${label}] ${match}"
  done < <(grep -Pn "$pattern" "${FILES[@]}" 2>/dev/null || true)
done

# ---------------------------------------------------------------------------
# Flag any .env files tracked in git
# ---------------------------------------------------------------------------
while IFS= read -r env_file; do
  log_finding "[env_file_committed] Tracked .env file: ${env_file}"
done < <(git -C "$REPO_ROOT" ls-files --error-unmatch -- '*.env' '.env' 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$FINDINGS" -eq 0 ]; then
  log_info "Secret scan PASSED – no issues found."
  rm -f "$REPORT_FILE"
  exit 0
else
  log_warn "Secret scan FAILED – ${FINDINGS} potential secret(s) detected."
  log_warn "Full report saved to: ${REPORT_FILE}"
  exit 1
fi
