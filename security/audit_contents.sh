#!/usr/bin/env bash
# audit_contents.sh – Search file contents for sensitive or dangerous patterns.
#
# Checks for:
#   - Security-related TODO/FIXME/HACK notes
#   - Dangerous function calls (injection sinks: eval, exec, system, ...)
#   - SQL injection red flags
#   - Debug / development flags left enabled
#   - Hard-coded public IP addresses
#   - Internal / localhost URLs
#   - Commented-out credential blocks
#   - Suspicious large base64 blobs
#   - Insecure cryptographic primitives (MD5, SHA1, DES, RC4)
#   - Plain HTTP endpoints in config/code
#   - Disabled TLS certificate verification
#
# Exit codes:
#   0 – no issues found
#   1 – one or more suspicious patterns detected

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
log_finding() { echo -e "${RED}[FINDING][${1}]${NC} ${2}"; FINDINGS=$((FINDINGS + 1)); }

# ---------------------------------------------------------------------------
# Helper: run a grep pattern and emit findings
# ---------------------------------------------------------------------------
scan() {
  local severity="$1" label="$2" pattern="$3"
  while IFS= read -r match; do
    log_finding "${severity}:${label}" "${match}"
  done < <(
    grep -rPn \
      --exclude-dir='.git' \
      --exclude-dir='node_modules' \
      --exclude-dir='vendor' \
      --exclude-dir='.venv' \
      --exclude-dir='dist' \
      --exclude-dir='build' \
      "$pattern" "$REPO_ROOT" 2>/dev/null || true
  )
}

# ---------------------------------------------------------------------------
# Security TODO / FIXME notes
# ---------------------------------------------------------------------------
log_info "Scanning for security-related TODO/FIXME comments ..."
scan LOW  "security_note"   '(?i)(todo|fixme|hack|xxx)\s*[:\-]?\s*(security|vuln|inject|xss|sqli|csrf|auth|bypass|cred|overflow)'

# ---------------------------------------------------------------------------
# Injection sinks
# ---------------------------------------------------------------------------
log_info "Scanning for dangerous injection sink calls ..."
scan HIGH "php_shell_exec"       '(?i)\b(shell_exec|passthru|system|popen|proc_open)\s*\('
scan HIGH "python_os_system"     '\bos\.system\s*\('
scan HIGH "python_shell_true"    'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True'
scan HIGH "js_eval"              '(?<![A-Za-z_.])\beval\s*\('
scan HIGH "node_exec"            'child_process\.(exec|execSync|spawnSync)\s*\('
scan HIGH "ruby_exec"            '(?i)\b(eval|exec|system|%x\[)'

# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------
log_info "Scanning for SQL injection red flags ..."
scan HIGH "sql_concat"           '(?i)(SELECT|INSERT|UPDATE|DELETE)\s.+(\+|\|\|)\s*[\$\{]'
scan HIGH "sql_percent_format"   '(?i)(execute|query|cursor\.execute)\s*\(\s*[f"\x27].*%[sd]'
scan HIGH "sql_fstring"          '(?i)(execute|query)\s*\(\s*f["\x27].*\{'

# ---------------------------------------------------------------------------
# Debug / development flags
# ---------------------------------------------------------------------------
log_info "Scanning for debug/development flags ..."
scan MEDIUM "debug_true"        '(?i)\bDEBUG\s*[=:]\s*(true|1)\b'
scan LOW    "node_env_dev"      '(?i)\bNODE_ENV\s*[=:]\s*["\x27]?development'
scan LOW    "verbose_true"      '(?i)\bVERBOSE\s*[=:]\s*(true|1)\b'
scan MEDIUM "tls_disabled"      '(?i)(verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*false|InsecureSkipVerify\s*:\s*true)'

# ---------------------------------------------------------------------------
# Insecure cryptographic primitives
# ---------------------------------------------------------------------------
log_info "Scanning for insecure cryptographic primitives ..."
scan HIGH   "md5_usage"         '(?i)\b(md5|MD5)\s*\('
scan HIGH   "sha1_usage"        '(?i)\b(sha1|SHA1)\s*\('
scan MEDIUM "des_cipher"        '(?i)\b(3DES|TripleDES|DESede)\b'
scan MEDIUM "rc4_cipher"        '\bRC4\b'

# ---------------------------------------------------------------------------
# Plain HTTP endpoints
# ---------------------------------------------------------------------------
log_info "Scanning for plain-HTTP endpoints ..."
scan MEDIUM "plain_http"        '(?i)http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9]'

# ---------------------------------------------------------------------------
# Hard-coded public IP addresses (non-RFC-1918)
# ---------------------------------------------------------------------------
log_info "Scanning for hard-coded public IP addresses ..."
scan LOW "hardcoded_public_ip"  '\b(?!127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)([0-9]{1,3}\.){3}[0-9]{1,3}\b'

# ---------------------------------------------------------------------------
# Internal / localhost URLs
# ---------------------------------------------------------------------------
log_info "Scanning for internal/localhost URLs ..."
scan LOW    "localhost_url"     '(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)(:[0-9]+)?'
scan MEDIUM "internal_domain"   '(?i)https?://[a-z0-9._-]+\.(internal|local|intranet|corp)\b'

# ---------------------------------------------------------------------------
# Commented-out credential blocks
# ---------------------------------------------------------------------------
log_info "Scanning for commented-out credentials ..."
scan MEDIUM "commented_cred"    '(?i)(#|//|/\*)\s*(password|passwd|api[_-]?key|secret)\s*[=:]\s*\S+'

# ---------------------------------------------------------------------------
# Large base64 blobs (potential embedded secrets or binaries)
# ---------------------------------------------------------------------------
log_info "Scanning for suspicious large base64 blobs ..."
scan LOW "large_base64"         '[A-Za-z0-9+/]{80,}={0,2}'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$FINDINGS" -eq 0 ]; then
  log_info "Content audit PASSED – no issues found."
  exit 0
else
  log_warn "Content audit FAILED – ${FINDINGS} issue(s) detected."
  exit 1
fi
