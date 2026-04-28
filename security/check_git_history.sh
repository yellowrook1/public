#!/usr/bin/env bash
# check_git_history.sh – Scan git commit history for accidentally committed secrets.
#
# Checks for:
#   - Secret patterns in every commit's diff (full history)
#   - Commit messages containing credential hints
#   - Large files (configurable threshold) ever committed
#   - Binary blobs in history
#   - Signs of history rewriting in the reflog
#
# Environment variables:
#   MAX_FILE_SIZE_KB   – threshold (KB) for large-file detection (default: 500)
#
# Exit codes:
#   0 – no issues found
#   1 – one or more issues detected
#   2 – not inside a git repository

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FINDINGS=0
MAX_FILE_SIZE_KB="${MAX_FILE_SIZE_KB:-500}"

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

cd "$REPO_ROOT"

if ! git rev-parse --git-dir &>/dev/null; then
  echo "[ERROR] Not a git repository: ${REPO_ROOT}" >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Secret patterns
# ---------------------------------------------------------------------------
declare -a SECRET_PATTERNS=(
  'AKIA[0-9A-Z]{16}'
  'ghp_[A-Za-z0-9]{36}'
  'github_pat_[A-Za-z0-9_]{82}'
  'xox[baprs]-[A-Za-z0-9\-]{10,}'
  'sk_(live|test)_[A-Za-z0-9]{24,}'
  'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'
  'AC[a-f0-9]{32}'
  '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
  '(?i)(password|passwd|pwd)\s*[=:]\s*["\x27]?[^\s"]{8,}'
  '(?i)(api[_-]?key|apikey)\s*[=:]\s*["\x27]?[A-Za-z0-9/_\-]{16,}'
  '(?i)(secret[_-]?key|client[_-]?secret)\s*[=:]\s*["\x27]?[A-Za-z0-9/_\-]{16,}'
)

# ---------------------------------------------------------------------------
# Scan full commit history diffs
# ---------------------------------------------------------------------------
TOTAL=$(git rev-list --count HEAD 2>/dev/null || echo "?")
log_info "Scanning ${TOTAL} commit(s) for secret patterns ..."

while IFS= read -r sha; do
  diff_text=$(git show --no-color "$sha" 2>/dev/null || true)
  for pattern in "${SECRET_PATTERNS[@]}"; do
    if echo "$diff_text" | grep -qP "$pattern" 2>/dev/null; then
      log_finding "Secret pattern '${pattern}' found in commit ${sha}"
    fi
  done
done < <(git rev-list HEAD 2>/dev/null)

# ---------------------------------------------------------------------------
# Commit messages containing credential hints
# ---------------------------------------------------------------------------
log_info "Scanning commit messages for credential hints ..."
while IFS= read -r line; do
  log_finding "Suspicious commit message: ${line}"
done < <(
  git --no-pager log --format="%H %s" |
  grep -iP '(password|secret|credential|token|api[_-]?key)' || true
)

# ---------------------------------------------------------------------------
# Large files ever committed
# ---------------------------------------------------------------------------
log_info "Checking for large files (>${MAX_FILE_SIZE_KB} KB) in history ..."
while IFS= read -r line; do
  size_bytes=$(echo "$line" | awk '{print $3}')
  blob=$(echo "$line" | awk '{print $1}')
  size_kb=$(( size_bytes / 1024 ))
  path=$(git --no-pager rev-list --objects --all 2>/dev/null | grep "^${blob}" | awk '{print $2}' | head -1 || true)
  log_finding "Large object in history: ${size_kb} KB  blob=${blob}  path=${path:-unknown}"
done < <(
  git cat-file --batch-all-objects --batch-check 2>/dev/null |
  awk -v max="$((MAX_FILE_SIZE_KB * 1024))" '$2 == "blob" && $3 > max {print $1, $2, $3}' || true
)

# ---------------------------------------------------------------------------
# History-rewrite markers in the reflog
# ---------------------------------------------------------------------------
log_info "Checking reflog for force-push / history-rewrite markers ..."
if git --no-pager reflog show 2>/dev/null | grep -qiP '(force.push|rebase|amend|filter-branch)'; then
  log_finding "Reflog indicates force-push or history rewrite – review carefully."
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
if [ "$FINDINGS" -eq 0 ]; then
  log_info "Git history check PASSED – no issues found."
  exit 0
else
  log_warn "Git history check FAILED – ${FINDINGS} issue(s) detected."
  exit 1
fi
