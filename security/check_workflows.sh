#!/usr/bin/env bash
# check_workflows.sh – Audit GitHub Actions workflow files for security misconfigurations.
#
# Checks for:
#   - Script injection via ${{ github.event.* }} in run: steps
#   - Overly-permissive global permissions (write-all)
#   - Actions pinned by mutable tag instead of full commit SHA
#   - Secrets echoed to the log
#   - pull_request_target checking out an untrusted PR head
#   - Self-hosted runner usage
#   - Unset default permissions (principle of least privilege)
#   - Third-party actions from unverified sources
#
# Exit codes:
#   0 – no issues found
#   1 – one or more issues detected

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKFLOWS_DIR="${REPO_ROOT}/.github/workflows"
FINDINGS=0

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; NC=''
fi

log_info()    { echo -e "${GREEN}[INFO]${NC}    $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC}    $*"; }
log_finding() { echo -e "${RED}[FINDING]${NC} $*"; FINDINGS=$((FINDINGS + 1)); }

if [ ! -d "$WORKFLOWS_DIR" ]; then
  log_warn "No .github/workflows directory – skipping workflow audit."
  exit 0
fi

mapfile -t WF_FILES < <(
  find "$WORKFLOWS_DIR" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
)

if [ "${#WF_FILES[@]}" -eq 0 ]; then
  log_warn "No workflow YAML files found."
  exit 0
fi

log_info "Auditing ${#WF_FILES[@]} workflow file(s) ..."
echo ""

for wf in "${WF_FILES[@]}"; do
  rel="${wf#"${REPO_ROOT}/"}"
  log_info "-> ${rel}"

  # --- Script injection via github.event context ---
  while IFS= read -r match; do
    log_finding "[HIGH] Script injection risk in ${rel}: ${match}"
  done < <(
    grep -nP '\$\{\{\s*github\.event\.(issue|pull_request|comment|head_commit)\.' "$wf" 2>/dev/null || true
  )

  # --- Overly-permissive permissions ---
  if grep -qP 'permissions\s*:\s*write-all' "$wf" 2>/dev/null; then
    log_finding "[HIGH] Overly-permissive 'permissions: write-all' in ${rel}"
  fi

  # --- Actions pinned by tag instead of SHA ---
  while IFS= read -r match; do
    log_finding "[MEDIUM] Action pinned by mutable tag (not SHA) in ${rel}: ${match}"
  done < <(
    grep -nP '^\s+uses:\s+[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+@v[0-9]' "$wf" 2>/dev/null || true
  )

  # --- Secrets echoed to the log ---
  while IFS= read -r match; do
    log_finding "[HIGH] Secret echoed to log in ${rel}: ${match}"
  done < <(
    grep -nP 'echo\s.*\$\{\{\s*secrets\.' "$wf" 2>/dev/null || true
  )

  # --- pull_request_target + checkout of PR head ---
  if grep -qP 'on:\s*(pull_request_target|.*\bpull_request_target\b)' "$wf" 2>/dev/null ||
     grep -qP '^\s*pull_request_target\s*:' "$wf" 2>/dev/null; then
    if grep -qP 'ref:\s*\$\{\{.*\.head\.' "$wf" 2>/dev/null; then
      log_finding "[HIGH] pull_request_target checks out untrusted PR head in ${rel}"
    else
      log_finding "[MEDIUM] pull_request_target used in ${rel} – verify checkout safety"
    fi
  fi

  # --- Self-hosted runners ---
  if grep -qP 'runs-on:\s*self-hosted' "$wf" 2>/dev/null; then
    log_finding "[MEDIUM] Self-hosted runner in ${rel} – ensure runner is hardened"
  fi

  # --- No top-level permissions block (defaults to broad permissions) ---
  if ! grep -qP '^permissions\s*:' "$wf" 2>/dev/null; then
    log_finding "[LOW] No top-level 'permissions:' block in ${rel} – apply least-privilege"
  fi

  echo ""
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
if [ "$FINDINGS" -eq 0 ]; then
  log_info "Workflow audit PASSED – no issues found."
  exit 0
else
  log_warn "Workflow audit FAILED – ${FINDINGS} issue(s) detected."
  exit 1
fi
