#!/usr/bin/env bash
# run_all_checks.sh – Master security examination runner.
#
# Runs every security check script in this directory and produces a
# consolidated summary report.
#
# Usage:
#   ./run_all_checks.sh [--fail-fast] [--report <file>]
#
#   --fail-fast    Stop after the first script that reports findings.
#   --report FILE  Write the consolidated report to FILE in addition to stdout.
#
# Exit codes:
#   0 – all checks passed
#   1 – one or more checks reported issues

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FAIL_FAST=false
REPORT_FILE=""

# ---------------------------------------------------------------------------
# Parse arguments
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fail-fast)  FAIL_FAST=true; shift ;;
    --report)     REPORT_FILE="$2"; shift 2 ;;
    *)            echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
  BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; YELLOW=''; GREEN=''; BOLD=''; NC=''
fi

# ---------------------------------------------------------------------------
# Ordered list of check scripts (edit to add/remove/reorder)
# ---------------------------------------------------------------------------
CHECKS=(
  scan_secrets.sh
  check_permissions.sh
  audit_contents.sh
  check_git_history.sh
  dependency_audit.sh
  check_workflows.sh
  integrity_check.sh
)

PASSED=0
FAILED=0
SKIPPED=0
declare -a FAILED_CHECKS=()

separator() { printf '%0.s─' {1..72}; echo; }

output() {
  echo -e "$*"
  [ -n "$REPORT_FILE" ] && echo -e "$*" >> "$REPORT_FILE"
}

# ---------------------------------------------------------------------------
# Initialise report file
# ---------------------------------------------------------------------------
if [ -n "$REPORT_FILE" ]; then
  : > "$REPORT_FILE"
  output "${BOLD}Security Examination Report${NC}"
  output "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  output "Repository: $(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || echo 'unknown')"
  output ""
fi

# ---------------------------------------------------------------------------
# Run each check
# ---------------------------------------------------------------------------
for check in "${CHECKS[@]}"; do
  script="${SCRIPT_DIR}/${check}"

  if [ ! -f "$script" ]; then
    output "${YELLOW}[SKIP]${NC}   ${check} (not found)"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  chmod +x "$script"

  separator
  output "${BOLD}Running: ${check}${NC}"
  separator

  exit_code=0
  if [ -n "$REPORT_FILE" ]; then
    bash "$script" 2>&1 | tee -a "$REPORT_FILE" || exit_code=$?
  else
    bash "$script" 2>&1 || exit_code=$?
  fi

  if [ "$exit_code" -eq 0 ]; then
    output "${GREEN}[PASS]${NC}   ${check}"
    PASSED=$((PASSED + 1))
  elif [ "$exit_code" -eq 2 ]; then
    output "${YELLOW}[SKIP]${NC}   ${check} (exit 2 – prerequisites not met)"
    SKIPPED=$((SKIPPED + 1))
  else
    output "${RED}[FAIL]${NC}   ${check}"
    FAILED=$((FAILED + 1))
    FAILED_CHECKS+=("$check")
    if $FAIL_FAST; then
      output "${RED}Stopping early due to --fail-fast.${NC}"
      break
    fi
  fi
  echo ""
done

# ---------------------------------------------------------------------------
# Final summary
# ---------------------------------------------------------------------------
separator
output "${BOLD}Security Examination Summary${NC}"
separator
output "  Passed : ${PASSED}"
output "  Failed : ${FAILED}"
output "  Skipped: ${SKIPPED}"

if [ "${#FAILED_CHECKS[@]}" -gt 0 ]; then
  output ""
  output "${RED}Failed checks:${NC}"
  for fc in "${FAILED_CHECKS[@]}"; do
    output "  • ${fc}"
  done
fi

if [ -n "$REPORT_FILE" ]; then
  output ""
  output "Report saved to: ${REPORT_FILE}"
fi

separator

if [ "$FAILED" -gt 0 ]; then
  exit 1
fi
exit 0
