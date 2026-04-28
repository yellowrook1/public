# Security Examination Suite

This directory contains a comprehensive set of security examination scripts for the repository.

## Scripts

| Script | Purpose |
|---|---|
| `scan_secrets.sh` | Scan file contents for hardcoded secrets, credentials and tokens |
| `check_permissions.sh` | Audit file and directory permission hygiene |
| `audit_contents.sh` | Detect dangerous code patterns (injection sinks, insecure crypto, etc.) |
| `integrity_check.sh` | Generate / verify SHA-256 file checksums |
| `check_git_history.sh` | Scan full git history for accidentally committed secrets |
| `dependency_audit.sh` | Detect vulnerable or unpinned dependencies (npm, pip, bundler, Go) |
| `check_workflows.sh` | Audit GitHub Actions workflows for security misconfigurations |
| `run_all_checks.sh` | **Master runner** – executes all of the above and summarises results |

## Quick start

```bash
# Run every check
bash security/run_all_checks.sh

# Run a single check
bash security/scan_secrets.sh

# Save a full report to a file
bash security/run_all_checks.sh --report /tmp/security_report.txt

# Stop at the first failure
bash security/run_all_checks.sh --fail-fast
```

## What each script detects

### `scan_secrets.sh`
- Passwords / passphrases assigned in plain text
- API keys, access tokens, bearer credentials
- AWS access key IDs and secret access keys
- GCP service-account JSON files
- PEM-encoded private keys
- GitHub PATs, Slack tokens, Stripe keys, SendGrid keys, Twilio SIDs
- Generic high-entropy base64 blobs tagged as secrets/tokens/keys
- `.env` files tracked in git

### `check_permissions.sh`
- World-writable files and directories
- SUID / SGID bits on regular files
- Unexpected executable bits on data/config file types (JSON, YAML, PNG, …)
- Overly-permissive shell scripts (group- or world-writable)
- Sensitive files (PEM, key, p12, …) readable by group or others

### `audit_contents.sh`
- Security-related TODO / FIXME / HACK comments
- Dangerous injection sinks (`eval`, `os.system`, `shell_exec`, `child_process.exec`, …)
- SQL injection red flags (string concatenation in queries, `%s`-formatted SQL)
- Debug flags left enabled (`DEBUG=True`, `NODE_ENV=development`)
- Disabled TLS certificate verification
- Insecure cryptographic primitives (MD5, SHA-1, DES, RC4)
- Plain-HTTP endpoints (non-localhost)
- Hard-coded public IP addresses
- Commented-out credential blocks
- Suspicious large base64 blobs

### `integrity_check.sh`
- First run (`generate`): writes a SHA-256 baseline to `security/.checksums`
- Subsequent runs (`verify`): detects modified, new, or deleted files

### `check_git_history.sh`
- Secret patterns in every commit's diff
- Commit messages referencing passwords / secrets / tokens
- Large objects (default ≥ 500 KB) ever committed
- Force-push / history-rewrite markers in the reflog

### `dependency_audit.sh`
- **npm**: floating version ranges (`~`, `^`), missing lock files, `npm audit`
- **Python pip**: unpinned dependencies, `pip-audit` / `safety`
- **Ruby**: `bundler-audit`
- **Go**: `govulncheck`

### `check_workflows.sh`
- Script injection via `${{ github.event.* }}` in `run:` steps
- `permissions: write-all`
- Actions pinned by mutable tag instead of commit SHA
- Secrets echoed to the log
- `pull_request_target` checking out an untrusted PR head
- Self-hosted runner usage
- Missing top-level `permissions:` block (defaults to broad permissions)

## CI Integration

The checks run automatically on every push and pull request via the
`.github/workflows/security.yml` workflow.

## Exit codes

All scripts follow the same convention:

| Code | Meaning |
|---|---|
| `0` | Check passed – no issues found |
| `1` | Check failed – one or more issues detected |
| `2` | Prerequisites not met (e.g. no manifests found, not a git repo) |
