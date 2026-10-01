#!/usr/bin/env bash
# Throwaway passwords for one run, appended as NAME=value lines to the file given ($GITHUB_ENV in CI, .env.lab locally).
set -euo pipefail
target="${1:?usage: ci-secrets.sh FILE}"
for name in SA_PASSWORD ADMIN_PASSWORD APP_PASSWORD TDE_MASTER_KEY_PASSWORD TDE_BACKUP_PASSWORD PG_ADMIN_PASSWORD PII_KEY; do
  value="Lab1-$(openssl rand -hex 16)"   # upper, lower, digit and symbol: meets SQL Server's complexity rules
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::add-mask::$value"; fi
  echo "$name=$value" >> "$target"
done
