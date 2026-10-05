#!/bin/bash
# Runner for the SonarQube auto-ticketing pipeline, intended to be invoked by a
# scheduler (cron, launchd, systemd timer, CI schedule, etc.).
#
# Why this wrapper exists: schedulers typically do NOT load your shell profile
# or run `source .env`, so the non-secret settings (SONAR_BASE_URL,
# JIRA_BASE_URL, JIRA_EMAIL, project keys) would be missing and the run would
# fail. The API tokens themselves come from the OS keyring at runtime (not from
# here) when configured.
#
# This script: cd into the project dir, load .env, then run the module with a
# timestamped log line so the output log shows when each run happened.

set -euo pipefail

# Project directory: override with AUTOTICKET_DIR, else use this script's dir.
PROJECT_DIR="${AUTOTICKET_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
PYTHON="${AUTOTICKET_PYTHON:-python3}"
LOG_FILE="${AUTOTICKET_ERR_LOG:-$PROJECT_DIR/run.log}"

cd "$PROJECT_DIR"

# Load non-secret settings (URLs, email, project keys) from .env if present.
# Tokens are NOT required here — they are read from the keyring by the code.
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

echo "===== autoticket run started: $(date '+%Y-%m-%d %H:%M:%S %Z') ====="

# Real run: creates/updates tickets and advances last_run.txt on success.
"$PYTHON" -m autoticket.main
STATUS=$?

echo "===== autoticket run finished (exit $STATUS): $(date '+%Y-%m-%d %H:%M:%S %Z') ====="

# Failure alert: if the run failed, open a Jira ticket so a broken scheduled run
# is not missed. The log line below also makes failures greppable.
if [ $STATUS -ne 0 ]; then
    echo "!!!!! autoticket FAILED with exit $STATUS — see $LOG_FILE"
    "$PYTHON" -m autoticket.notify --exit-code "$STATUS" --log "$LOG_FILE" || true
fi

exit $STATUS
