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

# ----------------------------------------------------------------------------
# Connectivity PREFLIGHT (e.g. VPN check)
#
# The pipeline can only create tickets if it can actually reach SonarQube. In
# many environments the SonarQube instance is only reachable over a corporate
# VPN or private network, so a scheduled run that fires while the host is off
# the network would otherwise crash mid-run (DNS resolution failure).
#
# This preflight probes reachability of the SonarQube host BEFORE the real run:
#   * Reachable            -> continue to the real run.
#   * Unreachable + TTY    -> interactive run: warn and ask for a go-ahead
#                             (connect to the network/VPN, then confirm).
#   * Unreachable + no TTY -> unattended/scheduled run: print a reminder and
#                             EXIT 0 WITHOUT running. Exiting 0 (not an error)
#                             is deliberate: it avoids opening a spurious
#                             failure ticket, and the watermark (last_run.txt)
#                             is left untouched so the next run retries cleanly.
#
# Set AUTOTICKET_SKIP_PREFLIGHT=1 to disable this check entirely.
# ----------------------------------------------------------------------------

# Derive the SonarQube host from SONAR_BASE_URL (sourced from .env above).
SONAR_HOST="$(printf '%s' "${SONAR_BASE_URL:-}" | sed -E 's#^[a-zA-Z]+://##; s#[:/].*$##')"

preflight_reachable() {
    # Returns 0 if the host resolves AND accepts a TCP 443 connection.
    local host="$1"
    [ -z "$host" ] && return 1
    # 1) DNS resolution.
    if command -v nslookup >/dev/null 2>&1; then
        nslookup "$host" >/dev/null 2>&1 || return 1
    fi
    # 2) TCP reachability on 443. Prefer nc with its own connect timeout
    #    (portable across macOS/Linux; note: macOS has no `timeout` binary).
    #    Fall back to a bare bash /dev/tcp attempt if nc is unavailable.
    if command -v nc >/dev/null 2>&1; then
        nc -z -G 5 "$host" 443 >/dev/null 2>&1 && return 0
        nc -z -w 5 "$host" 443 >/dev/null 2>&1 && return 0   # GNU nc uses -w
        return 1
    fi
    ( exec 3<>"/dev/tcp/${host}/443" ) >/dev/null 2>&1 && return 0
    return 1
}

if [ "${AUTOTICKET_SKIP_PREFLIGHT:-0}" != "1" ] && [ -n "$SONAR_HOST" ]; then
    echo "[preflight] checking connectivity to SonarQube host: $SONAR_HOST"
    if preflight_reachable "$SONAR_HOST"; then
        echo "[preflight] OK — $SONAR_HOST is reachable. Proceeding."
    else
        if [ -t 0 ]; then
            echo ""
            echo "  WARNING: cannot reach SonarQube ($SONAR_HOST)."
            echo "  You may not be connected to the required network/VPN."
            echo "  Connect now, then continue."
            echo ""
            printf "  Proceed with the run anyway? [y/N] "
            read -r REPLY || REPLY=""
            case "$REPLY" in
                [yY]|[yY][eE][sS])
                    echo "[preflight] Override accepted — proceeding despite failed probe."
                    ;;
                *)
                    echo "[preflight] Aborted by user. Nothing ran; watermark untouched."
                    exit 0
                    ;;
            esac
        else
            echo "[preflight] SonarQube unreachable and no TTY (scheduled run)."
            echo "[preflight] Skipping run so no spurious failure ticket is opened; watermark untouched."
            echo "[preflight] Connect to the network/VPN and re-run the job."
            echo "===== autoticket run finished (exit 0, SKIPPED: host unreachable): $(date '+%Y-%m-%d %H:%M:%S %Z') ====="
            exit 0
        fi
    fi
fi

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
