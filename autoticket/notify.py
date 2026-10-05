"""Failure notifier: open a Jira ticket when an autoticket run fails.

Primary failure alert for a scheduled pipeline run. When run_autoticket.sh
detects a non-zero exit, it invokes this module, which creates a Jira Task in
the configured project titled "Sonar Auto Ticket Failure", with the exit code
and log location in the body (and the configured assignee, if any).

Design notes:
  * Reuses the existing Settings + Jira auth (email + keyring token) so no new
    credentials are needed. A Jira ticket is a reliable, zero-setup alert
    channel that needs no SMTP/app-password configuration.
  * This is best-effort and must NEVER raise: a failure in the notifier must
    not mask the original run failure. All errors are caught and reported to
    stderr, and the module exits 0 regardless so the runner's own exit status
    (the real failure) is preserved.

Usage:
    python3 -m autoticket.notify --exit-code 1 --log /path/to/run.log
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys

from .config import Settings


FAILURE_SUMMARY = "Sonar Auto Ticket Failure"


def _create_failure_ticket(exit_code: int, log_path: str) -> str:
    """Create the failure Task. Returns the new issue key, or "" on error.

    Kept fully self-contained (own session) so it works even if other modules
    are the source of the failure. Never raises.
    """
    try:
        # dry_run=False so tokens are required (keyring); if creds are missing
        # this raises EnvironmentError, caught below.
        settings = Settings.load(dry_run=False)
    except Exception as e:  # noqa: BLE001 - notifier must never raise
        print(f"[notify] cannot load settings: {e}", file=sys.stderr)
        return ""

    try:
        import requests  # lazy import
    except Exception as e:  # noqa: BLE001
        print(f"[notify] requests unavailable: {e}", file=sys.stderr)
        return ""

    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S %Z")
    description = (
        f"The SonarQube auto-ticketing pipeline failed during its scheduled "
        f"run.\n\n"
        f"Timestamp: {now}\n"
        f"Exit code: {exit_code}\n"
        f"Log file: {log_path}\n\n"
        f"This ticket was created automatically by the pipeline's failure "
        f"notifier (autoticket.notify). Check the log file above for the "
        f"traceback / error detail. The run watermark (last_run.txt) was NOT "
        f"advanced, so the next run will retry the same window."
    )

    fields: dict = {
        "project": {"key": settings.jira_project_key},
        "summary": FAILURE_SUMMARY,
        "description": description,
        "issuetype": {"name": "Task"},
        "labels": ["sonarqube", "auto-ticketing", "pipeline-failure"],
    }
    if settings.assignee_account_id:
        fields["assignee"] = {"accountId": settings.assignee_account_id}

    try:
        session = requests.Session()
        session.auth = (settings.jira_email, settings.jira_token)
        session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )
        url = f"{settings.jira_base_url}/rest/api/2/issue"
        resp = session.post(url, json={"fields": fields}, timeout=30)
        resp.raise_for_status()
        key = resp.json().get("key", "")
        print(f"[notify] created failure ticket {key}", file=sys.stderr)
        return key
    except Exception as e:  # noqa: BLE001 - never raise
        print(f"[notify] failed to create Jira ticket: {e}", file=sys.stderr)
        return ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Create a failure ticket for a failed autoticket run.")
    p.add_argument("--exit-code", type=int, default=1, help="Exit code of the failed run.")
    p.add_argument("--log", default="run.log", help="Path to the run log.")
    args = p.parse_args(argv)
    _create_failure_ticket(args.exit_code, args.log)
    # Always exit 0: the notifier must not add its own failure on top of the run's.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
