"""Configuration for the SonarQube -> Jira auto-ticketing pipeline.

All secrets and environment-specific values are read from the environment (or
the OS keyring), so nothing sensitive is committed. See .env.example for the
full list of settings. The ticketing policy constants below are sensible
defaults and can all be overridden via environment variables.
"""

from __future__ import annotations

import getpass
import os
from dataclasses import dataclass, field
from pathlib import Path


# --- Secret loading: OS keyring first, .env/env-var fallback ----------------

# Keyring service names and the account used to store both secrets.
# Set these once with (macOS example; `keyring` supports Windows/Linux too):
#   security add-generic-password -s sonar-token -a "$USER" -w
#   security add-generic-password -s jira-token  -a "$USER" -w
KEYRING_SERVICES: dict[str, str] = {
    "SONAR_TOKEN": "sonar-token",
    "JIRA_TOKEN": "jira-token",
}


def _keyring_get(service: str) -> str | None:
    """Return a secret from the OS keyring via the `keyring` library.

    Returns None if keyring is unavailable, the lookup errors, or nothing is
    stored. Callers fall back to environment/.env when this returns None.
    """
    try:
        import keyring  # lazy import so dry-run/mock works without the dep
    except Exception:
        return None
    try:
        account = getpass.getuser()
        value = keyring.get_password(service, account)
        return value or None
    except Exception:
        return None


def _load_token(env_name: str) -> str:
    """Load a token: try the keyring first, then fall back to the env var.

    The keyring (secure, used in scheduled/production runs) takes priority. If
    nothing is in the keyring, the value from the environment (.env sourced
    into the shell) is used so local testing still works. Returns "" if
    neither source has it — the dry-run path tolerates empty tokens.
    """
    service = KEYRING_SERVICES.get(env_name)
    if service:
        secret = _keyring_get(service)
        if secret:
            return secret
    return os.environ.get(env_name, "") or ""


# --- Ticketing policy defaults (override via environment) -------------------

# Only these SonarQube severities trigger auto-ticketing.
TRIGGER_SEVERITIES: tuple[str, ...] = ("BLOCKER", "CRITICAL")

# Only vulnerability-type findings (not code smells / bugs / hotspots).
TRIGGER_TYPES: tuple[str, ...] = ("VULNERABILITY",)

# Default display name recorded on auto-created tickets. Override via
# JIRA_ASSIGNEE. Leave assignment unset to let Jira default it.
DEFAULT_ASSIGNEE_DISPLAY_NAME: str = ""

# Jira Cloud assigns by accountId (displayName is ignored on the create
# endpoint). Set JIRA_ASSIGNEE_ACCOUNT_ID to auto-assign; empty = unassigned.
DEFAULT_ASSIGNEE_ACCOUNT_ID: str = ""

# Optional parent issue key for all auto-created tickets (e.g. an epic).
# Empty = create tickets with no parent. Override via JIRA_PARENT_KEY.
DEFAULT_PARENT_KEY: str = ""

# Jira project the tickets are created in. Override via JIRA_PROJECT_KEY.
JIRA_PROJECT_KEY: str = "SEC"

# Findings created before this date are treated as pre-existing (assumed
# already triaged outside this pipeline). Only findings created on/after this
# cutoff are treated as genuinely NEW and eligible for a ticket, so a first run
# against a mature project does not raise a ticket for every historical finding.
#
# The cutoff is a moving watermark stored in last_run.txt at the project root
# (same folder as .env). It is read at the start of each run and advanced to
# today's date ONLY after a fully successful run (see main.py). This constant
# is just the seed used if the watermark file is missing.
NEW_SINCE_DEFAULT: str = "2024-01-01"

# Project root = two levels up from this file (autoticket/config.py -> project).
PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent

# Watermark file holding the "new since" cutoff as a single YYYY-MM-DD line.
WATERMARK_PATH: Path = PROJECT_ROOT / "last_run.txt"


def read_watermark() -> str:
    """Return the cutoff date (YYYY-MM-DD) from last_run.txt.

    Falls back to NEW_SINCE_DEFAULT if the file is missing/empty/unreadable, or
    if it does not look like an ISO date, so a corrupt file never silently
    widens the scan window.
    """
    try:
        text = WATERMARK_PATH.read_text().strip()
    except OSError:
        return NEW_SINCE_DEFAULT
    # Accept a date or an ISO timestamp; keep only the YYYY-MM-DD part.
    candidate = text[:10]
    if len(candidate) == 10 and candidate[4] == "-" and candidate[7] == "-":
        return candidate
    return NEW_SINCE_DEFAULT


def write_watermark(date_str: str) -> None:
    """Overwrite last_run.txt with date_str (expected YYYY-MM-DD).

    Called by main.py ONLY after a fully successful run so a failure never
    advances the window and skips findings.
    """
    WATERMARK_PATH.write_text(date_str + "\n")


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise EnvironmentError(
            f"Missing required environment variable: {name}. "
            "Copy .env.example to .env and fill it in."
        )
    return value


@dataclass
class Settings:
    """Runtime settings assembled from the environment.

    Use Settings.load() for a live run. In --dry-run mode the tokens are
    optional so the pipeline can be exercised with mock data and no creds.
    """

    sonar_base_url: str
    sonar_token: str
    jira_base_url: str
    jira_email: str
    jira_token: str
    jira_project_key: str = JIRA_PROJECT_KEY
    assignee_display_name: str = DEFAULT_ASSIGNEE_DISPLAY_NAME
    assignee_account_id: str = DEFAULT_ASSIGNEE_ACCOUNT_ID
    parent_key: str = DEFAULT_PARENT_KEY
    trigger_severities: tuple[str, ...] = TRIGGER_SEVERITIES
    trigger_types: tuple[str, ...] = TRIGGER_TYPES
    # Findings created before this ISO date are treated as pre-existing.
    new_since: str = NEW_SINCE_DEFAULT
    # Optional: restrict to specific SonarQube project keys. Empty = all.
    sonar_project_keys: list[str] = field(default_factory=list)
    # Optional: Jira projects to scan for pre-existing coverage (cross-ref).
    crossref_projects: tuple[str, ...] = ()

    @classmethod
    def load(cls, dry_run: bool = False) -> "Settings":
        """Build Settings from env vars.

        In dry-run mode, credentials are optional (defaulted to empty)
        so the flow can run against mock data without any secrets.
        """
        getter = os.environ.get if dry_run else _require

        # Load tokens keyring-first, .env fallback. On a live run (not dry-run)
        # a genuinely missing token must still fail loudly rather than silently
        # producing an empty credential, so re-create the old _require guard.
        sonar_token = _load_token("SONAR_TOKEN")
        jira_token = _load_token("JIRA_TOKEN")
        if not dry_run:
            if not sonar_token:
                raise EnvironmentError(
                    "Missing SONAR_TOKEN. Store it in the OS keyring "
                    "(service 'sonar-token') or set it in .env."
                )
            if not jira_token:
                raise EnvironmentError(
                    "Missing JIRA_TOKEN. Store it in the OS keyring "
                    "(service 'jira-token') or set it in .env."
                )

        project_keys_raw = os.environ.get("SONAR_PROJECT_KEYS", "").strip()
        project_keys = [k.strip() for k in project_keys_raw.split(",") if k.strip()]

        crossref_raw = os.environ.get("JIRA_CROSSREF_PROJECTS", "").strip()
        crossref_projects = tuple(
            p.strip() for p in crossref_raw.split(",") if p.strip()
        )

        # Optional severity override (comma-separated) — defaults to the
        # BLOCKER,CRITICAL set. Lets a run be scoped to a single severity.
        sev_raw = os.environ.get("SONAR_SEVERITIES", "").strip()
        severities = tuple(x.strip().upper() for x in sev_raw.split(",") if x.strip()) or TRIGGER_SEVERITIES

        return cls(
            sonar_base_url=(getter("SONAR_BASE_URL") or "").rstrip("/"),
            sonar_token=sonar_token,
            jira_base_url=(getter("JIRA_BASE_URL") or "").rstrip("/"),
            jira_email=getter("JIRA_EMAIL") or "",
            jira_token=jira_token,
            jira_project_key=os.environ.get("JIRA_PROJECT_KEY", JIRA_PROJECT_KEY),
            assignee_display_name=os.environ.get(
                "JIRA_ASSIGNEE", DEFAULT_ASSIGNEE_DISPLAY_NAME
            ),
            assignee_account_id=os.environ.get(
                "JIRA_ASSIGNEE_ACCOUNT_ID", DEFAULT_ASSIGNEE_ACCOUNT_ID
            ),
            parent_key=os.environ.get("JIRA_PARENT_KEY", DEFAULT_PARENT_KEY),
            # Cutoff comes from the watermark file (last_run.txt); SONAR_NEW_SINCE
            # env var still overrides it for ad-hoc testing.
            new_since=os.environ.get("SONAR_NEW_SINCE") or read_watermark(),
            trigger_severities=severities,
            sonar_project_keys=project_keys,
            crossref_projects=crossref_projects,
        )
