"""Jira client + reconciliation.

Creates one Jira ticket per PlannedTicket in the configured project, optionally
assigned and parented per the Settings (all policy is configurable).

Reconciliation model
---------------------
Because grouping is "one ticket per project per severity", each ticket is a
*living bucket*: findings enter and leave it across scans. So we cannot
identify "the" ticket for a bucket by its finding set (that set changes).
Instead, every ticket body embeds a stable **Autoticket ID**
(``<project>|<severity>``). On each run we locate the existing open ticket for
a bucket by that id, then compare its recorded dedupe keys against the current
scan to decide Case A/B/C/D (see reconcile() in main.py).

This module provides:
  * find_existing_buckets()  -> {autoticket_id: ExistingTicket}
  * create_ticket(planned)   -> new issue key           (Case A)
  * update_body(key, body)   -> replace description      (Case C / D)
  * add_comment(key, text)   -> append an audit comment  (Case C / D)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .config import Settings
from .grouping import render_body
from .models import PlannedTicket


@dataclass
class ExistingTicket:
    """An open ticket already representing a (project, severity) bucket."""

    key: str                       # Jira issue key, e.g. "SEC-1234"
    autoticket_id: str             # "<project>|<severity>" marker parsed from body
    dedupe_keys: set[str] = field(default_factory=set)  # SonarQube keys it covers


class JiraClient:
    def __init__(self, settings: Settings, session=None):
        self.settings = settings
        self._session = session

    def _get_session(self):
        if self._session is None:
            import requests  # lazy import

            s = requests.Session()
            s.auth = (self.settings.jira_email, self.settings.jira_token)
            s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
            self._session = s
        return self._session

    def find_existing_buckets(self) -> dict[str, ExistingTicket]:
        """Map each bucket's Autoticket ID to its existing open ticket.

        Scans open tickets in the configured project (optionally under the
        configured parent), parses the embedded ``Autoticket ID`` and
        ``Dedupe keys`` markers, and returns one ExistingTicket per bucket.
        This is the keystone lookup: it lets the pipeline find THE ticket for a
        (project, severity) pair regardless of which findings currently
        populate it.

        Uses the modern v3 search endpoint (GET /rest/api/3/search/jql) with
        cursor pagination — the legacy /rest/api/2/search was removed by
        Atlassian (410 Gone). Descriptions are ADF and flattened to text.
        """
        from .crossref import _adf_to_text  # shared ADF flattener

        session = self._get_session()
        jql = f"project = {self.settings.jira_project_key}"
        if self.settings.parent_key:
            jql += f" AND parent = {self.settings.parent_key}"
        jql += " AND statusCategory != Done"
        url = f"{self.settings.jira_base_url}/rest/api/3/search/jql"
        buckets: dict[str, ExistingTicket] = {}
        next_token: str | None = None
        while True:
            params = {"jql": jql, "fields": "description", "maxResults": 100}
            if next_token:
                params["nextPageToken"] = next_token
            resp = session.get(url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            for issue in data.get("issues", []):
                desc = _adf_to_text((issue.get("fields", {}) or {}).get("description"))
                autoticket_id = _parse_autoticket_id(desc)
                if not autoticket_id:
                    continue  # not one of ours / legacy ticket without the marker
                buckets[autoticket_id] = ExistingTicket(
                    key=issue.get("key", ""),
                    autoticket_id=autoticket_id,
                    dedupe_keys=_parse_dedupe_keys(desc),
                )
            if data.get("isLast", True) or not data.get("nextPageToken"):
                break
            next_token = data.get("nextPageToken")
        return buckets

    def create_ticket(self, ticket: PlannedTicket) -> str:
        """Create the Jira ticket; returns the new issue key. (Case A)

        Parent and assignee are included only when configured, so the pipeline
        works against any Jira project without requiring an epic or a specific
        user.
        """
        session = self._get_session()
        fields: dict = {
            "project": {"key": self.settings.jira_project_key},
            "summary": ticket.summary,
            "description": render_body(ticket),
            "issuetype": {"name": "Task"},
            "labels": ["sonarqube", "auto-ticketing", "vulnerability-management"],
        }
        if self.settings.parent_key:
            fields["parent"] = {"key": self.settings.parent_key}
        if self.settings.assignee_account_id:
            fields["assignee"] = {"accountId": self.settings.assignee_account_id}

        url = f"{self.settings.jira_base_url}/rest/api/2/issue"
        resp = session.post(url, json={"fields": fields}, timeout=30)
        resp.raise_for_status()
        return resp.json().get("key", "")

    def update_body(self, issue_key: str, body: str, summary: str | None = None) -> None:
        """Replace the ticket description (and optionally summary). (Case C/D)

        Deliberately does NOT touch status or assignee: a bucket may be
        mid-triage, and reopening/reassigning it on every scan would disrupt
        the analyst.
        """
        session = self._get_session()
        fields: dict = {"description": body}
        if summary is not None:
            fields["summary"] = summary
        url = f"{self.settings.jira_base_url}/rest/api/2/issue/{issue_key}"
        resp = session.put(url, json={"fields": fields}, timeout=30)
        resp.raise_for_status()

    def add_comment(self, issue_key: str, text: str) -> None:
        """Append an audit comment describing what changed. (Case C/D)"""
        session = self._get_session()
        url = f"{self.settings.jira_base_url}/rest/api/2/issue/{issue_key}/comment"
        resp = session.post(url, json={"body": text}, timeout=30)
        resp.raise_for_status()


# --- body marker parsing ---------------------------------------------------

def _parse_autoticket_id(description: str) -> str:
    """Extract the ``Autoticket ID`` marker (``<project>|<SEVERITY>``) from a
    ticket body.

    Robust to ADF-flattened descriptions where line breaks are lost and the
    marker runs together with following text (e.g. the ``(!)`` wiki symbol
    renders as ``:warning:`` and the Dedupe-keys line is appended). We match
    only the ``<project>|<SEVERITY>`` token immediately after the marker
    rather than taking the rest of the line.
    """
    import re
    m = re.search(r"Autoticket ID:\s*\{*\s*([^\s{}|]+\|[A-Z]+)", description)
    return m.group(1).strip() if m else ""


def _parse_dedupe_keys(description: str) -> set[str]:
    """Extract SonarQube issue keys from the ``Dedupe keys:`` marker.

    Robust to ADF flattening: capture the comma-separated key list after the
    marker, stopping at the next marker/section boundary so trailing text is
    not swallowed. Keys are alphanumeric tokens (no spaces/commas).
    """
    import re
    m = re.search(r"Dedupe keys:\s*([A-Za-z0-9,\s_-]+?)(?:Autoticket|\Z)", description)
    if not m:
        return set()
    return {k.strip() for k in m.group(1).split(",") if k.strip()}
