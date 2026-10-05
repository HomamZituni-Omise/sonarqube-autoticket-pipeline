"""SonarQube Web API client.

Pulls vulnerability-type issues at the configured severities using only the
public Web API (GET /api/issues/search) — no proprietary plugins, no CI-server
dependency.

`iter_findings` can serve mock data from a local JSON file so the end-to-end
flow can be exercised without a live instance.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .config import Settings
from .models import Finding


class SonarClient:
    def __init__(self, settings: Settings, session=None):
        self.settings = settings
        # requests is imported lazily so mock/dry-run works without the dep.
        self._session = session

    def _get_session(self):
        if self._session is None:
            import requests  # lazy import

            s = requests.Session()
            # SonarQube uses token as HTTP basic auth username, empty password.
            s.auth = (self.settings.sonar_token, "")
            self._session = s
        return self._session

    def iter_findings(
        self, mock_path: str | None = None, limit: int | None = None
    ) -> Iterable[Finding]:
        """Yield normalized Findings.

        If mock_path is provided, findings are read from that JSON file
        (a captured /api/issues/search response) instead of the live API.

        If limit is provided (> 0), at most `limit` findings are yielded.
        Useful for a low-risk first live contact against the real instance.
        """
        source = self._iter_mock(mock_path) if mock_path else self._iter_live(limit=limit)
        if limit is not None and limit > 0:
            count = 0
            for finding in source:
                yield finding
                count += 1
                if count >= limit:
                    return
        else:
            yield from source

    # --- mock path ---------------------------------------------------------

    def _iter_mock(self, mock_path: str) -> Iterable[Finding]:
        data = json.loads(Path(mock_path).read_text())
        components = {c["key"]: c for c in data.get("components", [])}
        for issue in data.get("issues", []):
            yield self._normalize(issue, components)

    # --- live path ---------------------------------------------------------

    def _iter_live(self, limit: int | None = None) -> Iterable[Finding]:
        """Yield findings, querying EACH project on its configured release
        branch. SonarQube's default branch is not reliably the release
        branch, and finding sets differ by branch, so we pin the
        branch per project via branches.branch_for(). Projects with no mapped
        branch fall back to the default (branch omitted) and are recorded in
        self.unmapped_projects for visibility.
        """
        from .branches import branch_for

        session = self._get_session()
        self.scanned_branches: dict[str, str] = {}   # project_key -> branch used
        self.unmapped_projects: list[str] = []

        # Which projects to scan: explicit override, else every project.
        if self.settings.sonar_project_keys:
            project_keys = list(self.settings.sonar_project_keys)
        else:
            project_keys = self._list_project_keys(session)

        yielded = 0
        for pkey in project_keys:
            branch = branch_for(pkey)
            if branch is None:
                self.unmapped_projects.append(pkey)
                self.scanned_branches[pkey] = "(default)"
            else:
                self.scanned_branches[pkey] = branch

            page = 1
            page_size = min(500, limit) if limit and limit > 0 else 500
            while True:
                params = {
                    "componentKeys": pkey,
                    "types": ",".join(self.settings.trigger_types),
                    "severities": ",".join(self.settings.trigger_severities),
                    "statuses": "OPEN,CONFIRMED,REOPENED",
                    "ps": page_size,
                    "p": page,
                }
                if branch is not None:
                    params["branch"] = branch

                url = f"{self.settings.sonar_base_url}/api/issues/search"
                resp = session.get(url, params=params, timeout=30)
                resp.raise_for_status()
                data = resp.json()

                components = {c["key"]: c for c in data.get("components", [])}
                issues = data.get("issues", [])
                for issue in issues:
                    yield self._normalize(issue, components)
                    yielded += 1
                    if limit and limit > 0 and yielded >= limit:
                        return

                total = data.get("total", 0)
                if page * page_size >= total or not issues:
                    break
                page += 1

    def _list_project_keys(self, session) -> list[str]:
        """Return all project keys visible to the token (paged)."""
        keys: list[str] = []
        page = 1
        while True:
            resp = session.get(
                f"{self.settings.sonar_base_url}/api/components/search",
                params={"qualifiers": "TRK", "ps": 500, "p": page},
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            comps = data.get("components", [])
            keys.extend(c["key"] for c in comps)
            total = data.get("paging", {}).get("total", len(keys))
            if page * 500 >= total or not comps:
                break
            page += 1
        return keys

    # --- normalization -----------------------------------------------------

    def _normalize(self, issue: dict, components: dict) -> Finding:
        component_key = issue.get("component", "")
        project_key = issue.get("project", "")
        comp = components.get(component_key, {})
        # component key looks like "project:path/to/File.java"
        file_path = component_key.split(":", 1)[1] if ":" in component_key else component_key
        project_name = components.get(project_key, {}).get("name", project_key)

        return Finding(
            issue_key=issue.get("key", ""),
            project_key=project_key,
            project_name=project_name,
            severity=issue.get("severity", ""),
            rule=issue.get("rule", ""),
            rule_name=issue.get("rule", ""),  # rule display name needs /api/rules; POC uses id
            message=issue.get("message", ""),
            file_path=file_path,
            line=issue.get("line"),
            remediation="",  # populated via rule lookup in a later iteration
            sonar_link=(
                f"{self.settings.sonar_base_url}/project/issues"
                f"?id={project_key}&open={issue.get('key', '')}"
            ),
            creation_date=issue.get("creationDate", "") or "",
        )
