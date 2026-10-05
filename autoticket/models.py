"""Shared data models for findings and planned tickets."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Finding:
    """A single SonarQube vulnerability finding (normalized)."""

    issue_key: str          # SonarQube issue key — stable, used for dedupe
    project_key: str        # SonarQube project/repo key
    project_name: str
    severity: str           # BLOCKER | CRITICAL (post-filter)
    rule: str               # rule ID, e.g. "java:S2076"
    rule_name: str
    message: str            # description / message
    file_path: str
    line: int | None
    remediation: str        # remediation guidance text (may be empty)
    sonar_link: str         # direct link to the finding in SonarQube
    creation_date: str = "" # SonarQube issue creationDate (ISO8601); "" if unknown


@dataclass
class PlannedTicket:
    """A Jira ticket the pipeline intends to create.

    One per (project, severity) per the grouping policy.
    """

    project_key: str
    project_name: str
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def summary(self) -> str:
        sev = self.severity.capitalize()
        n = len(self.findings)
        noun = "finding" if n == 1 else "findings"
        return f"[SonarQube][{sev}] {self.project_name} — {n} vulnerability {noun}"

    @property
    def dedupe_keys(self) -> list[str]:
        """SonarQube issue keys covered by this ticket (for dedupe)."""
        return sorted(f.issue_key for f in self.findings)

    @property
    def autoticket_id(self) -> str:
        """Stable identity for this (project, severity) bucket.

        This is the keystone marker for reconciliation. A ticket is a *living
        bucket*: findings enter and leave it across scans, so we cannot
        identify "the" ticket for a bucket by its finding set (that changes).
        Instead we embed this stable id in the body and match on it. Both
        dedupe and update logic key off this.
        """
        return f"{self.project_key}|{self.severity}"
