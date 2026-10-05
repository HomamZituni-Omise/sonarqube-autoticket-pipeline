"""Per-project release-branch mapping.

SonarQube findings should be read from each project's active release branch,
not whatever SonarQube treats as the default branch — the finding set can
differ by branch, so scanning the wrong branch yields the wrong results. This
is a correctness requirement, not a cosmetic one.

Keys are SonarQube PROJECT KEYS (as shown by /api/components/search on your
instance). Values are the exact branch name passed to
/api/issues/search?branch=... . Projects not listed here fall back to the
SonarQube default branch and are reported at the end of each run so you can add
them.

Customize PROJECT_BRANCHES for your environment. The examples below are
illustrative — replace them with your real project keys and branch names (or
leave the map empty to always use each project's SonarQube default branch).
"""

from __future__ import annotations

# SonarQube project key -> release branch to scan.
# Replace these example entries with your own projects.
PROJECT_BRANCHES: dict[str, str] = {
    "example-service-a": "main",
    "example-service-b": "release",
    "example-service-c": "develop",
    "org.example:legacy-app": "master",
}


def branch_for(project_key: str) -> str | None:
    """Return the configured release branch for a project key, or None if the
    project is not mapped (caller falls back to the SonarQube default)."""
    return PROJECT_BRANCHES.get(project_key)
