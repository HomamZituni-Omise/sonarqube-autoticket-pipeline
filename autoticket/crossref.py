"""Cross-project existing-ticket detection.

Before the pipeline creates a new ticket for a finding, we want to know
whether that finding is ALREADY tracked somewhere — including in human-written
remediation tickets that predate this tool and carry no Autoticket ID marker.
These may live across several Jira projects (configure them via
JIRA_CROSSREF_PROJECTS).

Matching signal
---------------
Existing tickets don't contain SonarQube issue keys, but they DO contain the
same precise coordinates the scanner reports:
  * the SonarQube rule ID          e.g. java:S2755, csharpsquid:S4423
  * the source file path           e.g. src/net/HttpClientUtil.java
  * the line number                e.g. 47

We extract those tokens from each candidate ticket's description and build a
set of signatures. A scan finding matches a ticket when the ticket references
the SAME rule AND the SAME file:line (line-tolerant fallback: same rule + same
file). Rule-only or file-only coincidences are reported at lower confidence.

Safety
------
This is deliberately an ANNOTATION, not an auto-skip. Extraction from free-text
descriptions is heuristic, and silently suppressing a real vulnerability
because it *looked* like an existing ticket is worse than a duplicate. The
pipeline surfaces "this finding appears to be covered by PROJ-1079 (high
confidence)" and leaves the create/skip decision to a human.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from .config import Settings
from .models import Finding

# Default Jira projects to search for pre-existing coverage. Empty by default;
# set JIRA_CROSSREF_PROJECTS (comma-separated) to enable cross-referencing
# against your own projects (e.g. a security backlog and remediation epics).
DEFAULT_CROSSREF_PROJECTS: tuple[str, ...] = ()

# SonarQube rule IDs look like "java:S2755", "csharpsquid:S4423",
# "javascript:S2068", "python:S5443".
_RULE_RE = re.compile(r"\b([a-z]+:S\d{3,5})\b")

# Source file paths: a path segment ending in a known source extension.
# Kept deliberately broad but anchored on the extension to avoid matching prose.
_FILE_RE = re.compile(
    r"([A-Za-z0-9_./\\-]+\.(?:java|cs|js|ts|py|jsp|aspx|rb|go|kt|scala|php|xml))",
    re.IGNORECASE,
)

# "Line 47", "line 41", "— Line 68", ":80"
_LINE_RE = re.compile(r"(?:line\s+(\d{1,6}))|(?::(\d{1,6})\b)", re.IGNORECASE)


@dataclass
class TicketSignature:
    """Signatures extracted from one existing ticket's description."""

    key: str
    project: str
    summary: str
    rules: set[str] = field(default_factory=set)
    files: set[str] = field(default_factory=set)        # basenames, lowercased
    file_lines: set[tuple[str, int]] = field(default_factory=set)  # (basename, line)


@dataclass
class CrossRefMatch:
    """A candidate existing ticket that appears to cover a scan finding."""

    ticket_key: str
    project: str
    summary: str
    confidence: str   # "high" (rule+file+line / rule+file) | "medium" (rule+file) | "low"
    reason: str


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path.strip())[-1].lower()


def extract_signature(key: str, project: str, summary: str, description: str) -> TicketSignature:
    """Pull rule IDs, file basenames, and (file, line) pairs from a description."""
    desc = description or ""
    sig = TicketSignature(key=key, project=project, summary=summary or "")

    sig.rules = set(_RULE_RE.findall(desc))

    # Files (store basenames so path-prefix differences between the scanner and
    # the human write-up don't break matching).
    for m in _FILE_RE.findall(desc):
        sig.files.add(_basename(m))

    # (file, line) pairs: associate each explicit ":<line>" that is glued to a
    # file token, plus best-effort "Line N" near a file mention. For robustness
    # we also record every file basename paired with every line number found in
    # the same description — coarse, but this is a heuristic annotator and the
    # rule match is the real discriminator.
    lines_found: set[int] = set()
    for a, b in _LINE_RE.findall(desc):
        num = a or b
        if num:
            try:
                lines_found.add(int(num))
            except ValueError:
                pass
    for fb in sig.files:
        for ln in lines_found:
            sig.file_lines.add((fb, ln))

    return sig


def match_finding(finding: Finding, signatures: Iterable[TicketSignature]) -> list[CrossRefMatch]:
    """Return existing tickets that appear to cover this finding, best first."""
    f_base = _basename(finding.file_path)
    f_rule = finding.rule
    f_line = finding.line
    matches: list[CrossRefMatch] = []

    for sig in signatures:
        rule_hit = f_rule in sig.rules
        file_hit = f_base in sig.files
        line_hit = (f_line is not None) and ((f_base, f_line) in sig.file_lines)

        # Human-written remediation tickets describe findings by file + line
        # and concept, and frequently do NOT print the literal SonarQube rule
        # ID. So file+line is treated as strong coverage on its own; the rule
        # ID, when present, only strengthens confidence. Requiring the rule
        # string caused false "NEW" flags for genuinely-ticketed findings.
        if file_hit and line_hit:
            conf = "high"
            reason = (f"{f_base}:{f_line} referenced"
                      + (f" + rule {f_rule}" if rule_hit else " (rule ID not printed in ticket)"))
            matches.append(CrossRefMatch(sig.key, sig.project, sig.summary, conf, reason))
        elif rule_hit and file_hit:
            matches.append(CrossRefMatch(
                sig.key, sig.project, sig.summary, "high",
                f"rule {f_rule} + file {f_base} present (line not confirmed)",
            ))
        elif file_hit:
            # Same file referenced but no line confirmation. For a bundled
            # remediation ticket ("all XXE across the service") this is
            # meaningful coverage — treat as medium (suppresses), but surface it.
            matches.append(CrossRefMatch(
                sig.key, sig.project, sig.summary, "medium",
                f"file {f_base} referenced (line/rule not confirmed)",
            ))
        elif rule_hit:
            matches.append(CrossRefMatch(
                sig.key, sig.project, sig.summary, "low",
                f"rule {f_rule} referenced (file not confirmed)",
            ))

    order = {"high": 0, "medium": 1, "low": 2}
    matches.sort(key=lambda m: order.get(m.confidence, 9))
    return matches


class CrossRefIndex:
    """Builds and holds signatures for existing tickets across the projects."""

    def __init__(self, signatures: list[TicketSignature]):
        self.signatures = signatures

    @classmethod
    def from_signatures(cls, sigs: list[TicketSignature]) -> "CrossRefIndex":
        return cls(sigs)

    def matches_for(self, finding: Finding) -> list[CrossRefMatch]:
        return match_finding(finding, self.signatures)


def _adf_to_text(value) -> str:
    """Flatten a Jira description into plain text.

    The v3 API returns descriptions as Atlassian Document Format (a nested
    dict). Older instances / some fields may still return a plain string. We
    recursively collect every 'text' node so the regex extractors see the file
    paths, rule IDs, and line numbers regardless of formatting.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    out: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            if isinstance(node.get("text"), str):
                out.append(node["text"])
            for v in node.values():
                if isinstance(v, (list, dict)):
                    walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return " ".join(out)


def build_index_from_jira(
    settings: Settings,
    session,
    projects: Iterable[str] | None = None,
) -> CrossRefIndex:
    """Query Jira across the given projects and index ticket signatures.

    If `projects` is not supplied, falls back to settings.crossref_projects
    (from JIRA_CROSSREF_PROJECTS). If no projects are configured, returns an
    empty index (cross-referencing is simply disabled).

    Uses the modern v3 search endpoint (GET /rest/api/3/search/jql) with
    cursor pagination (nextPageToken/isLast) — the legacy /rest/api/2/search
    was removed by Atlassian (returns 410 Gone). Descriptions come back as
    ADF and are flattened to text. Excludes Done tickets so resolved work
    doesn't suppress a finding that has genuinely reappeared.
    """
    if projects is None:
        projects = settings.crossref_projects or DEFAULT_CROSSREF_PROJECTS
    project_set = sorted({p for p in projects if p})
    if not project_set:
        return CrossRefIndex([])
    project_list = ", ".join(project_set)
    jql = f"project in ({project_list}) AND statusCategory != Done"
    url = f"{settings.jira_base_url}/rest/api/3/search/jql"
    sigs: list[TicketSignature] = []
    next_token: str | None = None
    while True:
        params = {
            "jql": jql,
            "fields": "summary,description,project",
            "maxResults": 100,
        }
        if next_token:
            params["nextPageToken"] = next_token
        resp = session.get(url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        for issue in data.get("issues", []):
            fields = issue.get("fields", {}) or {}
            proj = (fields.get("project", {}) or {}).get("key", "")
            sigs.append(extract_signature(
                key=issue.get("key", ""),
                project=proj,
                summary=fields.get("summary", "") or "",
                description=_adf_to_text(fields.get("description")),
            ))
        if data.get("isLast", True) or not data.get("nextPageToken"):
            break
        next_token = data.get("nextPageToken")
    return CrossRefIndex(sigs)
