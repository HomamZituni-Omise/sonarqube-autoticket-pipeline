"""Markdown run-report writer.

Writes a human-readable summary of each pipeline run to a Markdown file so the
operator has visible, at-a-glance confirmation that the job ran (and what it
found) without digging through logs or Jira.

Filename: AutoTicket-Job-MM-DD-YYYY.md  (today's date; one file per run-day).

Output location (first writable wins):
  1. $AUTOTICKET_REPORT_DIR, if set.
  2. ~/Desktop
  3. ~/Library/Logs  (fallback — e.g. macOS blocks background launchd agents
     from writing to the TCC-protected Desktop folder)

Design notes:
  * Best-effort and MUST NEVER raise. Report-writing is a convenience; a
    failure here must not fail the pipeline run or affect the watermark. All
    errors are swallowed and surfaced as a printed warning only.
"""

from __future__ import annotations

import datetime as _dt
import os
from pathlib import Path
from typing import Any


def _report_filename(when: _dt.date | None = None) -> str:
    """AutoTicket-Job-MM-DD-YYYY.md for the given date (default: today)."""
    d = when or _dt.date.today()
    return f"AutoTicket-Job-{d.strftime('%m-%d-%Y')}.md"


def _candidate_dirs() -> list[Path]:
    dirs: list[Path] = []
    env_dir = os.environ.get("AUTOTICKET_REPORT_DIR", "").strip()
    if env_dir:
        dirs.append(Path(env_dir).expanduser())
    dirs.append(Path.home() / "Desktop")
    dirs.append(Path.home() / "Library" / "Logs")
    return dirs


def _render_markdown(data: dict[str, Any]) -> str:
    """Render the collected run data into a Markdown document."""
    now = _dt.datetime.now()
    mode = data.get("mode", "live")
    counts = data.get("counts", {})
    buckets = data.get("buckets", [])          # list of per-bucket dicts
    unmapped = data.get("unmapped", [])
    total_findings = data.get("total_findings", 0)
    total_buckets = data.get("total_buckets", 0)
    cutoff = data.get("cutoff", "")
    severities = data.get("severities", "")
    types = data.get("types", "")
    crossref_count = data.get("crossref_count")
    watermark_advanced_to = data.get("watermark_advanced_to")

    created = counts.get("create", 0)
    skipped = counts.get("skip", 0)
    updated = counts.get("update", 0)
    annotated = counts.get("annotate", 0)

    headline = (
        "No new Blocker/Critical vulnerabilities"
        if created == 0
        else f"{created} bucket(s) with genuinely new findings"
    )

    lines: list[str] = []
    lines.append(f"# AutoTicket Job Report — {now.strftime('%Y-%m-%d')}")
    lines.append("")
    lines.append(f"**Run completed:** {now.strftime('%Y-%m-%d %H:%M:%S %Z').strip()}  ")
    lines.append(f"**Mode:** {mode}  ")
    lines.append(f"**Result:** {headline}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Findings fetched | {total_findings} |")
    lines.append(f"| Buckets (project × severity) | {total_buckets} |")
    lines.append(f"| Tickets created | {created} |")
    lines.append(f"| Skipped (already tracked / unchanged) | {skipped} |")
    lines.append(f"| Updated | {updated} |")
    lines.append(f"| Annotated (resolved) | {annotated} |")
    lines.append(f"| Severities scanned | {severities} |")
    lines.append(f"| Finding types | {types} |")
    lines.append(f"| New-since cutoff | {cutoff} |")
    if crossref_count is not None:
        lines.append(f"| Cross-project tickets indexed | {crossref_count} |")
    if watermark_advanced_to:
        lines.append(f"| Watermark advanced to | {watermark_advanced_to} |")
    lines.append("")

    if buckets:
        lines.append("## Buckets")
        lines.append("")
        lines.append("| Project | Severity | Findings | Outcome | Detail |")
        lines.append("|---|---|---|---|---|")
        for b in buckets:
            lines.append(
                f"| {b.get('project','')} | {b.get('severity','')} "
                f"| {b.get('count',0)} | {b.get('outcome','')} "
                f"| {b.get('detail','')} |"
            )
        lines.append("")
    else:
        lines.append("_No buckets with Blocker/Critical vulnerability findings._")
        lines.append("")

    if unmapped:
        lines.append("## Action needed — unmapped projects")
        lines.append("")
        lines.append(
            "These SonarQube projects have no release-branch mapping in "
            "`branches.py` and were scanned on the SonarQube **default** branch "
            "(which may be the wrong branch):"
        )
        lines.append("")
        for p in sorted(unmapped):
            lines.append(f"- `{p}`")
        lines.append("")
        lines.append(
            "Fix: add a `\"<project key>\": \"<release branch>\"` line to "
            "`PROJECT_BRANCHES` in `autoticket/branches.py`."
        )
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "_Generated automatically by the SonarQube auto-ticketing pipeline "
        "(`autoticket.report`)._"
    )
    lines.append("")
    return "\n".join(lines)


def write_report(data: dict[str, Any]) -> str | None:
    """Write the Markdown report to the first writable candidate directory.

    Returns the path written, or None on failure. Never raises.
    """
    try:
        filename = _report_filename()
        content = _render_markdown(data)
    except Exception as e:  # noqa: BLE001 - report must never break the run
        print(f"[report] could not render report: {e}")
        return None

    candidates = _candidate_dirs()
    last_err: Exception | None = None
    for i, target_dir in enumerate(candidates):
        is_last = i == len(candidates) - 1
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            out = target_dir / filename
            out.write_text(content, encoding="utf-8")
            if i > 0:
                print(
                    f"[report] preferred location(s) not writable; wrote report "
                    f"to {out} instead."
                )
            else:
                print(f"[report] Wrote run report to {out}")
            return str(out)
        except Exception as e:  # noqa: BLE001
            last_err = e
            if is_last:
                print(f"[report] could not write report anywhere ({last_err}).")
                return None
            continue
    return None
