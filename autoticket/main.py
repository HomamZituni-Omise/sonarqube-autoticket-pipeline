"""Main orchestrator for the SonarQube -> Jira auto-ticketing pipeline.

Flow:
  1. Query SonarQube for BLOCKER/CRITICAL vulnerability findings.
  2. Group them per project per severity.
  3. Reconcile each (project, severity) bucket against its existing open
     ticket, located by a stable Autoticket ID marker:
       Case A create / B skip / C update / D annotate-resolved.
  4. Create/update Jira tickets in the configured project.

Use --dry-run to print what WOULD happen without touching Jira.
Use --mock PATH to feed a captured SonarQube response (no live creds).
Use --limit N to pull at most N findings — low-risk first live contact.
Use --reconcile PATH to load a mock "existing tickets" state so Cases A-D can
   be demonstrated locally without any live systems (implies --dry-run --mock
   semantics for the Jira side).

Examples:
  python -m autoticket.main --dry-run --mock sample_data/sonar_issues.json
  python -m autoticket.main --dry-run --limit 5   # safe first live contact
  python -m autoticket.main --mock sample_data/sonar_scan2.json \\
      --reconcile sample_data/existing_tickets.json --dry-run
  python -m autoticket.main            # live run (requires .env creds)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
from pathlib import Path

from .config import Settings, write_watermark
from .crossref import CrossRefIndex, TicketSignature, extract_signature, build_index_from_jira
from .grouping import group_findings, render_body
from .jira_client import ExistingTicket, JiraClient
from .reconcile import Case, reconcile, update_comment
from .report import write_report
from .sonar_client import SonarClient


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="SonarQube -> Jira vulnerability auto-ticketing POC")
    p.add_argument("--dry-run", action="store_true", help="Print planned actions; do not write to Jira.")
    p.add_argument("--mock", metavar="PATH", help="Read SonarQube findings from a local JSON file.")
    p.add_argument(
        "--limit",
        type=int,
        metavar="N",
        help="Pull at most N findings from SonarQube (for a low-risk first live test).",
    )
    p.add_argument(
        "--reconcile",
        metavar="PATH",
        help=(
            "Load a mock 'existing tickets' JSON to demonstrate reconciliation "
            "Cases A-D locally (no live Jira). Format: "
            '{"<project>|<SEVERITY>": {"key": "PROJ-123", "dedupe_keys": [...]}}'
        ),
    )
    p.add_argument(
        "--crossref-mock",
        metavar="PATH",
        help=(
            "Load a mock 'existing cross-project tickets' JSON to demonstrate "
            "cross-project existing-ticket detection locally (no live "
            'Jira). Format: [{"key","project","summary","description"}, ...]'
        ),
    )
    p.add_argument(
        "--no-crossref",
        action="store_true",
        help="Disable cross-project existing-ticket detection on a live run.",
    )
    return p


def _load_crossref_mock(path: str) -> CrossRefIndex:
    """Build a CrossRefIndex from a local JSON list of existing tickets."""
    raw = json.loads(Path(path).read_text())
    sigs: list[TicketSignature] = []
    for rec in raw:
        sigs.append(extract_signature(
            key=rec.get("key", ""),
            project=rec.get("project", ""),
            summary=rec.get("summary", ""),
            description=rec.get("description", ""),
        ))
    return CrossRefIndex(sigs)


def _load_mock_existing(path: str) -> dict[str, ExistingTicket]:
    """Load a mock map of autoticket_id -> ExistingTicket for local demos."""
    raw = json.loads(Path(path).read_text())
    out: dict[str, ExistingTicket] = {}
    for autoticket_id, rec in raw.items():
        out[autoticket_id] = ExistingTicket(
            key=rec.get("key", ""),
            autoticket_id=autoticket_id,
            dedupe_keys=set(rec.get("dedupe_keys", [])),
        )
    return out


def _scan_label() -> str:
    return _dt.date.today().isoformat()


def _crossref_bucket(ticket, crossref) -> dict:
    """Return {finding_description: [CrossRefMatch,...]} for findings in this
    bucket that appear to already be covered by an existing ticket."""
    out: dict = {}
    for f in ticket.findings:
        ms = crossref.matches_for(f)
        if ms:
            loc = f"{f.file_path}:{f.line}" if f.line is not None else f.file_path
            out[f"{f.rule} @ {loc}"] = ms
    return out


def _bucket_of(ticket, findings):
    """Build a PlannedTicket carrying only the given findings (same project/
    severity). Used to create a ticket for the NEW findings subset only."""
    from .models import PlannedTicket
    nt = PlannedTicket(
        project_key=ticket.project_key,
        project_name=ticket.project_name,
        severity=ticket.severity,
    )
    nt.findings = list(findings)
    return nt


def run(
    dry_run: bool = False,
    mock_path: str | None = None,
    limit: int | None = None,
    reconcile_path: str | None = None,
    crossref_mock_path: str | None = None,
    no_crossref: bool = False,
) -> int:
    settings = Settings.load(dry_run=dry_run or bool(mock_path))

    sonar = SonarClient(settings)
    findings = list(sonar.iter_findings(mock_path=mock_path, limit=limit))
    tickets = group_findings(findings)

    limit_note = f", limited to {limit}" if limit and limit > 0 else ""
    print(f"Fetched {len(findings)} finding(s) -> {len(tickets)} bucket(s) "
          f"(severities={','.join(settings.trigger_severities)}, "
          f"types={','.join(settings.trigger_types)}{limit_note}).")

    jira = JiraClient(settings)

    # Locate existing tickets per bucket. Priority order:
    #   1. --reconcile mock file (local Case A-D demo)
    #   2. live Jira lookup (only on a real run)
    #   3. empty (dry/mock with nothing to reconcile against -> all Case A)
    if reconcile_path:
        existing = _load_mock_existing(reconcile_path)
    elif not dry_run and not mock_path:
        existing = jira.find_existing_buckets()
    else:
        existing = {}

    # Cross-project existing-ticket detection (configured via
    # JIRA_CROSSREF_PROJECTS).
    #   1. --crossref-mock file (local demo)
    #   2. live Jira search across the configured projects — built whenever
    #      real creds are usable (mock findings excepted) and not disabled.
    #      This runs in --dry-run too, so overlap can be reviewed read-only
    #      before any create.
    #   3. None (nothing to cross-reference against)
    crossref: CrossRefIndex | None = None
    if crossref_mock_path:
        crossref = _load_crossref_mock(crossref_mock_path)
    elif not no_crossref and not mock_path and settings.jira_token and settings.crossref_projects:
        crossref = build_index_from_jira(settings, jira._get_session())
    if crossref is not None:
        print(f"Cross-project index: {len(crossref.signatures)} existing "
              f"ticket(s) indexed for overlap checks.")

    scan_label = _scan_label()
    counts = {Case.CREATE: 0, Case.SKIP: 0, Case.UPDATE: 0, Case.ANNOTATE: 0}
    overlap_flags = 0
    # Per-bucket detail collected for the Markdown run report (report.py).
    report_buckets: list[dict] = []

    for t in tickets:
        rec = reconcile(t, existing.get(t.autoticket_id))
        counts[rec.case] += 1

        if rec.case is Case.SKIP:
            print(f"  [B] SKIP  {t.autoticket_id}: {t.summary} (unchanged)")
            report_buckets.append({
                "project": t.project_name, "severity": t.severity,
                "count": len(t.findings), "outcome": "Skip",
                "detail": "unchanged",
            })
            continue

        if rec.case is Case.CREATE:
            # PRIMARY new-vs-existing gate: the finding's SonarQube creation
            # date. Findings created before the cutoff (settings.new_since)
            # are treated as pre-existing (assumed already triaged outside
            # this pipeline), so a finding is genuinely NEW only if it was
            # created on/after the cutoff. This is authoritative and does not
            # depend on how each existing ticket was written.
            #
            # SECONDARY (annotation only): cross-project text match against the
            # configured cross-reference projects, shown for context. It never
            # overrides the date gate — a pre-cutoff finding is "already
            # tracked" even if the text match missed it, and a post-cutoff
            # finding is "new" even if a ticket happens to mention the same
            # file.
            cutoff = settings.new_since
            new_findings = []
            old_findings = []
            for f in t.findings:
                if f.creation_date and f.creation_date[:10] >= cutoff:
                    new_findings.append(f)
                else:
                    old_findings.append(f)

            all_old = bool(t.findings) and not new_findings

            if all_old:
                counts[Case.CREATE] -= 1
                counts[Case.SKIP] += 1
                overlap_flags += 1
                oldest = min((f.creation_date[:10] for f in t.findings if f.creation_date), default="?")
                print(f"  [B] ALREADY TRACKED  {t.autoticket_id}: {t.summary} "
                      f"— all {len(t.findings)} finding(s) pre-date {cutoff} "
                      f"(oldest {oldest}); no ticket created.")
                report_buckets.append({
                    "project": t.project_name, "severity": t.severity,
                    "count": len(t.findings), "outcome": "Already tracked",
                    "detail": f"all pre-date {cutoff} (oldest {oldest})",
                })
                continue

            # At least one genuinely new finding — report cross-project context
            # for the new ones.
            covered = {}
            for f in new_findings:
                ms = crossref.matches_for(f) if crossref else []
                strong = [m for m in ms if m.confidence in ("high", "medium")]
                if strong:
                    loc = f"{f.file_path}:{f.line}" if f.line is not None else f.file_path
                    covered[f"{f.rule} @ {loc}"] = strong[0]

            if dry_run:
                print("\n" + "=" * 72)
                print(f"[A] WOULD CREATE: {t.summary}  "
                      f"({len(new_findings)} new since {cutoff}, "
                      f"{len(old_findings)} pre-existing)")
                print(f"  autoticket-id: {t.autoticket_id}")
                print(f"  project : {settings.jira_project_key}")
                print(f"  parent  : {settings.parent_key}")
                print(f"  assignee: {settings.assignee_display_name}")
                print("  (+) Genuinely NEW findings (created on/after cutoff):")
                for f in new_findings:
                    loc = f"{f.file_path}:{f.line}" if f.line is not None else f.file_path
                    print(f"      - {f.creation_date[:10]}  {f.rule} @ {loc}")
                if covered:
                    print("  (!) Some NEW findings also text-match existing tickets (review):")
                    for desc, m in covered.items():
                        print(f"      - {desc} -> {m.ticket_key} [{m.project}, {m.confidence}]")
                print("-" * 72)
                # Ticket body should contain only the NEW findings.
                new_ticket = _bucket_of(t, new_findings)
                print(render_body(new_ticket))
                report_buckets.append({
                    "project": t.project_name, "severity": t.severity,
                    "count": len(t.findings), "outcome": "Would create",
                    "detail": f"{len(new_findings)} new since {cutoff}",
                })
            else:
                new_ticket = _bucket_of(t, new_findings)
                key = jira.create_ticket(new_ticket)
                print(f"  [A] CREATED {key}: {new_ticket.summary} "
                      f"({len(new_findings)} new finding(s))")
                report_buckets.append({
                    "project": t.project_name, "severity": t.severity,
                    "count": len(t.findings), "outcome": "Created",
                    "detail": f"{key} — {len(new_findings)} new finding(s)",
                })
            continue

        # Case C (UPDATE) or Case D (ANNOTATE) — both refresh an existing
        # ticket body and add an audit comment; neither closes/reassigns.
        resolved = set(rec.resolved_keys)
        body = render_body(t, resolved_keys=resolved, scan_label=scan_label)
        comment = update_comment(rec, scan_label)
        target = rec.existing.key if rec.existing else "?"
        tag = "C" if rec.case is Case.UPDATE else "D"
        verb = "UPDATE (new findings)" if rec.case is Case.UPDATE else "ANNOTATE (resolved)"

        if dry_run:
            print("\n" + "=" * 72)
            print(f"[{tag}] WOULD {verb}: {target} — {t.summary}")
            print(f"  autoticket-id: {t.autoticket_id}")
            if rec.added_keys:
                print(f"  + added   : {', '.join(rec.added_keys)}")
            if rec.resolved_keys:
                print(f"  - resolved: {', '.join(rec.resolved_keys)}")
            print("-" * 72)
            print(body)
            print("--- comment ---")
            print(comment)
        else:
            jira.update_body(target, body, summary=t.summary)
            jira.add_comment(target, comment)
            print(f"  [{tag}] {verb} {target}: {t.summary}")

        report_buckets.append({
            "project": t.project_name, "severity": t.severity,
            "count": len(t.findings),
            "outcome": ("Would " if dry_run else "") + verb,
            "detail": target,
        })

    print("\n" + "=" * 72)
    prefix = "DRY RUN complete" if dry_run else "Done"
    print(
        f"{prefix}: {counts[Case.CREATE]} create, {counts[Case.SKIP]} skip, "
        f"{counts[Case.UPDATE]} update, {counts[Case.ANNOTATE]} annotate-resolved."
    )
    if crossref is not None or True:
        if counts[Case.CREATE] == 0:
            print(
                f"No new Blocker/Critical vulnerabilities since {settings.new_since}: "
                f"every finding pre-dates the cutoff and is treated as already "
                f"tracked. No tickets created."
            )
        else:
            print(
                f"Result: {counts[Case.CREATE]} bucket(s) contain findings created "
                f"on/after {settings.new_since} (genuinely new); pre-existing "
                f"findings were skipped, not duplicated."
            )

    # Announce SonarQube projects that have no release-branch mapping in
    # branches.py. These were scanned on the SonarQube default branch
    # (branch_for() returned None), which may be the wrong branch since
    # finding sets differ by branch. This is the signal to hand-edit
    # PROJECT_BRANCHES in autoticket/branches.py: add a
    # "<project key>": "<release branch>" line. No restart needed — the next
    # run imports the updated map. Only the live path populates this list; mock
    # runs don't scan real projects, so the attribute may be absent/empty.
    unmapped = getattr(sonar, "unmapped_projects", None)
    if unmapped:
        print("\n" + "=" * 72)
        print(
            f"ACTION NEEDED: {len(unmapped)} SonarQube project(s) have no branch "
            f"mapping in branches.py and were scanned on the SonarQube DEFAULT "
            f"branch (may be the wrong branch):"
        )
        for pkey in sorted(unmapped):
            print(f"  - {pkey}")
        print(
            "  Fix: add a \"<project key>\": \"<release branch>\" line to "
            "PROJECT_BRANCHES in autoticket/branches.py. The next run picks it "
            "up automatically."
        )

    # Advance the watermark ONLY after a fully successful LIVE run. Dry-run and
    # mock runs do not represent a real completed scan, so they must not move
    # the window. Because any failure above raises before reaching this point,
    # last_run.txt is left untouched on failure and the next run retries from
    # the same cutoff.
    if not dry_run and not mock_path:
        today = _dt.date.today().isoformat()  # YYYY-MM-DD
        write_watermark(today)
        print(f"Watermark advanced: next run will scan for findings created "
              f"on/after {today} (saved to last_run.txt).")
        watermark_advanced_to = today
    else:
        watermark_advanced_to = None

    # Write a Markdown run report (best-effort; never raises). Gives
    # at-a-glance confirmation the job ran and what it found, so the operator
    # doesn't have to wonder or dig through logs.
    write_report({
        "mode": "dry-run" if dry_run else ("mock" if mock_path else "live"),
        "counts": {
            "create": counts[Case.CREATE],
            "skip": counts[Case.SKIP],
            "update": counts[Case.UPDATE],
            "annotate": counts[Case.ANNOTATE],
        },
        "buckets": report_buckets,
        "unmapped": list(unmapped) if unmapped else [],
        "total_findings": len(findings),
        "total_buckets": len(tickets),
        "cutoff": settings.new_since,
        "severities": ", ".join(settings.trigger_severities),
        "types": ", ".join(settings.trigger_types),
        "crossref_count": (len(crossref.signatures) if crossref is not None else None),
        "watermark_advanced_to": watermark_advanced_to,
    })

    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        return run(
            dry_run=args.dry_run,
            mock_path=args.mock,
            limit=args.limit,
            reconcile_path=args.reconcile,
            crossref_mock_path=args.crossref_mock,
            no_crossref=args.no_crossref,
        )
    except EnvironmentError as e:
        print(f"Config error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
