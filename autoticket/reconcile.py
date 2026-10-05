"""Reconciliation logic — Cases A-D.

Each (project, severity) bucket is a *living ticket*: findings enter and leave
across scans. For each bucket we compare the CURRENT scan's finding keys
against the keys recorded on the existing open ticket (located by its stable
Autoticket ID) and classify the action:

  Case A  No existing ticket, findings exist        -> CREATE
  Case B  Existing ticket, findings unchanged        -> SKIP
  Case C  Existing ticket, NEW findings appeared      -> UPDATE (append + comment)
  Case D  Existing ticket, some findings GONE         -> ANNOTATE resolved + comment
          (auto-close is intentionally never done here — left to human triage)

A bucket can be both C and D at once (some added, some gone); we surface that
as UPDATE with a comment covering both. Closed-then-reappears is handled at the
Jira layer: a bucket whose ticket is Done is not returned by find_existing_
buckets(), so it falls through to Case A (CREATE FRESH).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .jira_client import ExistingTicket
from .models import PlannedTicket


class Case(str, Enum):
    CREATE = "A"    # no existing ticket, findings exist
    SKIP = "B"      # existing ticket, unchanged
    UPDATE = "C"    # existing ticket, new findings appeared
    ANNOTATE = "D"  # existing ticket, some findings resolved (none added)


@dataclass
class Reconciliation:
    """The decided action for one (project, severity) bucket."""

    case: Case
    planned: PlannedTicket
    existing: ExistingTicket | None = None
    added_keys: list[str] = field(default_factory=list)     # new this scan (C)
    resolved_keys: list[str] = field(default_factory=list)  # gone this scan (D)

    @property
    def autoticket_id(self) -> str:
        return self.planned.autoticket_id


def reconcile(
    planned: PlannedTicket, existing: ExistingTicket | None
) -> Reconciliation:
    """Classify a single bucket into Case A/B/C/D."""
    current = set(planned.dedupe_keys)

    # Case A — nothing exists yet for this bucket.
    if existing is None:
        return Reconciliation(case=Case.CREATE, planned=planned)

    prior = set(existing.dedupe_keys)
    added = sorted(current - prior)
    resolved = sorted(prior - current)

    # Case B — identical finding set, nothing to do.
    if not added and not resolved:
        return Reconciliation(case=Case.SKIP, planned=planned, existing=existing)

    # Case C — new findings appeared (possibly alongside resolved ones). We
    # treat any addition as an UPDATE; resolved keys still get reported.
    if added:
        return Reconciliation(
            case=Case.UPDATE,
            planned=planned,
            existing=existing,
            added_keys=added,
            resolved_keys=resolved,
        )

    # Case D — only resolutions, no additions. Annotate; never auto-close.
    return Reconciliation(
        case=Case.ANNOTATE,
        planned=planned,
        existing=existing,
        resolved_keys=resolved,
    )


def update_comment(rec: Reconciliation, scan_label: str) -> str:
    """Audit comment text for a Case C/D update."""
    parts: list[str] = ["SonarQube auto-ticketing reconciliation " f"(scan {scan_label}):"]
    if rec.added_keys:
        parts.append(
            f"- Added {len(rec.added_keys)} new finding(s): "
            + ", ".join(rec.added_keys)
        )
    if rec.resolved_keys:
        parts.append(
            f"- {len(rec.resolved_keys)} finding(s) no longer present "
            f"(verify before closing): " + ", ".join(rec.resolved_keys)
        )
    parts.append(
        "Ticket body refreshed. Status/assignee left unchanged "
        "(auto-close left to human triage)."
    )
    return "\n".join(parts)
