"""Grouping + ticket-body rendering.

Grouping policy: one ticket per project per severity level. All Blocker
findings in a project -> one ticket; all Critical -> one ticket.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .models import Finding, PlannedTicket


def group_findings(findings: Iterable[Finding]) -> list[PlannedTicket]:
    """Bucket findings into (project_key, severity) -> PlannedTicket."""
    buckets: dict[tuple[str, str], PlannedTicket] = {}

    for f in findings:
        key = (f.project_key, f.severity)
        ticket = buckets.get(key)
        if ticket is None:
            ticket = PlannedTicket(
                project_key=f.project_key,
                project_name=f.project_name,
                severity=f.severity,
            )
            buckets[key] = ticket
        ticket.findings.append(f)

    # Stable order: project then severity (Blocker before Critical).
    sev_order = {"BLOCKER": 0, "CRITICAL": 1}
    return sorted(
        buckets.values(),
        key=lambda t: (t.project_name.lower(), sev_order.get(t.severity, 99)),
    )


# --- Rule -> compliance mapping -------------------------------------------
#
# Maps common SonarQube rule IDs to their CWE / OWASP classification so the
# Compliance section can be auto-populated from scanner output. This is a
# best-effort lookup for a handful of frequently-seen rules; rules not in the
# table fall back to a placeholder for the analyst to complete.
# (A future iteration can source this from SonarQube /api/rules instead.)
RULE_COMPLIANCE: dict[str, dict[str, str]] = {
    "java:S2755": {"cwe": "CWE-611 — Improper Restriction of XML External Entity Reference",
                   "owasp": "OWASP A4 — XML External Entities (XXE)",
                   "title": "Disable access to external entities in XML parsing"},
    "java:S4423": {"cwe": "CWE-327 — Use of a Broken or Risky Cryptographic Algorithm",
                   "owasp": "OWASP A6 — Security Misconfiguration",
                   "title": "Weak SSL/TLS protocol"},
    "java:S4830": {"cwe": "CWE-295 — Improper Certificate Validation",
                   "owasp": "OWASP A6 — Security Misconfiguration",
                   "title": "Server certificate validation disabled"},
    "java:S2076": {"cwe": "CWE-78 — OS Command Injection",
                   "owasp": "OWASP A1 — Injection",
                   "title": "OS command injection"},
    "java:S3649": {"cwe": "CWE-89 — SQL Injection",
                   "owasp": "OWASP A1 — Injection",
                   "title": "SQL injection"},
    "java:S2083": {"cwe": "CWE-22 — Path Traversal",
                   "owasp": "OWASP A1 — Injection",
                   "title": "Path traversal"},
    "java:S5344": {"cwe": "CWE-327 — Use of a Broken or Risky Cryptographic Algorithm",
                   "owasp": "OWASP A2 — Cryptographic Failures",
                   "title": "Weak password hashing"},
    "java:S2647": {"cwe": "CWE-522 — Insufficiently Protected Credentials",
                   "owasp": "OWASP A2 — Cryptographic Failures",
                   "title": "Basic authentication over insecure channel"},
    "javascript:S2068": {"cwe": "CWE-798 — Use of Hard-coded Credentials",
                         "owasp": "OWASP A7 — Identification and Authentication Failures",
                         "title": "Hard-coded credentials"},
    "csharpsquid:S4423": {"cwe": "CWE-327 — Use of a Broken or Risky Cryptographic Algorithm",
                          "owasp": "OWASP A6 — Security Misconfiguration",
                          "title": "Weak SSL/TLS protocol"},
    "python:S5443": {"cwe": "CWE-377 — Insecure Temporary File",
                     "owasp": "OWASP A1 — Injection",
                     "title": "Insecure temporary file"},
}

# Placeholder marker for sections that require analyst judgment. The template
# is explicit that scanner output and analyst judgment must be separated, so
# the pipeline auto-fills only what the scanner provides and flags the rest.
_ANALYST = "_[Analyst assessment required — complete during triage.]_"


def _compliance_for(rule: str) -> dict[str, str] | None:
    return RULE_COMPLIANCE.get(rule)


def render_body(
    ticket: PlannedTicket,
    resolved_keys: set[str] | None = None,
    scan_label: str = "",
) -> str:
    """Render the Jira ticket body following a Vulnerability Write-Up template.

    Section order: Overview, Vulnerability Details, Why This Matters,
    Compliance, Risk Assessment, Residual Risks, Recommendation, References,
    Notes.

    Scanner-derived fields (metadata, file:line, rule, message, links, and a
    best-effort CWE/OWASP mapping) are auto-populated. Sections that require
    analyst judgment are emitted as clearly-marked placeholders so the scanner
    output is never confused with human assessment (a core rule of the
    template). Uses Jira wiki markup (hN. headings, *bold*, _italic_,
    {{monospace}} for code refs).

    resolved_keys (Case D): SonarQube issue keys present on this bucket in a
    prior scan but absent now — listed as resolved-pending-verification. Never
    auto-closed (left to human triage).
    """
    resolved_keys = resolved_keys or set()
    sev = ticket.severity.capitalize()
    n = len(ticket.findings)
    noun = "finding" if n == 1 else "findings"
    lines: list[str] = []

    # --- Overview ----------------------------------------------------------
    lines.append("h2. Overview")
    lines.append("")
    lines.append(
        f"SonarQube static analysis reported {n} {sev}-severity vulnerability "
        f"{noun} in {ticket.project_name}. This ticket bundles all {sev} "
        f"vulnerabilities for this project (one ticket per project per "
        f"severity). Assessed severity and disposition require analyst review."
    )
    lines.append("")
    lines.append(f"* _Application:_ {ticket.project_name}")
    lines.append(f"* _Repository / project key:_ {{{{{ticket.project_key}}}}}")
    lines.append(f"* _Scanner Severity:_ {sev}")
    lines.append(f"* _Assessed Severity:_ {_ANALYST}")
    lines.append(f"* _Total findings:_ {n}")
    if resolved_keys:
        verify = f" in scan {scan_label}" if scan_label else ""
        lines.append(
            f"* _Resolved (pending verification):_ {len(resolved_keys)} "
            f"finding(s) no longer detected{verify} — verify before closing."
        )
    lines.append("")
    lines.append(
        "_Auto-created by the SonarQube Vulnerability Auto-Ticketing Pipeline. "
        "Scanner-derived fields are populated automatically; "
        "sections marked for analyst assessment must be completed during "
        "triage._"
    )
    lines.append("")

    # --- Vulnerability Details --------------------------------------------
    lines.append("h2. Vulnerability Details")
    lines.append("")
    lines.append(
        "The following findings were reported by SonarQube. Each lists the "
        "rule, exact location, and scanner message. Review each in "
        "implementation context before dispositioning."
    )
    lines.append("")
    for i, f in enumerate(ticket.findings, start=1):
        loc = f"{f.file_path}:{f.line}" if f.line is not None else f.file_path
        comp = _compliance_for(f.rule)
        title = comp["title"] if comp else (f.rule_name if f.rule_name and f.rule_name != f.rule else f.rule)
        lines.append(f"h3. {i}. {title} — {{{{{f.rule}}}}}")
        lines.append(f"* _File:_ {{{{{loc}}}}}")
        lines.append(f"* _Rule:_ {{{{{f.rule}}}}}")
        lines.append(f"* _Message:_ {f.message}")
        if f.remediation:
            lines.append(f"* _Remediation (scanner):_ {f.remediation}")
        lines.append(f"* _SonarQube link:_ {f.sonar_link}")
        lines.append(f"* _SonarQube issue key:_ {{{{{f.issue_key}}}}}")
        lines.append("")

    # --- Why This Matters --------------------------------------------------
    lines.append("h2. Why This Matters")
    lines.append("")
    lines.append(
        "Use this section to explain the real-world impact and exploit path in "
        "the context of the actual implementation (remediation framing)."
    )
    lines.append("")
    lines.append(f"# *Key risk driver* — {_ANALYST}")
    lines.append(f"# *Implementation context* — {_ANALYST}")
    lines.append(f"# *Security conclusion (is it exploitable, and why)* — {_ANALYST}")
    lines.append("")

    # --- Compliance --------------------------------------------------------
    lines.append("h2. Compliance")
    lines.append("")
    mapped = {}
    for f in ticket.findings:
        comp = _compliance_for(f.rule)
        if comp:
            mapped[comp["cwe"]] = True
            mapped[comp["owasp"]] = True
    if mapped:
        for item in sorted(mapped):
            lines.append(f"* {item}")
    else:
        lines.append(f"* {_ANALYST} (CWE / OWASP mapping — no auto-mapping for these rules)")
    lines.append(f"* _Scanner Severity:_ {sev}")
    lines.append(f"* _Assessed Severity:_ {_ANALYST}")
    lines.append(
        "* _Note:_ confirm which regulatory/compliance requirements (e.g. "
        "PCI DSS, SOC 2, HIPAA) apply to this system during triage."
    )
    lines.append("")

    # --- Risk Assessment ---------------------------------------------------
    lines.append("h2. Risk Assessment")
    lines.append("")
    lines.append(f"* _Exploitability:_ {_ANALYST}")
    lines.append(f"* _Impact if exploited:_ {_ANALYST}")
    lines.append(f"* _Can it be fixed:_ {_ANALYST}")
    lines.append(f"* _Compliance risk:_ {_ANALYST}")
    lines.append("")

    # --- Residual Risks ----------------------------------------------------
    lines.append("h2. Residual Risks")
    lines.append("")
    lines.append(f"* {_ANALYST}")
    lines.append("")

    # --- Recommendation ----------------------------------------------------
    lines.append("h2. Recommendation")
    lines.append("")
    lines.append(
        f"State the disposition (remediate / accept risk / false positive / "
        f"planned remediation). {_ANALYST}"
    )
    lines.append("")
    lines.append("*Actions:*")
    lines.append(f"* {_ANALYST}")
    lines.append("")

    # --- References --------------------------------------------------------
    lines.append("h2. References")
    lines.append("")
    seen_rules = []
    for f in ticket.findings:
        if f.rule not in seen_rules:
            seen_rules.append(f.rule)
    for rule in seen_rules:
        lines.append(f"* SonarQube rule {{{{{rule}}}}}")
    lines.append("* Vulnerability Write-Up Template (link to your own standard)")
    lines.append("")

    # --- Notes / Case D history -------------------------------------------
    lines.append("h2. Notes")
    lines.append("")
    if resolved_keys:
        label = f" (scan {scan_label})" if scan_label else ""
        lines.append(f"Resolved in a later scan{label} — verify before closing:")
        for key in sorted(resolved_keys):
            lines.append(f"* {{{{{key}}}}} — no longer detected; confirm remediation, then close manually.")
    else:
        lines.append("Attach supporting analysis or scanner evidence when available.")
    lines.append("")

    # --- Machine-readable reconciliation markers (keep for dedupe) ---------
    # Dedupe keys reflect the CURRENT finding set only (resolved keys drop off
    # so the next scan does not resurrect them).
    lines.append("----")
    lines.append(f"(!) Autoticket ID: {{{{{ticket.autoticket_id}}}}}")
    lines.append(f"(!) Dedupe keys: {', '.join(ticket.dedupe_keys)}")
    return "\n".join(lines)
