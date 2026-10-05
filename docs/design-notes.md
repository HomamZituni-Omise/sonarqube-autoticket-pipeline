# Design Notes

Background notes on the pipeline's design. **Not part of the runtime.**

## Why this exists

Static-analysis findings pile up faster than anyone triages them. The goal here
is to turn a specific, high-signal slice of SonarQube output — **Blocker and
Critical vulnerabilities** — into Jira tickets automatically, so the security
backlog reflects the scanner without manual copy-paste, and without drowning
triagers in noise.

## Core design decisions

1. **One ticket per project per severity.** Not one ticket per finding (too
   noisy) and not one giant ticket (unactionable). Each ticket is a *living
   bucket* of findings for a `(project, severity)` pair.

2. **Stable bucket identity.** Each ticket body embeds an `Autoticket ID` of
   the form `<project>|<severity>`. Re-runs locate the existing ticket by this
   marker rather than by its finding set (which changes over time), which is
   what makes idempotent updates possible.

3. **Issue-key dedupe.** The SonarQube issue key is the dedupe unit, recorded in
   the ticket body. Re-running never creates duplicates.

4. **New-vs-existing watermark.** A moving cutoff date (`last_run.txt`) lets the
   tool distinguish genuinely new findings from a pre-existing backlog, so the
   first run against a mature instance doesn't open a ticket for every historic
   finding. The watermark only advances after a fully successful run, so a
   failure never silently skips a window.

5. **Per-branch scanning.** Findings are read from each project's configured
   release branch, because the finding set can differ by branch. Unmapped
   projects fall back to the default branch and are reported for follow-up.

6. **Never auto-close.** Updates refresh the body and add an audit comment, but
   never reopen, reassign, or close — a bucket may be mid-triage. Resolved
   findings are annotated "verify before closing" and left for a human.

## Reconciliation (Cases A–D)

| Case | Situation | Action |
|------|-----------|--------|
| A | No existing ticket, findings exist | Create |
| B | Existing ticket, findings unchanged | Skip |
| C | Existing ticket, new findings appeared | Update body + comment |
| D | Existing ticket, some findings gone | Annotate resolved + comment |

## Running it hosted / on a schedule (illustrative)

The CLI is stateless apart from the small watermark file, so it ports cleanly to
a scheduled, hosted execution model. A typical shape:

- **Compute:** a short-lived scheduled job (a serverless function on a timer, or
  a scheduled container task). A full scan is quick, so a function with a
  generous timeout is usually enough.
- **Secrets:** store the SonarQube and Jira tokens in a managed secret/parameter
  store and read them at runtime via the job's identity, instead of a local
  `.env`.
- **State:** keep the "new since" watermark in that same parameter store so the
  job stays self-contained; advance it only on success.
- **Observability:** ship logs to your platform's log service and alarm on a
  non-zero exit so a silent failure is impossible.
- **Deploy:** infrastructure-as-code from the repo, deployed by CI, with the
  deploy identity federated rather than using long-lived keys.

These are sketches, not prescriptions — adapt them to whatever cloud/CI you run.
