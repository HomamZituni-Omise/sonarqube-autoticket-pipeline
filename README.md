# SonarQube Vulnerability Auto-Ticketing Pipeline

Scans the SonarQube Web API for **Blocker + Critical vulnerability** findings
and automatically creates/updates **Jira** tickets for security triage. It is a
small, dependency-light Python tool you can point at any SonarQube instance and
any Jira project.

It has **no CI-server dependency** — it needs only network access to the
SonarQube Web API and the Jira API, plus two API tokens (stored in your OS
keyring or a local `.env`).

## What it does

| Concern | Behavior |
|---------|----------|
| Triggers on | Severity **Blocker** + **Critical**, type **Vulnerability** (configurable) |
| Grouping | One ticket **per project, per severity** (all Blockers → 1 ticket; all Criticals → 1 ticket) |
| Dedup | Keyed on SonarQube **issue key** — re-runs do not create duplicates |
| New-vs-existing gate | Finding **creation date** vs. a moving watermark (`last_run.txt`); findings predating the cutoff are treated as already-triaged and are not raised |
| Reconciliation | Updates a ticket in place as findings appear/resolve; never auto-closes |
| Target | Any Jira project (set `JIRA_PROJECT_KEY`); optional parent/assignee |

Everything environment-specific (URLs, project keys, assignee, parent, branch
map) is configurable — there are no hardcoded organization values.

## Layout

```
.
├── autoticket/              # the Python package
│   ├── config.py            # settings; loads tokens keyring-first, .env fallback
│   ├── models.py            # Finding, PlannedTicket
│   ├── sonar_client.py      # SonarQube Web API client (project discovery + per-branch scan; mock path)
│   ├── branches.py          # per-project → release-branch map (customize for your projects)
│   ├── grouping.py          # per-project-per-severity grouping + ticket body render
│   ├── crossref.py          # optional cross-project existing-ticket detection for context
│   ├── reconcile.py         # Cases A–D decision logic for a (project, severity) bucket
│   ├── jira_client.py       # Jira create/update + dedupe (issue-key based)
│   ├── notify.py            # failure notifier: opens a Jira ticket if a scheduled run fails
│   └── main.py              # CLI orchestrator (--dry-run / --mock / --limit / --reconcile)
├── sample_data/             # synthetic API-shaped responses for offline dry-run demos
├── docs/                    # design notes (not part of the runtime)
├── run_autoticket.sh        # scheduled runner: sources .env, runs the module, alerts on failure
├── requirements.txt         # requests, keyring
├── .env.example             # template — placeholders only (copy to .env; never commit .env)
└── .gitignore
```

## Secrets & configuration

Two kinds of settings, loaded two different ways:

- **API tokens** (`SONAR_TOKEN`, `JIRA_TOKEN`) — read from your **OS keyring**
  first (via the `keyring` library), falling back to the environment only if
  the keyring has nothing (so local testing still works). Store them once, e.g.
  on macOS:
  ```bash
  security add-generic-password -s sonar-token -a "$USER" -w
  security add-generic-password -s jira-token  -a "$USER" -w
  ```
  (`keyring` also supports the Windows Credential Locker and the Linux Secret
  Service.)
- **Non-secret settings** (`SONAR_BASE_URL`, `JIRA_BASE_URL`, `JIRA_EMAIL`,
  project-key / assignee / parent / severity overrides) — live in a local
  **`.env`** file. Copy `.env.example` to `.env` and fill it in. `.env` is
  git-ignored and must never be committed.

## Quick start (dry run, no credentials needed)

```bash
python3 -m autoticket.main --dry-run --mock sample_data/sonar_issues.json
```

Prints the tickets that *would* be created — no Jira writes, no tokens required.

## First live contact (low-risk)

Once tokens are in the keyring (and non-secret settings in `.env`), do a small,
read-only sample against the live instance before any full run:

```bash
set -a; source .env; set +a
python3 -m autoticket.main --dry-run --limit 5   # pulls at most 5 findings, creates nothing
```

`--limit N` caps how many findings are pulled (and shrinks the API page size to
match), so the first live test stays fast and small instead of scanning every
project. Combine with `--dry-run` so nothing is written to Jira.

## Live run

```bash
pip install -r requirements.txt
set -a; source .env; set +a
python3 -m autoticket.main --dry-run     # verify against live SonarQube first
python3 -m autoticket.main               # actually create/update tickets
```

## Scheduled operation

`run_autoticket.sh` is a wrapper for running the pipeline unattended (e.g. from
cron, launchd, systemd timers, or a CI schedule). It cd's into the project,
loads `.env`, runs the module, and on a non-zero exit invokes `autoticket.notify`
to open a Jira ticket about the failed run. Set `AUTOTICKET_DIR` to the project
path if you don't run it from the project root.

### Connectivity preflight (VPN check)

Before the real run, the wrapper probes whether the SonarQube host (derived from
`SONAR_BASE_URL`) is reachable — useful when SonarQube is only accessible over a
corporate VPN or private network:

- **Reachable** → proceeds to the run.
- **Unreachable, interactive terminal** → warns and prompts for a go-ahead so
  you can connect to the VPN first.
- **Unreachable, unattended/scheduled run** → prints a reminder and exits `0`
  **without running**, so no spurious failure ticket is opened and the watermark
  is left untouched for a clean retry on the next run.

Set `AUTOTICKET_SKIP_PREFLIGHT=1` to disable the check.

### Example schedule (macOS launchd)

A monthly run is a common cadence. For example, to run on the **16th of each
month at 1:00 PM** local time, a launchd agent's calendar interval would be:

```xml
<key>StartCalendarInterval</key>
<dict>
    <key>Day</key>    <integer>16</integer>
    <key>Hour</key>   <integer>13</integer>
    <key>Minute</key> <integer>0</integer>
</dict>
```

`launchd` fires on the host's local wall-clock time and catches up missed runs
if the machine was asleep. The equivalent cron entry would be `0 13 16 * *`.

The **watermark** (`last_run.txt`) holds the "new since" cutoff. It advances to
today **only after a fully successful run**, so a failure never skips a window —
the next run retries from the same cutoff.

### Run report (Markdown)

Every run also writes a Markdown summary so you have at-a-glance confirmation the
job ran and what it found — without digging through logs or Jira. The file is
named `AutoTicket-Job-MM-DD-YYYY.md` (today's date) and is written to the first
writable location of:

1. `$AUTOTICKET_REPORT_DIR` (if set)
2. `~/Desktop`
3. `~/Library/Logs` (fallback)

The report contains the run timestamp/mode, a summary table (findings, buckets,
created/skipped/updated counts, cutoff, watermark), a per-bucket table, and an
"action needed" section listing any unmapped projects. Writing the report is
best-effort and never fails the run.

> Note: on modern macOS, background `launchd` agents are blocked from writing to
> the TCC-protected Desktop, so scheduled runs typically land the report in
> `~/Library/Logs` (or set `AUTOTICKET_REPORT_DIR` to a non-protected path).
> Interactive/manual runs write to the Desktop directly.

## Project discovery & branch mapping

The scan discovers projects **dynamically** — it lists every project visible to
the token via `/api/components/search`, so new SonarQube projects are picked up
automatically with no code change. (You can also restrict to specific projects
via `SONAR_PROJECT_KEYS`.)

Findings are read from each project's **release branch**, not SonarQube's
default branch, because the finding set can differ by branch. That mapping lives
in `autoticket/branches.py` (`PROJECT_BRANCHES`) — customize it for your
projects. A project with no entry is still scanned, but on the SonarQube default
branch; at the end of every run the pipeline prints an **`ACTION NEEDED`** block
listing any such unmapped projects so you can add them.

## Reconciliation behavior (Cases A–D)

Grouping is *one ticket per project per severity*, so each ticket is a **living
bucket**: findings enter and leave it across scans. Every ticket body embeds a
stable **Autoticket ID** (`<project>|<severity>`). On each run the pipeline
locates the existing open ticket for a bucket by that id and compares its
recorded finding keys against the current scan:

| Case | Situation | Action |
|------|-----------|--------|
| **A** | No existing ticket, findings exist | **Create** a new ticket |
| **B** | Existing ticket, findings unchanged | **Skip** (no-op) |
| **C** | Existing ticket, **new** findings appeared | **Update** the existing ticket (refresh body, add audit comment) — *no duplicate ticket* |
| **D** | Existing ticket, some findings **gone** | **Annotate** them "resolved — verify before closing" + comment; ticket stays open |

Updates never reopen, reassign, or close a ticket — a bucket may be mid-triage,
and auto-close is intentionally left to a human. A bucket whose ticket is
already `Done` is treated as Case A (create fresh) when the finding reappears.

### Demonstrate all four cases locally (no live systems)

```bash
python3 -m autoticket.main --dry-run \
    --mock sample_data/sonar_scan2.json \
    --reconcile sample_data/existing_tickets.json
```

`--reconcile PATH` loads a mock "existing tickets" state
(`{"<project>|<SEVERITY>": {"key": "PROJ-123", "dedupe_keys": [...]}}`) so Cases
A–D can be exercised end-to-end without touching Jira or SonarQube.

## CLI reference

| Flag | Purpose |
|------|---------|
| `--dry-run` | Print planned actions; do not write to Jira |
| `--mock PATH` | Read findings from a captured JSON file (no live creds) |
| `--limit N` | Pull at most N findings — low-risk first live contact |
| `--reconcile PATH` | Load mock "existing tickets" to demo Cases A–D locally |
| `--crossref-mock PATH` | Load mock cross-project tickets to demo overlap detection |
| `--no-crossref` | Disable cross-project existing-ticket detection on a live run |

## Optional: cross-project existing-ticket detection

If you track remediation work in other Jira projects (e.g. a security backlog or
remediation epics), set `JIRA_CROSSREF_PROJECTS` to a comma-separated list. The
pipeline then checks whether a new finding appears to already be covered by an
existing human-written ticket (matched heuristically by rule ID + file + line)
and surfaces that as context. This is **annotation only** — it never auto-skips
a finding; the create/skip decision stays with a human.

## docs/

Design notes, **not** part of the runtime — a generic example of planning a
hosted/scheduled deployment (e.g. a serverless function on a schedule, with
secrets in a parameter store). Illustrative only.

## Status

- [x] Scan + severity/type filter via SonarQube Web API
- [x] One ticket per project per severity, issue-key dedupe
- [x] Reconciliation Cases A–D (bucket-identity marker) — verified locally via `--reconcile`
- [x] Secrets via OS keyring; non-secret config in `.env`
- [x] Per-project release-branch mapping + unmapped-project announcement
- [x] Scheduled-run wrapper with failure alerting (Jira ticket)
- [ ] Populate rule display names + remediation via `/api/rules` lookup
