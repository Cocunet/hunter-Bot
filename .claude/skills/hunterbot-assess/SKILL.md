---
name: hunterbot-assess
description: Run a full HunterBot vulnerability assessment against a target in one guided pass -- check authorization, scan, optionally test for broken access control / IDOR, triage findings with Claude, and generate a report. Use this whenever someone asks to assess, scan, pentest, or "find vulnerabilities on" a target using HunterBot, asks what HunterBot found, or wants a prioritized security report instead of running `hunterbot scope`/`scan`/`findings`/`report` commands one at a time by hand. Also trigger on "run hunterbot against X", "check X for vulnerabilities", or "give me a report on X's security". Requires the `hunterbot` CLI to be installed and runnable in this environment (`pip install -e ".[dev]"` from the repo root if it isn't yet).
---

# HunterBot guided assessment

HunterBot is an **authorized-only** scanning tool: every scan use-case refuses to touch a
target that has no active `Scope` record. This workflow exists to drive that whole
pipeline -- authorization check, scan, triage, report -- as one continuous pass instead of
five separate commands, while never loosening the safety boundary that makes the tool
safe to run: it does not invent a target, a Scope, or an AuthSession that the user did not
give it.

## Before starting: confirm authorization

Run `hunterbot scope check <target>` first, always, no exceptions. Two outcomes:

- **Authorized** -- proceed to the scan stage.
- **Not authorized** -- stop here. Tell the user plainly that HunterBot has no active
  Scope for this target and ask whether they want to register one:
  `hunterbot scope add <target> --program "<name>" --authorized-by "<who>"`.
  Only run `scope add` if the user explicitly confirms they are authorized to test this
  target and gives you the program name and who granted authorization -- do not guess or
  fabricate those two fields, and do not proceed to scanning until they've answered.

This check exists because HunterBot's own architecture enforces it anyway (`scan run` and
`scan access-control` both call the same authorization gate and will hard-fail with a clear
error if scope is missing) -- checking first just means you find out *before* spending a
scan cycle, and can have the authorization conversation with the user up front instead of
via a stack trace.

## Step 1: Run the baseline scan

```
hunterbot scan run <base_url>
```

Ask the user two things before running it, since both change what gets tested:

1. **Adaptive mode?** `--adaptive` lets Claude pick which of the 10 built-in scanners are
   worth running based on a quick recon request, instead of always running all of them.
   Useful for a fast first pass on a large target; skip it (the default) when the user
   wants full, deterministic coverage. Falls back to running everything if adaptive
   selection fails for any reason, so it's a safe default to suggest either way.
2. **Authenticated?** If the user has already registered a session (see
   `hunterbot session list`) for this target, pass `--session <id>` so the scan runs as
   that logged-in identity instead of anonymously. Don't offer to create a session
   yourself -- HunterBot never performs a login (see `hunterbot session add --help` if the
   user needs the syntax); that has to happen out-of-band and be handed to you as an id.

Each finding printed is one line: `[id] SEVERITY — title (scanner-name)`. Keep the ids;
you'll reference the highest-severity ones in your final summary.

## Step 2: Offer the access-control / IDOR check (conditional)

This step only makes sense if the user already has **two** registered AuthSessions for
different accounts on the same target, plus at least one resource-shaped path they want
tested (e.g. `/api/orders/1001`) -- HunterBot doesn't crawl, so it can't discover
candidate paths on its own, and this scan can't run without them.

If the user hasn't mentioned having those, ask once: "Do you have two logged-in sessions
registered for this target, and any endpoints like `/api/orders/123` you want checked for
broken access control?" If yes, run:

```
hunterbot scan access-control <base_url> --baseline-session <id> --test-session <id> \
  --path <path> [--path <path> ...]
```

`--baseline-session` is whichever identity is presumed to own the resources at the given
paths; `--test-session` is the independent second identity being tested for cross-account
access. If the answer is no, skip this step entirely -- don't block the rest of the
workflow on it, and don't invent session ids or paths to make it runnable.

## Active scanners are out of scope for this guided pass

`hunterbot scan race-condition`, `scan file-upload-rce`, `scan xxe`, and `scan mass-assignment`
all exist, but never run any of them as part of this workflow, even if the user's target
looks like a good candidate (a coupon endpoint, an upload form, an XML import feature, a
user-update endpoint). All four send real state-changing requests -- the race scanner
actually performs a chosen action repeatedly, the upload scanner actually leaves a file on
the target, the XXE scanner actually posts a crafted XML body, the mass-assignment scanner
actually submits an extra field -- and all four require the tester to name a specific
endpoint (and, for uploads/mass-assignment, a field name) that nothing in this guided pass
collects or should guess. If the user explicitly asks for one of these by name and supplies
the endpoint themselves, run it as its own request with its own confirmation, not folded
into Steps 1-5 above.

## Step 3: Triage with Claude

```
hunterbot findings analyze
```

(add `--asset <base_url>` to scope it to just this target if other scans share the same
database). This is read-only -- it reasons about findings already in storage and never
re-scans -- and requires the `llm` extra plus `ANTHROPIC_API_KEY` to be configured. If it
errors because the LLM isn't set up, that's fine: say so, skip straight to Step 4, and
still summarize findings by severity yourself from the scan output.

## Step 4: Generate a report

Ask the user which format they want (`markdown`, `json`, `html`, `pdf`, `docx`, or
`xlsx`) -- default to `markdown` if they don't have a preference, since it's the easiest
to review inline. Then:

```
hunterbot report generate <path> --format <format>
```

Add `--asset <base_url>` to scope the report to this target only, same as Step 3.

## Step 5: Summarize in chat

Don't just say "done, see the report." Pull the highest-priority findings (critical/high
first, using the triage output from Step 3 if you got one, otherwise severity from the
raw scan output) and summarize them directly in the conversation: what was found, why it
matters, and where the full detail lives (the generated report path, or specific finding
ids). This is the payoff of running the whole pipeline instead of one command -- the user
should walk away knowing what to fix first without opening the report file, even though
it's there for the full detail.

## Guardrails (apply throughout, not just at the top)

- Never run `scan run` or `scan access-control` against a target you haven't confirmed is
  authorized in this same conversation -- a prior scope check from an earlier session
  doesn't count; scopes can expire.
- Never fabricate a Scope, AuthSession, program name, authorizer name, or candidate path.
  Every one of those either comes from the user or from a HunterBot command's own output
  (e.g. `hunterbot session list` to find a real session id) -- if you don't have a real
  value, ask, don't guess.
- If any step's command fails (target unreachable, database not initialized, missing
  extra), report the actual error to the user and stop there rather than pushing forward
  with a broken pipeline -- e.g. an uninitialized database means `hunterbot init-db` needs
  to run first, which is worth surfacing, not silently working around.
- Never run `scan race-condition`, `scan file-upload-rce`, `scan xxe`, or
  `scan mass-assignment` on your own initiative or as part of this guided pass -- all four
  send real state-changing requests with side effects on the target, and all four need an
  endpoint (and expected behavior) only the user can supply.
