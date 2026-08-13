# OWASP Risk Rating Methodology, applied to four vulnerability classes

This document scores real, commonly seen variants of four vulnerability classes —
CORS misconfiguration, cross-site scripting, race conditions, and file upload
vulnerabilities leading to remote code execution — using OWASP's Risk Rating
Methodology (https://owasp.org/www-community/OWASP_Risk_Rating_Methodology):
Likelihood and Impact are scored independently from threat-agent, vulnerability,
technical-impact, and business-impact factors, then combined. A flaw that's
trivial to find and exploit but leaks nothing of value stays low severity; one
that's hard to reach but catastrophic when it lands stays serious. Each entry
below states the Likelihood reasoning, the Impact reasoning, and the resulting
severity band, ordered from the mildest real-world shape of the bug to its worst.

## CORS misconfiguration

A CORS misconfiguration where the Access-Control-Allow-Origin header reflects
any requesting Origin but Access-Control-Allow-Credentials is absent is low
risk: any origin can discover this with a single request, but only data that
the endpoint already serves anonymously is exposed, since a compliant browser
withholds credentialed responses without the credentials header being set.
This maps to CWE-942 (Permissive Cross-domain Policy with Untrusted Domains).

A CORS misconfiguration that combines a wildcard Access-Control-Allow-Origin: *
with Access-Control-Allow-Credentials: true is invalid per the Fetch
specification, but some non-browser HTTP clients and older engines still honor
it, which is high risk: wherever it's honored, any origin receives full
authenticated response bodies instead of only the anonymous ones. CWE-942,
OWASP Security Misconfiguration (A05:2021).

A CORS misconfiguration that reflects the request's Origin header verbatim and
sets Access-Control-Allow-Credentials: true on an authenticated, data-bearing
endpoint is critical severity: a single attacker-controlled page with a
background fetch, requiring no victim action beyond an existing login, can
exfiltrate session tokens, personal data, or CSRF tokens wholesale. CWE-942,
OWASP Security Misconfiguration.

A CORS misconfiguration that trusts a null Origin value while still allowing
credentials is also critical severity: the sandboxed-iframe trick that
produces a null Origin is public and well documented, needs no victim
interaction beyond loading a page, and reaches the same blast radius as a
reflected-Origin misconfiguration above. CWE-942.

## Cross-site scripting

Reflected cross-site scripting (XSS) that only fires after a victim submits a
specific crafted form, with output otherwise HTML-encoded everywhere else, is
low risk: it needs targeted social engineering per victim rather than one
shareable link, and even a successful attempt exposes only that one victim's
session or actions. CWE-79, OWASP Injection (A03:2021).

Reflected cross-site scripting (XSS) delivered through a URL parameter on a
page with no Content-Security-Policy is medium severity: one crafted link is
the entire attack, and commodity phishing can deliver it at scale, hijacking
the session or forcing actions for whoever clicks it. CWE-79.

Stored cross-site scripting (XSS) in content visible to other regular users,
such as a public profile field or a comment, is high risk: the payload
persists once and then fires passively against every subsequent viewer with
zero further attacker effort, enabling session takeover across the whole
audience and worm-like propagation. CWE-79, OWASP Injection.

Stored or DOM-based cross-site scripting (XSS) reachable from an
administrative or support console is critical severity: the same passive
persistence as ordinary stored XSS is aimed at a small, near-guaranteed,
high-value audience, and an admin session compromise typically means full
application compromise rather than a single user account. CWE-79.

## Race conditions

A race condition that lets an attacker duplicate a low-value action, such as
double-submitting a "like" or redeeming a coupon that's capped elsewhere in
the system, is low risk: exploiting it needs concurrency tooling that most
attackers won't bother with over something this low-value, and an api
endpoint with no rate limiting only produces a bounded, cosmetic, or trivially
reversible outcome. CWE-362 (Concurrent Execution using Shared Resource with
Improper Synchronization), OWASP Insecure Design (A04:2021).

A race condition in a coupon or loyalty-point redemption api endpoint, where
concurrent requests bypass a check-then-use balance check, is medium
severity: this is a well-documented technique, and public request-burst
tooling makes it routine against any endpoint that lacks rate limiting,
producing a real but bounded financial loss per exploited account. CWE-362.

A race condition on a withdrawal or transfer endpoint, where a
time-of-check-to-time-of-use gap between checking and debiting a balance is
exploited with concurrent requests, is high risk and amounts to broken access
control over the account's own funds: the same commodity request-burst
tooling is aimed at a more sensitive code path, causing direct, potentially
unbounded financial loss and ledger integrity damage. CWE-362, OWASP Broken
Access Control (A01:2021).

A race condition that lets concurrent requests consume a password-reset
token, invite code, or one-time passcode more than once is critical severity
and is a clear authorization bypass: unlike a bounded financial loss, the
outcome is full account takeover, reached with the same commodity concurrency
tooling against a specific, sometimes rate-limited endpoint. CWE-362.

## File upload leading to remote code execution

Unrestricted file upload closed off by layered input validation — an
extension allowlist, a MIME-type check, and magic-byte inspection — combined
with storing uploads outside the webroot and serving them through a signed
URL, is informational: every common bypass technique is independently
blocked, and even a successful bypass lands on non-executing storage. CWE-434
(Unrestricted Upload of File with Dangerous Type).

Unrestricted file upload protected only by an extension blacklist, with files
landing inside the webroot, is high risk: input validation gaps like
alternate executable extensions, double extensions, or case tricks on legacy
stacks are public and well known, and wherever the server has a
handler-chaining misconfiguration for the bypassed extension, the uploaded
file executes with the web server's own privileges. CWE-434, OWASP Security
Misconfiguration (A05:2021).

Unrestricted file upload with no real server-side input validation, where
checks are only client-side or rely on a spoofable Content-Type header and
uploads land in a web-executable path, is critical severity: public tooling
automates the entire attack end to end, and this is one of the
best-documented paths to remote code execution on the server, typically
resulting in full host compromise. CWE-434, CWE-94 (Improper Control of
Generation of Code), OWASP Injection (A03:2021).

Unrestricted file upload that feeds a vulnerable processing pipeline, such as
an outdated image library, an archive extractor vulnerable to zip-slip, or an
unsafe deserialization step, is critical severity: exploitation needs the
exact vulnerable library and version, but public exploit code usually already
exists once one is identified, reaching remote code execution through a
dependency instead of the upload handler's own input validation. CWE-434,
CWE-502 (Deserialization of Untrusted Data), OWASP Vulnerable and Outdated
Components (A06:2021).

## Reading the scale against a real finding

Match a real finding to the closest paragraph above on likelihood first — can
it be found and exploited with commodity tooling, or does it need a bespoke
chain — then confirm the impact reasoning still holds for the target's actual
data and users. A finding that sits between two entries should be rated
toward the worse case whenever it touches authentication, payments, or
personal data, rather than rounded down for convenience.
