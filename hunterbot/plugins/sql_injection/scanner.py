from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# A single unescaped quote is the classic "dumb" SQLi probe: in both a
# numeric context (`... WHERE id = 1'`) and a string context
# (`... WHERE name = 'foo1''`), an application that concatenates this
# straight into a query breaks the statement's syntax and, unless errors
# are suppressed, the underlying driver's own error message leaks back.
_PROBE_VALUE = "1'"

_CANDIDATE_PARAMS = (
    "id",
    "user",
    "username",
    "email",
    "search",
    "q",
    "query",
    "category",
    "product",
    "page",
    "sort",
    "order",
    "filter",
    "name",
)

# Substrings from real database driver error messages, lowercased. Every
# entry here is specific enough to a SQL error (a driver/exception class
# name, or wording that only appears in a syntax-error message) that it's
# very unlikely to appear on an unrelated page by coincidence -- which is
# also why each hit is still cross-checked against a baseline GET of "/"
# before being reported, in case a target's own content happens to mention
# one of these strings for unrelated reasons.
_ERROR_SIGNATURES = (
    "you have an error in your sql syntax",  # MySQL
    "warning: mysql",
    "mysqli_sql_exception",
    "unclosed quotation mark after the character string",  # MSSQL
    "system.data.sqlclient.sqlexception",
    "quoted string not properly terminated",  # Oracle
    "ora-01756",
    "ora-00933",
    "org.postgresql.util.psqlexception",  # PostgreSQL
    "pg_query(): query failed",
    "sqlstate[",  # generic PDO
    "sqlite3.operationalerror",  # SQLite
    'near "\'": syntax error',
    "unrecognized token",
    "microsoft odbc",
)


class SqlInjectionScanner:
    """Probes common query parameters for a reflected database error.

    Sends one read-only GET per candidate parameter with a single unescaped
    quote appended to its value, then checks whether the response contains
    a database driver's own error-message signature that wasn't already
    present on a plain GET of "/". This is error-based detection only --
    the fastest and lowest-noise SQLi signal to check for without issuing
    boolean/time-based payloads, which need multiple comparison requests
    and a higher false-positive tolerance than a single-shot scanner
    should carry. A hit here is strong, direct evidence (the target's own
    database driver named itself in the response); it does not attempt to
    extract data or otherwise exploit the injection.
    """

    name = "sql-injection"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline = http_client.get("/")
        baseline_text = baseline.text.lower() if baseline is not None else ""

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            probe_path = f"/?{param}={_PROBE_VALUE}"
            response = http_client.get(probe_path)
            if response is None:
                continue

            body_lower = response.text.lower()
            matched_signature = next(
                (
                    signature
                    for signature in _ERROR_SIGNATURES
                    if signature in body_lower and signature not in baseline_text
                ),
                None,
            )
            if matched_signature is None:
                continue

            findings.append(
                Finding(
                    title=f"SQL injection via '{param}' query parameter",
                    category=VulnerabilityCategory.INPUT_VALIDATION,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=(
                        f"A GET request to {probe_path} returned a database error "
                        f"({matched_signature!r}) not present in a baseline response, indicating "
                        f"the '{param}' parameter's value reaches a SQL query without being safely "
                        "parameterized or escaped."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Probe payload {_PROBE_VALUE!r} triggered database error signature {matched_signature!r} in the HTTP {response.status_code} response.",
                    reproduction_steps=(
                        f"Request {probe_path} and confirm the response contains a database error "
                        "message. Follow up manually with boolean- or time-based payloads to confirm "
                        "data can actually be extracted before reporting as exploitable."
                    ),
                    remediation=(
                        "Use parameterized queries or prepared statements for every database call "
                        "built from user input; never concatenate request data into SQL text. "
                        "Disable verbose database error output in production regardless."
                    ),
                    scanner_name=self.name,
                )
            )
        return findings
