from urllib.parse import quote

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# A minimal filter-breaking probe: naively concatenated into a filter like
# "(uid=<input>)" this becomes "(uid=*)(&)", malformed LDAP filter syntax
# that an unescaped library will fail to parse. Percent-encoded when built
# into a request path (see scan()) since it contains '&', which would
# otherwise be parsed as a query-string separator rather than part of the
# value.
_PROBE_VALUE = "*)(&"

_CANDIDATE_PARAMS = (
    "username",
    "user",
    "uid",
    "cn",
    "search",
    "query",
    "filter",
    "name",
    "dn",
    "group",
    "ou",
    "q",
)

# Substrings from real LDAP library error messages, lowercased. As with
# SqlInjectionScanner, every hit is still cross-checked against a baseline
# GET of "/" before being reported.
_ERROR_SIGNATURES = (
    "javax.naming.directory",
    "javax.naming.namingexception",
    "com.sun.jndi.ldap",
    "ldapexception",
    "system.directoryservices",
    "invalid dn syntax",
    "bad search filter",
    "ldap_search()",
    "supplied argument is not a valid ldap",
    "size limit exceeded",
    "ldap: error code",
    "unindexed search",
    "invalid attribute syntax",
)


class LdapInjectionScanner:
    """Probes common directory-search parameters for a reflected LDAP error.

    Sends one read-only GET per candidate parameter with a filter-breaking
    probe appended to its value, then checks whether the response contains
    an LDAP library's own error-message signature that wasn't already
    present on a plain GET of "/" -- the same error-based technique
    SqlInjectionScanner uses, applied to LDAP's own driver error strings
    instead of a database's.
    """

    name = "ldap-injection"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline = http_client.get("/")
        baseline_text = baseline.text.lower() if baseline is not None else ""

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            probe_path = f"/?{param}={quote(_PROBE_VALUE, safe='')}"
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
                    title=f"LDAP injection via '{param}' query parameter",
                    category=VulnerabilityCategory.INPUT_VALIDATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"A GET request to {probe_path} returned an LDAP error "
                        f"({matched_signature!r}) not present in a baseline response, indicating "
                        f"the '{param}' parameter's value reaches an LDAP filter without being "
                        "safely escaped."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Probe payload {_PROBE_VALUE!r} triggered LDAP error signature {matched_signature!r} in the HTTP {response.status_code} response.",
                    reproduction_steps=(
                        f"Request {probe_path} and confirm the response contains an LDAP error "
                        "message. Follow up manually to confirm filter logic can actually be "
                        "altered (e.g. a wildcard bypassing an intended search scope) before "
                        "reporting as exploitable."
                    ),
                    remediation=(
                        "Escape LDAP special characters (*, (, ), \\, NUL) in any value built into a "
                        "filter, or use a parameterized/typed LDAP query API where the underlying "
                        "library escapes for you."
                    ),
                    scanner_name=self.name,
                )
            )
        return findings
