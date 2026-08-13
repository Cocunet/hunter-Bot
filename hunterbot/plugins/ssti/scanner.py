from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# 1337*1337 rather than the more common 7*7 textbook example: "49" is a
# common enough number (a price, a count, a year fragment) to plausibly
# appear on an arbitrary page by coincidence even after excluding the
# baseline; "1787569" effectively never does. Same computation expressed
# in three template engines' own syntax, since which one (if any) a given
# target uses isn't known in advance.
_EXPECTED_RESULT = "1787569"
_PAYLOADS = (
    ("jinja2/twig", "{{1337*1337}}"),
    ("freemarker/el", "${1337*1337}"),
    ("erb", "<%= 1337*1337 %>"),
)

_CANDIDATE_PARAMS = (
    "name",
    "message",
    "comment",
    "search",
    "q",
    "template",
    "view",
    "page",
    "title",
    "content",
    "input",
    "text",
    "greeting",
)


class SstiScanner:
    """Probes common parameters for server-side template injection.

    Sends one read-only GET per (parameter, engine syntax) pair with an
    arithmetic template expression appended to the value, then checks
    whether the response contains the *computed result* -- proof the
    engine actually evaluated the expression -- while the raw payload
    string itself does not appear (ruling out plain unescaped reflection,
    which is a different bug: see ReflectedXssScanner) and the result
    wasn't already present in a baseline response. A hit is about as
    directly confirmable as SSTI gets without further exploitation: the
    computed number appearing where a literal string was submitted has no
    other explanation.
    """

    name = "ssti"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline = http_client.get("/")
        baseline_text = baseline.text if baseline is not None else ""
        if _EXPECTED_RESULT in baseline_text:
            return []

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            for engine, payload in _PAYLOADS:
                probe_path = f"/?{param}={payload}"
                response = http_client.get(probe_path)
                if response is None:
                    continue
                if payload in response.text:
                    continue  # reflected verbatim, not evaluated -- an XSS-shaped finding, not this one
                if _EXPECTED_RESULT not in response.text:
                    continue

                findings.append(
                    Finding(
                        title=f"Server-side template injection via '{param}' query parameter",
                        category=VulnerabilityCategory.INPUT_VALIDATION,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        description=(
                            f"A GET request to {probe_path} returned the computed result "
                            f"({_EXPECTED_RESULT}) of the injected {engine}-syntax expression "
                            f"1337*1337, rather than the literal payload text -- the '{param}' "
                            "parameter's value is being evaluated as a template expression, not "
                            "rendered as plain text. Template injection commonly escalates to full "
                            "remote code execution depending on the engine."
                        ),
                        affected_asset=base_url,
                        location=response.url,
                        evidence=f"Payload {payload!r} evaluated to {_EXPECTED_RESULT!r} in the HTTP {response.status_code} response body.",
                        reproduction_steps=(
                            f"Request {probe_path} and confirm the response contains {_EXPECTED_RESULT!r} "
                            "rather than the literal expression text."
                        ),
                        remediation=(
                            "Never construct a template from user input. If user content must appear "
                            "in a rendered page, pass it as template *data* (a variable) rather than "
                            "concatenating it into the template *source*."
                        ),
                        scanner_name=self.name,
                    )
                )
        return findings
