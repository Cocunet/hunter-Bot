from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# A distinctive, unlikely-to-occur-by-coincidence token wrapped in a payload
# that breaks out of an HTML attribute/text context. Any HTML-encoding
# (the correct fix) turns '<' and '>' into '&lt;'/'&gt;', which breaks this
# exact substring match -- so a literal hit means the server echoed the
# payload back completely unescaped.
_MARKER = "hunterbotXSS1"
_PAYLOAD = f'"><script>{_MARKER}</script>'

# Parameter names commonly wired straight into a page's HTML without
# encoding: search boxes, greeting/name fields, error/status messages,
# JSONP-style callbacks, and generic passthrough params.
_CANDIDATE_PARAMS = (
    "q",
    "search",
    "s",
    "query",
    "keyword",
    "name",
    "message",
    "comment",
    "text",
    "input",
    "term",
    "callback",
    "page",
    "lang",
)


class ReflectedXssScanner:
    """Probes common query parameters for unescaped reflection of a script payload.

    Sends one read-only GET per candidate parameter with a payload that
    breaks out of an HTML attribute and injects a marked <script> tag, then
    checks whether the response body contains that exact payload verbatim.
    Nothing is submitted or changed on the target; every request is a GET,
    and no JavaScript is ever actually executed -- detection is purely a
    string match against the raw response body, the same technique any
    browser-less DAST scanner uses. A verbatim hit is strong evidence but not
    proof a real browser would execute it (the reflection could land inside
    a non-executing context, e.g. an HTML comment), hence MEDIUM confidence
    rather than HIGH -- confirm manually before reporting.
    """

    name = "reflected-xss"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            probe_path = f"/?{param}={_PAYLOAD}"
            response = http_client.get(probe_path)
            if response is None or _PAYLOAD not in response.text:
                continue

            findings.append(
                Finding(
                    title=f"Reflected XSS via '{param}' query parameter",
                    category=VulnerabilityCategory.INPUT_VALIDATION,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"A GET request to {probe_path} echoed the injected payload back in the "
                        f"response body completely unescaped -- the '{param}' parameter is written "
                        "into the page without HTML-encoding it first. Confirm in a browser before "
                        "reporting: the reflection point may or may not be in a context a browser "
                        "actually executes (e.g. inside an HTML comment vs. the page body)."
                    ),
                    affected_asset=base_url,
                    location=response.url,
                    evidence=f"Requested payload {_PAYLOAD!r} found verbatim in the HTTP {response.status_code} response body.",
                    reproduction_steps=(
                        f"Visit {base_url}{probe_path} in a browser and check whether the injected "
                        "<script> tag executes."
                    ),
                    remediation=(
                        "Context-appropriately encode all user-controlled output before writing it "
                        "into HTML (e.g. HTML-entity-encode text nodes, attribute-encode attribute "
                        "values), and set a Content-Security-Policy as defense in depth."
                    ),
                    scanner_name=self.name,
                )
            )
        return findings
