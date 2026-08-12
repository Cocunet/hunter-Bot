from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# PHP/Express-style bracket syntax turns a query-string value into an
# operator object server-side (?param[$ne]=1 becomes {"param": {"$ne": "1"}}
# once parsed) -- the most common purely-GET NoSQL injection vector, no
# JSON request body required. Two probes: $ne is the classic auth-bypass
# shape ("not equal to this"), $where triggers MongoDB's own server-side
# JavaScript evaluation path and is far more likely to surface a distinct
# driver error if reached at all.
_PROBES = (
    ("ne", "param[$ne]=1"),
    ("where", "param[$where]=1"),
)

_CANDIDATE_PARAMS = (
    "username",
    "user",
    "email",
    "search",
    "q",
    "query",
    "filter",
    "id",
    "category",
    "name",
)

_ERROR_SIGNATURES = (
    "mongoerror",
    "mongoserverror",
    "mongo\\driver\\exception",
    "bsonerror",
    "e11000 duplicate key",
    "unknown operator",
    "unknown top level operator",
    "operator not permitted",
    "$where is not allowed",
    "castexception",
    "pymongo.errors",
    "com.mongodb.mongoexception",
    "bad query",
)


class NoSqlInjectionScanner:
    """Probes common parameters for NoSQL (MongoDB-style) operator injection.

    Sends one read-only GET per candidate parameter with a bracket-syntax
    operator ($ne, $where) substituted in place of the parameter name, then
    checks the response for a NoSQL driver's own error-message signature
    not present in a baseline GET of "/" -- the same error-based technique
    as SqlInjectionScanner and LdapInjectionScanner, applied here to a
    MongoDB-shaped driver instead. Detects the injection primitive (the
    operator reached a query unescaped); it does not attempt an
    authentication-bypass proof, which would require a state-changing POST
    against a login endpoint the tester would need to name.
    """

    name = "nosql-injection"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline = http_client.get("/")
        baseline_text = baseline.text.lower() if baseline is not None else ""

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            for operator_name, probe_template in _PROBES:
                probe_path = f"/?{probe_template.replace('param', param)}"
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
                        title=f"NoSQL injection via '{param}' query parameter",
                        category=VulnerabilityCategory.INPUT_VALIDATION,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"A GET request to {probe_path} -- substituting a ${operator_name} "
                            f"operator for the '{param}' parameter's expected scalar value -- "
                            f"returned a NoSQL driver error ({matched_signature!r}) not present in a "
                            "baseline response, indicating the parameter reaches a query without "
                            "type or structure validation."
                        ),
                        affected_asset=base_url,
                        location=response.url,
                        evidence=f"Probe {probe_template.replace('param', param)!r} triggered signature {matched_signature!r} in the HTTP {response.status_code} response.",
                        reproduction_steps=(
                            f"Request {probe_path} and confirm the response contains a NoSQL driver "
                            "error. On an authentication endpoint specifically, test whether "
                            "?username[$ne]=x&password[$ne]=x bypasses login -- that requires a POST "
                            "and the tester's own judgment about scope."
                        ),
                        remediation=(
                            "Validate that request parameters are the expected scalar type before "
                            "passing them into a query (reject arrays/objects where a string or "
                            "number is expected), and disable server-side JavaScript evaluation "
                            "($where, mapReduce) unless specifically required."
                        ),
                        scanner_name=self.name,
                    )
                )
        return findings
