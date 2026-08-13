from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# An RFC 2606 reserved TLD: guaranteed to never resolve. If a parameter's
# value reaches a server-side fetch (rather than just being stored or
# echoed), pointing it here produces a DNS-resolution failure specifically
# -- a distinct signal from "the app didn't fetch anything" or "the app
# fetched it and got a normal response". Same trick OpenRedirectScanner
# uses for the same reason: a non-resolving probe target needs no live
# infrastructure and never actually reaches a third party.
_DNS_PROBE_TARGET = "http://ssrf-probe.hunterbot-ssrf.invalid/"

# The AWS/GCP/Azure instance metadata address, identical across all three
# major clouds. A parameter that fetches this server-side and reflects the
# response back is a direct, in-band-confirmable SSRF into the cloud
# control plane -- no out-of-band listener needed to prove it.
_METADATA_PROBE_TARGET = "http://169.254.169.254/latest/meta-data/"

_CANDIDATE_PARAMS = (
    "url",
    "uri",
    "path",
    "dest",
    "destination",
    "redirect",
    "callback",
    "webhook",
    "image",
    "src",
    "target",
    "feed",
    "proxy",
    "fetch",
    "avatar",
)

_DNS_FAILURE_SIGNATURES = (
    "could not resolve",
    "getaddrinfo",
    "name or service not known",
    "unknown host",
    "nodename nor servname",
    "no such host",
    "dns lookup failed",
    "failed to connect",
    "connection refused",
    "econnrefused",
    "network is unreachable",
)

_METADATA_SIGNATURES = (
    "ami-id",
    "instance-id",
    "iam/security-credentials",
    "latest/meta-data",
    "instance-life-cycle",
    "local-ipv4",
)


class SsrfScanner:
    """Probes common URL-fetching parameters for server-side request forgery.

    Two independent, read-only checks per candidate parameter, each a
    single GET:

    1. DNS-failure signature -- pointing the parameter at a guaranteed
       non-resolving domain and checking whether a DNS/connection-error
       message (not present in a baseline GET of "/") comes back. A hit
       proves the parameter drives a genuine server-side fetch at all --
       the necessary precondition for SSRF -- without needing an
       out-of-band listener. MEDIUM severity: it confirms the primitive,
       not that internal network boundaries can actually be crossed.
    2. Cloud metadata reflection -- pointing the parameter at the
       AWS/GCP/Azure instance metadata address and checking whether
       metadata-shaped content (not present in the baseline) comes back.
       A hit is direct, in-band proof of the worst realistic outcome:
       CRITICAL, CONFIRMED.

    Neither check attempts to reach an internal service beyond these two
    fixed, well-known targets -- HunterBot doesn't have a network map of
    the target's internal infrastructure to guess at, and guessing would
    mean sending requests HunterBot can't account for the effect of.
    """

    name = "ssrf"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline = http_client.get("/")
        baseline_text = baseline.text.lower() if baseline is not None else ""

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            metadata_finding = self._check(
                base_url=base_url,
                http_client=http_client,
                param=param,
                probe_target=_METADATA_PROBE_TARGET,
                signatures=_METADATA_SIGNATURES,
                baseline_text=baseline_text,
                severity=Severity.CRITICAL,
                confidence=Confidence.CONFIRMED,
                outcome="reflected cloud instance metadata content",
            )
            if metadata_finding is not None:
                findings.append(metadata_finding)
                continue

            dns_finding = self._check(
                base_url=base_url,
                http_client=http_client,
                param=param,
                probe_target=_DNS_PROBE_TARGET,
                signatures=_DNS_FAILURE_SIGNATURES,
                baseline_text=baseline_text,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                outcome="a DNS/connection error consistent with a genuine server-side fetch attempt",
            )
            if dns_finding is not None:
                findings.append(dns_finding)

        return findings

    def _check(
        self,
        *,
        base_url: str,
        http_client: HttpClient,
        param: str,
        probe_target: str,
        signatures: tuple[str, ...],
        baseline_text: str,
        severity: Severity,
        confidence: Confidence,
        outcome: str,
    ) -> Finding | None:
        probe_path = f"/?{param}={probe_target}"
        response = http_client.get(probe_path)
        if response is None:
            return None

        body_lower = response.text.lower()
        matched_signature = next(
            (signature for signature in signatures if signature in body_lower and signature not in baseline_text),
            None,
        )
        if matched_signature is None:
            return None

        return Finding(
            title=f"Server-side request forgery via '{param}' parameter",
            category=VulnerabilityCategory.API_SECURITY,
            severity=severity,
            confidence=confidence,
            description=(
                f"A GET request to {probe_path} produced {outcome} (signature "
                f"{matched_signature!r}, not present in a baseline response), indicating the "
                f"'{param}' parameter's value is fetched server-side without validating the "
                "destination against an allowlist."
            ),
            affected_asset=base_url,
            location=response.url,
            evidence=f"Probe target {probe_target!r} triggered signature {matched_signature!r} in the HTTP {response.status_code} response.",
            reproduction_steps=(
                f"Request {probe_path} and confirm the response shows evidence of a server-side "
                "fetch. Follow up manually against internal-only addresses (in scope) or a "
                "collaborator-style out-of-band listener to confirm the full internal blast radius "
                "before reporting as exploitable."
            ),
            remediation=(
                "Validate any server-side-fetched URL against a strict allowlist of hosts/schemes "
                "before making the request, and block requests to link-local and private address "
                "ranges (including 169.254.169.254) at the network layer as defense in depth."
            ),
            scanner_name=self.name,
        )
