import time

from hunterbot.core.domain import Confidence, Finding, Severity, VulnerabilityCategory
from hunterbot.core.interfaces import HttpClient

# Two payload shapes covering the two most common shell-metacharacter
# contexts a naively-concatenated command reaches: statement separation
# (";") and command substitution (backticks). Both are side-effect-free --
# `sleep` only blocks, it doesn't read, write, or exfiltrate anything --
# and the delay itself is the entire proof.
_DELAY_SECONDS = 6
_PAYLOADS = (
    f"; sleep {_DELAY_SECONDS} ;",
    f"`sleep {_DELAY_SECONDS}`",
)

_CANDIDATE_PARAMS = (
    "host",
    "ip",
    "domain",
    "target",
    "cmd",
    "command",
    "exec",
    "ping",
    "query",
    "file",
    "name",
    "path",
)

# A hit must clear this bound (comfortably under the 6s payload delay, to
# tolerate ordinary network/server jitter) on TWO independent requests
# before being reported -- a single slow response proves nothing on its
# own, since it might just be a slow server.
_MIN_DELTA_SECONDS = 4.0


class CommandInjectionScanner:
    """Time-based blind detection of OS command injection.

    Sends one read-only GET per (parameter, payload) pair with a shell
    delay command appended to the value, measures how long the request
    takes, and compares it against a baseline request's duration. A delta
    that clears the threshold is re-requested once more before being
    reported -- both attempts have to show the delay, which rules out a
    single slow response (server hiccup, network jitter) being mistaken
    for injection. This never reads a file, writes anything, or runs a
    command with any effect beyond the delay itself.
    """

    name = "command-injection"

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        baseline_duration = self._timed_get(http_client, "/")
        if baseline_duration is None:
            return []

        findings: list[Finding] = []
        for param in _CANDIDATE_PARAMS:
            for payload in _PAYLOADS:
                probe_path = f"/?{param}={payload}"
                first_delta = self._delay_delta(http_client, probe_path, baseline_duration)
                if first_delta is None or first_delta < _MIN_DELTA_SECONDS:
                    continue

                second_delta = self._delay_delta(http_client, probe_path, baseline_duration)
                if second_delta is None or second_delta < _MIN_DELTA_SECONDS:
                    continue

                findings.append(
                    Finding(
                        title=f"OS command injection via '{param}' query parameter",
                        category=VulnerabilityCategory.INPUT_VALIDATION,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"Two independent GET requests to {probe_path} each took roughly "
                            f"{_DELAY_SECONDS} seconds longer than a baseline request to '/', "
                            f"consistent with a `sleep {_DELAY_SECONDS}` payload actually executing "
                            f"server-side after being appended to the '{param}' parameter's value."
                        ),
                        affected_asset=base_url,
                        location=base_url + probe_path,
                        evidence=(
                            f"Baseline duration ~{baseline_duration:.2f}s; two probe requests took "
                            f"+{first_delta:.2f}s and +{second_delta:.2f}s over baseline (threshold "
                            f"{_MIN_DELTA_SECONDS:.1f}s)."
                        ),
                        reproduction_steps=(
                            f"Request {probe_path} and time the response; repeat without the payload "
                            "and confirm the delay disappears. Timing-based signals carry more "
                            "false-positive risk than a direct reflection -- re-verify manually before "
                            "reporting as exploitable."
                        ),
                        remediation=(
                            "Never pass user input to a shell. Use language-native APIs (e.g. "
                            "subprocess with an argument list, not a shell string) or, if a shell is "
                            "unavoidable, strictly allowlist the input."
                        ),
                        scanner_name=self.name,
                    )
                )
        return findings

    def _timed_get(self, http_client: HttpClient, path: str) -> float | None:
        start = time.monotonic()
        response = http_client.get(path)
        if response is None:
            return None
        return time.monotonic() - start

    def _delay_delta(self, http_client: HttpClient, path: str, baseline_duration: float) -> float | None:
        duration = self._timed_get(http_client, path)
        if duration is None:
            return None
        return duration - baseline_duration
