from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.ssrf.scanner import _DNS_PROBE_TARGET, _METADATA_PROBE_TARGET, SsrfScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestSsrfScanner:
    def test_flags_reflected_cloud_metadata(self) -> None:
        probe_path = f"/?url={_METADATA_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text="ami-id\ninstance-id\nlocal-ipv4",
                    url=_BASE_URL + probe_path,
                ),
            }
        )

        findings = SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'url' parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "critical"
        assert matching[0].confidence.value == "confirmed"

    def test_flags_dns_failure_signature_when_metadata_not_reflected(self) -> None:
        metadata_path = f"/?url={_METADATA_PROBE_TARGET}"
        dns_path = f"/?url={_DNS_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                metadata_path: ScannerResponse(
                    status_code=502, headers={}, text="Bad Gateway", url=_BASE_URL + metadata_path
                ),
                dns_path: ScannerResponse(
                    status_code=502,
                    headers={},
                    text="Error: getaddrinfo ENOTFOUND ssrf-probe.hunterbot-ssrf.invalid",
                    url=_BASE_URL + dns_path,
                ),
            }
        )

        findings = SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'url' parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "medium"
        assert matching[0].confidence.value == "medium"

    def test_metadata_hit_takes_priority_over_dns_check_for_same_param(self) -> None:
        metadata_path = f"/?url={_METADATA_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="home", url=_BASE_URL + "/"),
                metadata_path: ScannerResponse(
                    status_code=200, headers={}, text="ami-id present", url=_BASE_URL + metadata_path
                ),
            }
        )

        findings = SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        url_findings = [f for f in findings if "'url' parameter" in f.title]
        assert len(url_findings) == 1
        assert url_findings[0].severity.value == "critical"
        # The DNS probe path for "url" should never have been requested once metadata already hit.
        dns_path = f"/?url={_DNS_PROBE_TARGET}"
        assert dns_path not in http_client.requested_paths

    def test_signature_present_in_baseline_is_not_flagged(self) -> None:
        metadata_path = f"/?url={_METADATA_PROBE_TARGET}"
        dns_path = f"/?url={_DNS_PROBE_TARGET}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="ami-id getaddrinfo", url=_BASE_URL + "/"),
                metadata_path: ScannerResponse(
                    status_code=200, headers={}, text="ami-id present", url=_BASE_URL + metadata_path
                ),
                dns_path: ScannerResponse(
                    status_code=200, headers={}, text="getaddrinfo failed", url=_BASE_URL + dns_path
                ),
            }
        )

        findings = SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_probes_every_candidate_parameter(self) -> None:
        http_client = FakeHttpClient({"/": ScannerResponse(status_code=200, headers={}, text="home", url=_BASE_URL)})

        SsrfScanner().scan(base_url=_BASE_URL, http_client=http_client)

        probed = [p for p in http_client.requested_paths if p != "/"]
        # metadata probe + DNS probe per candidate param, since neither ever matches here
        assert len(probed) == 15 * 2
