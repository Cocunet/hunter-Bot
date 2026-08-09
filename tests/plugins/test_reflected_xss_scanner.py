from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.reflected_xss.scanner import _PAYLOAD, ReflectedXssScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class TestReflectedXssScanner:
    def test_flags_verbatim_reflection(self) -> None:
        probe_path = f"/?q={_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text=f"<html>results for {_PAYLOAD}</html>",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = ReflectedXssScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'q' query parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "high"
        assert matching[0].confidence.value == "medium"

    def test_html_encoded_reflection_is_not_flagged(self) -> None:
        probe_path = f"/?q={_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text="<html>results for &quot;&gt;&lt;script&gt;hunterbotXSS1&lt;/script&gt;</html>",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = ReflectedXssScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unrelated_response_is_not_flagged(self) -> None:
        probe_path = f"/?q={_PAYLOAD}"
        http_client = FakeHttpClient(
            {
                probe_path: ScannerResponse(
                    status_code=200,
                    headers={},
                    text="<html>no results</html>",
                    url=_BASE_URL + probe_path,
                )
            }
        )

        findings = ReflectedXssScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = ReflectedXssScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_probes_every_candidate_parameter(self) -> None:
        http_client = FakeHttpClient({})

        ReflectedXssScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert len(http_client.requested_paths) == 14
        assert all(path.startswith("/?") and _PAYLOAD in path for path in http_client.requested_paths)
