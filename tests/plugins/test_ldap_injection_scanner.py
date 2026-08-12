from urllib.parse import quote

from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.ldap_injection.scanner import _PROBE_VALUE, LdapInjectionScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"
_ENCODED_PROBE = quote(_PROBE_VALUE, safe="")


class TestLdapInjectionScanner:
    def test_flags_reflected_ldap_error(self) -> None:
        probe_path = f"/?username={_ENCODED_PROBE}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=500,
                    headers={},
                    text="javax.naming.directory.InvalidSearchFilterException: bad search filter",
                    url=_BASE_URL + probe_path,
                ),
            }
        )

        findings = LdapInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'username' query parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "high"
        assert matching[0].confidence.value == "high"

    def test_error_present_in_baseline_is_not_flagged(self) -> None:
        probe_path = f"/?username={_ENCODED_PROBE}"
        error_text = "bad search filter"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text=error_text, url=_BASE_URL + "/"),
                probe_path: ScannerResponse(status_code=200, headers={}, text=error_text, url=_BASE_URL + probe_path),
            }
        )

        findings = LdapInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unrelated_response_is_not_flagged(self) -> None:
        probe_path = f"/?username={_ENCODED_PROBE}"
        http_client = FakeHttpClient(
            {
                "/": ScannerResponse(status_code=200, headers={}, text="<html>home</html>", url=_BASE_URL + "/"),
                probe_path: ScannerResponse(
                    status_code=200, headers={}, text="<html>no results</html>", url=_BASE_URL + probe_path
                ),
            }
        )

        findings = LdapInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_target_yields_no_findings(self) -> None:
        http_client = FakeHttpClient({})

        findings = LdapInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
