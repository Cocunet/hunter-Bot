import httpx

from hunterbot.core.interfaces import ScannerResponse


class ScannerHttpClient:
    """Safety-constrained HTTP client shared by every scanner plugin.

    Centralizing timeouts and redirect limits here means individual
    scanners never configure their own networking — read-only GET requests
    only, bounded timeout, bounded redirects. A failed or erroring request
    resolves to ``None`` rather than raising, so a single unreachable path
    doesn't abort a whole scan. Implements hunterbot.core.interfaces.HttpClient.
    """

    DEFAULT_TIMEOUT_SECONDS = 8.0
    MAX_REDIRECTS = 3

    def __init__(self, base_url: str) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            timeout=self.DEFAULT_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=self.MAX_REDIRECTS,
        )

    def get(self, path: str) -> ScannerResponse | None:
        return self._get(path, follow_redirects=True)

    def get_no_redirect(self, path: str) -> ScannerResponse | None:
        return self._get(path, follow_redirects=False)

    def _get(self, path: str, *, follow_redirects: bool) -> ScannerResponse | None:
        try:
            response = self._client.get(path, follow_redirects=follow_redirects)
        except httpx.HTTPError:
            return None
        return ScannerResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            url=str(response.url),
        )

    def close(self) -> None:
        self._client.close()
