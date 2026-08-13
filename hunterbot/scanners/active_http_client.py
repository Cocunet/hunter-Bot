import httpx

from hunterbot.core.interfaces import ScannerResponse


class ActiveScannerHttpClient:
    """Write-capable HTTP client for HunterBot's opt-in *active* scans.

    Deliberately a separate class from ScannerHttpClient, not a subclass or
    an extension of it: every default, always-safe ScannerPlugin is built
    against ScannerHttpClient and the read-only HttpClient Protocol it
    implements, which has no `post`. Only RunRaceConditionScanUseCase and
    RunFileUploadRceScanUseCase (hunterbot.core.use_cases) ever construct
    one of these -- see hunterbot.core.interfaces.ActiveHttpClient for why
    those two specifically need state-changing requests. Implements that
    Protocol.

    Shares ScannerHttpClient's safety-conscious defaults (bounded timeout,
    bounded redirects, a failed/erroring request resolves to ``None`` rather
    than raising) so a single unreachable path doesn't abort a whole scan
    here either.
    """

    DEFAULT_TIMEOUT_SECONDS = 10.0
    MAX_REDIRECTS = 3

    def __init__(self, base_url: str, *, extra_headers: dict[str, str] | None = None) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            timeout=self.DEFAULT_TIMEOUT_SECONDS,
            follow_redirects=True,
            max_redirects=self.MAX_REDIRECTS,
            headers=extra_headers,
        )

    def get(self, path: str) -> ScannerResponse | None:
        try:
            response = self._client.get(path)
        except httpx.HTTPError:
            return None
        return self._to_scanner_response(response)

    def post(
        self, path: str, *, body: str | None = None, content_type: str | None = None
    ) -> ScannerResponse | None:
        headers = {"Content-Type": content_type} if content_type else None
        try:
            response = self._client.post(path, content=body, headers=headers)
        except httpx.HTTPError:
            return None
        return self._to_scanner_response(response)

    def post_multipart(
        self, path: str, *, files: dict[str, tuple[str, bytes, str]], data: dict[str, str] | None = None
    ) -> ScannerResponse | None:
        try:
            response = self._client.post(path, files=files, data=data)
        except httpx.HTTPError:
            return None
        return self._to_scanner_response(response)

    def _to_scanner_response(self, response: httpx.Response) -> ScannerResponse:
        return ScannerResponse(
            status_code=response.status_code,
            headers=dict(response.headers),
            text=response.text,
            url=str(response.url),
        )

    def close(self) -> None:
        self._client.close()
