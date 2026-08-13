from __future__ import annotations

from typing import Protocol

from hunterbot.core.interfaces.scanner import ScannerResponse


class ActiveHttpClient(Protocol):
    """What an opt-in *active* scan use-case is allowed to do over the network.

    Deliberately a separate Protocol from HttpClient
    (hunterbot.core.interfaces.scanner), not an extension of it: every
    default ScannerPlugin is typed against HttpClient alone, which has no
    `post`/`post_multipart` method at all, so a read-only scanner cannot
    call them even by accident. Only two use-cases depend on this wider
    Protocol -- RunRaceConditionScanUseCase and RunFileUploadRceScanUseCase
    (hunterbot.core.use_cases) -- because both inherently require
    state-changing requests to confirm anything: winning a real race needs
    concurrent writes to the same endpoint, and proving upload-to-RCE needs
    an actual file on the target. Neither is a ScannerPlugin and neither
    runs as part of `hunterbot scan run`'s default pipeline; each is its
    own explicitly-invoked CLI command / API route.
    """

    def get(self, path: str) -> ScannerResponse | None: ...

    def post(
        self, path: str, *, body: str | None = None, content_type: str | None = None
    ) -> ScannerResponse | None:
        """Send a single state-changing POST with a raw request body."""
        ...

    def post_multipart(
        self, path: str, *, files: dict[str, tuple[str, bytes, str]], data: dict[str, str] | None = None
    ) -> ScannerResponse | None:
        """Send a multipart/form-data POST -- the shape a file upload takes.

        ``files`` maps a form field name to (filename, content, content_type),
        mirroring httpx's own multipart argument shape.
        """
        ...

    def close(self) -> None: ...
