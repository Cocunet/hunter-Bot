from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from hunterbot.core.domain import Finding


@dataclass(frozen=True)
class ScannerResponse:
    status_code: int
    headers: dict[str, str]
    text: str
    url: str


class HttpClient(Protocol):
    """What a scanner plugin is allowed to do over the network.

    Scanner plugins and the scan use-case depend on this Protocol, not on a
    concrete HTTP library, so tests can pass a fake without touching the
    network and the real implementation (hunterbot.scanners.ScannerHttpClient)
    can live outside core without core depending on it.
    """

    def get(self, path: str) -> ScannerResponse | None: ...

    def close(self) -> None: ...


class ScannerPlugin(Protocol):
    """A single, independent vulnerability check.

    Adding a new scanner means writing a class that satisfies this Protocol
    and registering it (see hunterbot.scanners.registry) — nothing in
    hunterbot.core needs to change.
    """

    name: str

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]: ...
