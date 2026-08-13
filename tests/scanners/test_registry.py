import pytest

from hunterbot.core.domain import Finding
from hunterbot.core.interfaces import HttpClient
from hunterbot.scanners import ScannerRegistry


class _StubScanner:
    def __init__(self, name: str) -> None:
        self.name = name

    def scan(self, *, base_url: str, http_client: HttpClient) -> list[Finding]:
        return []


class TestScannerRegistry:
    def test_register_and_list_all(self) -> None:
        registry = ScannerRegistry()
        registry.register(_StubScanner("a"))
        registry.register(_StubScanner("b"))

        names = {plugin.name for plugin in registry.all()}

        assert names == {"a", "b"}

    def test_duplicate_name_raises(self) -> None:
        registry = ScannerRegistry()
        registry.register(_StubScanner("a"))

        with pytest.raises(ValueError, match="already registered"):
            registry.register(_StubScanner("a"))

    def test_empty_registry_returns_empty_list(self) -> None:
        assert ScannerRegistry().all() == []
