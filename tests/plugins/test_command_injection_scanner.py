import time

from hunterbot.core.interfaces import ScannerResponse
from hunterbot.plugins.command_injection.scanner import _PAYLOADS, CommandInjectionScanner
from tests.conftest import FakeHttpClient

_BASE_URL = "https://example.com"


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _TimingHttpClient(FakeHttpClient):
    """A FakeHttpClient that advances a shared fake clock on every get()
    by a per-path amount, so CommandInjectionScanner's time.monotonic()
    deltas can be controlled deterministically without a real sleep."""

    def __init__(self, clock: _FakeClock, delays: dict[str, float]) -> None:
        super().__init__({})
        self._clock = clock
        self._delays = delays

    def get(self, path: str) -> ScannerResponse | None:
        self.requested_paths.append(path)
        self._clock.advance(self._delays.get(path, 0.01))
        return ScannerResponse(status_code=200, headers={}, text="ok", url=_BASE_URL + path)


class TestCommandInjectionScanner:
    def test_flags_consistently_delayed_response(self, monkeypatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr(time, "monotonic", clock.monotonic)
        vulnerable_path = f"/?host={_PAYLOADS[0]}"
        http_client = _TimingHttpClient(clock, delays={vulnerable_path: 6.0})

        findings = CommandInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        matching = [f for f in findings if "'host' query parameter" in f.title]
        assert len(matching) == 1
        assert matching[0].severity.value == "critical"
        assert matching[0].confidence.value == "medium"

    def test_single_slow_response_is_not_enough(self, monkeypatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr(time, "monotonic", clock.monotonic)
        vulnerable_path = f"/?host={_PAYLOADS[0]}"

        call_count = {"n": 0}
        original_delays = {vulnerable_path: 6.0}

        class _FlakyClient(_TimingHttpClient):
            def get(self, path: str):
                if path == vulnerable_path:
                    call_count["n"] += 1
                    if call_count["n"] > 1:
                        # only the first of the two required confirmations is slow
                        self._delays = {}
                return super().get(path)

        http_client = _FlakyClient(clock, delays=original_delays)

        findings = CommandInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_no_delay_yields_no_findings(self, monkeypatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr(time, "monotonic", clock.monotonic)
        http_client = _TimingHttpClient(clock, delays={})

        findings = CommandInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []

    def test_unreachable_baseline_yields_no_findings(self, monkeypatch) -> None:
        clock = _FakeClock()
        monkeypatch.setattr(time, "monotonic", clock.monotonic)
        http_client = FakeHttpClient({})

        findings = CommandInjectionScanner().scan(base_url=_BASE_URL, http_client=http_client)

        assert findings == []
