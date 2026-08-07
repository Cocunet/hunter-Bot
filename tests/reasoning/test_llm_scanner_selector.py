from dataclasses import dataclass, field

import pytest

from hunterbot.core.interfaces import HttpClient
from hunterbot.reasoning import LLMScannerSelector, ScannerSelectionError
from hunterbot.reasoning import llm_scanner_selector as llm_scanner_selector_module
from hunterbot.reasoning.llm_scanner_selector import _SelectionResult

_BASE_URL = "https://example.com"


class _StubScanner:
    """A stub scanner used only for selector tests."""

    def __init__(self, name: str) -> None:
        self.name = name

    def scan(self, *, base_url: str, http_client: HttpClient):
        return []


@dataclass
class _FakeResponse:
    parsed_output: _SelectionResult
    stop_reason: str = "end_turn"


@dataclass
class _FakeMessages:
    response: object
    calls: list = field(default_factory=list)
    error: Exception | None = None

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


class _FakeClient:
    def __init__(self, response=None, error=None) -> None:
        self.messages = _FakeMessages(response=response, error=error)


class TestLLMScannerSelectorAvailability:
    def test_is_available_true_when_anthropic_installed(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_SelectionResult()))
        selector = LLMScannerSelector(client=client)
        assert selector.is_available() is True

    def test_raises_when_anthropic_unavailable_and_no_client_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(llm_scanner_selector_module, "_ANTHROPIC_AVAILABLE", False)
        with pytest.raises(ScannerSelectionError, match="requires the 'llm' extra"):
            LLMScannerSelector()

    def test_injected_client_bypasses_availability_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(llm_scanner_selector_module, "_ANTHROPIC_AVAILABLE", False)
        client = _FakeClient(response=_FakeResponse(parsed_output=_SelectionResult()))
        LLMScannerSelector(client=client)


class TestLLMScannerSelectorSelect:
    def test_empty_available_scanners_returns_empty_without_calling_client(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_SelectionResult()))
        selector = LLMScannerSelector(client=client)

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=[])

        assert result == []
        assert client.messages.calls == []

    def test_returns_valid_selected_names(self) -> None:
        response = _FakeResponse(
            parsed_output=_SelectionResult(selected_scanner_names=["scanner-a"], reasoning="Relevant.")
        )
        client = _FakeClient(response=response)
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a"), _StubScanner("scanner-b")]

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)

        assert result == ["scanner-a"]

    def test_filters_out_hallucinated_names_keeping_valid_ones(self) -> None:
        response = _FakeResponse(
            parsed_output=_SelectionResult(selected_scanner_names=["scanner-a", "made-up-scanner"])
        )
        client = _FakeClient(response=response)
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a"), _StubScanner("scanner-b")]

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)

        assert result == ["scanner-a"]

    def test_all_hallucinated_names_falls_back_to_every_scanner(self) -> None:
        response = _FakeResponse(parsed_output=_SelectionResult(selected_scanner_names=["made-up-scanner"]))
        client = _FakeClient(response=response)
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a"), _StubScanner("scanner-b")]

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)

        assert set(result) == {"scanner-a", "scanner-b"}

    def test_empty_selection_falls_back_to_every_scanner(self) -> None:
        response = _FakeResponse(parsed_output=_SelectionResult(selected_scanner_names=[]))
        client = _FakeClient(response=response)
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a"), _StubScanner("scanner-b")]

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)

        assert set(result) == {"scanner-a", "scanner-b"}

    def test_refusal_falls_back_to_every_scanner(self) -> None:
        response = _FakeResponse(parsed_output=_SelectionResult(), stop_reason="refusal")
        client = _FakeClient(response=response)
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a"), _StubScanner("scanner-b")]

        result = selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)

        assert set(result) == {"scanner-a", "scanner-b"}

    def test_client_errors_are_wrapped_as_scanner_selection_error(self) -> None:
        client = _FakeClient(error=RuntimeError("boom"))
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a")]

        with pytest.raises(ScannerSelectionError, match="boom") as exc_info:
            selector.select(base_url=_BASE_URL, recon_signal="status=200", available_scanners=scanners)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_prompt_includes_recon_signal_and_scanner_descriptions(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_SelectionResult()))
        selector = LLMScannerSelector(client=client)
        scanners = [_StubScanner("scanner-a")]

        selector.select(base_url=_BASE_URL, recon_signal="status=200, server=nginx", available_scanners=scanners)

        prompt = client.messages.calls[0]["messages"][0]["content"]
        assert _BASE_URL in prompt
        assert "status=200, server=nginx" in prompt
        assert "scanner-a" in prompt
        assert "A stub scanner used only for selector tests." in prompt
