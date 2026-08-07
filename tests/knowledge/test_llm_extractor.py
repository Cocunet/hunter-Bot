from dataclasses import dataclass, field

import pytest

from hunterbot.core.domain import Severity, Source, SourceType, VulnerabilityCategory
from hunterbot.knowledge.extraction import LLMExtractionError, LLMKnowledgeExtractor
from hunterbot.knowledge.extraction import llm_extractor as llm_extractor_module
from hunterbot.knowledge.extraction.llm_extractor import _ExtractedItem, _ExtractionResult

_SOURCE = Source(id=1, name="Test Source", source_type=SourceType.DOCUMENTATION)


@dataclass
class _FakeResponse:
    parsed_output: _ExtractionResult
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


def _extraction_result(*items: _ExtractedItem) -> _ExtractionResult:
    return _ExtractionResult(items=list(items))


class TestLLMKnowledgeExtractorAvailability:
    def test_is_available_true_when_anthropic_installed(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)
        assert extractor.is_available() is True

    def test_raises_when_anthropic_unavailable_and_no_client_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(llm_extractor_module, "_ANTHROPIC_AVAILABLE", False)
        with pytest.raises(LLMExtractionError, match="requires the 'llm' extra"):
            LLMKnowledgeExtractor()

    def test_injected_client_bypasses_availability_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(llm_extractor_module, "_ANTHROPIC_AVAILABLE", False)
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        # Should not raise, since a client was explicitly injected.
        LLMKnowledgeExtractor(client=client)


class TestLLMKnowledgeExtractorModelResolution:
    def test_defaults_to_claude_opus_5(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)
        extractor.extract(text="some text", source=_SOURCE)
        assert client.messages.calls[0]["model"] == "claude-opus-5"

    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERBOT_ANTHROPIC_MODEL", "claude-haiku-4-5")
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)
        extractor.extract(text="some text", source=_SOURCE)
        assert client.messages.calls[0]["model"] == "claude-haiku-4-5"

    def test_constructor_param_overrides_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERBOT_ANTHROPIC_MODEL", "claude-haiku-4-5")
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(model="claude-sonnet-5", client=client)
        extractor.extract(text="some text", source=_SOURCE)
        assert client.messages.calls[0]["model"] == "claude-sonnet-5"


class TestLLMKnowledgeExtractorExtract:
    def test_requires_persisted_source(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)
        unpersisted = Source(name="No Id", source_type=SourceType.BLOG)
        with pytest.raises(ValueError, match="must be persisted"):
            extractor.extract(text="anything", source=unpersisted)

    def test_empty_text_short_circuits_without_calling_client(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)
        items = extractor.extract(text="   ", source=_SOURCE)
        assert items == []
        assert client.messages.calls == []

    def test_converts_extracted_items_to_knowledge_items(self) -> None:
        extracted = _ExtractedItem(
            title="SQL Injection",
            summary="Untrusted input concatenated into a SQL query.",
            category=VulnerabilityCategory.INPUT_VALIDATION,
            cwe="CWE-89",
            owasp_category="A03:2021",
            severity_hint=Severity.CRITICAL,
            tags=["sql injection", "database"],
        )
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result(extracted)))
        extractor = LLMKnowledgeExtractor(client=client)

        items = extractor.extract(text="SQL injection notes...", source=_SOURCE)

        assert len(items) == 1
        item = items[0]
        assert item.source_id == 1
        assert item.title == "SQL Injection"
        assert item.category == VulnerabilityCategory.INPUT_VALIDATION
        assert item.cwe == "CWE-89"
        assert item.owasp_category == "A03:2021"
        assert item.severity_hint == Severity.CRITICAL
        assert item.tags == ("sql injection", "database")
        assert len(item.content_hash) == 64

    def test_returns_empty_list_on_refusal(self) -> None:
        extracted = _ExtractedItem(
            title="Should not appear",
            summary="This should be discarded because the response was refused.",
            category=VulnerabilityCategory.OTHER,
        )
        response = _FakeResponse(parsed_output=_extraction_result(extracted), stop_reason="refusal")
        client = _FakeClient(response=response)
        extractor = LLMKnowledgeExtractor(client=client)

        items = extractor.extract(text="anything", source=_SOURCE)

        assert items == []

    def test_deduplicates_items_with_identical_summaries(self) -> None:
        first = _ExtractedItem(
            title="XSS",
            summary="Reflected cross-site scripting via an unescaped query parameter.",
            category=VulnerabilityCategory.INPUT_VALIDATION,
        )
        duplicate = _ExtractedItem(
            title="XSS (duplicate)",
            summary="Reflected cross-site scripting via an unescaped query parameter.",
            category=VulnerabilityCategory.INPUT_VALIDATION,
        )
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result(first, duplicate)))
        extractor = LLMKnowledgeExtractor(client=client)

        items = extractor.extract(text="anything", source=_SOURCE)

        assert len(items) == 1

    def test_skips_items_with_empty_title_or_summary(self) -> None:
        blank_title = _ExtractedItem(title="  ", summary="Valid summary text.", category=VulnerabilityCategory.OTHER)
        blank_summary = _ExtractedItem(title="Valid title", summary="  ", category=VulnerabilityCategory.OTHER)
        client = _FakeClient(
            response=_FakeResponse(parsed_output=_extraction_result(blank_title, blank_summary))
        )
        extractor = LLMKnowledgeExtractor(client=client)

        items = extractor.extract(text="anything", source=_SOURCE)

        assert items == []

    def test_client_errors_are_wrapped_as_llm_extraction_error(self) -> None:
        # Covers both typed SDK errors (APIStatusError, APIConnectionError)
        # and untyped ones the SDK raises directly (e.g. a TypeError when no
        # credentials are configured) -- all must surface as a clean,
        # catchable error rather than a raw traceback from SDK internals.
        client = _FakeClient(error=RuntimeError("boom"))
        extractor = LLMKnowledgeExtractor(client=client)

        with pytest.raises(LLMExtractionError, match="boom") as exc_info:
            extractor.extract(text="anything", source=_SOURCE)
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_sends_system_prompt_and_output_schema(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_extraction_result()))
        extractor = LLMKnowledgeExtractor(client=client)

        extractor.extract(text="some text", source=_SOURCE)

        call = client.messages.calls[0]
        assert "security knowledge extraction" in call["system"]
        assert call["output_format"] is _ExtractionResult
        assert call["messages"] == [{"role": "user", "content": "some text"}]
