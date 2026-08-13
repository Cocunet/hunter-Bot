from dataclasses import dataclass, field

import pytest

from hunterbot.core.domain import (
    Confidence,
    Finding,
    KnowledgeItem,
    Severity,
    TriagePriority,
    VulnerabilityCategory,
)
from hunterbot.reasoning import LLMAnalysisError, LLMFindingAnalyzer
from hunterbot.reasoning import llm_analyzer as llm_analyzer_module
from hunterbot.reasoning.llm_analyzer import _AnalysisResult, _AttackChainItem, _FindingTriageItem

_BASE_URL = "https://example.com"


def _finding(finding_id: int, title: str = "Test finding") -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="A test finding.",
        affected_asset=_BASE_URL,
        location=_BASE_URL + "/",
        scanner_name="stub-scanner",
    )


@dataclass
class _FakeResponse:
    parsed_output: _AnalysisResult
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


def _analysis_result(summary="A summary.", triage=(), attack_chains=()) -> _AnalysisResult:
    return _AnalysisResult(summary=summary, triage=list(triage), attack_chains=list(attack_chains))


class TestLLMFindingAnalyzerAvailability:
    def test_is_available_true_when_anthropic_installed(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)
        assert analyzer.is_available() is True

    def test_raises_when_anthropic_unavailable_and_no_client_given(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(llm_analyzer_module, "_ANTHROPIC_AVAILABLE", False)
        with pytest.raises(LLMAnalysisError, match="requires the 'llm' extra"):
            LLMFindingAnalyzer()

    def test_injected_client_bypasses_availability_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(llm_analyzer_module, "_ANTHROPIC_AVAILABLE", False)
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        LLMFindingAnalyzer(client=client)


class TestLLMFindingAnalyzerModelResolution:
    def test_defaults_to_claude_opus_5(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)
        analyzer.analyze(findings=[_finding(1)])
        assert client.messages.calls[0]["model"] == "claude-opus-5"

    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERBOT_ANTHROPIC_MODEL", "claude-haiku-4-5")
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)
        analyzer.analyze(findings=[_finding(1)])
        assert client.messages.calls[0]["model"] == "claude-haiku-4-5"

    def test_constructor_param_overrides_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("HUNTERBOT_ANTHROPIC_MODEL", "claude-haiku-4-5")
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(model="claude-sonnet-5", client=client)
        analyzer.analyze(findings=[_finding(1)])
        assert client.messages.calls[0]["model"] == "claude-sonnet-5"


class TestLLMFindingAnalyzerAnalyze:
    def test_empty_findings_short_circuits_without_calling_client(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[])

        assert result.summary == "No findings to analyze."
        assert client.messages.calls == []

    def test_converts_triage_and_attack_chains(self) -> None:
        triage_item = _FindingTriageItem(finding_id=1, priority=TriagePriority.HIGH, reasoning="Exploitable.")
        chain_item = _AttackChainItem(
            title="Config leak enables takeover",
            finding_ids=[1, 2],
            narrative="Combined, these expose credentials.",
            severity=Severity.CRITICAL,
        )
        response = _FakeResponse(
            parsed_output=_analysis_result(
                summary="High risk target.", triage=[triage_item], attack_chains=[chain_item]
            )
        )
        client = _FakeClient(response=response)
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[_finding(1), _finding(2)])

        assert result.summary == "High risk target."
        assert len(result.triage) == 1
        assert result.triage[0].finding_id == 1
        assert result.triage[0].priority == TriagePriority.HIGH
        assert len(result.attack_chains) == 1
        assert result.attack_chains[0].finding_ids == (1, 2)
        assert result.attack_chains[0].severity == Severity.CRITICAL

    def test_filters_out_triage_referencing_unknown_finding_id(self) -> None:
        triage_item = _FindingTriageItem(finding_id=999, priority=TriagePriority.HIGH, reasoning="Hallucinated.")
        response = _FakeResponse(parsed_output=_analysis_result(triage=[triage_item]))
        client = _FakeClient(response=response)
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[_finding(1)])

        assert result.triage == ()

    def test_drops_attack_chain_left_with_no_valid_finding_ids(self) -> None:
        chain_item = _AttackChainItem(
            title="Hallucinated chain", finding_ids=[999], narrative="Not real.", severity=Severity.HIGH
        )
        response = _FakeResponse(parsed_output=_analysis_result(attack_chains=[chain_item]))
        client = _FakeClient(response=response)
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[_finding(1)])

        assert result.attack_chains == ()

    def test_partially_hallucinated_attack_chain_keeps_valid_ids_only(self) -> None:
        chain_item = _AttackChainItem(
            title="Mixed chain", finding_ids=[1, 999], narrative="Partly real.", severity=Severity.HIGH
        )
        response = _FakeResponse(parsed_output=_analysis_result(attack_chains=[chain_item]))
        client = _FakeClient(response=response)
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[_finding(1)])

        assert len(result.attack_chains) == 1
        assert result.attack_chains[0].finding_ids == (1,)

    def test_returns_declined_summary_on_refusal(self) -> None:
        response = _FakeResponse(parsed_output=_analysis_result(), stop_reason="refusal")
        client = _FakeClient(response=response)
        analyzer = LLMFindingAnalyzer(client=client)

        result = analyzer.analyze(findings=[_finding(1)])

        assert "declined" in result.summary.lower()

    def test_client_errors_are_wrapped_as_llm_analysis_error(self) -> None:
        client = _FakeClient(error=RuntimeError("boom"))
        analyzer = LLMFindingAnalyzer(client=client)

        with pytest.raises(LLMAnalysisError, match="boom") as exc_info:
            analyzer.analyze(findings=[_finding(1)])
        assert isinstance(exc_info.value.__cause__, RuntimeError)

    def test_sends_system_prompt_and_output_schema(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)

        analyzer.analyze(findings=[_finding(1)])

        call = client.messages.calls[0]
        assert "security triage" in call["system"]
        assert call["output_format"] is _AnalysisResult

    def test_includes_knowledge_context_in_prompt(self) -> None:
        client = _FakeClient(response=_FakeResponse(parsed_output=_analysis_result()))
        analyzer = LLMFindingAnalyzer(client=client)
        knowledge_item = KnowledgeItem(
            id=7,
            source_id=1,
            category=VulnerabilityCategory.MISSING_SECURITY_HEADERS,
            title="Missing X-Frame-Options",
            summary="Enables clickjacking.",
            content_hash="a" * 64,
        )

        analyzer.analyze(findings=[_finding(1)], knowledge_context=[knowledge_item])

        prompt = client.messages.calls[0]["messages"][0]["content"]
        assert "Missing X-Frame-Options" in prompt
